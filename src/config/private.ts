import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { z } from 'zod';
import { UserError } from '../shared/errors.js';
import { isHostname } from '../conversion/network.js';

export const URLTEST_DEFAULTS = {
  url: 'https://www.gstatic.com/generate_204', interval: '1m', tolerance: 80,
};

export function validConnectionName(name: string): boolean {
  const match = /^([A-Za-z0-9][A-Za-z0-9_-]*)(?: [\u{1F1E6}-\u{1F1FF}]{2})?$/u.exec(name);
  return !!match && match[0] === name && [...name].length <= 64 && !['auto', 'vpn', '__proto__', 'constructor', 'prototype'].includes(match[1]!);
}

const nonempty = z.string().trim().min(1);
const port = z.number().int().min(1).max(65535);
const host = z.string().refine(value => !!isIP(value) || isHostname(value), 'Нужен IP или hostname');
const httpUrl = z.string().refine(value => {
  try { const u = new URL(value); return ['http:', 'https:'].includes(u.protocol) && !u.username && !u.password && !u.hash; }
  catch { return false; }
}, 'Нужен HTTP(S) URL без credentials и fragment');
const httpsUrl = httpUrl.refine(value => value.startsWith('https:'), 'Нужен HTTPS URL');

export function privateIpv4Subnet(value: string): boolean {
  try {
    const [ip, prefix] = ipaddr.parseCIDR(value);
    if (ip.kind() !== 'ipv4' || !/^\d+\.\d+\.\d+\.\d+\/(?:[1-9]|[12]\d|3[0-2])$/.test(value)) return false;
    const bytes = ip.toByteArray();
    const address = bytes.reduce((n, byte) => n * 256 + byte, 0);
    const size = 2 ** (32 - prefix);
    if (address % size !== 0) return false;
    return (bytes[0] === 10 && prefix >= 8) ||
      (bytes[0] === 172 && bytes[1]! >= 16 && bytes[1]! <= 31 && prefix >= 12) ||
      (bytes[0] === 192 && bytes[1] === 168 && prefix >= 16);
  } catch { return false; }
}

export function subnetsOverlap(left: string, right: string): boolean {
  const [a, pa] = ipaddr.parseCIDR(left);
  const [b, pb] = ipaddr.parseCIDR(right);
  return a.kind() === b.kind() && a.match(b, Math.min(pa, pb));
}

const subnet = z.string().refine(privateIpv4Subnet, 'Нужна приватная IPv4-подсеть с адресом сети');
const reservedSubnet = z.string().refine(value => {
  try { ipaddr.parseCIDR(value); return true; } catch { return false; }
}, 'Нужен CIDR');
const endpoint = z.strictObject({ host, port });
const wgInbound = z.strictObject({
  port, subnet, mtu: z.number().int().min(576).max(65535).optional(), endpoint: endpoint.optional(),
});
const realityInbound = z.strictObject({
  port,
  reality: z.strictObject({
    target: z.string().refine(value => {
      try {
        const match = value.startsWith('[') ? /^\[([^\]]+)\]:(\d+)$/.exec(value) : /^([^:]+):(\d+)$/.exec(value);
        return !!match && (!!isIP(match[1]!) || isHostname(match[1]!)) && Number(match[2]) > 0 && Number(match[2]) <= 65535;
      } catch { return false; }
    }, 'Нужен host:port'),
    serverNames: z.array(host).min(1),
  }),
  endpoint: endpoint.optional(),
});

export const panelSchema = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('wg-easy'), url: httpUrl, password: nonempty }),
  z.strictObject({ type: z.literal('3x-ui'), url: httpUrl, apiToken: nonempty }),
]);
export const connectionSchema = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('wireguard'), panel: nonempty, inbound: wgInbound.optional() }),
  z.strictObject({ type: z.literal('vless-reality'), panel: nonempty, inbound: realityInbound }),
]);

export const vpnConfigSchema = z.strictObject({
  version: z.literal(1),
  panels: z.record(z.string(), panelSchema).optional(),
  connections: z.record(z.string().refine(validConnectionName, 'Недопустимое имя подключения'), connectionSchema).optional(),
  s3: z.strictObject({ endpoint: httpsUrl, region: nonempty, bucket: nonempty, accessKeyId: nonempty, secretAccessKey: nonempty }).optional(),
  routing: z.strictObject({ rulesUrl: httpsUrl }).optional(),
  dns: z.strictObject({ server: host, serverName: host }).optional(),
  urltest: z.strictObject({
    url: httpsUrl.default(URLTEST_DEFAULTS.url),
    interval: z.string().regex(/^(?:[1-9]\d*)(?:ms|s|m|h)$/, 'Нужна положительная длительность').default(URLTEST_DEFAULTS.interval),
    tolerance: z.number().int().min(0).max(65535).default(URLTEST_DEFAULTS.tolerance),
  }).default(URLTEST_DEFAULTS),
  network: z.strictObject({ reservedSubnets: z.array(reservedSubnet).default([]) }).optional(),
}).superRefine((config, ctx) => {
  const problem = (path: (string | number)[], message: string) => ctx.addIssue({ code: 'custom', path, message });
  const ranges: { name: string; subnet: string }[] = [];
  for (const [name, connection] of Object.entries(config.connections ?? {})) {
    const panel = config.panels?.[connection.panel];
    if (!panel) { problem(['connections', name, 'panel'], 'Не найдена панель'); continue; }
    if (panel.type === 'wg-easy') {
      if (connection.type !== 'wireguard') problem(['connections', name, 'type'], 'wg-easy поддерживает только WireGuard');
      if (connection.inbound !== undefined) problem(['connections', name, 'inbound'], 'Для wg-easy inbound не задаётся');
      continue;
    }
    if (!name.startsWith('3x-')) problem(['connections', name], 'Имя подключения 3x-ui должно начинаться с 3x-');
    if (!connection.inbound) { problem(['connections', name, 'inbound'], 'Нужны параметры создания inbound'); continue; }
    if (connection.type === 'wireguard') ranges.push({ name, subnet: connection.inbound.subnet });
  }
  for (const [index, range] of ranges.entries()) {
    if (!privateIpv4Subnet(range.subnet)) continue;
    const reserved = ['172.19.0.0/30', 'fdfe:dcba:9876::/126', ...(config.network?.reservedSubnets ?? [])];
    if (reserved.some(other => { try { return subnetsOverlap(range.subnet, other); } catch { return false; } })) {
      problem(['connections', range.name, 'inbound', 'subnet'], 'Подсеть пересекается с зарезервированной сетью или TUN');
    }
    for (const earlier of ranges.slice(0, index)) {
      if (privateIpv4Subnet(earlier.subnet) && subnetsOverlap(range.subnet, earlier.subnet)) {
        problem(['connections', range.name, 'inbound', 'subnet'], 'Подсеть пересекается с другим WG-пулом');
      }
    }
  }
});

export type VpnConfig = z.infer<typeof vpnConfigSchema>;
export type PanelConfig = z.infer<typeof panelSchema>;
export type ConnectionConfig = z.infer<typeof connectionSchema>;

export function parseVpnConfig(input: unknown): VpnConfig {
  const parsed = vpnConfigSchema.safeParse(input);
  if (!parsed.success) {
    // Never include Zod input or its default messages: unknown-key errors can contain secrets.
    const fields = [...new Set(parsed.error.issues.map(issue => {
      const path = issue.path.map(part => typeof part === 'number' ? String(part) : /^[\w-]{1,64}$/.test(String(part)) ? String(part) : '<ключ>').join('.') || 'config';
      const reason = issue.code === 'custom' ? issue.message : 'неверное значение или структура';
      return `${path}: ${reason}`;
    }))];
    throw new UserError(`Невалидный приватный конфиг: ${fields.join('; ')}.`);
  }
  return parsed.data;
}

export async function loadVpnConfig(path?: string, env: NodeJS.ProcessEnv = process.env): Promise<VpnConfig> {
  const selected = path ?? env.VPN_CONFIG;
  if (!selected?.trim()) throw new UserError('Укажите --config <file> или VPN_CONFIG.');
  let contents: string;
  try { contents = await readFile(resolve(selected), 'utf8'); }
  catch { throw new UserError('Не удалось прочитать приватный конфиг.'); }
  let input: unknown;
  try { input = JSON.parse(contents); }
  catch { throw new UserError('Некорректный JSON приватного конфига.'); }
  return parseVpnConfig(input);
}

export function requireConfig(config: VpnConfig, needs: Array<'panels' | 's3' | 'routing' | 'dns'>): void {
  for (const field of needs) if (!config[field]) throw new UserError(`Для команды требуется раздел ${field}.`);
  if (needs.includes('panels') && !Object.keys(config.connections ?? {}).length) {
    throw new UserError('Для команды нужен непустой раздел connections.');
  }
}
