import { generateKeyPairSync, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { z } from 'zod';
import type { ConnectionConfig } from '../config/private.js';
import { privateIpv4Subnet, subnetsOverlap } from '../config/private.js';
import { UserError } from '../shared/errors.js';
import { requestText } from '../shared/http.js';
import { validateUrl } from '../shared/validation.js';
import { applyClientPatches, createClientPatchRegistry, type ClientPatchRegistry } from './client-patches.js';

const objectSchema = z.record(z.string(), z.unknown());
const jsonObjectSchema = z.preprocess(value => {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value) as unknown; } catch { return null; }
}, objectSchema);
const inboundSchema = z.object({
  id: z.number().int().positive(), remark: z.string(), protocol: z.string(),
  port: z.number().int().min(1).max(65535), enable: z.boolean(),
  listen: z.string().nullish(), nodeId: z.number().nullish(),
  settings: jsonObjectSchema, streamSettings: z.preprocess(value => value == null || value === '' ? {} : value, jsonObjectSchema),
}).passthrough();
export type ThreeXInbound = z.infer<typeof inboundSchema>;
const clientSchema = z.object({
  email: z.string(), id: z.union([z.number(), z.string()]).optional(), uuid: z.string().optional(),
  enable: z.boolean().optional(), flow: z.string().optional(),
  privateKey: z.string().optional(), publicKey: z.string().optional(),
  allowedIPs: z.union([z.string(), z.array(z.string())]).optional(),
}).passthrough();
const hydrateSchema = z.object({
  client: clientSchema, inboundIds: z.array(z.number().int()).nullish().transform(value => value ?? []),
  tunnelAllowedIPs: z.record(z.string(), z.string()).optional(),
}).passthrough();
export type ThreeXClient = z.infer<typeof hydrateSchema>;
const envelopeSchema = z.object({ success: z.boolean(), msg: z.string().optional(), obj: z.unknown().optional() });

function parsed<T>(schema: z.ZodType<T>, input: unknown, label: string): T {
  const result = schema.safeParse(input);
  if (!result.success) throw new UserError(`3x-ui: неверный формат ${label}.`);
  return result.data;
}
function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
function strings(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return typeof value === 'string' ? value.split(',').map(x => x.trim()).filter(Boolean) : [];
}
function entries(inbound: ThreeXInbound): Record<string, unknown>[] {
  return ['clients', 'peers'].flatMap(field => Array.isArray(inbound.settings[field])
    ? (inbound.settings[field] as unknown[]).map(record) : []);
}
function transport(inbound: ThreeXInbound): string {
  return String(inbound.streamSettings.network ?? inbound.streamSettings.method ?? 'tcp').toLowerCase();
}
function reality(inbound: ThreeXInbound): Record<string, unknown> { return record(inbound.streamSettings.realitySettings); }
function keyBytes(key: string): Buffer {
  const bytes = Buffer.from(key, 'base64');
  if (bytes.length !== 32) throw new UserError('3x-ui: неверный ключ WireGuard.');
  return bytes;
}
function wgPublicKey(privateKey: string): string {
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), keyBytes(privateKey)]), format: 'der', type: 'pkcs8' });
  return Buffer.from(String(createPublicKey(key).export({ format: 'jwk' }).x), 'base64url').toString('base64');
}
function realityPublicKey(inbound: ThreeXInbound): string {
  const r = reality(inbound);
  const supplied = record(r.settings).publicKey ?? r.publicKey;
  if (typeof supplied === 'string' && supplied) return supplied;
  if (typeof r.privateKey !== 'string') return '';
  return Buffer.from(wgPublicKey(Buffer.from(r.privateKey, 'base64url').toString('base64')), 'base64').toString('base64url');
}
function addressesInside(addresses: string[], subnet: string): boolean {
  const [network, bits] = ipaddr.parseCIDR(subnet);
  return addresses.length > 0 && addresses.every(address => {
    try { const [ip, prefix] = ipaddr.parseCIDR(address); return ip.kind() === 'ipv4' && prefix === 32 && ip.match(network, bits); }
    catch { return false; }
  });
}

export class ThreeXClientApi {
  private readonly baseUrl: string;
  constructor(url: string, private readonly token: string, private readonly patches: ClientPatchRegistry = createClientPatchRegistry()) {
    const base = validateUrl(url, '3x-ui URL');
    if (base.search || base.hash || base.username || base.password || !token) throw new UserError('Неверные настройки доступа к 3x-ui.');
    this.baseUrl = `${base.href.replace(/\/+$/, '')}/panel/api/`;
  }
  private async envelope(path: string, body?: unknown) {
    const response = await requestText(`${this.baseUrl}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { Authorization: `Bearer ${this.token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }, '3x-ui');
    let value: unknown;
    try { value = JSON.parse(response.text); } catch { throw new UserError('3x-ui: ответ не является JSON.'); }
    return parsed(envelopeSchema, value, 'ответа API');
  }
  async request(path: string, body?: unknown): Promise<unknown> {
    const response = await this.envelope(path, body);
    if (!response.success) throw new UserError('3x-ui: операция не выполнена; проверьте состояние панели.');
    return response.obj;
  }
  async status(): Promise<Record<string, unknown>> { return parsed(objectSchema, await this.request('server/status'), 'статуса'); }
  async listInbounds(): Promise<ThreeXInbound[]> {
    const list = parsed(z.array(inboundSchema), await this.request('inbounds/list'), 'списка inbound');
    if (new Set(list.map(x => x.id)).size !== list.length) throw new UserError('3x-ui: повторные ID inbound.');
    return list;
  }
  async getClient(email: string): Promise<ThreeXClient | undefined> {
    const response = await this.envelope(`clients/get/${encodeURIComponent(email)}`);
    if (!response.success) {
      if (response.obj == null && /record not found/i.test(response.msg ?? '')) return undefined;
      throw new UserError('3x-ui: не удалось получить клиента.');
    }
    const result = parsed(hydrateSchema, response.obj, 'клиента');
    if (result.client.email !== email) throw new UserError('3x-ui: получен другой клиент.');
    return result;
  }
  async links(email: string): Promise<string[]> {
    return parsed(z.array(z.string()), await this.request(`clients/links/${encodeURIComponent(email)}`), 'ссылок клиента');
  }
  findInbound(inbounds: ThreeXInbound[], name: string): ThreeXInbound | undefined {
    const matching = inbounds.filter(x => (x.nodeId == null || x.nodeId === 0) && x.remark === name);
    if (matching.length > 1) throw new UserError(`3x-ui: неоднозначное примечание ${name}.`);
    return matching[0];
  }
  validateInbound(inbound: ThreeXInbound, connection: ConnectionConfig, name: string): void {
    const expected = connection.inbound;
    if (!expected) throw new UserError(`Подключению ${name} нужны параметры inbound.`);
    const fail = (field: string): never => { throw new UserError(`3x-ui: ${name}: конфликт ${field}.`); };
    if (!inbound.enable) fail('enable');
    if (inbound.port !== expected.port) fail('port');
    if (connection.type === 'wireguard') {
      if (inbound.protocol !== 'wireguard') fail('protocol');
      const wg = connection.inbound!;
      if (wg.mtu !== undefined && inbound.settings.mtu !== wg.mtu) fail('mtu');
      if (typeof inbound.settings.subnetIp === 'string' && inbound.settings.subnetIp && typeof inbound.settings.subnetCidr === 'number' &&
          `${inbound.settings.subnetIp}/${inbound.settings.subnetCidr}` !== wg.subnet) fail('subnet');
      for (const client of entries(inbound)) {
        const addresses = strings(client.allowedIPs).filter(x => !['0.0.0.0/0', '::/0'].includes(x));
        if (addresses.length && !addressesInside(addresses, wg.subnet)) fail('subnet');
      }
    } else {
      if (inbound.protocol !== 'vless' || !['tcp', 'raw'].includes(transport(inbound)) || inbound.streamSettings.security !== 'reality') fail('protocol/transport/security');
      const r = reality(inbound);
      if ((r.target ?? r.dest) !== connection.inbound.reality.target) fail('reality.target');
      const actual = strings(r.serverNames).sort();
      if (JSON.stringify(actual) !== JSON.stringify([...connection.inbound.reality.serverNames].sort())) fail('reality.serverNames');
    }
  }
  async ensureInbound(name: string, connection: ConnectionConfig, inbounds: ThreeXInbound[], readOnly = false): Promise<ThreeXInbound> {
    const existing = this.findInbound(inbounds, name);
    if (existing) { this.validateInbound(existing, connection, name); return existing; }
    if (readOnly) throw new UserError(`3x-ui: inbound ${name} отсутствует (только чтение).`);
    const expected = connection.inbound;
    if (!expected) throw new UserError(`Подключению ${name} нужны параметры inbound.`);
    const udp = connection.type === 'wireguard';
    if (inbounds.some(x => (x.nodeId == null || x.nodeId === 0) && x.port === expected.port && (x.protocol === 'wireguard') === udp)) {
      throw new UserError(`3x-ui: ${name}: порт занят другим inbound.`);
    }
    const body: Record<string, unknown> = {
      remark: name, enable: true, listen: '', port: expected.port, expiryTime: 0, total: 0,
      sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false },
    };
    if (connection.type === 'wireguard') {
      const cfg = connection.inbound!;
      if (!privateIpv4Subnet(cfg.subnet)) throw new UserError(`3x-ui: ${name}: нужна приватная подсеть.`);
      for (const other of inbounds.filter(x => x.protocol === 'wireguard' || x.protocol === 'amneziawg')) {
        const pool = other.protocol === 'wireguard' ? other.settings : record(other.settings.server);
        if (typeof pool.subnetIp === 'string' && pool.subnetIp && typeof pool.subnetCidr === 'number' && subnetsOverlap(cfg.subnet, `${pool.subnetIp}/${pool.subnetCidr}`)) {
          throw new UserError(`3x-ui: ${name}: подсеть пересекается с существующим WG-пулом.`);
        }
      }
      const { privateKey } = generateKeyPairSync('x25519');
      const secretKey = Buffer.from(String(privateKey.export({ format: 'jwk' }).d), 'base64url').toString('base64');
      Object.assign(body, { protocol: 'wireguard', settings: {
        secretKey, clients: [], peers: [], noKernelTun: false, subnetIp: cfg.subnet.split('/')[0], subnetCidr: Number(cfg.subnet.split('/')[1]),
        ...(cfg.mtu === undefined ? {} : { mtu: cfg.mtu }),
      }, streamSettings: {} });
    } else {
      const keys = parsed(z.object({ privateKey: z.string().min(1), publicKey: z.string().min(1) }), await this.request('server/getNewX25519Cert'), 'ключей REALITY');
      Object.assign(body, { protocol: 'vless', settings: { clients: [], decryption: 'none', fallbacks: [] }, streamSettings: {
        network: 'tcp', security: 'reality', realitySettings: {
          show: false, target: connection.inbound.reality.target, xver: 0,
          serverNames: connection.inbound.reality.serverNames, privateKey: keys.privateKey,
          shortIds: [randomBytes(8).toString('hex')], settings: {
            publicKey: keys.publicKey, fingerprint: 'chrome', serverName: connection.inbound.reality.serverNames[0], spiderX: '/',
          },
        },
      } });
    }
    // A failed response can mean that creation succeeded. Re-read before deciding.
    let failed = false;
    try { await this.request('inbounds/add', body); } catch { failed = true; }
    const after = await this.listInbounds();
    const created = this.findInbound(after, name);
    if (!created) throw new UserError(`3x-ui: ${name}: ${failed ? 'результат создания не подтверждён' : 'созданный inbound не найден'}; POST не повторялся.`);
    this.validateInbound(created, connection, name);
    inbounds.splice(0, inbounds.length, ...after);
    return created;
  }
  async ensureClient(email: string, selected: { name: string; config: ConnectionConfig; inbound: ThreeXInbound }[], inbounds: ThreeXInbound[], readOnly = false): Promise<ThreeXClient> {
    let client = await this.getClient(email);
    if (client?.client.enable === false) throw new UserError('3x-ui: клиент отключён.');
    const targets = selected.map(target => target.inbound);
    const patchContext = { ...(client ? { client } : {}), targets, inbounds };
    // Validate all protocol requirements before creating or attaching anything.
    // The same requirements seed new clients and reconcile existing ones.
    const creationFields = this.patches.creationFields(patchContext);
    const wgSelected = selected.filter(x => x.config.type === 'wireguard');
    let addresses = strings(client?.client.allowedIPs);
    if (wgSelected.length) {
      const first = wgSelected[0]!;
      const subnet = first.config.type === 'wireguard' ? first.config.inbound!.subnet : '';
      if (!addresses.length) addresses = [allocateAddress(subnet, inbounds, email)];
      // 3x-ui currently carries one WG address on ClientRecord during attach.
      // Never silently renumber or claim success for incompatible disjoint pools.
      if (wgSelected.some(x => x.config.type === 'wireguard' && !addressesInside(addresses, x.config.inbound!.subnet))) {
        throw new UserError('3x-ui: адрес WG-клиента не входит во все выбранные WG-пулы; существующие адреса не менялись.');
      }
    }
    if (!client) {
      if (readOnly) throw new UserError('3x-ui: клиент отсутствует (только чтение).');
      // Start with a protocol that uses the requested fields, so the panel does
      // not discard them as irrelevant to the initial binding (e.g. WG + flow).
      const first = selected.find(target => this.patches.requirements({ targets: [target.inbound], inbounds }).length > 0) ?? selected[0]!;
      const payload: Record<string, unknown> = { email, enable: true, totalGB: 0, expiryTime: 0, limitIp: 0, tgId: 0, subId: randomBytes(12).toString('hex') };
      Object.assign(payload, creationFields);
      if (addresses.length) payload.allowedIPs = addresses;
      try { await this.request('clients/add', { client: payload, inboundIds: [first.inbound.id] }); } catch { /* read-back below is authoritative */ }
      client = await this.getClient(email);
      if (!client) throw new UserError('3x-ui: создание клиента не подтверждено; POST не повторялся.');
    }
    for (const target of selected) {
      if (client.inboundIds.includes(target.inbound.id)) continue;
      if (readOnly) throw new UserError(`3x-ui: нет привязки ${target.name} (только чтение).`);
      try { await this.request(`clients/${encodeURIComponent(email)}/attach`, { inboundIds: [target.inbound.id] }); } catch { /* even success:false can have attached some inbounds */ }
      const after = await this.getClient(email);
      if (!after || !after.inboundIds.includes(target.inbound.id)) throw new UserError(`3x-ui: привязка ${target.name} не подтверждена; POST не повторялся.`);
      client = after;
    }
    // Attach may generate protocol fields or drop irrelevant creation fields.
    // Plan against the latest read-back and apply only still-missing values.
    client = await applyClientPatches(this.patches, { client, targets, inbounds }, this, readOnly);
    for (const target of wgSelected) {
      const actual = strings(client.tunnelAllowedIPs?.[String(target.inbound.id)] ?? client.client.allowedIPs);
      if (target.config.type === 'wireguard' && !addressesInside(actual, target.config.inbound!.subnet)) throw new UserError(`3x-ui: ${target.name}: панель выдала адрес вне заданной подсети.`);
    }
    return client;
  }
  selectLink(links: string[], client: ThreeXClient, inbound: ThreeXInbound, connection: ConnectionConfig, name: string): string {
    const endpoint = connection.inbound?.endpoint;
    const candidates = links.filter(link => {
      let uri: URL;
      try { uri = new URL(link); } catch { return false; }
      const hostname = uri.hostname.replace(/^\[|\]$/g, '').toLowerCase();
      if (endpoint && (hostname !== endpoint.host.replace(/^\[|\]$/g, '').toLowerCase() || Number(uri.port) !== endpoint.port)) return false;
      // Without a user endpoint, use the inbound's advertised port; credentials
      // additionally bind the URL to the specific inbound even with shared hosts.
      const advertised = advertisedEndpoints(inbound);
      if (!endpoint && advertised.length && !advertised.some(x => x.host.toLowerCase() === hostname && x.port === Number(uri.port))) return false;
      if (!endpoint && !advertised.length && Number(uri.port) !== inbound.port) return false;
      if (connection.type === 'wireguard') {
        if (uri.protocol !== 'wireguard:') return false;
        const key = typeof inbound.settings.publicKey === 'string' ? inbound.settings.publicKey : typeof inbound.settings.pubKey === 'string' ? inbound.settings.pubKey :
          typeof inbound.settings.secretKey === 'string' ? wgPublicKey(inbound.settings.secretKey) : '';
        if (!key || uri.searchParams.get('publickey') !== key) return false;
        let privateKey: string;
        try { privateKey = decodeURIComponent(uri.username); } catch { return false; }
        return privateKey === client.client.privateKey;
      }
      if (uri.protocol !== 'vless:' || uri.searchParams.get('security') !== 'reality' || uri.searchParams.get('flow') !== 'xtls-rprx-vision') return false;
      const uuid = client.client.uuid ?? (typeof client.client.id === 'string' ? client.client.id : '');
      const r = reality(inbound);
      let username: string;
      try { username = decodeURIComponent(uri.username); } catch { return false; }
      return username === uuid && uri.searchParams.get('pbk') === realityPublicKey(inbound) &&
        strings(r.shortIds).includes(uri.searchParams.get('sid') ?? '') && strings(r.serverNames).includes(uri.searchParams.get('sni') ?? '');
    });
    const byIdentity = new Map<string, string>();
    for (const candidate of candidates) {
      const uri = new URL(candidate); uri.hash = ''; uri.searchParams.sort();
      if (!byIdentity.has(uri.href)) byIdentity.set(uri.href, candidate);
    }
    const unique = [...byIdentity.values()];
    if (unique.length !== 1) throw new UserError(`3x-ui: ${name}: ${unique.length ? 'неоднозначные ссылки; укажите inbound.endpoint' : 'подходящая ссылка не найдена'}.`);
    return unique[0]!;
  }
}

export function allocateAddress(subnet: string, inbounds: ThreeXInbound[], email: string): string {
  if (!privateIpv4Subnet(subnet)) throw new UserError('Неверная подсеть выделения WG.');
  const [network, prefix] = ipaddr.parseCIDR(subnet);
  const base = network.toByteArray().reduce((n, byte) => n * 256 + byte, 0);
  const size = 2 ** (32 - prefix);
  const occupied = inbounds.filter(x => ['wireguard', 'amneziawg'].includes(x.protocol)).flatMap(entries)
    .filter(x => x.email !== email).flatMap(x => strings(x.allowedIPs)).filter(x => !['0.0.0.0/0', '::/0'].includes(x));
  const ranges = occupied.map(cidr => {
    try {
      const [ip, bits] = ipaddr.parseCIDR(cidr);
      if (ip.kind() !== 'ipv4') return undefined;
      const n = ip.toByteArray().reduce((a, b) => a * 256 + b, 0), length = 2 ** (32 - bits);
      return { start: Math.floor(n / length) * length, end: Math.floor(n / length) * length + length - 1 };
    } catch { throw new UserError('3x-ui: некорректный занятый WG-адрес.'); }
  }).filter((x): x is { start: number; end: number } => x !== undefined).sort((a, b) => a.start - b.start);
  // Reserve network, gateway (.1) and broadcast for ordinary pools.
  let candidate = base + (prefix <= 30 ? 2 : 0);
  const end = base + size - (prefix <= 30 ? 2 : 1);
  for (const range of ranges) {
    if (range.start > candidate) break;
    if (range.end >= candidate) candidate = range.end + 1;
  }
  if (candidate > end) throw new UserError('3x-ui: WG-пул исчерпан.');
  return `${[24, 16, 8, 0].map(shift => Math.floor(candidate / 2 ** shift) % 256).join('.')}/32`;
}
function advertisedEndpoints(inbound: ThreeXInbound): { host: string; port: number }[] {
  const result: { host: string; port: number }[] = [];
  if (inbound.shareAddrStrategy === 'custom' && typeof inbound.shareAddr === 'string' && inbound.shareAddr) result.push({ host: inbound.shareAddr, port: inbound.port });
  for (const item of Array.isArray(inbound.streamSettings.externalProxy) ? inbound.streamSettings.externalProxy : []) {
    const x = record(item);
    if (typeof x.dest === 'string' && typeof x.port === 'number') result.push({ host: x.dest.replace(/^\[|\]$/g, ''), port: x.port });
  }
  if (typeof inbound.listen === 'string' && isIP(inbound.listen) && !['0.0.0.0', '::'].includes(inbound.listen) && !result.length) result.push({ host: inbound.listen, port: inbound.port });
  return result;
}
