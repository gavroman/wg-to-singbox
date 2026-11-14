import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import type { JsonObject, WireGuardConfig } from '../types.js';
import { UserError, invalidConfig } from '../shared/errors.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { validateUrl } from '../shared/validation.js';
import { URLTEST_DEFAULTS, validConnectionName } from '../config/private.js';
import { buildSingleWireGuardConfig } from './builder.js';
import { parseWireGuard } from './parser.js';
import { integer, isHostname, parseEndpoint } from './network.js';
import { validateWireGuard } from './validation.js';

export type ConnectionMap = Record<string, string>;
export interface ParsedConnection {
  section: 'endpoints' | 'outbounds';
  config: JsonObject;
  wireGuard?: WireGuardConfig;
}
export type ConnectionHandler = (url: URL, tag: string) => ParsedConnection;

const handlers = new Map<string, ConnectionHandler>();

// Registering a parser does not change grouping, DNS or publication.
export function registerConnectionProtocol(protocol: string, handler: ConnectionHandler): () => void {
  if (!/^[a-z][a-z0-9+-]*$/.test(protocol) || handlers.has(protocol)) throw new UserError('Обработчик протокола уже существует или имя неверно.');
  handlers.set(protocol, handler);
  return () => { handlers.delete(protocol); };
}

export function parseConnectionMap(input: unknown): ConnectionMap {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new UserError('Нужна мапка имя подключения → URI.');
  const entries = Object.entries(input);
  if (!entries.length) throw new UserError('Мапка подключений пуста.');
  for (const [name, value] of entries) {
    if (!validConnectionName(name)) throw new UserError('Недопустимое или зарезервированное имя подключения.');
    if (typeof value !== 'string' || !value.trim()) throw new UserError(`Подключение ${name}: нужен URI.`);
  }
  return Object.fromEntries(entries) as ConnectionMap;
}

function checkedUrl(value: string): URL {
  try {
    const url = new URL(value);
    if (url.password || !url.username || (url.pathname && url.pathname !== '/')) throw new Error();
    parseEndpoint(`${url.hostname}:${url.port}`);
    decodeURIComponent(url.username);
    return url;
  } catch { throw new UserError('Некорректный URI подключения.'); }
}

function parameters(url: URL, allowed: string[]): URLSearchParams {
  const seen = new Set<string>();
  for (const [key] of url.searchParams) {
    if (seen.has(key) || !allowed.includes(key)) throw new UserError('Повторный или неподдерживаемый параметр URI.');
    seen.add(key);
  }
  return url.searchParams;
}

function required(params: URLSearchParams, key: string): string {
  const value = params.get(key);
  if (!value) throw new UserError(`В URI не задан ${key}.`);
  return value;
}

function list(params: URLSearchParams, key: string, fallback?: string): string[] {
  const value = params.get(key) ?? fallback;
  if (value === undefined) return [];
  const result = value.split(',').map(item => item.trim());
  if (result.some(item => !item)) throw new UserError(`В URI неверный ${key}.`);
  return result;
}

function optionalNumber(params: URLSearchParams, key: string, min: number, max: number): number | undefined {
  const value = params.get(key);
  return value === null ? undefined : integer(value, key, min, max);
}

export function parseWireGuardUri(value: string): WireGuardConfig {
  const url = checkedUrl(value);
  if (url.protocol !== 'wireguard:') throw new UserError('Ожидается WireGuard URI.');
  const p = parameters(url, ['address', 'publickey', 'mtu', 'allowedips', 'presharedkey', 'keepalive', 'listenport', 'dns']);
  required(p, 'address');
  const mtu = optionalNumber(p, 'mtu', 576, 65535);
  const listenPort = optionalNumber(p, 'listenport', 0, 65535);
  const keepalive = optionalNumber(p, 'keepalive', 0, 65535);
  const presharedKey = p.get('presharedkey');
  const config: WireGuardConfig = {
    privateKey: decodeURIComponent(url.username), addresses: list(p, 'address'), dns: list(p, 'dns'),
    ...(mtu !== undefined ? { mtu } : {}), ...(listenPort !== undefined ? { listenPort } : {}),
    peers: [{
      publicKey: required(p, 'publickey'), endpoint: parseEndpoint(`${url.hostname}:${url.port}`),
      allowedIps: list(p, 'allowedips', '0.0.0.0/0'),
      ...(presharedKey !== null ? { presharedKey } : {}), ...(keepalive !== undefined ? { keepalive } : {}),
    }],
  };
  validateWireGuard(config, false);
  return config;
}

export function wireGuardToUri(text: string): string {
  const wg = parseWireGuard(text);
  if (wg.peers.length !== 1) throw new UserError('WireGuard URI поддерживает ровно один Peer; многопировый .conf не преобразуется.');
  const peer = wg.peers[0]!;
  const host = isIP(peer.endpoint.address) === 6 ? `[${peer.endpoint.address}]` : peer.endpoint.address;
  const p = new URLSearchParams({ address: wg.addresses.join(','), publickey: peer.publicKey, allowedips: peer.allowedIps.join(',') });
  if (wg.dns.length) p.set('dns', wg.dns.join(','));
  if (wg.mtu !== undefined) p.set('mtu', String(wg.mtu));
  if (wg.listenPort !== undefined) p.set('listenport', String(wg.listenPort));
  if (peer.presharedKey !== undefined) p.set('presharedkey', peer.presharedKey);
  if (peer.keepalive !== undefined) p.set('keepalive', String(peer.keepalive));
  return `wireguard://${encodeURIComponent(wg.privateKey)}@${host}:${peer.endpoint.port}?${p}`;
}

function wireGuardEndpoint(wg: WireGuardConfig, tag: string): JsonObject {
  return {
    type: 'wireguard', tag, system: false, address: wg.addresses, private_key: wg.privateKey,
    domain_resolver: '@bootstrap',
    ...(wg.mtu !== undefined ? { mtu: wg.mtu } : {}),
    ...(wg.listenPort !== undefined ? { listen_port: wg.listenPort } : {}),
    peers: wg.peers.map(peer => ({
      address: peer.endpoint.address, port: peer.endpoint.port, public_key: peer.publicKey, allowed_ips: peer.allowedIps,
      ...(peer.presharedKey !== undefined ? { pre_shared_key: peer.presharedKey } : {}),
      ...(peer.keepalive !== undefined ? { persistent_keepalive_interval: peer.keepalive } : {}),
    })),
  };
}

function parseVless(url: URL, tag: string): ParsedConnection {
  const p = parameters(url, ['encryption', 'flow', 'fp', 'pbk', 'security', 'sid', 'sni', 'spx', 'support-x25519mlkem768', 'type']);
  const uuid = decodeURIComponent(url.username);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) invalidConfig('VLESS UUID');
  if (p.get('security') !== 'reality' || p.get('flow') !== 'xtls-rprx-vision' ||
      (p.has('type') && p.get('type') !== 'tcp') || (p.has('encryption') && p.get('encryption') !== 'none')) {
    throw new UserError('Поддерживается только VLESS + TCP + REALITY + Vision без дополнительного шифрования.');
  }
  const publicKey = required(p, 'pbk');
  if (!/^[A-Za-z0-9_-]{43}=?$/.test(publicKey) || Buffer.from(publicKey, 'base64url').length !== 32 ||
      Buffer.from(publicKey, 'base64url').toString('base64url') !== publicKey.replace(/=$/, '')) invalidConfig('REALITY pbk: нужен base64url-ключ из 32 байт');
  const shortId = p.get('sid') ?? '';
  if (!/^(?:[0-9a-fA-F]{2}){0,8}$/.test(shortId)) invalidConfig('REALITY sid');
  const serverName = required(p, 'sni');
  if (!isHostname(serverName) && !isIP(serverName)) invalidConfig('REALITY sni');
  const fingerprint = p.get('fp') ?? 'chrome';
  if (!['chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'].includes(fingerprint)) invalidConfig('REALITY fp');
  const endpoint = parseEndpoint(`${url.hostname}:${url.port}`);
  return { section: 'outbounds', config: {
    type: 'vless', tag, server: endpoint.address, server_port: endpoint.port, uuid,
    flow: 'xtls-rprx-vision', domain_resolver: '@bootstrap',
    tls: { enabled: true, server_name: serverName, utls: { enabled: true, fingerprint },
      reality: { enabled: true, public_key: publicKey.replace(/=$/, ''), short_id: shortId } },
  } };
}

registerConnectionProtocol('wireguard', (url, tag) => {
  const wg = parseWireGuardUri(url.href);
  return { section: 'endpoints', config: wireGuardEndpoint(wg, tag), wireGuard: wg };
});
registerConnectionProtocol('vless', parseVless);

function parseConnections(connections: ConnectionMap): ParsedConnection[] {
  return Object.entries(parseConnectionMap(connections)).map(([tag, value]) => {
    const url = checkedUrl(value);
    const handler = handlers.get(url.protocol.slice(0, -1));
    if (!handler) throw new UserError(`Подключение ${tag}: неподдерживаемый протокол.`);
    const parsed = handler(url, tag);
    if (parsed.config.tag !== tag) throw new UserError(`Подключение ${tag}: обработчик изменил имя.`);
    return parsed;
  });
}

export function connectionParts(connections: ConnectionMap): { endpoints: JsonObject[]; outbounds: JsonObject[] } {
  const parsed = parseConnections(connections);
  return {
    endpoints: parsed.filter(item => item.section === 'endpoints').map(item => item.config),
    outbounds: parsed.filter(item => item.section === 'outbounds').map(item => item.config),
  };
}

export interface ConverterOptions {
  name: string;
  rulesUrl: string;
  dns?: { server: string; serverName: string };
  urltest?: { url: string; interval: string; tolerance: number };
  profileUrl?: string;
}

export const RULES_MODE = 'По правилам';
export const ALL_TRAFFIC_MODE = 'Все через VPN';

function withRoutingModes(config: JsonObject, outbound: string, ipv4Only: boolean): JsonObject {
  const route = config.route as JsonObject;
  const rules = route.rules as JsonObject[];
  const dns = config.dns as JsonObject;
  const vpnDns = dns.final as string;
  const policyStart = rules.findIndex(rule => rule.rule_set === '@vpn-rules');
  const globalRules: JsonObject[] = [
    ...(ipv4Only ? [{ clash_mode: ALL_TRAFFIC_MODE, ip_version: 6, action: 'reject' }] : []),
    { clash_mode: ALL_TRAFFIC_MODE, action: 'route', outbound },
  ];
  return {
    ...config,
    dns: { ...dns, rules: [
      ...((dns.rules ?? []) as JsonObject[]),
      { clash_mode: ALL_TRAFFIC_MODE, action: 'route', server: vpnDns },
      { clash_mode: RULES_MODE, rule_set: '@vpn-rules', action: 'evaluate', server: vpnDns, tag: 'vpn-answer' },
      { clash_mode: RULES_MODE, match_response: 'vpn-answer', rule_set: '@vpn-rules', action: 'respond' },
    ], final: '@bootstrap' },
    route: { ...route, default_domain_resolver: '@bootstrap', rules: [
      // Sniffing and DNS interception still happen before either routing mode.
      ...rules.slice(0, policyStart),
      // A named domain_resolver bypasses DNS rules. Resolve user destinations
      // through the DNS rule engine before route selection; bootstrap dialers
      // for VPN servers and the rules download stay explicitly independent.
      { action: 'resolve' }, ...globalRules,
      ...rules.slice(policyStart).map(rule => rule.action === 'route' && rule.rule_set === '@vpn-rules'
        ? { ...rule, clash_mode: RULES_MODE } : rule),
    ] },
    experimental: { ...(config.experimental as JsonObject), clash_api: { default_mode: RULES_MODE } },
  };
}

export class ConnectionConverter {
  private readonly options: ConverterOptions;
  constructor(options: ConverterOptions) {
    normalizeProfileName(options.name);
    validateUrl(options.rulesUrl, 'routing.rulesUrl', true);
    this.options = structuredClone(options);
  }

  convert(connections: ConnectionMap): JsonObject {
    const parsed = parseConnections(connections);
    const single = parsed.length === 1 ? parsed[0]! : undefined;
    if (single?.wireGuard?.dns.length) {
      const config = buildSingleWireGuardConfig(single.wireGuard, this.options.rulesUrl, String(single.config.tag));
      return withRoutingModes(config, String(single.config.tag), (config.dns as JsonObject).strategy === 'ipv4_only');
    }
    const dns = this.options.dns;
    if (!dns || (!isIP(dns.server) && !isHostname(dns.server)) || (!isIP(dns.serverName) && !isHostname(dns.serverName))) {
      throw new UserError('Для этого профиля нужен раздел dns с server и serverName.');
    }
    const urltest = { ...URLTEST_DEFAULTS, ...this.options.urltest };
    const testUrl = validateUrl(urltest.url, 'urltest.url', true);
    if (!/^[1-9]\d*(?:ms|s|m|h)$/.test(urltest.interval) || !Number.isInteger(urltest.tolerance) || urltest.tolerance < 0 || urltest.tolerance > 65535) {
      throw new UserError('Некорректные interval/tolerance urltest.');
    }
    const tags = parsed.map(item => String(item.config.tag));
    const multiple = tags.length > 1;
    const detour = multiple ? 'vpn' : tags[0]!;
    const endpointConfigs = parsed.filter(item => item.section === 'endpoints').map(item => item.config);
    const outboundConfigs = parsed.filter(item => item.section === 'outbounds').map(item => item.config);
    const bootstrapDomains = [...new Set([...(multiple ? [testUrl.hostname] : []), ...(!isIP(dns.server) ? [dns.server] : [])])];
    return withRoutingModes({
      log: { level: 'info', timestamp: true },
      dns: {
        servers: [
          { type: 'local', tag: '@bootstrap' },
          { type: 'https', tag: '@vpn-dns', server: dns.server, server_port: 443, path: '/dns-query',
            tls: { enabled: true, server_name: dns.serverName }, detour, domain_resolver: '@bootstrap' },
        ],
        ...(bootstrapDomains.length ? { rules: [{ domain: bootstrapDomains, action: 'route', server: '@bootstrap' }] } : {}),
        final: '@vpn-dns', strategy: 'ipv4_only', reverse_mapping: true,
      },
      http_clients: [{ tag: '@rules-http', domain_resolver: '@bootstrap' }],
      ...(endpointConfigs.length ? { endpoints: endpointConfigs } : {}),
      inbounds: [{
        type: 'tun', tag: '@tun', auto_route: true, strict_route: true, dns_mode: 'hijack',
        address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'], route_address: ['0.0.0.0/0', '::/0'],
      }],
      outbounds: [
        { type: 'direct', tag: '@direct' }, ...outboundConfigs,
        ...(multiple ? [
          { type: 'selector', tag: 'vpn', outbounds: ['auto', ...tags], default: 'auto', interrupt_exist_connections: false },
          { type: 'urltest', tag: 'auto', outbounds: tags, ...urltest, interrupt_exist_connections: false },
        ] : []),
      ],
      route: {
        auto_detect_interface: true, default_domain_resolver: '@vpn-dns', final: '@direct',
        rules: [
          { action: 'sniff' },
          { type: 'logical', mode: 'or', rules: [{ protocol: 'dns' }, { port: 53 }], action: 'hijack-dns' },
          { rule_set: '@vpn-rules', ip_version: 6, action: 'reject' },
          { rule_set: '@vpn-rules', action: 'route', outbound: detour },
        ],
        rule_set: [{ type: 'remote', tag: '@vpn-rules', format: 'source', url: this.options.rulesUrl,
          http_client: '@rules-http', update_interval: '1h' }],
      },
      experimental: { cache_file: { enabled: true, ...(multiple ? {
        cache_id: createHash('sha256').update(this.options.profileUrl ?? normalizeProfileName(this.options.name)).digest('hex'),
      } : {}) } },
    }, detour, true);
  }
}

export function convertInput(text: string, name: string): ConnectionMap {
  const input = text.trim();
  if (input.startsWith('[Interface]')) return { [normalizeProfileName(name)]: wireGuardToUri(input) };
  if (/^[a-z][a-z0-9+-]*:\/\//i.test(input)) return { [normalizeProfileName(name)]: input };
  let data: unknown;
  try { data = JSON.parse(input); } catch { throw new UserError('Ожидается .conf, URI или JSON-мапка подключений.'); }
  return parseConnectionMap(data);
}
