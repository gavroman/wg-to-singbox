import { expect, it } from 'vitest';
import { ALL_TRAFFIC_MODE, RULES_MODE, ConnectionConverter, connectionParts, convertInput, parseConnectionMap, parseWireGuardUri, registerConnectionProtocol, wireGuardToUri } from '../src/conversion/connections.js';
import { buildSingBoxConfig, parseWireGuard } from '../src/conversion/index.js';
import { key, TEST_RULES_URL, wireGuard } from './fixtures/config.js';

const vless = `vless://76c7c64e-a672-4bae-90c9-c77aa71de206@vless.example.com:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=${Buffer.alloc(32, 4).toString('base64url')}&security=reality&sid=c933f0b8&sni=dl.google.com&spx=%2Fb7b4dace&support-x25519mlkem768=true&type=tcp#iphone`;
const panelWg = `wireguard://${encodeURIComponent(key(4))}@192.0.2.1:27247?address=10.20.0.2%2F32&mtu=1420&publickey=${encodeURIComponent(key(5))}#wg-iphone`;
const options = { name: 'iphone', rulesUrl: TEST_RULES_URL, dns: { server: '1.1.1.1', serverName: 'cloudflare-dns.com' } };

it('preserves country flags in protocol tags and all group references', () => {
  const connections = { 'wg-easy-riga 🇱🇻': wireGuardToUri(wireGuard()), '3x-helsinki-wg 🇫🇮': panelWg, '3x-paris-vless 🇫🇷': vless };
  const config = new ConnectionConverter(options).convert(connections) as any;
  expect(config.endpoints.map((node: any) => node.tag)).toEqual(['wg-easy-riga 🇱🇻', '3x-helsinki-wg 🇫🇮']);
  expect(config.outbounds.find((node: any) => node.type === 'vless').tag).toBe('3x-paris-vless 🇫🇷');
  expect(config.outbounds.find((node: any) => node.type === 'urltest').outbounds).toEqual(Object.keys(connections));
  expect(config.outbounds.find((node: any) => node.type === 'selector').outbounds).toEqual(['auto', ...Object.keys(connections)]);
  expect(convertInput(JSON.stringify(connections), 'iphone')).toEqual(connections);
  const single = new ConnectionConverter(options).convert({ 'wg-easy-riga 🇱🇻': connections['wg-easy-riga 🇱🇻'] }) as any;
  expect(single.dns.servers[1].detour).toBe('wg-easy-riga 🇱🇻');
  expect(single.route.rules.at(-1).outbound).toBe('wg-easy-riga 🇱🇻');
});

it.each([false, true])('preserves WG parameters while adding mode-aware DNS and routing, dualStack=%s', dualStack => {
  const original = parseWireGuard(wireGuard(dualStack));
  const uri = wireGuardToUri(wireGuard(dualStack));
  expect(parseWireGuardUri(uri)).toEqual(original);
  const baseline = buildSingBoxConfig(original, TEST_RULES_URL, 'iphone');
  // Only the explicitly expected structured references are renamed.
  const expected = structuredClone(baseline) as any;
  expected.endpoints[0].tag = 'wg-easy';
  expected.dns.servers[1].detour = 'wg-easy';
  expected.route.rules.at(-1).outbound = 'wg-easy';
  expected.route.rules.at(-1).clash_mode = RULES_MODE;
  expected.route.rules.splice(2, 0,
    { action: 'resolve' },
    ...(!dualStack ? [{ clash_mode: ALL_TRAFFIC_MODE, ip_version: 6, action: 'reject' }] : []),
    { clash_mode: ALL_TRAFFIC_MODE, action: 'route', outbound: 'wg-easy' });
  expected.dns.rules = [
    { clash_mode: ALL_TRAFFIC_MODE, action: 'route', server: '@wg-dns' },
    { clash_mode: RULES_MODE, rule_set: '@vpn-rules', action: 'evaluate', server: '@wg-dns', tag: 'vpn-answer' },
    { clash_mode: RULES_MODE, match_response: 'vpn-answer', rule_set: '@vpn-rules', action: 'respond' },
  ];
  expected.dns.final = '@bootstrap';
  expected.route.default_domain_resolver = '@bootstrap';
  expected.experimental.clash_api = { default_mode: RULES_MODE };
  const actual = new ConnectionConverter(options).convert({ 'wg-easy': uri });
  expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
  expect(connectionParts({ 'wg-easy': uri }).endpoints).toEqual(expected.endpoints);
});

it.each([
  { 'wg-easy': wireGuardToUri(wireGuard()) },
  { '3x-wg': panelWg },
  { '3x-vless': vless },
  { 'wg-easy': wireGuardToUri(wireGuard()), '3x-vless': vless },
])('always exposes both routing modes and keeps DNS interception before the global route: %j', connections => {
  const config = new ConnectionConverter(options).convert(connections) as any;
  const rules = config.route.rules;
  const globalIndex = rules.findIndex((rule: any) => rule.clash_mode === ALL_TRAFFIC_MODE && rule.action === 'route');
  const ipv6Index = rules.findIndex((rule: any) => rule.clash_mode === ALL_TRAFFIC_MODE && rule.ip_version === 6);
  const normalIndex = rules.findIndex((rule: any) => rule.clash_mode === RULES_MODE);
  const dnsIndex = rules.findIndex((rule: any) => rule.action === 'hijack-dns');
  const resolveIndex = rules.findIndex((rule: any) => rule.action === 'resolve');
  expect(dnsIndex).toBeLessThan(resolveIndex);
  expect(resolveIndex).toBeLessThan(ipv6Index);
  expect(rules[resolveIndex]).toEqual({ action: 'resolve' });
  expect(ipv6Index).toBeLessThan(globalIndex);
  expect(globalIndex).toBeLessThan(normalIndex);
  expect(rules[globalIndex]).toEqual({ clash_mode: ALL_TRAFFIC_MODE, action: 'route', outbound: Object.keys(connections).length > 1 ? 'vpn' : Object.keys(connections)[0] });
  expect(rules[normalIndex].rule_set).toBe('@vpn-rules');
  expect(config.route.final).toBe('@direct');
  expect(config.experimental.clash_api).toEqual({ default_mode: RULES_MODE });
  const vpnDns = config.dns.servers.find((server: any) => server.tag !== '@bootstrap');
  expect(config.dns.rules.slice(-3)).toEqual([
    { clash_mode: ALL_TRAFFIC_MODE, action: 'route', server: vpnDns.tag },
    { clash_mode: RULES_MODE, rule_set: '@vpn-rules', action: 'evaluate', server: vpnDns.tag, tag: 'vpn-answer' },
    { clash_mode: RULES_MODE, match_response: 'vpn-answer', rule_set: '@vpn-rules', action: 'respond' },
  ]);
  expect(config.dns.final).toBe('@bootstrap');
  expect(config.route.default_domain_resolver).toBe('@bootstrap');
  expect(config.route.rule_set).toHaveLength(1);
  expect(config.route.rule_set[0].tag).toBe('@vpn-rules');
  expect(new Set(rules.filter((rule: any) => rule.clash_mode).map((rule: any) => rule.clash_mode))).toEqual(new Set([RULES_MODE, ALL_TRAFFIC_MODE]));
});

it('converts the real panel WG URI shape without requiring DNS or losing percent-encoded keys', () => {
  const wg = parseWireGuardUri(panelWg);
  expect(wg.privateKey).toBe(key(4));
  expect(wg.dns).toEqual([]);
  expect(wg.peers[0]).toMatchObject({ publicKey: key(5), allowedIps: ['0.0.0.0/0'] });
  const config = new ConnectionConverter(options).convert({ '3x-wg': panelWg }) as any;
  expect(config.dns.servers[1]).toMatchObject({ type: 'https', detour: '3x-wg' });
  expect(config.outbounds).toEqual([{ type: 'direct', tag: '@direct' }]);
  expect(config.experimental.cache_file.cache_id).toBeUndefined();
});

it('builds every configured connection with fixed groups and independent bootstrap', () => {
  const connections = { 'wg-easy': wireGuardToUri(wireGuard()), '3x-wg': panelWg, '3x-vless': vless };
  const config = new ConnectionConverter(options).convert(connections) as any;
  expect(config.endpoints.map((x: any) => x.tag)).toEqual(['wg-easy', '3x-wg']);
  expect(config.outbounds.filter((x: any) => ['selector', 'urltest'].includes(x.type)).map((x: any) => x.tag)).toEqual(['vpn', 'auto']);
  expect(config.outbounds.find((x: any) => x.tag === 'auto')).toEqual({
    type: 'urltest', tag: 'auto', outbounds: Object.keys(connections),
    url: 'https://www.gstatic.com/generate_204', interval: '1m', tolerance: 80, interrupt_exist_connections: false,
  });
  expect(config.outbounds.find((x: any) => x.tag === 'vpn')).toMatchObject({
    type: 'selector', default: 'auto', outbounds: ['auto', ...Object.keys(connections)],
  });
  expect(config.dns.servers[1].detour).toBe('vpn');
  expect(config.dns.rules).toContainEqual({ domain: ['www.gstatic.com'], action: 'route', server: '@bootstrap' });
  expect(config.dns.rules[0]).toEqual({ domain: ['www.gstatic.com'], action: 'route', server: '@bootstrap' });
  expect(config.http_clients).toEqual([{ tag: '@rules-http', domain_resolver: '@bootstrap' }]);
  const proxy = config.outbounds.find((x: any) => x.type === 'vless');
  expect(proxy).not.toHaveProperty('network');
  expect(proxy).not.toHaveProperty('transport');
  expect(proxy).not.toHaveProperty('spx');
  expect(proxy.domain_resolver).toBe('@bootstrap');
  expect(proxy.flow).toBe('xtls-rprx-vision');
  expect(config.route.rules.at(-2)).toEqual({ rule_set: '@vpn-rules', ip_version: 6, action: 'reject' });
  expect(connectionParts(connections).outbounds).toEqual([proxy]);
});

it('has no groups for a single VLESS and never exposes secrets in tags', () => {
  const config = new ConnectionConverter(options).convert({ '3x-vless': vless }) as any;
  expect(config.endpoints).toBeUndefined();
  expect(config.outbounds.map((x: any) => x.type)).toEqual(['direct', 'vless']);
  expect(config.route.rules.at(-1).outbound).toBe('3x-vless');
  expect(config.experimental.cache_file.cache_id).toBeUndefined();
});

it('keeps names and cache identity stable through reordered links and A/B/A', () => {
  const converter = new ConnectionConverter({ ...options, profileUrl: 'https://storage.example/profiles/sf-iphone/sing-box.json' });
  const a = { 'wg-easy': wireGuardToUri(wireGuard()) };
  const b = { ...a, '3x-vless': vless };
  const first = converter.convert(a);
  const multi = converter.convert(b) as any;
  expect(converter.convert(a)).toEqual(first);
  const reverse = converter.convert({ '3x-vless': vless.replace('#iphone', '#other'), ...a }) as any;
  expect(reverse.experimental).toEqual(multi.experimental);
  expect(reverse.outbounds.find((x: any) => x.type === 'vless')).toEqual(multi.outbounds.find((x: any) => x.type === 'vless'));
  const other = new ConnectionConverter({ ...options, profileUrl: 'https://storage.example/profiles/sf-other/sing-box.json' }).convert(b) as any;
  expect(other.experimental).not.toEqual(multi.experimental);
});

it('handles additional protocols through the registry without changing orchestration', () => {
  const unregister = registerConnectionProtocol('testproto', (url, tag) => ({ section: 'outbounds', config: { type: 'testproto', tag, server: url.hostname } }));
  try {
    const config = new ConnectionConverter(options).convert({ demo: 'testproto://test@example.com:1234', '3x-vless': vless }) as any;
    expect(config.outbounds.find((x: any) => x.tag === 'auto').outbounds).toEqual(['demo', '3x-vless']);
  } finally { unregister(); }
});

it('validates all inputs without leaking URI credentials', () => {
  for (const input of [
    {}, { auto: vless }, { demo: '' }, { demo: 'unknown://secret@example.com:443' },
    { demo: vless.replace(/pbk=[^&]+/, 'pbk=') }, { demo: vless.replace('type=tcp', 'type=ws') },
    { demo: vless.replace('flow=xtls-rprx-vision', 'flow=unsupported') },
    { demo: panelWg.replace('address=', 'unexpected=') },
    { demo: panelWg.replace('#wg-iphone', '&publickey=secret') },
    { demo: panelWg.replace('mtu=1420', 'mtu=bad') },
  ]) {
    expect(() => new ConnectionConverter(options).convert(input)).toThrow();
    try { new ConnectionConverter(options).convert(input); }
    catch (error) { expect(String(error)).not.toContain('wireguard://'); expect(String(error)).not.toContain('vless://'); expect(String(error)).not.toContain(key(4)); }
  }
  expect(() => wireGuardToUri(wireGuard() + `\n[Peer]\nPublicKey = ${key(6)}\nEndpoint = second.example.com:1234\nAllowedIPs = 10.0.0.0/8\n`)).toThrow('Peer');
  expect(() => new ConnectionConverter({ name: 'iphone', rulesUrl: TEST_RULES_URL }).convert({ demo: vless })).toThrow('dns');
});

it('normalizes standalone inputs while preserving map names', () => {
  expect(convertInput(vless, 'iphone')).toEqual({ 'sf-iphone': vless });
  expect(convertInput(wireGuard(), 'iphone')).toEqual({ 'sf-iphone': wireGuardToUri(wireGuard()) });
  expect(convertInput(JSON.stringify({ '3x-vless': vless }), 'iphone')).toEqual({ '3x-vless': vless });
  expect(() => parseConnectionMap(JSON.parse('{"__proto__":"secret"}'))).toThrow();
});
