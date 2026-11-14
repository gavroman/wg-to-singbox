import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import { mkdtemp, rm, readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseVpnConfig } from '../src/config/private.js';
import { prepareProfile, provisionManaged, preservedRulesUrl, updateProfiles } from '../src/provision/managed.js';
import { collectConnections } from '../src/panels/index.js';
import { wireGuardToUri } from '../src/conversion/connections.js';
import { buildSingBoxConfig, parseWireGuard } from '../src/conversion/index.js';
import { mockServices } from './server.js';
import { wireGuard, key, TEST_RULES_URL } from './fixtures/config.js';
import { UserError } from '../src/shared/errors.js';

vi.mock('../src/panels/index.js', () => ({ collectConnections: vi.fn() }));
let service: Awaited<ReturnType<typeof mockServices>>;
let directory: string;
const reality = `vless://a5e304d8-f350-4800-b413-e84f4805ca07@198.51.100.2:443?security=reality&flow=xtls-rprx-vision&type=tcp&fp=chrome&sni=example.com&pbk=${Buffer.from(key(3), 'base64').toString('base64url')}&sid=1234`;
beforeEach(async () => {
  vi.stubEnv('NODE_TLS_REJECT_UNAUTHORIZED', '0');
  service = await mockServices();
  directory = await mkdtemp(join(tmpdir(), 'managed-profile-'));
  vi.mocked(collectConnections).mockImplementation(async config => Object.fromEntries(
    Object.keys(config.connections!).map(name => [name, name === '3x-vless' ? reality : wireGuardToUri(wireGuard())]),
  ));
});
afterEach(async () => { await service?.close(); if (directory) await rm(directory, { recursive: true, force: true }); vi.unstubAllEnvs(); vi.clearAllMocks(); });
function settings(multi = false) {
  return parseVpnConfig({ version: 1,
    s3: { endpoint: service.url, region: 'test', bucket: 'test-bucket', accessKeyId: 'test', secretAccessKey: 'test' },
    panels: { wg: { type: 'wg-easy', url: service.url, password: 'test' },
      xui: { type: '3x-ui', url: service.url, apiToken: 'test' } },
    connections: { 'wg-easy': { type: 'wireguard', panel: 'wg' }, ...(multi ? {
      '3x-wg': { type: 'wireguard', panel: 'xui', inbound: { port: 51822, subnet: '10.20.0.0/24' } },
      '3x-vless': { type: 'vless-reality', panel: 'xui', inbound: { port: 443, reality: { target: 'example.com:443', serverNames: ['example.com'] } } },
    } : {}) }, routing: { rulesUrl: TEST_RULES_URL }, dns: { server: '1.1.1.1', serverName: 'cloudflare-dns.com' },
  });
}
it('prepares A → B → A with the same implementation, exact configured names, no S3 writes', async () => {
  const a = await prepareProfile(settings(), 'iphone');
  const b = await prepareProfile(settings(true), 'iphone');
  const again = await prepareProfile(settings(), 'iphone');
  expect(again).toEqual(a);
  expect(a.connections).toHaveProperty('wg-easy');
  expect(b.connections).toHaveProperty('3x-vless');
  expect(b.config.outbounds).toEqual(expect.arrayContaining([
    expect.objectContaining({ tag: 'auto', type: 'urltest', outbounds: ['wg-easy', '3x-wg', '3x-vless'] }),
    expect.objectContaining({ tag: 'vpn', type: 'selector', default: 'auto' }),
  ]));
  const old = buildSingBoxConfig(parseWireGuard(wireGuard()), TEST_RULES_URL, 'iphone');
  const expected = JSON.parse(JSON.stringify(old));
  expected.endpoints[0].tag = 'wg-easy';
  expected.dns.servers.find((server: { detour?: string }) => server.detour === 'sf-iphone').detour = 'wg-easy';
  expected.route.rules.find((rule: { outbound?: string }) => rule.outbound === 'sf-iphone').outbound = 'wg-easy';
  expected.route.rules.at(-1).clash_mode = 'По правилам';
  expected.route.rules.splice(2, 0,
    { action: 'resolve' },
    { clash_mode: 'Все через VPN', ip_version: 6, action: 'reject' },
    { clash_mode: 'Все через VPN', action: 'route', outbound: 'wg-easy' });
  expected.dns.rules = [
    { clash_mode: 'Все через VPN', action: 'route', server: '@wg-dns' },
    { clash_mode: 'По правилам', rule_set: '@vpn-rules', action: 'evaluate', server: '@wg-dns', tag: 'vpn-answer' },
    { clash_mode: 'По правилам', match_response: 'vpn-answer', rule_set: '@vpn-rules', action: 'respond' },
  ];
  expected.dns.final = '@bootstrap';
  expected.route.default_domain_resolver = '@bootstrap';
  expected.experimental.clash_api = { default_mode: 'По правилам' };
  expect(a.config).toEqual(expected);
  expect(service.state.requests).toHaveLength(0);
});
it('retains the managed rules version and rejects versions on other or signed URLs', () => {
  const old = (url: string) => ({ route: { rule_set: [{ type: 'remote', format: 'source', url }] } });
  expect(preservedRulesUrl(TEST_RULES_URL, old(`${TEST_RULES_URL}?v=old`))).toBe(`${TEST_RULES_URL}?v=old`);
  expect(preservedRulesUrl(TEST_RULES_URL, old(`${TEST_RULES_URL}?v=old&signature=secret`))).toBe(TEST_RULES_URL);
  expect(preservedRulesUrl(TEST_RULES_URL, old('https://other.example/rules.json?v=old'))).toBe(TEST_RULES_URL);
});
it('publishes A → B → A preserving old WG files and rules version, then fails without changing S3', async () => {
  const prefix = '/test-bucket/profiles/sf-iphone/';
  service.state.objects.set(prefix + 'wireguard.conf', Buffer.from(wireGuard()));
  service.state.objects.set(prefix + 'sing-box.json', Buffer.from(JSON.stringify({ route: {
    rule_set: [{ type: 'remote', url: `${TEST_RULES_URL}?v=keep` }],
  } })));
  // A legacy manifest remains readable while the source format changes.
  service.state.objects.set(prefix + 'data.json', Buffer.from(JSON.stringify({ name: 'sf-iphone', clientId: 'old', wireGuardUrl: service.url + prefix + 'wireguard.conf' })));
  const first = await provisionManaged(settings(), 'iphone', { outputDirectory: directory });
  const firstBytes = Buffer.from(service.state.objects.get(prefix + 'sing-box.json')!);
  await provisionManaged(settings(true), 'iphone', { outputDirectory: directory });
  await provisionManaged(settings(), 'iphone', { outputDirectory: directory });
  expect(service.state.objects.get(prefix + 'sing-box.json')).toEqual(firstBytes);
  expect(service.state.objects.get(prefix + 'wireguard.conf')!.toString()).toBe(wireGuard());
  expect(firstBytes.toString()).toContain('?v=keep');
  expect(JSON.parse(await readFile(first.connectionsPath, 'utf8'))).toHaveProperty('wg-easy');
  const before = new Map(service.state.objects);
  vi.mocked(collectConnections).mockRejectedValueOnce(new UserError('Панель недоступна.'));
  await expect(provisionManaged(settings(true), 'iphone', { outputDirectory: directory })).rejects.toThrow('Панель');
  expect(service.state.objects).toEqual(before);
});
it('create-only refuses an existing profile before panel mutations', async () => {
  service.state.objects.set('/test-bucket/profiles/sf-iphone/sing-box.json', Buffer.from('{}'));
  await expect(provisionManaged(settings(), 'iphone', { createOnly: true, outputDirectory: directory })).rejects.toThrow('create-only');
  expect(collectConnections).not.toHaveBeenCalled();
  expect(service.state.requests.filter(request => request.method !== 'GET')).toHaveLength(0);
});
it.each(['data.json', 'qr.png', 'connections.json', 'wireguard.conf', 'index.html'])(
  'create-only refuses an orphan %s before collecting connections', async file => {
    service.state.objects.set(`/test-bucket/profiles/sf-iphone/${file}`, Buffer.from('existing-object'));
    await expect(provisionManaged(settings(), 'iphone', { createOnly: true, outputDirectory: directory })).rejects.toThrow('create-only');
    expect(collectConnections).not.toHaveBeenCalled();
    expect(service.state.requests.every(request => request.method === 'GET')).toBe(true);
    expect(service.state.objects.get(`/test-bucket/profiles/sf-iphone/${file}`)!.toString()).toBe('existing-object');
  },
);
it('rejects an invalid local destination before contacting S3 or panels', async () => {
  const file = join(directory, 'not-a-directory');
  await writeFile(file, 'preserve');
  await expect(provisionManaged(settings(), 'iphone', { outputDirectory: file })).rejects.toThrow('каталог artifacts');
  expect(collectConnections).not.toHaveBeenCalled();
  expect(service.state.requests).toHaveLength(0);
  expect(await readFile(file, 'utf8')).toBe('preserve');
});
it('creates a new profile alongside existing local artifacts without service metadata', async () => {
  await mkdir(join(directory, 'profiles/old'), { recursive: true });
  await mkdir(join(directory, 'rules'), { recursive: true });
  await writeFile(join(directory, 'profiles/old/sing-box.json'), 'existing-profile');
  await writeFile(join(directory, 'rules/vpn_rules.json'), 'existing-rules');
  const result = await provisionManaged(settings(), 'iphone', { outputDirectory: directory, createOnly: true });
  expect(result.name).toBe('sf-iphone');
  expect(await readFile(join(directory, 'profiles/old/sing-box.json'), 'utf8')).toBe('existing-profile');
  expect(await readFile(join(directory, 'rules/vpn_rules.json'), 'utf8')).toBe('existing-rules');
  expect((await readdir(directory)).sort()).toEqual(['profiles', 'rules']);
  expect(service.state.requests.every(request => request.method === 'PUT' || request.path.startsWith('/test-bucket/profiles/sf-iphone/'))).toBe(true);
});
it.each(['panels', 'routing', 'dns', 'bucket', 'rules override'])(
  'validates %s locally before provision or bulk-update network requests', async field => {
    const config = field === 'panels' ? parseVpnConfig({ version: 1, s3: settings().s3 }) : settings(true);
    if (field === 'routing') delete config.routing;
    if (field === 'dns') delete config.dns;
    if (field === 'bucket') config.s3!.bucket = 'invalid bucket';
    const options = { outputDirectory: directory, ...(field === 'rules override' ? { rulesUrl: 'not-a-url' } : {}) };
    await expect(provisionManaged(config, 'iphone', options)).rejects.toThrow();
    await expect(updateProfiles(config, options)).rejects.toThrow();
    expect(collectConnections).not.toHaveBeenCalled();
    expect(service.state.requests).toHaveLength(0);
  },
);
it('reports each profile when a bulk update partly fails', async () => {
  for (const name of ['sf-one', 'sf-two']) service.state.objects.set(`/test-bucket/profiles/${name}/sing-box.json`, Buffer.from('{}'));
  vi.mocked(collectConnections).mockRejectedValueOnce(new UserError('Нет доступа.'));
  const result = await updateProfiles(settings(), { outputDirectory: directory });
  expect(result).toEqual([
    { name: 'sf-one', updated: false, error: 'Нет доступа.' },
    { name: 'sf-two', updated: true },
  ]);
});
