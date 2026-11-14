import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mockServices } from './server.js';
import { wireGuard, TEST_RULES_URL } from './fixtures/config.js';
import { ConnectionConverter, wireGuardToUri } from '../src/conversion/connections.js';
import { publishConnectionsProfile } from '../src/provision/connections-publication.js';
import { pullConfigs } from '../src/configs/pull.js';
import { readOptionalObject, publishObject } from '../src/storage/object.js';
import { profilePaths } from '../src/artifacts/paths.js';
import { writePrivateFile } from '../src/artifacts/files.js';
import { updateRules } from '../src/rules/update.js';

let mock: Awaited<ReturnType<typeof mockServices>>;
let directory: string;
const storage = () => ({ endpoint: mock.url, region: 'ru-central1', bucket: 'test-bucket', accessKeyId: 'synthetic-key', secretAccessKey: 'synthetic-secret' });
const map = () => ({ 'wg-easy': wireGuardToUri(wireGuard()) });
const config = () => new ConnectionConverter({ name: 'phone', rulesUrl: TEST_RULES_URL }).convert(map());

beforeEach(async () => {
  vi.stubEnv('NODE_TLS_REJECT_UNAUTHORIZED', '0');
  directory = await mkdtemp(join(tmpdir(), 'libertd-connections-storage-'));
  mock = await mockServices();
});
afterEach(async () => {
  await mock?.close();
  if (directory) await rm(directory, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

it('publishes a connections bundle and preserves legacy WG bytes and links on upgrade', async () => {
  const prefix = '/test-bucket/profiles/sf-phone/';
  const wireGuardUrl = `${mock.url}${prefix}wireguard.conf`;
  mock.state.objects.set(prefix + 'wireguard.conf', Buffer.from('legacy WG bytes'));
  mock.state.objects.set(prefix + 'data.json', Buffer.from(JSON.stringify({ name: 'sf-phone', clientId: 'client-1', wireGuardUrl })));
  const result = await publishConnectionsProfile({ name: 'phone', storage: storage(), config: config(), connections: map(), outputDirectory: directory });
  expect(result.wireGuardUrl).toBe(wireGuardUrl);
  expect(result.clientId).toBe('client-1');
  expect(mock.state.objects.get(prefix + 'wireguard.conf')!.toString()).toBe('legacy WG bytes');
  expect(mock.state.requests.filter(r => r.method === 'PUT').map(r => r.path.split('?')[0])).toEqual(
    ['sing-box.json', 'connections.json', 'qr.png', 'index.html', 'data.json'].map(file => prefix + file));
  expect(JSON.parse(await readFile(result.connectionsPath, 'utf8'))).toEqual(map());
  expect(JSON.parse(await readFile(result.dataPath, 'utf8'))).toMatchObject({ connectionsUrl: result.connectionsUrl, wireGuardUrl, clientId: 'client-1' });
  expect(await readdir(directory)).toEqual(['profiles']);
});

it('rejects mismatched map before any network writes or reads', async () => {
  const bad = config();
  (bad.endpoints as { private_key: string }[])[0]!.private_key = 'private-secret';
  await expect(publishConnectionsProfile({ name: 'phone', storage: storage(), config: bad, connections: map(), outputDirectory: directory })).rejects.toThrow('не соответствуют');
  expect(mock.state.requests).toHaveLength(0);
});

it('create-only checks every legacy and new key and sends conditional PUT requests', async () => {
  const options = { name: 'phone', storage: storage(), config: config(), connections: map(), outputDirectory: directory, createOnly: true };
  await publishConnectionsProfile(options);
  expect(mock.state.requests.filter(r => r.method === 'PUT')).toHaveLength(5);
  expect(mock.state.requests.filter(r => r.method === 'PUT').every(r => r.headers['if-none-match'] === '*')).toBe(true);
  const snapshot = new Map(mock.state.objects);
  mock.state.requests = [];
  await expect(publishConnectionsProfile(options)).rejects.toThrow('create-only');
  expect(mock.state.requests.some(r => r.method === 'PUT')).toBe(false);
  expect(mock.state.objects).toEqual(snapshot);
});

it('conditional upload refuses an object that appeared after preflight', async () => {
  const key = 'profiles/sf-phone/sing-box.json';
  mock.state.objects.set('/test-bucket/' + key, Buffer.from('existing'));
  await expect(publishObject(storage(), key, '{}', { createOnly: true })).rejects.toThrow('S3');
  expect(mock.state.objects.get('/test-bucket/' + key)!.toString()).toBe('existing');
});

it('optional reads suppress only 404, never authorization or network failures', async () => {
  expect(await readOptionalObject(storage(), 'profiles/sf-missing/connections.json')).toBeUndefined();
  mock.state.privateRead = true;
  await expect(readOptionalObject(storage(), 'profiles/sf-missing/connections.json')).rejects.toThrow('403');
});

it('pulls mixed snapshots and requires a manifest-declared connections file', async () => {
  mock.state.objects.set('/test-bucket/rules/vpn_rules.json', Buffer.from('{"version":5,"rules":[]}'));
  for (const name of ['sf-old', 'sf-new']) {
    const prefix = `/test-bucket/profiles/${name}/`;
    for (const file of ['sing-box.json', 'qr.png', 'index.html']) mock.state.objects.set(prefix + file, Buffer.from(file));
    const data = name === 'sf-old' ? { name } : { name, connectionsUrl: `${mock.url}${prefix}connections.json` };
    mock.state.objects.set(prefix + 'data.json', Buffer.from(JSON.stringify(data)));
    mock.state.objects.set(prefix + (name === 'sf-old' ? 'wireguard.conf' : 'connections.json'), Buffer.from(name));
  }
  const result = await pullConfigs({ storage: storage(), outputDirectory: directory });
  expect(result.profiles.sort()).toEqual(['sf-new', 'sf-old']);
  expect(await readdir(profilePaths('new', directory).root)).not.toContain('wireguard.conf');
  expect(await readdir(profilePaths('old', directory).root)).not.toContain('connections.json');
  mock.state.objects.delete('/test-bucket/profiles/sf-new/connections.json');
  await expect(pullConfigs({ storage: storage(), outputDirectory: directory })).rejects.toThrow('404');
  expect(await readFile(profilePaths('new', directory).connections, 'utf8')).toBe('sf-new');
});

it('uses local rules without requiring service metadata', async () => {
  const rules = '{"version":5,"rules":[{"domain_suffix":["example.com"]}]}';
  await writePrivateFile(join(directory, 'rules/vpn_rules.json'), rules);
  const result = await updateRules({ storage: storage(), outputDirectory: directory });
  expect(mock.state.objects.get('/test-bucket/rules/vpn_rules.json')!.toString()).toBe(rules);
  expect(result.failed).toEqual([]);
  expect(result.pullError).toBeUndefined();
  expect(await readdir(directory)).toEqual(['rules']);
});
