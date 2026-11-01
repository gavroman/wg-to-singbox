import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mockServices } from './server.js';
import { pullConfigs } from '../src/configs/pull.js';
import { artifactRulesPath, profilePaths } from '../src/artifacts/paths.js';
import { writePrivateFile } from '../src/artifacts/files.js';

let mock: Awaited<ReturnType<typeof mockServices>>;
let directory: string;
let cache: string;
const files = ['sing-box.json', 'wireguard.conf', 'qr.png', 'index.html', 'data.json'];
const storage = () => ({ endpoint: mock.url, region: 'ru-central1', bucket: 'test-bucket',
  accessKeyId: 'synthetic-key', secretAccessKey: 'synthetic-secret' });

beforeEach(async () => {
  vi.stubEnv('NODE_TLS_REJECT_UNAUTHORIZED', '0');
  directory = await mkdtemp(join(tmpdir(), 'libertd-pull-'));
  cache = join(directory, 'artifacts');
  mock = await mockServices();
  mock.state.objects.set('/test-bucket/rules/vpn_rules.json', Buffer.from('{"version":5,"rules":[]}'));
  for (const name of ['sf-phone', 'sf-Phone']) {
    for (const file of files) mock.state.objects.set(`/test-bucket/profiles/${name}/${file}`, Buffer.from(`${name}/${file}\n`));
  }
});
afterEach(async () => {
  try { await mock?.close(); if (directory) await rm(directory, { recursive: true, force: true }); }
  finally { vi.unstubAllEnvs(); }
});

it('recreates the cache byte for byte from S3, without local metadata', async () => {
  await writePrivateFile(join(cache, 'old-profile/metadata/client.json'), 'stale');
  await writePrivateFile(profilePaths('phone', cache).singBox, 'unpublished-local-edit');
  mock.state.listPageSize = 2;
  const result = await pullConfigs({ storage: storage(), outputDirectory: cache });
  expect(result.profiles.sort()).toEqual(['sf-Phone', 'sf-phone']);
  expect((await readdir(cache)).sort()).toEqual(['profiles', 'rules']);
  expect(await readFile(artifactRulesPath(cache))).toEqual(mock.state.objects.get('/test-bucket/rules/vpn_rules.json'));
  for (const name of result.profiles) {
    const paths = profilePaths(name, cache);
    expect((await readdir(paths.root)).sort()).toEqual([...files].sort());
    for (const file of files) {
      const path = join(paths.root, file);
      expect(await readFile(path)).toEqual(mock.state.objects.get(`/test-bucket/profiles/${name}/${file}`));
      if (process.platform !== 'win32') expect((await stat(path)).mode & 0o777).toBe(0o600);
    }
  }
  expect(mock.state.requests.every(request => request.method === 'GET')).toBe(true);
  expect(mock.state.requests.some(request => request.path.startsWith('/api/'))).toBe(false);
});

it('keeps the previous snapshot intact if any file cannot be downloaded', async () => {
  await writePrivateFile(profilePaths('phone', cache).singBox, 'previous-cache');
  mock.state.objects.delete('/test-bucket/profiles/sf-phone/qr.png');
  await expect(pullConfigs({ storage: storage(), outputDirectory: cache })).rejects.toThrow('404');
  expect(await readFile(profilePaths('phone', cache).singBox, 'utf8')).toBe('previous-cache');
  expect(await readdir(profilePaths('phone', cache).root)).toEqual(['sing-box.json']);
  expect((await readdir(directory)).filter(name => name.startsWith('.configs-'))).toEqual([]);
});

it('removes cached profiles that no longer exist in S3', async () => {
  await pullConfigs({ storage: storage(), outputDirectory: cache });
  for (const file of files) mock.state.objects.delete(`/test-bucket/profiles/sf-Phone/${file}`);
  await pullConfigs({ storage: storage(), outputDirectory: cache });
  await expect(stat(profilePaths('Phone', cache).root)).rejects.toMatchObject({ code: 'ENOENT' });
  expect(await readdir(join(cache, 'profiles'))).toHaveLength(1);
});
