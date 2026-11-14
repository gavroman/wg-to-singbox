import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, readdir, rm, stat, writeFile, cp, copyFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mockServices } from './server.js';
import { wireGuard } from './fixtures/config.js';
import { buildSingBoxConfig, parseWireGuard } from '../src/conversion/index.js';
import { formatRulesVersion, setRulesVersion } from '../src/rules/version.js';
import { updateRules } from '../src/rules/update.js';
import { profilePaths } from '../src/artifacts/paths.js';
import { formatJson, writePrivateFile } from '../src/artifacts/files.js';
import { PACKAGE_ROOT } from '../src/config/index.js';

it('formats the version in UTC without a timezone suffix', () => {
  expect(formatRulesVersion(new Date('2026-11-01T17:30:15.123Z'))).toBe('2026_11_01_17_30_15_123');
});

it('replaces only v in matching remote source rules and preserves profile content', () => {
  const rulesUrl = 'https://example.com/rules/vpn_rules.json';
  const config = buildSingBoxConfig(parseWireGuard(wireGuard()), rulesUrl, 'phone');
  const original = structuredClone(config);
  expect(setRulesVersion(config, rulesUrl, '2026_11_01_17_30_15_123')).toBe(true);
  expect(setRulesVersion(config, rulesUrl, '2026_11_02_17_30_15_123')).toBe(true);
  const route = config.route as { rule_set: { url: string }[] };
  expect(route.rule_set[0]!.url).toBe(`${rulesUrl}?v=2026_11_02_17_30_15_123`);
  expect(setRulesVersion(config, rulesUrl, '2026_11_02_17_30_15_123')).toBe(false);
  route.rule_set[0]!.url = rulesUrl;
  expect(config).toEqual(original);
  const fresh = buildSingBoxConfig(parseWireGuard(wireGuard()), rulesUrl, 'new-phone');
  expect(fresh.route).toMatchObject({ rule_set: [{ url: rulesUrl }] });
});

describe('rules:update with local S3', () => {
  let mock: Awaited<ReturnType<typeof mockServices>>;
  let directory: string;
  let rulesPath: string;
  let cacheDirectory: string;
  const contents = '{"version":5,"rules":[{"domain_suffix":["example.com"]}]}\n';
  beforeEach(async () => {
    vi.stubEnv('NODE_TLS_REJECT_UNAUTHORIZED', '0');
    directory = await mkdtemp(join(tmpdir(), 'libertd-rules-update-'));
    mock = await mockServices();
    rulesPath = join(directory, 'rules.json');
    cacheDirectory = join(directory, 'artifacts');
    await writeFile(rulesPath, contents);
  });
  afterEach(async () => {
    try {
      await mock?.close();
      if (directory) await rm(directory, { recursive: true, force: true });
    } finally { vi.unstubAllEnvs(); }
  });
  const settings = (endpoint: string) => ({ endpoint, region: 'ru-central1', bucket: 'test-bucket',
    accessKeyId: 'synthetic-key', secretAccessKey: 'synthetic-secret' });

  function seedProfile(name: string, rulesUrl: string) {
    const config = buildSingBoxConfig(parseWireGuard(wireGuard()), rulesUrl, name);
    mock.state.objects.set(`/test-bucket/profiles/${name}/sing-box.json`, Buffer.from(formatJson(config)));
    for (const file of ['wireguard.conf', 'qr.png', 'index.html', 'data.json']) {
      mock.state.objects.set(`/test-bucket/profiles/${name}/${file}`, Buffer.from(`cloud-${file}`));
    }
    mock.state.objects.set(`/test-bucket/profiles/${name}/data.json`, Buffer.from(JSON.stringify({ name })));
    return config;
  }

  it('updates all pages with one version, changes only configs and pulls the S3 snapshot over local edits', async () => {
    const rulesUrl = `${mock.url}/test-bucket/rules/vpn_rules.json`;
    const first = seedProfile('sf-phone', rulesUrl);
    const second = seedProfile('sf-Phone', `${rulesUrl}?v=old&v=duplicate`);
    for (const name of ['sf-phone', 'sf-Phone']) {
      for (const file of ['wireguard.conf', 'qr.png', 'index.html', 'data.json']) {
        mock.state.objects.set(`/test-bucket/profiles/${name}/${file}`, Buffer.from(`unchanged-${file}`));
      }
      mock.state.objects.set(`/test-bucket/profiles/${name}/data.json`, Buffer.from(JSON.stringify({ name })));
    }
    const before = new Map([...mock.state.objects].map(([key, value]) => [key, Buffer.from(value)]));
    mock.state.listPageSize = 2;
    const local = structuredClone(first);
    local.log = { level: 'debug' }; // Preserve local edits instead of replacing with the cloud copy.
    await writePrivateFile(profilePaths('phone', cacheDirectory).singBox, formatJson(local));
    const result = await updateRules({ storage: settings(mock.url), rulesPath, outputDirectory: cacheDirectory });
    expect(result.version).toMatch(/^\d{4}(?:_\d{2}){5}_\d{3}$/);
    expect(result.updated.sort()).toEqual(['sf-Phone', 'sf-phone']);
    expect(result.failed).toEqual([]);
    expect(result.pullError).toBeUndefined();
    expect(result.pull?.profiles.sort()).toEqual(['sf-Phone', 'sf-phone']);
    expect(mock.state.objects.get('/test-bucket/rules/vpn_rules.json')?.toString()).toBe(contents);
    for (const [name, original] of [['sf-phone', first], ['sf-Phone', second]] as const) {
      const key = `/test-bucket/profiles/${name}/sing-box.json`;
      const expected = structuredClone(original);
      setRulesVersion(expected, rulesUrl, result.version);
      expect(JSON.parse(mock.state.objects.get(key)!.toString())).toEqual(expected);
      for (const file of ['wireguard.conf', 'qr.png', 'index.html', 'data.json']) {
        expect(mock.state.objects.get(`/test-bucket/profiles/${name}/${file}`)).toEqual(before.get(`/test-bucket/profiles/${name}/${file}`));
      }
    }
    const localResult = JSON.parse(await readFile(profilePaths('phone', cacheDirectory).singBox, 'utf8'));
    expect(localResult.log).toEqual(first.log);
    expect(localResult.route.rule_set[0].url).toBe(`${rulesUrl}?v=${result.version}`);
    expect((await readdir(profilePaths('Phone', cacheDirectory).root)).sort()).toEqual(['data.json', 'index.html', 'qr.png', 'sing-box.json', 'wireguard.conf']);
    expect(mock.state.requests.filter(request => request.path.includes('list-type=2')).length).toBeGreaterThan(1);
    const putKeys = mock.state.requests.filter(request => request.method === 'PUT').map(request => request.path.split('?')[0]);
    expect(putKeys).toEqual(['/test-bucket/rules/vpn_rules.json', '/test-bucket/profiles/sf-Phone/sing-box.json', '/test-bucket/profiles/sf-phone/sing-box.json']);
    expect(mock.state.requests.some(request => request.path.startsWith('/api/'))).toBe(false);
  });

  it('skips foreign, custom-query and inline rules, and ignores non-profile object keys', async () => {
    const rulesUrl = `${mock.url}/test-bucket/rules/vpn_rules.json`;
    seedProfile('sf-external', 'https://external.example/rules.json');
    seedProfile('sf-signed', `${rulesUrl}?X-Amz-Signature=secret`);
    seedProfile('sf-pinned', `${rulesUrl}?versionId=one`);
    mock.state.objects.set('/test-bucket/profiles/sf-inline/sing-box.json', Buffer.from('{"route":{"rule_set":[{"type":"inline","rules":[{"domain":"example.com"}]}]}}'));
    mock.state.objects.set('/test-bucket/profiles/legacy.json', Buffer.from('legacy'));
    mock.state.objects.set('/test-bucket/profiles/sf-other/data.json', Buffer.from('metadata'));
    const before = new Map(mock.state.objects);
    const result = await updateRules({ storage: settings(mock.url), rulesPath, outputDirectory: cacheDirectory });
    expect(result.updated).toEqual([]);
    expect(result.skipped.sort()).toEqual(['sf-external', 'sf-inline', 'sf-pinned', 'sf-signed']);
    for (const [key, value] of before) expect(mock.state.objects.get(key)).toEqual(value);
    expect(mock.state.requests.filter(request => request.method === 'PUT')).toHaveLength(1);
  });

  it('does not publish anything when validation or listing fails', async () => {
    mock.state.failList = true;
    await expect(updateRules({ storage: settings(mock.url), rulesPath })).rejects.toThrow('ListBucket');
    expect(mock.state.requests.some(request => request.method === 'PUT')).toBe(false);
    mock.state.requests = [];
    await writeFile(rulesPath, '{"invalid":true}');
    await expect(updateRules({ storage: settings(mock.url), rulesPath })).rejects.toThrow('VPN rules');
    expect(mock.state.requests).toHaveLength(0);
  });

  it('does not update profiles if rules publication fails', async () => {
    const rulesUrl = `${mock.url}/test-bucket/rules/vpn_rules.json`;
    const original = seedProfile('sf-phone', rulesUrl);
    mock.state.failUploadKey = '/test-bucket/rules/vpn_rules.json';
    await expect(updateRules({ storage: settings(mock.url), rulesPath })).rejects.toThrow('S3');
    expect(JSON.parse(mock.state.objects.get('/test-bucket/profiles/sf-phone/sing-box.json')!.toString())).toEqual(original);
  });

  it('reports partial failures and continues updating other profiles', async () => {
    const rulesUrl = `${mock.url}/test-bucket/rules/vpn_rules.json`;
    seedProfile('sf-bad', rulesUrl);
    seedProfile('sf-good', rulesUrl);
    mock.state.objects.set('/test-bucket/profiles/sf-invalid/sing-box.json', Buffer.from('PRIVATE-KEY-not-json'));
    mock.state.failUploadKey = '/test-bucket/profiles/sf-bad/sing-box.json';
    const result = await updateRules({ storage: settings(mock.url), rulesPath, outputDirectory: cacheDirectory });
    expect(result.updated).toEqual(['sf-good']);
    expect(result.failed.map(item => item.name)).toEqual(['sf-bad', 'sf-invalid']);
    expect(JSON.stringify(result)).not.toContain('PRIVATE-KEY');
    expect(mock.state.objects.get('/test-bucket/rules/vpn_rules.json')?.toString()).toBe(contents);
  });

  it('runs rules:update without WG credentials and returns nonzero on partial failure', async () => {
    const rulesUrl = `${mock.url}/test-bucket/rules/vpn_rules.json`;
    const name = `sf-rules-test-${process.pid}`;
    seedProfile(name, rulesUrl);
    const configPath = join(directory, 'vpn.private.json');
    await writePrivateFile(configPath, formatJson({ version: 1, s3: settings(mock.url) }));
    const env = { ...process.env, WG_EASY_URL: '', WG_EASY_PASSWORD: '', VPN_CONFIG: configPath };
    const project = join(directory, 'project');
    await cp(join(PACKAGE_ROOT, 'src'), join(project, 'src'), { recursive: true });
    await copyFile(join(PACKAGE_ROOT, 'package.json'), join(project, 'package.json'));
    await symlink(join(PACKAGE_ROOT, 'node_modules'), join(project, 'node_modules'), 'dir');
    const args = ['--import', 'tsx', 'src/cli/main.ts', 'rules:update', '--input', rulesPath];
    const first = await promisify(execFile)(process.execPath, args, { cwd: project, env });
    expect(JSON.parse(first.stdout).updated).toEqual([name]);
    mock.state.failUploadKey = `/test-bucket/profiles/${name}/sing-box.json`;
    await expect(promisify(execFile)(process.execPath, args, { cwd: project, env })).rejects.toMatchObject({ code: 1 });
    expect(mock.state.requests.some(request => request.path.startsWith('/api/'))).toBe(false);
    mock.state.failUploadKey = '';
    const pulled = await promisify(execFile)(process.execPath, ['--import', 'tsx', 'src/cli/main.ts', 'configs:pull'], { cwd: project, env });
    expect(JSON.parse(pulled.stdout).profiles).toEqual([name]);
    await expect(promisify(execFile)(process.execPath, ['--import', 'tsx', 'src/cli/main.ts', 'rules:publish'], { cwd: project, env })).rejects.toMatchObject({ code: 1 });
  }, 20_000);
});
