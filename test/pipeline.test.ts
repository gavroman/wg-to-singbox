import { TEST_RULES_URL } from './fixtures/config.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, readdir, rm, stat, chmod, symlink, link, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { PNG } from 'pngjs';
import { createRequire } from 'node:module';
const decodeQr = createRequire(import.meta.url)('jsqr') as (data: Uint8ClampedArray, width: number, height: number) => { data: string } | null;
import { mockServices } from './server.js';
import { obtainWireGuard } from '../src/wireguard/index.js';
import { publishJson, publishObject } from '../src/storage/index.js';
import { RULES_TEMPLATE_PATH } from '../src/rules/source.js';
import { updateRules } from '../src/rules/update.js';
import { ProfileOperationError } from '../src/artifacts/workspace.js';
import { provision } from '../src/provision/index.js';
import { uploadProfile } from '../src/provision/upload.js';
import { buildSingBoxConfig, parseWireGuard } from '../src/conversion/index.js';
import { key, wireGuard } from './fixtures/config.js';
import { makeImportUri, writeQr } from '../src/connection/index.js';
import { PACKAGE_ROOT, storageSettings, wgSettings } from '../src/config/index.js';
import { conversionOutput, profilePaths } from '../src/artifacts/paths.js';
import { writePrivateFile } from '../src/artifacts/files.js';
import { handlers } from '../src/cli/handlers.js';
import { validateRules } from '../src/rules/validation.js';

const exec = promisify(execFile);
describe('pipeline with local HTTPS and S3 mocks', () => {
  let mock: Awaited<ReturnType<typeof mockServices>>;
  let directory: string;
  const failedWork: string[] = [];
  async function operationFailure(promise: Promise<unknown>): Promise<ProfileOperationError> {
    try { await promise; throw new Error("Expected operation failure"); }
    catch (error) {
      expect(error).toBeInstanceOf(ProfileOperationError);
      const failure = error as ProfileOperationError; failedWork.push(failure.work.root); return failure;
    }
  }
  beforeEach(async () => {
    // Only local test services use a self-signed certificate. Never part of production code.
    vi.stubEnv('NODE_TLS_REJECT_UNAUTHORIZED', '0');
    mock = await mockServices(); directory = await mkdtemp(join(tmpdir(), 'libertd-test-'));
  });
  afterEach(async () => { await mock?.close(); for (const path of failedWork.splice(0)) await rm(path, { recursive: true, force: true }); if (directory) await rm(directory, { recursive: true, force: true }); vi.unstubAllEnvs(); vi.restoreAllMocks(); });
  const name = 'sf-iphone';
  const settings = (endpoint: string) => ({ endpoint, region: 'ru-central1', bucket: 'test-bucket', accessKeyId: 'synthetic-key', secretAccessKey: 'synthetic-secret' });
  const wg = (baseUrl: string) => ({ baseUrl, name, password: 'synthetic-password' });

  it('reuses an existing named client', async () => {
    mock.state.clients.push({ id: 'existing', name });
    expect(await obtainWireGuard(wg(mock.url))).toMatchObject({ clientId: 'existing', created: false });
    expect(mock.state.requests.filter(r => r.method === 'POST' && r.path.endsWith('/client'))).toHaveLength(0);
    mock.state.clients.push({ id: 'duplicate', name });
    await expect(obtainWireGuard(wg(mock.url))).rejects.toThrow('--client-id');
    expect(await obtainWireGuard({ ...wg(mock.url), clientId: 'existing' })).toMatchObject({ clientId: 'existing' });
    await expect(obtainWireGuard({ ...wg(mock.url), name: 'other', clientId: 'existing' })).rejects.toThrow('Имя');
  });

  it('prefixes the WG name once and leaves old unprefixed clients untouched', async () => {
    mock.state.clients.push({ id: 'old-client', name: 'iphone' });
    const options = { ...wg(mock.url), name: 'iphone' };
    const created = await obtainWireGuard(options);
    expect(created).toMatchObject({ clientId: 'client-2', created: true });
    expect(options.name).toBe('iphone');
    expect(mock.state.clients.map(client => client.name)).toEqual(['iphone', 'sf-iphone']);
    expect(await obtainWireGuard({ ...options, name: 'sf-iphone' })).toMatchObject({ clientId: 'client-2', created: false });
    await expect(obtainWireGuard({ ...options, clientId: 'old-client' })).rejects.toThrow('Имя');
    const creations = mock.state.requests.filter(request => request.method === 'POST' && request.path.endsWith('/client'));
    expect(creations.map(request => JSON.parse(request.body))).toEqual([{ name: 'sf-iphone' }]);
  });

  it('rejects names exceeding the limit after prefixing before requests', async () => {
    await expect(obtainWireGuard({ ...wg(mock.url), name: 'a'.repeat(62) })).rejects.toThrow('64');
    expect(mock.state.requests).toHaveLength(0);
  });

  it('does not retry ambiguous creation', async () => {
    mock.state.creation = 'lost';
    await expect(obtainWireGuard(wg(mock.url))).rejects.toThrow('неизвестен');
    expect(mock.state.requests.filter(r => r.method === 'POST' && r.path.endsWith('/client'))).toHaveLength(1);
    expect(await obtainWireGuard(wg(mock.url))).toMatchObject({ clientId: 'client-1', created: false });
    mock.state.clients = []; mock.state.creation = 'duplicate';
    await expect(obtainWireGuard(wg(mock.url))).rejects.toThrow('однозначно');
  });

  it('persists confirmed identity before configuration download', async () => {
    mock.state.failDownload = true;
    const failure = await operationFailure(provision({ wg: wg(mock.url), storage: settings(mock.url), rulesUrl: TEST_RULES_URL, outputDirectory: directory }));
    expect(failure.message).toContain('client-1');
    expect(JSON.parse(await readFile(failure.work.client, 'utf8'))).toMatchObject({ clientId: 'client-1', created: true });
  });

  it('validates names before requests and refuses disabled clients', async () => {
    await expect(obtainWireGuard({ ...wg(mock.url), name: '../escape' })).rejects.toThrow('Имя');
    expect(mock.state.requests).toHaveLength(0);
    mock.state.clients.push({ id: 'disabled', name, enabled: false });
    await expect(obtainWireGuard(wg(mock.url))).rejects.toThrow('отключён');
    expect(mock.state.requests.some(r => r.path.endsWith('/configuration'))).toBe(false);
  });

  it('publishes a readable stable profile url', async () => {
    const contents = '{"version":1}\n';
    const url = await publishJson(settings(mock.url), 'profiles/sf-iphone/sing-box.json', contents);
    expect(await publishJson(settings(mock.url), 'profiles/sf-iphone/sing-box.json', '{"version":2}')).toBe(url);
    expect(url).toBe(`${mock.url}/test-bucket/profiles/sf-iphone/sing-box.json`);
    const put = mock.state.requests.find(r => r.method === 'PUT')!;
    expect(put.body).toBe(contents);
    expect(put.headers).toMatchObject({ 'content-type': 'application/json', 'cache-control': 'no-store', 'x-amz-acl': 'public-read' });
    expect(put.headers.authorization).toContain('synthetic-key');
    expect(mock.state.requests.find(r => r.method === 'GET')?.headers.authorization).toBeUndefined();
    mock.state.corruptRead = true;
    await expect(publishJson(settings(mock.url), 'profiles/sf-iphone/sing-box.json', contents)).rejects.toThrow('не совпадает');
    mock.state.privateRead = true;
    await expect(publishJson(settings(mock.url), 'profiles/sf-iphone/sing-box.json', contents)).rejects.toThrow('403');
  });

  it('publishes all five files and remote-only data under the profile prefix', async () => {
    const result = await provision({ wg: wg(mock.url), storage: settings(mock.url),
      rulesUrl: TEST_RULES_URL, outputDirectory: directory });
    const prefix = '/test-bucket/profiles/sf-iphone/';
    const expected = ['sing-box.json', 'wireguard.conf', 'qr.png', 'index.html', 'data.json'];
    expect([...mock.state.objects.keys()]).toEqual(expected.map(file => prefix + file));
    expect(mock.state.objects.get(prefix + 'sing-box.json')).toEqual(await readFile(result.singBoxPath));
    expect(mock.state.objects.get(prefix + 'wireguard.conf')).toEqual(await readFile(result.wireGuardPath));
    const remoteQr = mock.state.objects.get(prefix + 'qr.png')!;
    expect(remoteQr).toEqual(await readFile(result.qrPath));
    const png = PNG.sync.read(remoteQr);
    expect(decodeQr(new Uint8ClampedArray(png.data), png.width, png.height)?.data).toBe(result.importUri);
    expect(new URL(result.importUri).searchParams.get('url')).toBe(`${mock.url}${prefix}sing-box.json`);
    const dataBytes = mock.state.objects.get(prefix + 'data.json')!;
    expect(dataBytes).toEqual(await readFile(result.dataPath));
    expect(JSON.parse(dataBytes.toString())).toEqual({
      name, clientId: result.clientId, profileUrl: result.profileUrl, wireGuardUrl: result.wireGuardUrl,
      qrUrl: result.qrUrl, pageUrl: result.pageUrl, importUri: result.importUri,
    });
    expect(dataBytes.toString()).not.toContain(directory);
    expect(dataBytes.toString()).not.toContain(key(1));
    expect(result.dataUrl).toBe(`${mock.url}${prefix}data.json`);
    expect(result.pageUrl).toBe(`${mock.url}${prefix}index.html`);
    const pageBytes = mock.state.objects.get(prefix + 'index.html')!;
    expect(pageBytes).toEqual(await readFile(result.pagePath));
    const page = pageBytes.toString();
    expect(page).toContain(`<h1>${name}</h1>`);
    expect(page).toContain(`src="${result.qrUrl}"`);
    expect(page).toContain(`href="${result.importUri}"`);
    expect(page).toContain(`href="${result.profileUrl}"`);
    expect(page).not.toContain(directory);
    expect(page).not.toContain(key(1));
    const uploads = mock.state.requests.filter(request => request.method === 'PUT');
    expect(uploads.map(request => request.headers['content-type'])).toEqual([
      'application/json', 'text/plain; charset=utf-8', 'image/png', 'text/html; charset=utf-8', 'application/json',
    ]);
    expect(uploads.find(request => request.path.split('?')[0]?.endsWith('/index.html'))?.headers['content-disposition']).toBe('inline');
    for (const upload of uploads) {
      expect(upload.headers['cache-control']).toBe('no-store');
      expect(mock.state.requests.some(request => request.method === 'GET' && request.path === upload.path.split('?')[0] && !request.headers.authorization)).toBe(true);
    }
  });

  it('rejects old flat profile keys and checks binary downloads byte for byte', async () => {
    await expect(publishJson(settings(mock.url), 'profiles/sf-iphone.json', '{}')).rejects.toThrow('ключ');
    expect(mock.state.requests).toHaveLength(0);
    const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0xff, 0, 0x80]);
    await publishObject(settings(mock.url), 'profiles/sf-iphone/qr.png', bytes);
    expect(mock.state.objects.get('/test-bucket/profiles/sf-iphone/qr.png')).toEqual(bytes);
    mock.state.corruptRead = true;
    await expect(publishObject(settings(mock.url), 'profiles/sf-iphone/qr.png', bytes)).rejects.toThrow('не совпадает');
  });

  it.each(['wireguard.conf', 'qr.png', 'index.html', 'data.json'])('recovers a partial bundle after %s upload failure without WG access', async failedFile => {
    mock.state.failUploadKey = `/test-bucket/profiles/sf-iphone/${failedFile}`;
    const failure = await operationFailure(provision({ wg: wg(mock.url), storage: settings(mock.url), rulesUrl: TEST_RULES_URL,
      outputDirectory: directory }));
    expect(failure.message).toContain('S3');
    const paths = failure.work;
    expect(JSON.parse(await readFile(paths.result, 'utf8')).profileUrl).toBe(`${mock.url}/test-bucket/profiles/sf-iphone/sing-box.json`);
    expect(mock.state.objects.has('/test-bucket/profiles/sf-iphone/data.json')).toBe(false);
    const apiRequests = mock.state.requests.filter(request => request.path.startsWith('/api/')).length;
    mock.state.failUploadKey = '';
    const recovered = await uploadProfile({ name, input: paths.singBox, wireGuardInput: paths.wireGuard, storage: settings(mock.url), outputDirectory: directory });
    expect(recovered.clientId).toBeUndefined();
    expect(mock.state.objects).toHaveLength(5);
    expect(mock.state.requests.filter(request => request.path.startsWith('/api/'))).toHaveLength(apiRequests);
    expect(mock.state.clients).toHaveLength(1);
  });

  it('uploads an explicit config pair and rejects missing or mismatched WG before requests', async () => {
    const jsonPath = join(directory, 'manual.json');
    const wgPath = join(directory, 'manual.conf');
    const contents = wireGuard();
    await writeFile(jsonPath, JSON.stringify(buildSingBoxConfig(parseWireGuard(contents), TEST_RULES_URL, name)));
    const options = { name, input: jsonPath, storage: settings(mock.url), outputDirectory: directory };
    expect((await operationFailure(uploadProfile(options))).message).toContain('--wireguard');
    mock.state.requests = [];
    await writeFile(wgPath, contents.replace(key(1), key(4)));
    expect((await operationFailure(uploadProfile({ ...options, wireGuardInput: wgPath }))).message).toContain('не соответствует');
    expect(mock.state.requests).toHaveLength(0);
    await writeFile(wgPath, contents);
    const result = await uploadProfile({ ...options, wireGuardInput: wgPath });
    expect(result.clientId).toBeUndefined();
    expect(mock.state.objects).toHaveLength(5);
    expect(mock.state.clients).toHaveLength(0);
    expect(JSON.parse(mock.state.objects.get('/test-bucket/profiles/sf-iphone/data.json')!.toString()).clientId).toBeUndefined();
  });

  it('uses the WG file and client ID from S3 when upload omits --wireguard', async () => {
    const original = await provision({ wg: wg(mock.url), storage: settings(mock.url),
      rulesUrl: TEST_RULES_URL, outputDirectory: directory });
    const input = join(directory, 'input.json');
    await writeFile(input, await readFile(original.singBoxPath));
    const paths = profilePaths(name, directory);
    await rm(paths.root, { recursive: true, force: true });
    await writePrivateFile(paths.wireGuard, 'stale-local-file');
    const apiCount = mock.state.requests.filter(request => request.path.startsWith('/api/')).length;
    const result = await uploadProfile({ name, input, storage: settings(mock.url), outputDirectory: directory });
    expect(result.clientId).toBe(original.clientId);
    expect(await readFile(result.wireGuardPath, 'utf8')).toContain('[Interface]');
    expect(mock.state.requests.filter(request => request.path.startsWith('/api/'))).toHaveLength(apiCount);
    expect((await readdir(paths.root)).sort()).toEqual(['data.json', 'index.html', 'qr.png', 'sing-box.json', 'wireguard.conf']);
  });

  it('publishes local rules without changing their contents', async () => {
    await updateRules({ storage: settings(mock.url), rulesPath: RULES_TEMPLATE_PATH, outputDirectory: join(directory, 'cache') });
    expect(mock.state.objects.get('/test-bucket/rules/vpn_rules.json')).toEqual(await readFile(RULES_TEMPLATE_PATH));
    expect(mock.state.requests.filter(request => request.method === 'PUT')).toHaveLength(1);
  });

  it('rejects invalid rules before any upload', async () => {
    const path = join(directory, 'rules.json');
    for (const rule of [{ domain_suffix: 42 }, { ip_cidr: ['broken'] },
      { type: 'logical', mode: 'or', rules: [{ domain: 3 }] },
      { type: 'logical', mode: ['and'], rules: [{ domain: 'example.com' }] }, { unsupported: true }]) {
      await writeFile(path, JSON.stringify({ version: 5, rules: [rule] }));
      await expect(updateRules({ storage: settings(mock.url), rulesPath: path, outputDirectory: join(directory, 'cache') })).rejects.toThrow('VPN rules');
    }
    expect(mock.state.requests).toHaveLength(0);
    expect(() => validateRules(JSON.stringify({ version: 5, rules: [{ type: 'logical', mode: 'and',
      rules: [{ domain_suffix: 'example.com' }, { port: [80, 443], network: 'tcp' }] }] }))).not.toThrow();
  });

  it('rejects HTTP upload endpoints before publishing', async () => {
    const commands = handlers({ S3_ENDPOINT: mock.url.replace('https:', 'http:'), S3_BUCKET: 'test-bucket', S3_ACCESS_KEY_ID: 'test', S3_SECRET_ACCESS_KEY: 'test' }, () => {});
    await expect(commands.upload({ input: 'unused.json', name })).rejects.toThrow('HTTPS');
    expect(mock.state.requests).toHaveLength(0);
  });

  it('replaces cached links without modifying their targets', async () => {
    const paths = profilePaths(name, directory);
    await writePrivateFile(paths.data, '{}');
    await writePrivateFile(join(directory, 'protected'), 'before');
    await symlink(join(directory, 'protected'), paths.qr);
    const result = await provision({ wg: wg(mock.url), storage: settings(mock.url), rulesUrl: TEST_RULES_URL,
      outputDirectory: directory });
    expect(await readFile(join(directory, 'protected'), 'utf8')).toBe('before');
    expect(PNG.sync.read(await readFile(result.qrPath)).width).toBeGreaterThan(0);
    expect((await readdir(paths.root)).sort()).toEqual(['data.json', 'index.html', 'qr.png', 'sing-box.json', 'wireguard.conf']);
  });

  it('preserves artifacts after upload failure', async () => {
    const options = { wg: wg(mock.url), storage: settings(mock.url), rulesUrl: TEST_RULES_URL, outputDirectory: directory };
    mock.state.failUpload = true;
    const failure = await operationFailure(provision(options));
    expect(failure.message).toContain('S3');
    const paths = failure.work;
    expect(await readFile(paths.wireGuard, 'utf8')).toContain('[Interface]');
    expect(JSON.parse(await readFile(paths.singBox, 'utf8'))).toHaveProperty('endpoints');
    mock.state.failUpload = false;
    const result = await provision(options);
    expect(result.clientId).toBe('client-1'); expect(mock.state.clients).toHaveLength(1);
    expect([...mock.state.objects.keys()]).toEqual(['sing-box.json', 'wireguard.conf', 'qr.png', 'index.html', 'data.json'].map(file => `/test-bucket/profiles/sf-iphone/${file}`));
  });

  it.each(['client', 'result'])('keeps profile and metadata separate for name %s', async profileName => {
    const result = await provision({ wg: { ...wg(mock.url), name: profileName }, storage: settings(mock.url),
      rulesUrl: TEST_RULES_URL, outputDirectory: directory });
    const paths = profilePaths(profileName, directory);
    expect(JSON.parse(await readFile(result.singBoxPath, 'utf8'))).toHaveProperty('endpoints');
    expect(JSON.parse(await readFile(paths.data, 'utf8'))).toHaveProperty('clientId');
    expect(JSON.parse(await readFile(paths.data, 'utf8'))).toHaveProperty('importUri');
  });

  it('keeps case-sensitive profiles separate on disk and in WG and S3', async () => {
    const results = [];
    for (const profileName of ['iphone', 'iPhone']) {
      results.push(await provision({ wg: { ...wg(mock.url), name: profileName }, storage: settings(mock.url),
        rulesUrl: TEST_RULES_URL, outputDirectory: directory }));
    }
    // A case-insensitive filesystem must not consider these paths equivalent.
    expect(results[0]!.singBoxPath.toLowerCase()).not.toBe(results[1]!.singBoxPath.toLowerCase());
    for (const [index, profileName] of ['iphone', 'iPhone'].entries()) {
      const paths = profilePaths(profileName, directory);
      const config = JSON.parse(await readFile(paths.singBox, 'utf8'));
      expect(config.endpoints[0].tag).toBe(`sf-${profileName}`);
      expect(JSON.parse(await readFile(paths.data, 'utf8'))).toMatchObject({
        name: `sf-${profileName}`, clientId: results[index]!.clientId,
      });
      expect(JSON.parse(await readFile(paths.data, 'utf8')).name).toBe(`sf-${profileName}`);
      expect(results[index]!.profileUrl).toBe(`${mock.url}/test-bucket/profiles/sf-${profileName}/sing-box.json`);
      const png = PNG.sync.read(await readFile(paths.qr));
      expect(decodeQr(new Uint8ClampedArray(png.data), png.width, png.height)?.data).toBe(results[index]!.importUri);
    }
    const repeated = await provision({ wg: wg(mock.url), storage: settings(mock.url),
      rulesUrl: TEST_RULES_URL, outputDirectory: directory });
    expect(repeated).toEqual(results[0]);
    expect(mock.state.clients.map(client => client.name)).toEqual(['sf-iphone', 'sf-iPhone']);
    expect([...mock.state.objects.keys()]).toEqual(['sf-iphone', 'sf-iPhone'].flatMap(profile => ['sing-box.json', 'wireguard.conf', 'qr.png', 'index.html', 'data.json'].map(file => `/test-bucket/profiles/${profile}/${file}`)));
  });

  it('encodes import uri and qr consistently', async () => {
    const url = 'https://example.com/profile.json?x=a%20b&v=2#fragment';
    const uri = makeImportUri(url, 'Phone_A-2');
    expect(new URL(uri).searchParams.get('url')).toBe(url);
    expect(new URL(uri).hash).toBe('#sf-Phone_A-2');
    const path = join(directory, 'qr.png'); await writeQr(uri, path);
    const png = PNG.sync.read(await readFile(path));
    expect(decodeQr(new Uint8ClampedArray(png.data), png.width, png.height)?.data).toBe(uri);
  });

  it('protects files and rejects input aliases', async () => {
    const input = join(directory, 'vpn.conf'); await writePrivateFile(input, 'before');
    await chmod(input, 0o644); await writePrivateFile(input, 'after');
    if (process.platform !== 'win32') expect((await stat(input)).mode & 0o777).toBe(0o600);
    await link(input, join(directory, 'hard.conf')); await symlink(input, join(directory, 'sym.conf'));
    for (const output of ['vpn.conf', 'hard.conf', 'sym.conf']) await expect(conversionOutput(input, output)).rejects.toThrow('Перезапись');
    await expect(writePrivateFile(join(directory, 'sym.conf'), 'bad')).rejects.toThrow();
    expect(await readFile(input, 'utf8')).toBe('after');
  });

  it('validates only the required environment and hides credentials', () => {
    expect(() => storageSettings({})).toThrow('S3_ACCESS_KEY_ID');
    expect(() => wgSettings({ WG_EASY_URL: 'bad-secret-url', WG_EASY_PASSWORD: 'private' }, name)).toThrow('WG_EASY_URL');
    try { wgSettings({ WG_EASY_URL: 'bad-secret-url' }, name); } catch (error) { expect(String(error)).not.toContain('bad-secret-url'); }
  });

  it('runs the complete cli pipeline', async () => {
    const cliName = `test-${process.pid}`;
    const env = { ...process.env, WG_EASY_URL: mock.url, WG_EASY_PASSWORD: 'test',
      S3_ENDPOINT: mock.url, S3_BUCKET: 'test-bucket', S3_REGION: 'ru-central1',
      S3_ACCESS_KEY_ID: 'synthetic-key', S3_SECRET_ACCESS_KEY: 'synthetic-secret', VPN_RULES_URL: TEST_RULES_URL };
    try {
      const args = ['--import', 'tsx', 'src/cli/main.ts', 'provision', '--name', cliName];
      const first = await exec(process.execPath, args, { cwd: PACKAGE_ROOT, env });
      const result = JSON.parse(first.stdout);
      expect(result.name).toBe(`sf-${cliName}`); expect(result.importUri).toContain('sing-box://');
      expect(await stat(result.qrPath)).toBeDefined();
      expect(first.stdout).not.toContain('synthetic-secret');
      const apiCount = mock.state.requests.filter(request => request.path.startsWith('/api/')).length;
      const uploaded = await exec(process.execPath, ['--import', 'tsx', 'src/cli/main.ts', 'upload',
        '--input', result.singBoxPath, '--wireguard', result.wireGuardPath, '--name', cliName], {
        cwd: PACKAGE_ROOT, env: { ...env, WG_EASY_URL: '', WG_EASY_PASSWORD: '' },
      });
      expect(JSON.parse(uploaded.stdout).dataUrl).toBe(`${mock.url}/test-bucket/profiles/sf-${cliName}/data.json`);
      expect(mock.state.requests.filter(request => request.path.startsWith('/api/'))).toHaveLength(apiCount);
      await exec(process.execPath, [...args.slice(0, -1), `sf-${cliName}`], { cwd: PACKAGE_ROOT, env });
      expect(mock.state.clients).toHaveLength(1);
      expect(mock.state.clients[0]?.name).toBe(`sf-${cliName}`);
      expect(result.profileUrl).toBe(`${mock.url}/test-bucket/profiles/sf-${cliName}/sing-box.json`);
      await expect(exec(process.execPath, [...args.slice(0, -1), '../bad'], { cwd: PACKAGE_ROOT, env })).rejects.toMatchObject({ code: 1 });
      const input = join(directory, 'vpn.conf');
      await writeFile(input, '[Interface]\n');
      await expect(exec(process.execPath, ['--import', 'tsx', 'src/cli/main.ts', 'convert', '--input', input], { cwd: PACKAGE_ROOT, env })).rejects.toMatchObject({ code: 1 });
    } finally { await rm(profilePaths(cliName).root, { recursive: true, force: true }); }
  }, 20_000);
});
