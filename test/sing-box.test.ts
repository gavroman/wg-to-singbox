import { TEST_RULES_URL } from './fixtures/config.js';
import { it, expect } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSingBoxConfig, parseWireGuard } from '../src/conversion/index.js';
import { RULES_TEMPLATE_PATH } from '../src/rules/source.js';
import { wireGuard } from './fixtures/config.js';

it('passes sing-box 1.14.4 validation', async () => {
  const exec = promisify(execFile);
  const binary = process.env.SING_BOX_BINARY ?? 'sing-box';
  const version = await exec(binary, ['version']); // Missing binary is a failure, never a skip.
  expect(version.stdout).toMatch(/^sing-box version 1\.14\.4\s/m);
  const directory = await mkdtemp(join(tmpdir(), 'libertd-core-'));
  try {
    await exec(binary, ['rule-set', 'compile', '--output', join(directory, 'rules.srs'), RULES_TEMPLATE_PATH]);
    for (const dualStack of [false, true]) {
      const path = join(directory, `config-${dualStack}.json`);
      const config = buildSingBoxConfig(parseWireGuard(wireGuard(dualStack)), TEST_RULES_URL, 'iphone');
      await writeFile(path, JSON.stringify(config));
      const checked = await exec(binary, ['check', '-c', path], { cwd: directory });
      expect(checked.stdout + checked.stderr).not.toContain('independent_cache');
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
}, 30_000);

it('validates the same converter for single WG, single VLESS, and multiple connections', async () => {
  const { ConnectionConverter, wireGuardToUri } = await import('../src/conversion/connections.js');
  const exec = promisify(execFile);
  const binary = process.env.SING_BOX_BINARY ?? 'sing-box';
  const version = await exec(binary, ['version']);
  expect(version.stdout).toMatch(/^sing-box version 1\.14\.4\s/m);
  const directory = await mkdtemp(join(tmpdir(), 'libertd-multi-core-'));
  const vless = 'vless://b72afc0b-bd96-4bad-a089-33c162ab31b1@198.51.100.2:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=example.com&pbk=' + Buffer.alloc(32, 3).toString('base64url') + '&sid=1234&fp=chrome';
  const wg = wireGuardToUri(wireGuard());
  const maps: Record<string, string>[] = [{ 'wg-easy': wg }, { 'wg-dual': wireGuardToUri(wireGuard(true)) }, { '3x-vless': vless }, { 'wg-easy': wg, '3x-wg': wg, '3x-vless': vless }];
  const converter = new ConnectionConverter({ name: 'iphone', rulesUrl: TEST_RULES_URL,
    dns: { server: '1.1.1.1', serverName: 'cloudflare-dns.com' } });
  try {
    for (const [index, connections] of maps.entries()) {
      const path = join(directory, `config-${index}.json`);
      const config = converter.convert(connections);
      await writeFile(path, JSON.stringify(config));
      const checked = await exec(binary, ['check', '-c', path], { cwd: directory });
      expect(checked.stdout + checked.stderr).not.toMatch(/legacy address filter|deprecated/i);
      // Load the actual mixed domain/IP/port rules locally: this check never
      // downloads a rule-set or opens a VPN connection.
      (config.route as Record<string, unknown>).rule_set = [{
        type: 'local', tag: '@vpn-rules', format: 'source', path: RULES_TEMPLATE_PATH,
      }];
      await writeFile(path, JSON.stringify(config));
      const checkedLocal = await exec(binary, ['check', '-c', path], { cwd: directory });
      expect(checkedLocal.stdout + checkedLocal.stderr).not.toMatch(/legacy address filter|deprecated/i);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
}, 30_000);

it('starts the DNS rule engine with mixed rules without deprecated address filtering', async () => {
  const { ConnectionConverter, wireGuardToUri } = await import('../src/conversion/connections.js');
  const binary = process.env.SING_BOX_BINARY ?? 'sing-box';
  const config = new ConnectionConverter({ name: 'dns-check', rulesUrl: TEST_RULES_URL,
    dns: { server: '1.1.1.1', serverName: 'cloudflare-dns.com' },
  }).convert({ first: wireGuardToUri(wireGuard()), second: wireGuardToUri(wireGuard()) });
  // Keep the generated DNS rules, but remove listeners, VPN endpoints, probes,
  // remote DNS and remote rule downloads. Startup must perform no network I/O.
  config.inbounds = [];
  config.endpoints = [];
  config.outbounds = [{ type: 'direct', tag: '@direct' }, { type: 'direct', tag: 'vpn' }];
  const dns = config.dns as Record<string, unknown>;
  dns.servers = ['@bootstrap', '@vpn-dns'].map(tag => ({ type: 'hosts', tag,
    predefined: { 'example.com': ['192.0.2.1'] },
  }));
  const route = config.route as Record<string, unknown>;
  delete route.auto_detect_interface;
  route.rule_set = [{ type: 'local', tag: '@vpn-rules', format: 'source', path: RULES_TEMPLATE_PATH }];
  (config.experimental as Record<string, unknown>).cache_file = { enabled: false };
  const directory = await mkdtemp(join(tmpdir(), 'libertd-dns-startup-'));
  const path = join(directory, 'config.json');
  await writeFile(path, JSON.stringify(config));
  const child = spawn(binary, ['run', '-c', path], { cwd: directory, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  const closed = new Promise<void>(resolve => child.once('close', () => resolve()));
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Core startup timed out: ' + output)), 5000);
      const receive = (data: Buffer) => {
        output += data.toString();
        if (/sing-box started/i.test(output)) { clearTimeout(timer); resolve(); }
      };
      child.stdout.on('data', receive);
      child.stderr.on('data', receive);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', code => { clearTimeout(timer); reject(new Error(`Core exited ${code}: ${output}`)); });
    });
    expect(output).not.toMatch(/legacy address filter|deprecated/i);
  } finally {
    child.kill('SIGTERM');
    const force = setTimeout(() => child.kill('SIGKILL'), 2000);
    try { await closed; } finally { clearTimeout(force); await rm(directory, { recursive: true, force: true }); }
  }
}, 10_000);
