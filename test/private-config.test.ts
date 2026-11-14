import { afterEach, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadVpnConfig, parseVpnConfig, requireConfig, validConnectionName } from '../src/config/private.js';

function input() {
  return {
    version: 1,
    panels: {
      wg: { type: 'wg-easy', url: 'http://localhost:51821', password: 'synthetic-password' },
      '3x-main': { type: '3x-ui', url: 'http://localhost:2053/private/', apiToken: 'synthetic-token' },
    },
    connections: {
      'wg-easy': { type: 'wireguard', panel: 'wg' },
      '3x-wg': { type: 'wireguard', panel: '3x-main', inbound: { port: 51822, subnet: '10.20.0.0/24' } },
      '3x-vless': { type: 'vless-reality', panel: '3x-main', inbound: { port: 443,
        reality: { target: 'dl.google.com:443', serverNames: ['dl.google.com'] } } },
    },
  };
}

it('accepts connection names with country flags while keeping names safe and reserved tags unavailable', () => {
  const base = input();
  const connections = {
    'wg-easy-riga 🇱🇻': base.connections['wg-easy'],
    '3x-helsinki-vless 🇫🇮': base.connections['3x-vless'],
    '3x-paris-wg 🇫🇷': base.connections['3x-wg'],
  };
  expect(Object.keys(parseVpnConfig({ ...base, connections }).connections!)).toEqual(Object.keys(connections));
  for (const name of ['auto 🇱🇻', 'vpn 🇫🇮', '../test 🇫🇷', '3x-test\n', '3x-test 🇫', '3x-test 🇫🇷 ', 'a'.repeat(65), 'a'.repeat(62) + ' 🇫🇷']) {
    expect(validConnectionName(name), name).toBe(false);
  }
  expect(validConnectionName('a'.repeat(61) + ' 🇫🇷')).toBe(true);
});

it('loads private settings with optional sections and partial urltest defaults', () => {
  expect(parseVpnConfig({ version: 1 }).urltest).toEqual({ url: 'https://www.gstatic.com/generate_204', interval: '1m', tolerance: 80 });
  const config = parseVpnConfig({ ...input(), urltest: { interval: '30s' } });
  expect(config.urltest).toEqual({ url: 'https://www.gstatic.com/generate_204', interval: '30s', tolerance: 80 });
  expect(() => requireConfig(config, ['panels'])).not.toThrow();
  expect(() => requireConfig(config, ['s3'])).toThrow('s3');
  expect(() => requireConfig(parseVpnConfig({ version: 1, panels: {} }), ['panels'])).toThrow('connections');
});

it('validates panel references, compatible protocol, inbound parameters and 3x names before I/O', () => {
  const base = input();
  for (const connections of [
    { '3x-wg': { type: 'wireguard', panel: 'missing', inbound: { port: 51822, subnet: '10.20.0.0/24' } } },
    { '3x-wg': { type: 'wireguard', panel: '3x-main' } },
    { wg: base.connections['3x-wg'] },
    { 'wg-easy': { ...base.connections['wg-easy'], inbound: { port: 5, subnet: '10.1.0.0/24' } } },
    { '3x-vless': { ...base.connections['3x-vless'], panel: 'wg' } },
    { auto: base.connections['wg-easy'] },
  ]) expect(() => parseVpnConfig({ ...base, connections })).toThrow();
  expect(() => parseVpnConfig({ ...base, connections: { '3x-wg': {
    ...base.connections['3x-wg'], inbound: { ...base.connections['3x-wg'].inbound, id: 7, remark: 'test' },
  } } })).toThrow();
});

it('rejects overlapping and non-private WG pools including TUN and explicit reservations', () => {
  const base = input();
  for (const subnet of ['8.8.8.0/24', '10.20.0.1/24', '172.19.0.0/24', 'fd00::/64']) {
    expect(() => parseVpnConfig({ ...base, connections: { '3x-wg': {
      ...base.connections['3x-wg'], inbound: { port: 51822, subnet },
    } } })).toThrow('subnet');
  }
  expect(() => parseVpnConfig({ ...base, network: { reservedSubnets: ['10.0.0.0/8'] } })).toThrow('subnet');
  expect(() => parseVpnConfig({ ...base, connections: { ...base.connections, '3x-wg2': {
    ...base.connections['3x-wg'], inbound: { port: 51823, subnet: '10.20.0.128/25' },
  } } })).toThrow('subnet');
  expect(() => parseVpnConfig({ ...base, network: { reservedSubnets: ['10.0.8.0/24'] } })).not.toThrow();
});

it('does not reveal values or unknown secret property names in errors', () => {
  const secret = 'DO_NOT_LOG_THIS';
  for (const value of [
    { ...input(), s3: { endpoint: secret, secretAccessKey: secret } },
    { version: 1, [secret]: secret },
    { ...input(), urltest: { interval: secret } },
  ]) {
    try { parseVpnConfig(value); throw new Error('Expected invalid input'); }
    catch (error) { expect(String(error)).not.toContain(secret); }
  }
});

const directories: string[] = [];
afterEach(async () => { for (const directory of directories.splice(0)) await rm(directory, { force: true, recursive: true }); });
it('requires a selected file and gives --config priority over VPN_CONFIG', async () => {
  await expect(loadVpnConfig(undefined, {})).rejects.toThrow('VPN_CONFIG');
  const directory = await mkdtemp(join(tmpdir(), 'vpn-private-test-')); directories.push(directory);
  const explicit = join(directory, 'explicit.json');
  const fallback = join(directory, 'fallback.json');
  await writeFile(explicit, JSON.stringify({ version: 1, urltest: { tolerance: 12 } }));
  await writeFile(fallback, JSON.stringify({ version: 1, urltest: { tolerance: 34 } }));
  expect((await loadVpnConfig(explicit, { VPN_CONFIG: fallback })).urltest.tolerance).toBe(12);
  expect((await loadVpnConfig(undefined, { VPN_CONFIG: fallback })).urltest.tolerance).toBe(34);
  await writeFile(explicit, '{ "secret": "DO_NOT_LOG_THIS"');
  await expect(loadVpnConfig(explicit)).rejects.toThrow('Некорректный JSON');
});
