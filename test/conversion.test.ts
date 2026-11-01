import { TEST_RULES_URL } from './fixtures/config.js';
import { describe, expect, it } from 'vitest';
import { buildSingBoxConfig, parseWireGuard } from '../src/conversion/index.js';
import { key, wireGuard } from './fixtures/config.js';

describe('WireGuard conversion', () => {
  it('parses wg-quick lists and multiple peers', () => {
    const text = wireGuard().replace('Address = 10.8.0.2/24', 'Address = 10.8.0.2/24 # comment\nAddress = fd00::2/64')
      .replace('DNS = 10.8.0.1', 'DNS = 10.8.0.1, home.example\nDNS = fd00::1')
      .replace('AllowedIPs = 0.0.0.0/0', 'AllowedIPs = 0.0.0.0/0\nAllowedIPs = ::/1, 8000::/1') +
      `[Peer]\nPublicKey = ${key(4)}\nEndpoint = [2001:db8::1]:5000\nAllowedIPs = 192.0.2.0/24\n`;
    const parsed = parseWireGuard(text.replaceAll('\n', '\r\n'));
    expect(parsed.addresses).toEqual(['10.8.0.2/24', 'fd00::2/64']);
    expect(parsed.dns).toEqual(['10.8.0.1', 'fd00::1']);
    expect(parsed.peers).toHaveLength(2);
    expect(parsed.peers[0]?.allowedIps).toHaveLength(3);
    expect(parsed.peers[0]?.keepalive).toBe(25);
    expect(parsed.peers[1]?.endpoint).toEqual({ address: '2001:db8::1', port: 5000 });
  });

  it.each([
    [`PrivateKey = ${key(1)}`, 'PrivateKey = secret-invalid'],
    ['10.8.0.2/24', '10.8.0.2/33'], ['10.8.0.2/24', 'fd00::2/129'],
    ['10.8.0.2/24', '10.8.0.2/024'], ['10.8.0.2/24', 'fe80::2%en0/64'],
    ['0.0.0.0/0', '0.0.0.0/00'], ['0.0.0.0/0', 'fe80::%en0/64'],
    ['vpn.example.com:51820', '2001:db8::1:51820'], ['vpn.example.com:51820', '[not-ip]:51820'],
    ['vpn.example.com:51820', 'vpn.example.com:65536'], ['vpn.example.com:51820', '999.1.1.1:80'],
    ['MTU = 1420', 'MTU = 1420\nMTU = 1400'], ['MTU = 1420', 'MTU = 20'],
    ['PersistentKeepalive = 25', 'PersistentKeepalive = 65536'],
    ['ListenPort = 0', 'ListenPort = 65536'],
    ['ListenPort = 0', 'PostUp = echo secret-invalid'],
    ['ListenPort = 0', 'Table = off'],
  ])('rejects invalid wireguard fields (%s)', (before, after) => {
    expect(() => parseWireGuard(wireGuard().replace(before, after))).toThrow('Невалидный конфиг');
    try { parseWireGuard(wireGuard().replace(before, after)); } catch (e) {
      expect(String(e)).not.toContain('secret-invalid');
    }
  });

  it('rejects missing dns', () => {
    for (const replacement of ['', 'DNS =', 'DNS = search.example']) {
      expect(() => parseWireGuard(wireGuard().replace('DNS = 10.8.0.1', replacement)))
        .toThrowError('Невалидный конфиг: не хватает DNS');
    }
  });

  it('separates bootstrap and application dns', () => {
    const config = buildSingBoxConfig(parseWireGuard(wireGuard()), TEST_RULES_URL, 'iphone');
    expect(config.dns).toMatchObject({ final: '@wg-dns', reverse_mapping: true, servers: [
      { type: 'local', tag: '@bootstrap' }, { server: '10.8.0.1', detour: 'sf-iphone' },
    ] });
    expect(config.http_clients).toEqual([{ tag: '@rules-http', domain_resolver: '@bootstrap' }]);
    expect(config.endpoints).toMatchObject([{ tag: 'sf-iphone', domain_resolver: '@bootstrap' }]);
    expect(config.route).toMatchObject({ final: '@direct', default_domain_resolver: '@wg-dns', rule_set: [
      { http_client: '@rules-http', update_interval: '1h', url: TEST_RULES_URL },
    ] });
  });

  it('enables ipv6 only with usable routes', () => {
    for (const allowed of ['::/0', '::/1, 8000::/1']) {
      const config = buildSingBoxConfig(parseWireGuard(wireGuard(true).replace('::/0', allowed)), TEST_RULES_URL);
      expect(config.dns).toMatchObject({ strategy: 'prefer_ipv4' });
      expect(JSON.stringify(config.route)).not.toContain('reject');
    }
    for (const text of [wireGuard(), wireGuard(true).replace('::/0', 'fd00::/64'), wireGuard(true).replace(', fd00::2/64', '')]) {
      const config = buildSingBoxConfig(parseWireGuard(text), TEST_RULES_URL);
      expect(config.dns).toMatchObject({ strategy: 'ipv4_only' });
      expect(config.route).toMatchObject({ rules: expect.arrayContaining([{ rule_set: '@vpn-rules', ip_version: 6, action: 'reject' }]) });
      expect(config.inbounds).toMatchObject([{ address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'], route_address: ['0.0.0.0/0', '::/0'] }]);
    }
  });

  it('rejects unreachable dns and insufficient ipv6 MTU', () => {
    expect(() => buildSingBoxConfig(parseWireGuard(wireGuard().replace('0.0.0.0/0', '192.0.2.0/24')), TEST_RULES_URL)).toThrow('DNS');
    expect(() => buildSingBoxConfig(parseWireGuard(wireGuard(true).replace('1420', '1200')), TEST_RULES_URL)).toThrow('MTU');
    expect(() => buildSingBoxConfig(parseWireGuard(wireGuard().replace('DNS = 10.8.0.1', 'DNS = fd00::1')), TEST_RULES_URL)).toThrow('DNS');
  });
});
