import type { JsonObject, WireGuardConfig } from '../types.js';
import { validateUrl } from '../shared/validation.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { selectNetwork, validateWireGuard } from './validation.js';

export function buildSingBoxConfig(wg: WireGuardConfig, rulesUrl: string, name = 'vpn'): JsonObject {
  return buildSingleWireGuardConfig(wg, rulesUrl, normalizeProfileName(name));
}

// The new pipeline supplies the exact connection name; the legacy wrapper retains its API.
export function buildSingleWireGuardConfig(wg: WireGuardConfig, rulesUrl: string, name: string): JsonObject {
  validateUrl(rulesUrl, 'VPN_RULES_URL', true);
  validateWireGuard(wg);
  const { ipv6, dns } = selectNetwork(wg);
  const strategy = ipv6 ? 'prefer_ipv4' : 'ipv4_only';
  return {
    log: { level: 'info', timestamp: true },
    dns: {
      servers: [
        { type: 'local', tag: '@bootstrap' },
        { type: 'udp', tag: '@wg-dns', server: dns, detour: name },
      ],
      final: '@wg-dns', strategy, reverse_mapping: true,
    },
    // No detour: this HTTP client owns its direct dialer and bootstrap resolver.
    http_clients: [{ tag: '@rules-http', domain_resolver: '@bootstrap' }],
    endpoints: [{
      type: 'wireguard', tag: name, system: false,
      address: wg.addresses, private_key: wg.privateKey,
      domain_resolver: '@bootstrap',
      ...(wg.mtu !== undefined ? { mtu: wg.mtu } : {}),
      ...(wg.listenPort !== undefined ? { listen_port: wg.listenPort } : {}),
      peers: wg.peers.map(peer => ({
        address: peer.endpoint.address, port: peer.endpoint.port,
        public_key: peer.publicKey, allowed_ips: peer.allowedIps,
        ...(peer.presharedKey !== undefined ? { pre_shared_key: peer.presharedKey } : {}),
        ...(peer.keepalive !== undefined ? { persistent_keepalive_interval: peer.keepalive } : {}),
      })),
    }],
    inbounds: [{
      type: 'tun', tag: '@tun', auto_route: true, strict_route: true, dns_mode: 'hijack',
      // Capture IPv6 even when WG is IPv4-only so selected traffic cannot bypass reject.
      address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
      route_address: ['0.0.0.0/0', '::/0'],
    }],
    outbounds: [{ type: 'direct', tag: '@direct' }],
    route: {
      auto_detect_interface: true, default_domain_resolver: '@wg-dns', final: '@direct',
      rules: [
        { action: 'sniff' },
        { type: 'logical', mode: 'or', rules: [{ protocol: 'dns' }, { port: 53 }], action: 'hijack-dns' },
        ...(!ipv6 ? [{ rule_set: '@vpn-rules', ip_version: 6, action: 'reject' }] : []),
        { rule_set: '@vpn-rules', action: 'route', outbound: name },
      ],
      rule_set: [{
        type: 'remote', tag: '@vpn-rules', format: 'source', url: rulesUrl,
        http_client: '@rules-http', update_interval: '1h',
      }],
    },
    experimental: { cache_file: { enabled: true } },
  };
}
