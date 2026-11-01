import { isIP } from 'node:net';
import type { WireGuardConfig } from '../types.js';
import { invalidConfig } from '../shared/errors.js';
import { containsIp, coversIpv6Internet, integer, parseEndpoint, validateCidr } from './network.js';

export function validateWireGuard(wg: WireGuardConfig): void {
  validateKey(wg.privateKey, 'PrivateKey');
  if (!wg.addresses.length) invalidConfig('не хватает Address');
  wg.addresses.forEach(cidr => validateCidr(cidr, 'Address'));
  if (!wg.dns.some(address => isIP(address))) invalidConfig('не хватает DNS');
  if (wg.dns.some(address => !isIP(address))) invalidConfig('DNS: нужен IP-адрес');
  if (!wg.peers.length) invalidConfig('нет Peer');
  const peerKeys = new Set<string>();
  for (const peer of wg.peers) {
    validateKey(peer.publicKey, 'PublicKey');
    if (peerKeys.has(peer.publicKey)) invalidConfig('повторный PublicKey у peers');
    peerKeys.add(peer.publicKey);
    if (peer.presharedKey !== undefined) validateKey(peer.presharedKey, 'PresharedKey');
    if (!peer.allowedIps.length) invalidConfig('не хватает AllowedIPs');
    peer.allowedIps.forEach(cidr => validateCidr(cidr, 'AllowedIPs'));
    const host = isIP(peer.endpoint.address) === 6 ? `[${peer.endpoint.address}]` : peer.endpoint.address;
    parseEndpoint(`${host}:${peer.endpoint.port}`);
    if (peer.keepalive !== undefined) integer(String(peer.keepalive), 'PersistentKeepalive', 0, 65535);
  }
  if (wg.mtu !== undefined) integer(String(wg.mtu), 'MTU', 576, 65535);
  if (wg.listenPort !== undefined) integer(String(wg.listenPort), 'ListenPort', 0, 65535);
}

function validateKey(value: string, field: string): void {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(value) || Buffer.from(value, 'base64').length !== 32 ||
      Buffer.from(value, 'base64').toString('base64') !== value) invalidConfig(`${field}: нужен base64-ключ из 32 байт`);
}

export function selectNetwork(wg: WireGuardConfig): { ipv6: boolean; dns: string } {
  const routes = wg.peers.flatMap(peer => peer.allowedIps);
  const ipv6 = wg.addresses.some(cidr => isIP(cidr.split('/')[0]!) === 6) && coversIpv6Internet(routes);
  if (ipv6 && wg.mtu !== undefined && wg.mtu < 1280) invalidConfig('MTU для IPv6 должен быть не меньше 1280');
  const dns = wg.dns.find(address => {
    const family = isIP(address);
    return (family === 4 || ipv6) && wg.addresses.some(cidr => isIP(cidr.split('/')[0]!) === family) &&
      routes.some(cidr => containsIp(cidr, address));
  });
  if (!dns) invalidConfig('нет подходящего DNS, достижимого через AllowedIPs и адреса интерфейса');
  return { ipv6, dns };
}
