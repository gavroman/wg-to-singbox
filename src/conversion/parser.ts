import { isIP } from 'node:net';
import type { WireGuardConfig, WgPeer } from '../types.js';
import { invalidConfig } from '../shared/errors.js';
import { integer, isHostname, parseEndpoint } from './network.js';
import { validateWireGuard } from './validation.js';

type Section = Map<string, string[]>;
const INTERFACE_FIELDS = new Set(['PrivateKey', 'Address', 'DNS', 'MTU', 'ListenPort']);
const PEER_FIELDS = new Set(['PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive']);
const LIST_FIELDS = new Set(['Address', 'DNS', 'AllowedIPs']);

export function parseWireGuard(text: string): WireGuardConfig {
  const { iface, peers } = readSections(text);
  const dns = list(iface, 'DNS', true);
  // wg-quick allows search domains; these are not DNS server addresses.
  if (!dns.some(value => isIP(value))) invalidConfig('не хватает DNS');
  if (dns.some(value => !value)) invalidConfig('DNS: пустой элемент списка');
  if (dns.some(value => !isIP(value) && (!isHostname(value) || /^[\d.]+$/.test(value)))) invalidConfig('DNS: неверный адрес');
  const config: WireGuardConfig = {
    privateKey: required(iface, 'PrivateKey'), addresses: list(iface, 'Address'),
    dns: dns.filter(value => isIP(value)), peers: peers.map(parsePeer),
    ...optionalNumber(iface, 'MTU', 'mtu', 576, 65535),
    ...optionalNumber(iface, 'ListenPort', 'listenPort', 0, 65535),
  };
  validateWireGuard(config);
  return config;
}

function readSections(text: string): { iface: Section; peers: Section[] } {
  let iface: Section | undefined;
  const peers: Section[] = [];
  let current: Section | undefined;
  let allowed = INTERFACE_FIELDS;
  for (const [index, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.replace(/[#;].*$/, '').trim();
    if (!line) continue;
    if (line === '[Interface]') {
      if (iface || peers.length) invalidConfig('повторная секция Interface');
      iface = current = new Map(); allowed = INTERFACE_FIELDS; continue;
    }
    if (line === '[Peer]') {
      if (!iface) invalidConfig('Peer перед Interface');
      current = new Map(); peers.push(current); allowed = PEER_FIELDS; continue;
    }
    const match = /^([A-Za-z]+)\s*=\s*(.*)$/.exec(line);
    if (!current || !match) invalidConfig(`синтаксис в строке ${index + 1}`);
    const key = match[1]!;
    if (!allowed.has(key)) invalidConfig(`неподдерживаемый параметр в строке ${index + 1} (hooks не исполняются)`);
    if (current.has(key) && !LIST_FIELDS.has(key)) invalidConfig(`повторный ${key}`);
    current.set(key, [...(current.get(key) ?? []), match[2]!.trim()]);
  }
  if (!iface) invalidConfig('нет Interface');
  if (!peers.length) invalidConfig('нет Peer');
  return { iface, peers };
}

function required(section: Section, key: string): string {
  const value = section.get(key)?.[0];
  if (!value) invalidConfig(`не хватает ${key}`);
  return value;
}

function list(section: Section, key: string, allowEmpty = false): string[] {
  const values = (section.get(key) ?? []).flatMap(value => value.split(',').map(item => item.trim()));
  if (!allowEmpty && values.some(value => !value)) invalidConfig(`${key}: пустой элемент списка`);
  return values;
}

function optionalNumber<K extends string>(section: Section, field: string, property: K, min: number, max: number): Partial<Record<K, number>> {
  const value = section.get(field)?.[0];
  return value === undefined ? {} : { [property]: integer(value, field, min, max) } as Record<K, number>;
}

function parsePeer(section: Section): WgPeer {
  return {
    publicKey: required(section, 'PublicKey'), endpoint: parseEndpoint(required(section, 'Endpoint')),
    allowedIps: list(section, 'AllowedIPs'),
    ...(section.has('PresharedKey') ? { presharedKey: required(section, 'PresharedKey') } : {}),
    ...optionalNumber(section, 'PersistentKeepalive', 'keepalive', 0, 65535),
  };
}
