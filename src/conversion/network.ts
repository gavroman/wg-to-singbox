import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { invalidConfig } from '../shared/errors.js';

export function isHostname(value: string): boolean {
  const hostname = value.replace(/\.$/, '');
  return hostname.length <= 253 && hostname.split('.').every(label =>
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
}

export function validateCidr(value: string, field: string): void {
  const parts = value.split('/');
  const family = isIP(parts[0] ?? '');
  if (parts.length !== 2 || !family || value.includes('%') || !/^(0|[1-9]\d{0,2})$/.test(parts[1] ?? '') ||
      Number(parts[1]) > (family === 4 ? 32 : 128)) invalidConfig(`${field}: неверный CIDR`);
}

export function parseEndpoint(value: string): { address: string; port: number } {
  const match = value.startsWith('[') ? /^\[([^\]]+)\]:(\d+)$/.exec(value) : /^([^:]+):(\d+)$/.exec(value);
  if (!match) invalidConfig('Endpoint: ожидается host:port или [IPv6]:port');
  const address = match[1]!;
  if (value.startsWith('[') ? isIP(address) !== 6 : !isIP(address) && (!isHostname(address) || /^[\d.]+$/.test(address))) {
    invalidConfig('Endpoint: неверный адрес');
  }
  return { address, port: integer(match[2]!, 'Endpoint port', 1, 65535) };
}

export function integer(value: string, field: string, min: number, max: number): number {
  const number = Number(value);
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(number) || number < min || number > max) {
    invalidConfig(`${field}: ожидается целое число от ${min} до ${max}`);
  }
  return number;
}

export function containsIp(cidr: string, address: string): boolean {
  const [network, prefix] = ipaddr.parseCIDR(cidr);
  const ip = ipaddr.parse(address);
  return network.kind() === ip.kind() && ip.match(network, prefix);
}

// Merge ranges: ::/0 and a pair of /1 routes provide the same coverage.
export function coversIpv6Internet(cidrs: string[]): boolean {
  const ranges = cidrs.filter(cidr => isIP(cidr.split('/')[0]!) === 6).map(cidr => {
    const [address, prefix] = ipaddr.parseCIDR(cidr);
    const value = address.toByteArray().reduce((n, byte) => (n << 8n) | BigInt(byte), 0n);
    const size = 1n << BigInt(128 - prefix);
    const start = value / size * size;
    return { start, end: start + size };
  }).sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
  let covered = 0n;
  for (const range of ranges) {
    if (range.start > covered) return false;
    if (range.end > covered) covered = range.end;
  }
  return covered === 1n << 128n;
}
