import { normalizeProfileName } from '../shared/profile-name.js';
import { UserError } from '../shared/errors.js';

export function profileKeys(name: string) {
  const prefix = `profiles/${normalizeProfileName(name)}`;
  return { singBox: `${prefix}/sing-box.json`, wireGuard: `${prefix}/wireguard.conf`,
    connections: `${prefix}/connections.json`,
    qr: `${prefix}/qr.png`, page: `${prefix}/index.html`, data: `${prefix}/data.json` };
}

export function profileKey(name: string): string { return profileKeys(name).singBox; }

export function objectContentType(key: string): string {
  if (key === 'rules/vpn_rules.json') return 'application/json';
  const match = /^profiles\/sf-[A-Za-z0-9_-]{0,61}\/(sing-box\.json|connections\.json|wireguard\.conf|qr\.png|index\.html|data\.json)$/.exec(key);
  if (!match) throw new UserError('Недопустимый ключ объекта S3.');
  if (match[1] === 'wireguard.conf') return 'text/plain; charset=utf-8';
  if (match[1] === 'qr.png') return 'image/png';
  if (match[1] === 'index.html') return 'text/html; charset=utf-8';
  return 'application/json';
}
