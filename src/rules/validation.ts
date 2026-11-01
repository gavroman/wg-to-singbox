import { isIP } from 'node:net';
import { validateCidr } from '../conversion/network.js';
import { UserError } from '../shared/errors.js';
import { parseJsonObject } from '../shared/json.js';

// Explicitly support the site's domain/IP rules and their logical combinations.
// Unknown fields fail closed instead of publishing an unvalidated shared ruleset.
const matchFields = new Set(['domain', 'domain_suffix', 'domain_keyword', 'ip_cidr', 'source_ip_cidr', 'network', 'port', 'source_port']);

export function validateRules(contents: string): void {
  const data = parseJsonObject(contents);
  if (Object.keys(data).some(key => !['version', 'rules'].includes(key)) || data.version !== 5 ||
      !Array.isArray(data.rules) || !data.rules.length) fail('ожидается source rule-set v5 с массивом rules');
  data.rules.forEach(rule => validateRule(rule, 0));
}

function validateRule(value: unknown, depth: number): void {
  if (depth > 32 || !value || typeof value !== 'object' || Array.isArray(value)) fail('неверный объект правила');
  const rule = value as Record<string, unknown>;
  if (rule.invert !== undefined && typeof rule.invert !== 'boolean') fail('invert должен быть boolean');
  if (rule.type === 'logical') {
    if (Object.keys(rule).some(key => !['type', 'mode', 'rules', 'invert'].includes(key)) ||
        typeof rule.mode !== 'string' || !['and', 'or'].includes(rule.mode) ||
        !Array.isArray(rule.rules) || !rule.rules.length) fail('неверное logical rule');
    rule.rules.forEach(child => validateRule(child, depth + 1));
    return;
  }
  if (rule.type !== undefined && rule.type !== 'default') fail('неподдерживаемый type');
  const fields = Object.keys(rule).filter(key => !['type', 'invert'].includes(key));
  if (!fields.length) fail('пустое правило');
  for (const field of fields) {
    if (!matchFields.has(field)) fail('неподдерживаемое поле правила');
    const items = Array.isArray(rule[field]) ? rule[field] : [rule[field]];
    if (!items.length) fail('пустой список');
    for (const item of items) validateMatch(field, item);
  }
}

function validateMatch(field: string, value: unknown): void {
  if (field === 'port' || field === 'source_port') {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 65535) fail('неверный port');
    return;
  }
  if (typeof value !== 'string' || !value.trim()) fail('ожидается непустая строка');
  if (field === 'network' && !['tcp', 'udp', 'icmp'].includes(value)) fail('неверный network');
  if (field.endsWith('ip_cidr')) {
    try {
      if (value.includes('%')) fail('IPv6 zone не поддерживается');
      if (!isIP(value)) validateCidr(value, field);
    } catch { fail('неверный IP/CIDR'); }
  }
}

function fail(reason: string): never { throw new UserError(`VPN rules: ${reason}.`); }
