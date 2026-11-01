import type { JsonObject, JsonValue } from '../types.js';

export function formatRulesVersion(date = new Date()): string {
  return date.toISOString().slice(0, -1).replace(/[-T:.]/g, '_');
}

export function setRulesVersion(config: JsonObject, rulesUrl: string, version: string): boolean {
  const target = new URL(rulesUrl);
  if (!isObject(config.route) || !Array.isArray(config.route.rule_set)) return false;
  let changed = false;
  for (const entry of config.route.rule_set) {
    if (!isObject(entry) || entry.type !== 'remote' || typeof entry.url !== 'string') continue;
    if (entry.format !== undefined && entry.format !== 'source') continue;
    let url: URL;
    try { url = new URL(entry.url); } catch { continue; }
    if (url.origin !== target.origin || url.pathname !== target.pathname) continue;
    // Preserve custom/presigned/pinned URLs: only our unversioned or ?v= URL is managed.
    if ([...url.searchParams.keys()].some(key => key !== 'v')) continue;
    url.searchParams.set('v', version);
    if (url.href === entry.url) continue;
    entry.url = url.href;
    changed = true;
  }
  return changed;
}

function isObject(value: JsonValue | undefined): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
