import type { JsonObject, JsonValue } from '../types.js';
import type { VpnConfig } from '../config/private.js';
import { requireConfig } from '../config/private.js';
import { ConnectionConverter, parseConnectionMap } from '../conversion/connections.js';
import { collectConnections } from '../panels/index.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { UserError } from '../shared/errors.js';
import { parseJsonObject } from '../shared/json.js';
import { validateUrl } from '../shared/validation.js';
import { objectUrl, readOptionalObject, validateStorage } from '../storage/object.js';
import { profileKeys } from '../storage/keys.js';
import { listProfiles, readProfile } from '../storage/profiles.js';
import { preflightConnectionsPublication, publishConnectionsProfile } from './connections-publication.js';

export interface PrepareOptions {
  rulesUrl?: string;
  previous?: JsonObject;
  clientId?: string;
  readOnly?: boolean;
}
export interface PreparedProfile {
  name: string;
  connections: Record<string, string>;
  config: JsonObject;
}

export function preservedRulesUrl(rulesUrl: string, previous?: JsonObject): string {
  const target = new URL(rulesUrl);
  if ([...target.searchParams.keys()].some(key => key !== 'v')) return rulesUrl;
  const route = previous?.route;
  if (!isObject(route) || !Array.isArray(route.rule_set)) return rulesUrl;
  for (const rule of route.rule_set) {
    if (!isObject(rule) || rule.type !== 'remote' || typeof rule.url !== 'string') continue;
    if (rule.format !== undefined && rule.format !== 'source') continue;
    let old: URL;
    try { old = new URL(rule.url); } catch { continue; }
    if (old.origin !== target.origin || old.pathname !== target.pathname || old.hash !== target.hash ||
        [...old.searchParams.keys()].some(key => key !== 'v')) continue;
    const version = old.searchParams.get('v');
    if (version) { target.searchParams.set('v', version); return target.href; }
  }
  return rulesUrl;
}

/** Validate command dependencies locally, before reads or mutations of any remote service. */
function validatePreparation(config: VpnConfig, options: PrepareOptions = {}): string {
  requireConfig(config, ['panels']);
  const rulesUrl = options.rulesUrl ?? config.routing?.rulesUrl;
  if (!rulesUrl) throw new UserError('Для команды требуется routing.rulesUrl или --rules.');
  validateUrl(rulesUrl, 'routing.rulesUrl', true);
  const entries = Object.values(config.connections!);
  if (entries.length > 1 || entries.some(entry => config.panels![entry.panel]?.type !== 'wg-easy')) requireConfig(config, ['dns']);
  if (config.s3) validateStorage(config.s3);
  if (options.clientId !== undefined) {
    if (!/^[A-Za-z0-9_-]+$/.test(options.clientId)) throw new UserError('Некорректный ID клиента.');
    const wgPanels = new Set(entries.filter(entry => config.panels![entry.panel]?.type === 'wg-easy').map(entry => entry.panel));
    if (wgPanels.size !== 1) throw new UserError('--client-id требует ровно одну выбранную панель wg-easy.');
  }
  return rulesUrl;
}

/** Shared preparation for CLI, publication, and A → B → A acceptance. No S3 writes. */
export async function prepareProfile(config: VpnConfig, name: string, options: PrepareOptions = {}): Promise<PreparedProfile> {
  name = normalizeProfileName(name);
  const rulesUrl = validatePreparation(config, options);
  const converter = new ConnectionConverter({ name,
    rulesUrl: preservedRulesUrl(rulesUrl, options.previous),
    ...(config.dns ? { dns: config.dns } : {}), urltest: config.urltest,
    ...(config.s3 ? { profileUrl: objectUrl(config.s3, profileKeys(name).singBox) } : {}),
  });
  const connections = await collectConnections(config, name, {
    ...(options.clientId !== undefined ? { clientId: options.clientId } : {}),
    ...(options.readOnly !== undefined ? { readOnly: options.readOnly } : {}),
  });
  return { name, connections, config: converter.convert(connections) };
}

export async function loadPreviousProfile(config: VpnConfig, name: string): Promise<JsonObject | undefined> {
  requireConfig(config, ['s3']);
  const bytes = await readOptionalObject(config.s3!, profileKeys(normalizeProfileName(name)).singBox);
  return bytes === undefined ? undefined : parseJsonObject(bytes.toString('utf8'));
}

export async function provisionManaged(config: VpnConfig, name: string, options: PrepareOptions & {
  outputDirectory?: string; createOnly?: boolean;
} = {}) {
  name = normalizeProfileName(name);
  requireConfig(config, ['s3']);
  validatePreparation(config, options);
  await preflightConnectionsPublication({ name, storage: config.s3!,
    ...(options.outputDirectory !== undefined ? { outputDirectory: options.outputDirectory } : {}),
    ...(options.createOnly !== undefined ? { createOnly: options.createOnly } : {}),
  });
  const previous = await loadPreviousProfile(config, name);
  if (options.createOnly && previous) throw new UserError('Профиль уже существует; --create-only запрещает перезапись.');
  const prepared = await prepareProfile(config, name, { ...options, ...(previous ? { previous } : {}) });
  return publishConnectionsProfile({ ...prepared, storage: config.s3!,
    ...(options.outputDirectory ? { outputDirectory: options.outputDirectory } : {}),
    ...(options.createOnly !== undefined ? { createOnly: options.createOnly } : {}),
  });
}

export async function updateProfiles(config: VpnConfig, options: { outputDirectory?: string; rulesUrl?: string } = {}) {
  requireConfig(config, ['panels', 's3']);
  validatePreparation(config, options);
  const results: { name: string; updated: boolean; error?: string }[] = [];
  for (const profile of await listProfiles(config.s3!)) {
    try {
      await provisionManaged(config, profile.name, options);
      results.push({ name: profile.name, updated: true });
    } catch (error) {
      results.push({ name: profile.name, updated: false,
        error: error instanceof UserError ? error.message : 'Не удалось пересобрать профиль.' });
    }
  }
  return results;
}

export async function describeProfiles(config: VpnConfig) {
  requireConfig(config, ['s3']);
  const results = [];
  for (const profile of await listProfiles(config.s3!)) {
    const document = parseJsonObject(await readProfile(config.s3!, profile));
    const connections = [document.endpoints, document.outbounds].flatMap(items => Array.isArray(items) ? items : [])
      .filter(isObject).filter(item => !['direct', 'selector', 'urltest', 'block', 'dns'].includes(String(item.type)))
      .map(item => ({ name: item.tag, type: item.type }));
    results.push({ name: profile.name, profileUrl: objectUrl(config.s3!, profile.key), connections });
  }
  return results;
}

export async function uploadConnections(config: VpnConfig, name: string, document: JsonObject, map?: unknown,
  options: { outputDirectory?: string; createOnly?: boolean } = {}) {
  requireConfig(config, ['s3']);
  if (map === undefined) {
    const bytes = await readOptionalObject(config.s3!, profileKeys(normalizeProfileName(name)).connections);
    if (!bytes) throw new UserError('Нет connections.json в S3. Укажите --connections <file> или выполните provision.');
    try { map = JSON.parse(bytes.toString('utf8')); }
    catch { throw new UserError('Некорректный connections.json в S3.'); }
  }
  return publishConnectionsProfile({ name, config: document, connections: parseConnectionMap(map), storage: config.s3!, ...options });
}

function isObject(value: JsonValue | undefined): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
