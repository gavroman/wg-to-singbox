import { readFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import type { JsonObject, JsonValue, StorageOptions } from '../types.js';
import { connectionParts, parseConnectionMap } from '../conversion/connections.js';
import { createWorkingProfile, removeWorkingProfile, ProfileOperationError } from '../artifacts/workspace.js';
import { ARTIFACTS_DIRECTORY } from '../artifacts/paths.js';
import { ensureDirectory } from '../artifacts/snapshot.js';
import { formatJson, writePrivateFile } from '../artifacts/files.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { UserError } from '../shared/errors.js';
import { validateUrl } from '../shared/validation.js';
import { parseJsonObject } from '../shared/json.js';
import { profileKeys } from '../storage/keys.js';
import { objectUrl, publishObject, readOptionalObject, validateStorage } from '../storage/object.js';
import { makeImportUri, writeQr } from '../connection/index.js';
import { renderProfilePage } from '../connection/page.js';
import { pullProfile } from '../configs/pull.js';

export interface PublishConnectionsOptions {
  name: string;
  storage: StorageOptions;
  config: JsonObject;
  connections: Record<string, string>;
  outputDirectory?: string;
  createOnly?: boolean;
}

export type ConnectionsPublicationPreflight = Pick<PublishConnectionsOptions,
  'name' | 'storage' | 'outputDirectory' | 'createOnly'>;

export interface PublishConnectionsResult {
  name: string;
  profileUrl: string;
  connectionsUrl: string;
  qrUrl: string;
  pageUrl: string;
  dataUrl: string;
  importUri: string;
  clientId?: string;
  wireGuardUrl?: string;
  singBoxPath: string;
  connectionsPath: string;
  qrPath: string;
  pagePath: string;
  dataPath: string;
}

function object(value: JsonValue | undefined): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Validate only connection nodes; routing, logging and other profile policy may be customized. */
export function validatePublishedConnections(config: JsonObject, connections: Record<string, string>): void {
  const expected = connectionParts(parseConnectionMap(connections));
  const seen = new Set<string>();
  for (const field of ['endpoints', 'outbounds'] as const) {
    const actual = config[field] ?? [];
    if (!Array.isArray(actual)) throw new UserError('В sing-box JSON ожидаются массивы endpoints/outbounds.');
    const wanted = new Map(expected[field].map(node => [node.tag, node]));
    for (const node of actual) {
      if (!object(node) || typeof node.tag !== 'string' || seen.has(node.tag)) {
        throw new UserError('Некорректный или повторный тег в sing-box JSON.');
      }
      seen.add(node.tag);
      const entry = wanted.get(node.tag);
      if (entry) {
        if (!isDeepStrictEqual(node, entry)) throw new UserError('Подключения в sing-box JSON не соответствуют connections.json.');
        wanted.delete(node.tag);
      } else if (field === 'endpoints' || !['direct', 'selector', 'urltest'].includes(String(node.type))) {
        throw new UserError('В sing-box JSON есть подключение, отсутствующее в connections.json.');
      }
    }
    if (wanted.size) throw new UserError('В sing-box JSON отсутствуют подключения из connections.json.');
  }
}

/** Check local destination and create-only conflicts before any panel mutation. */
export async function preflightConnectionsPublication(options: ConnectionsPublicationPreflight): Promise<void> {
  const name = normalizeProfileName(options.name);
  validateStorage(options.storage);
  validateUrl(options.storage.endpoint, 'S3_ENDPOINT для remote profile', true);
  const directory = options.outputDirectory ?? ARTIFACTS_DIRECTORY;
  try { await ensureDirectory(directory); }
  catch { throw new UserError('Не удалось подготовить каталог artifacts. Проверьте путь и права доступа.'); }
  if (options.createOnly) {
    for (const key of Object.values(profileKeys(name))) {
      if (await readOptionalObject(options.storage, key) !== undefined) {
        throw new UserError('Профиль уже существует в S3: режим create-only запрещает перезапись.');
      }
    }
  }
}

export async function publishConnectionsProfile(options: PublishConnectionsOptions): Promise<PublishConnectionsResult> {
  const name = normalizeProfileName(options.name);
  validatePublishedConnections(options.config, options.connections);
  await preflightConnectionsPublication(options);
  const directory = options.outputDirectory ?? ARTIFACTS_DIRECTORY;
  const work = await createWorkingProfile(name);
  try {
    const keys = profileKeys(name);
    const oldBytes = await readOptionalObject(options.storage, keys.data);
    const old = oldBytes === undefined ? undefined : parseJsonObject(oldBytes.toString('utf8'));
    if (old && old.name !== name) throw new UserError('Метаданные S3 не соответствуют профилю.');
    const profileUrl = objectUrl(options.storage, keys.singBox);
    const connectionsUrl = objectUrl(options.storage, keys.connections);
    const qrUrl = objectUrl(options.storage, keys.qr);
    const pageUrl = objectUrl(options.storage, keys.page);
    const dataUrl = objectUrl(options.storage, keys.data);
    const importUri = makeImportUri(profileUrl, name);
    const retained: { clientId?: string; wireGuardUrl?: string } = {};
    if (old?.clientId !== undefined) {
      if (typeof old.clientId !== 'string' || !/^[A-Za-z0-9_-]+$/.test(old.clientId)) throw new UserError('Некорректный clientId в data.json.');
      retained.clientId = old.clientId;
    }
    if (old?.wireGuardUrl !== undefined) {
      if (old.wireGuardUrl !== objectUrl(options.storage, keys.wireGuard)) throw new UserError('Некорректный wireGuardUrl в data.json.');
      if (await readOptionalObject(options.storage, keys.wireGuard) === undefined) throw new UserError('В data.json указан отсутствующий WireGuard-файл.');
      retained.wireGuardUrl = old.wireGuardUrl;
    }
    const data = { name, ...retained, profileUrl, connectionsUrl, qrUrl, pageUrl, importUri };
    // Fully prepare all artifacts, including QR and HTML, before any remote write.
    await writePrivateFile(work.singBox, formatJson(options.config));
    await writePrivateFile(work.connections, formatJson(options.connections));
    await writeQr(importUri, work.qr);
    await writePrivateFile(work.page, renderProfilePage({ name, profileUrl, qrUrl }));
    await writePrivateFile(work.data, formatJson(data));
    const files = ['singBox', 'connections', 'qr', 'page', 'data'] as const;
    const contents = await Promise.all(files.map(file => readFile(work[file])));
    const checkpoint = { name, completed: [] as string[] };
    await writePrivateFile(work.result, formatJson(checkpoint));
    for (const [index, file] of files.entries()) {
      await publishObject(options.storage, keys[file], contents[index]!,
        options.createOnly === undefined ? {} : { createOnly: options.createOnly });
      checkpoint.completed.push(file);
      await writePrivateFile(work.result, formatJson(checkpoint));
    }
    const cache = await pullProfile(options.storage, name, directory);
    await removeWorkingProfile(work);
    return { ...data, dataUrl, singBoxPath: cache.singBox, connectionsPath: cache.connections,
      qrPath: cache.qr, pagePath: cache.page, dataPath: cache.data };
  } catch (error) { throw new ProfileOperationError(error, work); }
}
