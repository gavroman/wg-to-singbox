import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { ProfileData, PublishProfileOptions, PublishProfileResult } from './types.js';
import { createWorkingProfile, removeWorkingProfile, ProfileOperationError } from '../artifacts/workspace.js';
import type { WorkingProfile } from '../artifacts/workspace.js';
import { pullProfile } from '../configs/pull.js';
import { formatJson, readTextFile, writePrivateFile } from '../artifacts/files.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { UserError } from '../shared/errors.js';
import { validateUrl } from '../shared/validation.js';
import { parseJsonObject } from '../shared/json.js';
import { parseWireGuard } from '../conversion/index.js';
import { makeImportUri, writeQr } from '../connection/index.js';
import { renderProfilePage } from '../connection/page.js';
import { profileKeys, publishJson, publishObject, validateStorage } from '../storage/index.js';

export async function publishProfile(options: PublishProfileOptions): Promise<PublishProfileResult> {
  const work = await createWorkingProfile(options.name);
  try {
    const result = await publishPreparedProfile(options, work);
    await removeWorkingProfile(work);
    return result;
  } catch (error) { throw new ProfileOperationError(error, work); }
}

export async function publishPreparedProfile(options: PublishProfileOptions, paths: WorkingProfile): Promise<PublishProfileResult> {
  const name = normalizeProfileName(options.name);
  validateStorage(options.storage);
  validateUrl(options.storage.endpoint, 'S3_ENDPOINT для remote profile', true);
  const keys = profileKeys(name);
  const singBoxPath = resolve(options.singBoxPath);
  const wireGuardPath = resolve(options.wireGuardPath);
  // Read and validate both inputs before the first remote write.
  const contents = await readTextFile(singBoxPath);
  const wireGuard = await readTextFile(wireGuardPath);
  const config = parseJsonObject(contents);
  const wg = parseWireGuard(wireGuard);
  if (!Array.isArray(config.endpoints) || !config.endpoints.some(endpoint =>
    endpoint && typeof endpoint === 'object' && !Array.isArray(endpoint) &&
    endpoint.type === 'wireguard' && endpoint.private_key === wg.privateKey)) {
    throw new UserError('Исходный WireGuard-файл не соответствует WG endpoint в sing-box JSON.');
  }
  await writePrivateFile(paths.singBox, contents);
  await writePrivateFile(paths.wireGuard, wireGuard);

  const checkpoint: Record<string, string> = { name, singBoxPath, wireGuardPath };
  if (options.clientId !== undefined) checkpoint.clientId = options.clientId;
  const saveCheckpoint = () => writePrivateFile(paths.result, formatJson(checkpoint));
  const profileUrl = await publishJson(options.storage, keys.singBox, contents);
  const importUri = makeImportUri(profileUrl, name);
  Object.assign(checkpoint, { profileUrl, importUri });
  await saveCheckpoint();
  const wireGuardUrl = await publishObject(options.storage, keys.wireGuard, wireGuard);
  Object.assign(checkpoint, { wireGuardUrl });
  await saveCheckpoint();
  await writeQr(importUri, paths.qr);
  checkpoint.qrPath = paths.qr;
  await saveCheckpoint();
  const qrUrl = await publishObject(options.storage, keys.qr, await readFile(paths.qr));
  checkpoint.qrUrl = qrUrl;
  await saveCheckpoint();
  const page = renderProfilePage({ name, profileUrl, qrUrl });
  await writePrivateFile(paths.page, page);
  checkpoint.pagePath = paths.page;
  await saveCheckpoint();
  const pageUrl = await publishObject(options.storage, keys.page, page);
  checkpoint.pageUrl = pageUrl;
  await saveCheckpoint();

  // Publish the manifest last, with remote URLs only and no local filesystem paths.
  const data: ProfileData = { name, ...(options.clientId !== undefined ? { clientId: options.clientId } : {}),
    profileUrl, wireGuardUrl, qrUrl, pageUrl, importUri };
  const dataContents = formatJson(data);
  await writePrivateFile(paths.data, dataContents);
  checkpoint.dataPath = paths.data;
  await saveCheckpoint();
  const dataUrl = await publishJson(options.storage, keys.data, dataContents);
  checkpoint.dataUrl = dataUrl;
  await saveCheckpoint();
  const cache = await pullProfile(options.storage, name, options.outputDirectory);
  const result = { ...data, singBoxPath: cache.singBox, wireGuardPath: cache.wireGuard,
    qrPath: cache.qr, pagePath: cache.page, dataPath: cache.data, dataUrl };
  return result;
}
