import type { ProvisionOptions, ProvisionResult, WgOptions } from '../types.js';
import { obtainWireGuard } from '../wireguard/index.js';
import { buildSingBoxConfig, parseWireGuard } from '../conversion/index.js';
import { validateStorage } from '../storage/index.js';
import { makeImportUri, writeQr } from '../connection/index.js';
import { createWorkingProfile, removeWorkingProfile, ProfileOperationError } from '../artifacts/workspace.js';
import { formatJson, writePrivateFile } from '../artifacts/files.js';
import { validateUrl } from '../shared/validation.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { publishPreparedProfile } from './publication.js';

export async function downloadProfile(wg: WgOptions) {
  wg = { ...wg, name: normalizeProfileName(wg.name) };
  const paths = await createWorkingProfile(wg.name);
  try {
    const result = await obtainWireGuard(wg, async identity => {
      await writePrivateFile(paths.client, formatJson({ name: wg.name, ...identity }));
    });
    await writePrivateFile(paths.wireGuard, result.text);
    return { ...result, paths };
  } catch (error) { throw new ProfileOperationError(error, paths); }
}

export async function connectProfile(url: string, name: string) {
  name = normalizeProfileName(name);
  const importUri = makeImportUri(url, name);
  const paths = await createWorkingProfile(name);
  const published = { name, profileUrl: url, importUri };
  // Standalone connection details belong to the operation workspace, not the S3 cache.
  await writePrivateFile(paths.result, formatJson(published));
  await writeQr(importUri, paths.qr);
  const result = { ...published, qrPath: paths.qr };
  await writePrivateFile(paths.result, formatJson(result));
  return result;
}

export async function provision(options: ProvisionOptions): Promise<ProvisionResult> {
  options = { ...options, wg: { ...options.wg, name: normalizeProfileName(options.wg.name) } };
  validateUrl(options.rulesUrl, 'VPN_RULES_URL', true);
  validateStorage(options.storage);
  // Remote profiles need HTTPS. HTTP remains supported by publishJson for local mocks.
  validateUrl(options.storage.endpoint, 'S3_ENDPOINT для remote profile', true);
  const downloaded = await downloadProfile(options.wg);
  try {
    const config = buildSingBoxConfig(parseWireGuard(downloaded.text), options.rulesUrl, options.wg.name);
    await writePrivateFile(downloaded.paths.singBox, formatJson(config));
    const result = await publishPreparedProfile({ name: options.wg.name, storage: options.storage,
      clientId: downloaded.clientId, wireGuardPath: downloaded.paths.wireGuard, singBoxPath: downloaded.paths.singBox,
      outputDirectory: options.outputDirectory }, downloaded.paths);
    await removeWorkingProfile(downloaded.paths);
    return { ...result, clientId: downloaded.clientId };
  } catch (error) { throw new ProfileOperationError(error, downloaded.paths); }
}
