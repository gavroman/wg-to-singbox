import { rm } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import type { StorageOptions } from '../storage/types.js';
import type { ConfigsPullOptions, ConfigsPullResult } from './types.js';
import { ARTIFACTS_DIRECTORY, artifactRulesPath, profilePaths } from '../artifacts/paths.js';
import { writePrivateFile } from '../artifacts/files.js';
import { createSnapshotStage, ensureDirectory, installSnapshot } from '../artifacts/snapshot.js';
import { profileKeys } from '../storage/keys.js';
import { listProfiles } from '../storage/profiles.js';
import { readObject, readOptionalObject, validateStorage, objectUrl } from '../storage/object.js';
import { parseJsonObject } from '../shared/json.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { UserError } from '../shared/errors.js';

async function downloadProfileFiles(storage: StorageOptions, name: string, paths: ReturnType<typeof profilePaths>): Promise<void> {
  const keys = profileKeys(name);
  const dataBytes = await readObject(storage, keys.data);
  const data = parseJsonObject(dataBytes.toString('utf8'));
  if (data.name !== normalizeProfileName(name)) throw new UserError('Метаданные S3 не соответствуют профилю.');
  await writePrivateFile(paths.data, dataBytes);
  for (const file of ['singBox', 'qr', 'page'] as const) {
    await writePrivateFile(paths[file], await readObject(storage, keys[file]));
  }
  if (data.connectionsUrl !== undefined) {
    if (data.connectionsUrl !== objectUrl(storage, keys.connections)) throw new UserError('Некорректный URL мапки подключений в data.json.');
    await writePrivateFile(paths.connections, await readObject(storage, keys.connections));
    const wireGuard = await readOptionalObject(storage, keys.wireGuard);
    if (wireGuard !== undefined) await writePrivateFile(paths.wireGuard, wireGuard);
    else if (data.wireGuardUrl !== undefined) throw new UserError('В data.json указан отсутствующий WireGuard-файл.');
  } else {
    await writePrivateFile(paths.wireGuard, await readObject(storage, keys.wireGuard));
    const connections = await readOptionalObject(storage, keys.connections);
    if (connections !== undefined) await writePrivateFile(paths.connections, connections);
  }
}

export async function pullProfile(storage: StorageOptions, name: string, directory = ARTIFACTS_DIRECTORY) {
  validateStorage(storage);
  await ensureDirectory(resolve(directory));
  const paths = profilePaths(name, directory);
  await ensureDirectory(dirname(paths.root));
  const stage = await createSnapshotStage(paths.root);
  const staged = { ...paths, root: stage };
  for (const file of ['singBox', 'wireGuard', 'connections', 'qr', 'page', 'data'] as const) staged[file] = join(stage, relative(paths.root, paths[file]));
  try {
    await downloadProfileFiles(storage, name, staged);
    await installSnapshot(stage, paths.root);
    return paths;
  } finally { await rm(stage, { recursive: true, force: true }); }
}

export async function pullConfigs(options: ConfigsPullOptions): Promise<ConfigsPullResult> {
  validateStorage(options.storage);
  const directory = resolve(options.outputDirectory ?? ARTIFACTS_DIRECTORY);
  const profiles = await listProfiles(options.storage);
  const stage = await createSnapshotStage(directory);
  try {
    await writePrivateFile(artifactRulesPath(stage), await readObject(options.storage, 'rules/vpn_rules.json'));
    for (const profile of profiles) {
      await downloadProfileFiles(options.storage, profile.name, profilePaths(profile.name, stage));
    }
    await installSnapshot(stage, directory);
    return { directory, profiles: profiles.map(profile => profile.name), rulesPath: artifactRulesPath(directory) };
  } finally { await rm(stage, { recursive: true, force: true }); }
}
