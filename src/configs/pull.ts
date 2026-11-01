import { rm } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import type { StorageOptions } from '../storage/types.js';
import type { ConfigsPullOptions, ConfigsPullResult } from './types.js';
import { ARTIFACTS_DIRECTORY, artifactRulesPath, profilePaths } from '../artifacts/paths.js';
import { writePrivateFile } from '../artifacts/files.js';
import { createSnapshotStage, ensureDirectory, installSnapshot } from '../artifacts/snapshot.js';
import { profileKeys } from '../storage/keys.js';
import { listProfiles } from '../storage/profiles.js';
import { readObject, validateStorage } from '../storage/object.js';

async function downloadProfileFiles(storage: StorageOptions, name: string, paths: ReturnType<typeof profilePaths>): Promise<void> {
  const keys = profileKeys(name);
  for (const file of ['singBox', 'wireGuard', 'qr', 'page', 'data'] as const) {
    await writePrivateFile(paths[file], await readObject(storage, keys[file]));
  }
}

export async function pullProfile(storage: StorageOptions, name: string, directory = ARTIFACTS_DIRECTORY) {
  validateStorage(storage);
  await ensureDirectory(resolve(directory));
  const paths = profilePaths(name, directory);
  await ensureDirectory(dirname(paths.root));
  const stage = await createSnapshotStage(paths.root);
  const staged = { ...paths, root: stage };
  for (const file of ['singBox', 'wireGuard', 'qr', 'page', 'data'] as const) staged[file] = join(stage, relative(paths.root, paths[file]));
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
