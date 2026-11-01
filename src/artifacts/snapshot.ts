import { lstat, mkdir, mkdtemp, rename, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { UserError } from '../shared/errors.js';

export async function ensureDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new UserError('Каталог artifacts не должен быть файловой ссылкой.');
}

export async function createSnapshotStage(target: string): Promise<string> {
  await ensureDirectory(dirname(target));
  return mkdtemp(join(dirname(target), '.configs-pull-'));
}

// Replace a complete cache only after all downloads succeeded; keep the old cache on failure.
export async function installSnapshot(stage: string, target: string): Promise<void> {
  const info = await lstat(target).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  });
  if (info && (!info.isDirectory() || info.isSymbolicLink())) throw new UserError('Нельзя заменить artifacts: ожидался обычный каталог.');
  if (!info) { await rename(stage, target); return; }
  const backup = await mkdtemp(join(dirname(target), '.configs-backup-'));
  const previous = join(backup, 'previous');
  let canRemoveBackup = false;
  try {
    await rename(target, previous);
    try { await rename(stage, target); canRemoveBackup = true; }
    catch (error) { await rename(previous, target); canRemoveBackup = true; throw error; }
  } finally {
    // A failed rollback leaves the backup intact for recovery.
    if (canRemoveBackup) await rm(backup, { recursive: true, force: true });
  }
}
