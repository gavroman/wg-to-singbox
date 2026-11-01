import { constants } from 'node:fs';
import { mkdir, open, readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { UserError } from '../shared/errors.js';

export async function writePrivateFile(path: string, contents: string | Buffer): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  // Set permissions before truncating existing files; refuse symlink destinations.
  const file = await open(path, constants.O_WRONLY | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    if (process.platform !== 'win32') await file.chmod(0o600);
    await file.truncate(0);
    await file.writeFile(contents);
  } finally { await file.close(); }
}

export async function readTextFile(path: string): Promise<string> {
  try { return await readFile(path, 'utf8'); }
  catch { throw new UserError('Не удалось прочитать входной файл. Проверьте путь и права доступа.'); }
}

export function formatJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}
