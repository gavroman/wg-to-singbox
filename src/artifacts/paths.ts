import { join, resolve, dirname, basename } from 'node:path';
import { stat } from 'node:fs/promises';
import { normalizeProfileName } from '../shared/profile-name.js';
import { PACKAGE_ROOT } from '../config/index.js';
import { UserError } from '../shared/errors.js';

export const ARTIFACTS_DIRECTORY = join(PACKAGE_ROOT, 'artifacts');

export function artifactRulesPath(directory = ARTIFACTS_DIRECTORY): string {
  return resolve(directory, 'rules/vpn_rules.json');
}

export function profilePaths(name: string, directory = ARTIFACTS_DIRECTORY) {
  name = normalizeProfileName(name);
  // The lowercase hex suffix preserves case distinctions even on case-insensitive filesystems.
  const directoryName = `${name}--${Buffer.from(name, 'utf8').toString('hex')}`;
  const root = resolve(directory, 'profiles', directoryName);
  return { root, wireGuard: join(root, 'wireguard.conf'), singBox: join(root, 'sing-box.json'),
    connections: join(root, 'connections.json'),
    qr: join(root, 'qr.png'), page: join(root, 'index.html'), data: join(root, 'data.json') };
}

export async function conversionOutput(input: string, filename: string): Promise<string> {
  if (basename(filename) !== filename || filename === '.' || filename === '..' || /[\\/]/.test(filename)) {
    throw new UserError('--output должен быть именем файла рядом с input.');
  }
  const output = resolve(dirname(input), filename);
  if (resolve(input) === output) throw new UserError('Перезапись input запрещена.');
  const source = await stat(input);
  const target = await stat(output).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  });
  if (target && source.dev === target.dev && source.ino === target.ino) throw new UserError('Перезапись input через файловую ссылку запрещена.');
  return output;
}
