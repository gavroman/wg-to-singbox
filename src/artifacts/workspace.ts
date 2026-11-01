import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalizeProfileName } from '../shared/profile-name.js';
import { UserError } from '../shared/errors.js';

export interface WorkingProfile {
  root: string;
  client: string;
  result: string;
  wireGuard: string;
  singBox: string;
  qr: string;
  page: string;
  data: string;
}

export async function createWorkingProfile(name: string): Promise<WorkingProfile> {
  const root = await mkdtemp(join(tmpdir(), `libertd-${normalizeProfileName(name)}-`));
  return { root, client: join(root, 'client.json'), result: join(root, 'result.json'),
    wireGuard: join(root, 'wireguard.conf'), singBox: join(root, 'sing-box.json'),
    qr: join(root, 'qr.png'), page: join(root, 'index.html'), data: join(root, 'data.json') };
}

export async function removeWorkingProfile(work: WorkingProfile): Promise<void> {
  await rm(work.root, { recursive: true, force: true });
}

export class ProfileOperationError extends UserError {
  constructor(error: unknown, public readonly work: WorkingProfile) {
    const reason = error instanceof UserError ? error.message : 'Операция не выполнена.';
    super(`${reason} Рабочие файлы для восстановления: ${work.root}`);
  }
}
