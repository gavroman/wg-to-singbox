import { readTextFile, writePrivateFile } from '../artifacts/files.js';
import { createWorkingProfile, removeWorkingProfile, ProfileOperationError } from '../artifacts/workspace.js';
import type { PublishProfileResult, StorageOptions } from '../types.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { UserError } from '../shared/errors.js';
import { parseJsonObject } from '../shared/json.js';
import { profileKeys } from '../storage/keys.js';
import { readObject } from '../storage/object.js';
import { publishPreparedProfile } from './publication.js';

export interface UploadOptions {
  name: string;
  input: string;
  wireGuardInput?: string;
  storage: StorageOptions;
  outputDirectory?: string;
}

export async function uploadProfile(options: UploadOptions): Promise<PublishProfileResult> {
  const name = normalizeProfileName(options.name);
  const work = await createWorkingProfile(name);
  try {
    let clientId: string | undefined;
    let wireGuard: string;
    if (options.wireGuardInput !== undefined) {
      wireGuard = await readTextFile(options.wireGuardInput);
    } else {
      const keys = profileKeys(name);
      try {
        wireGuard = (await readObject(options.storage, keys.wireGuard)).toString('utf8');
        const data = parseJsonObject((await readObject(options.storage, keys.data)).toString('utf8'));
        if (data.name !== name || (data.clientId !== undefined &&
          (typeof data.clientId !== 'string' || !/^[A-Za-z0-9_-]+$/.test(data.clientId)))) {
          throw new UserError('Метаданные S3 не соответствуют профилю.');
        }
        clientId = data.clientId as string | undefined;
      } catch { throw new UserError('Не удалось получить исходный WG и data.json из S3. Для первого выпуска или восстановления укажите --wireguard <file>.'); }
    }
    await writePrivateFile(work.wireGuard, wireGuard);
    const result = await publishPreparedProfile({ name, storage: options.storage, singBoxPath: options.input,
      wireGuardPath: work.wireGuard, ...(clientId !== undefined ? { clientId } : {}),
      ...(options.outputDirectory !== undefined ? { outputDirectory: options.outputDirectory } : {}) }, work);
    await removeWorkingProfile(work);
    return result;
  } catch (error) { throw new ProfileOperationError(error, work); }
}
