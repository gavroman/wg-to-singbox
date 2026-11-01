import type { StorageOptions } from './types.js';
import { parseJsonObject } from '../shared/json.js';
import { UserError } from '../shared/errors.js';
import { objectContentType } from './keys.js';
import { publishObject } from './object.js';

export { parseJsonObject } from '../shared/json.js';
export { profileKey, profileKeys } from './keys.js';
export { publishObject, validateStorage } from './object.js';

export async function publishJson(options: StorageOptions, key: string, contents: string): Promise<string> {
  parseJsonObject(contents);
  if (objectContentType(key) !== 'application/json') throw new UserError('Для JSON нужен ключ с расширением .json.');
  return publishObject(options, key, contents);
}
