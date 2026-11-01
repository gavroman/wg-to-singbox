import { UserError } from './errors.js';
import { validateName } from './validation.js';

const PROFILE_PREFIX = 'sf-';

export function normalizeProfileName(name: string): string {
  validateName(name);
  const result = name.startsWith(PROFILE_PREFIX) ? name : `${PROFILE_PREFIX}${name}`;
  if (result.length > 64) throw new UserError('Имя профиля вместе с префиксом sf- должно быть не длиннее 64 символов.');
  return result;
}
