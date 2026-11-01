import { UserError } from './errors.js';

export function validateName(name: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)) {
    throw new UserError('Имя: 1–64 символа A–Z, a–z, 0–9, _ или -; первый — буква или цифра.');
  }
}

export function validateUrl(value: string, label: string, httpsOnly = false): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new UserError(`Некорректный URL: ${label}.`); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
      (httpsOnly && url.protocol !== 'https:')) {
    throw new UserError(`${label}: нужен ${httpsOnly ? 'HTTPS' : 'HTTP(S)'} URL без credentials.`);
  }
  return url;
}
