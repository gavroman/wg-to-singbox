import type { JsonObject } from '../types.js';
import { UserError } from './errors.js';

export function parseJsonObject(contents: string): JsonObject {
  let data: unknown;
  try { data = JSON.parse(contents); } catch { throw new UserError('Некорректный JSON.'); }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new UserError('Ожидается JSON-объект.');
  return data as JsonObject;
}
