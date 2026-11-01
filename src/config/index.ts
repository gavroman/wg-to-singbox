import { config } from 'dotenv';
import { cleanEnv, str, url } from 'envalid';
import { fileURLToPath } from 'node:url';
import type { StorageOptions, WgOptions } from '../types.js';
import { UserError } from '../shared/errors.js';

export const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url));

export function loadEnvironment(path = `${PACKAGE_ROOT}.env`, env = process.env): NodeJS.ProcessEnv {
  const result = config({ path, quiet: true, processEnv: env });
  if (result.error && (result.error as NodeJS.ErrnoException).code !== 'ENOENT') {
    throw new UserError('Не удалось прочитать .env.');
  }
  return env;
}

const reporter = ({ errors }: { errors: Partial<Record<string, Error>> }): void => {
  const names = Object.keys(errors);
  if (names.length) throw new UserError(`Проверьте переменные окружения: ${names.join(', ')}.`);
};

export function wgSettings(env: NodeJS.ProcessEnv, name: string, clientId?: string): WgOptions {
  const e = cleanEnv(env, { WG_EASY_URL: url(), WG_EASY_PASSWORD: str() }, { reporter });
  if (!e.WG_EASY_PASSWORD) throw new UserError('Не задан WG_EASY_PASSWORD.');
  return { baseUrl: e.WG_EASY_URL, password: e.WG_EASY_PASSWORD, name, ...(clientId !== undefined ? { clientId } : {}) };
}

export function storageSettings(env: NodeJS.ProcessEnv): StorageOptions {
  const e = cleanEnv(env, {
    S3_ACCESS_KEY_ID: str(), S3_SECRET_ACCESS_KEY: str(),
    S3_ENDPOINT: url({ default: 'https://storage.yandexcloud.net' }),
    S3_REGION: str({ default: 'ru-central1' }), S3_BUCKET: str(),
  }, { reporter });
  if (!e.S3_ACCESS_KEY_ID || !e.S3_SECRET_ACCESS_KEY) throw new UserError('Задайте S3_ACCESS_KEY_ID и S3_SECRET_ACCESS_KEY.');
  if (!e.S3_BUCKET.trim()) throw new UserError('Не задан S3_BUCKET.');
  return { endpoint: e.S3_ENDPOINT, region: e.S3_REGION, bucket: e.S3_BUCKET,
    accessKeyId: e.S3_ACCESS_KEY_ID, secretAccessKey: e.S3_SECRET_ACCESS_KEY };
}

export function rulesSetting(env: NodeJS.ProcessEnv, override?: string): string {
  return override ?? cleanEnv(env, { VPN_RULES_URL: url() }, { reporter }).VPN_RULES_URL;
}
