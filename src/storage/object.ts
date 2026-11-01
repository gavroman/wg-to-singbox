import { PutObjectCommand } from '@aws-sdk/client-s3';
import type { StorageOptions } from './types.js';
import { UserError } from '../shared/errors.js';
import { requestBytes, REQUEST_TIMEOUT_MS } from '../shared/http.js';
import { validateUrl } from '../shared/validation.js';
import { objectContentType } from './keys.js';
import { createStorageClient } from './client.js';

export function validateStorage(options: StorageOptions): void {
  const url = validateUrl(options.endpoint, 'S3_ENDPOINT');
  if (url.pathname !== '/' || url.search || url.hash) throw new UserError('S3_ENDPOINT должен содержать только origin.');
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(options.bucket)) throw new UserError('Некорректный S3_BUCKET.');
  if (!options.region || !options.accessKeyId || !options.secretAccessKey) throw new UserError('Не заданы настройки доступа к S3.');
}

export async function publishObject(options: StorageOptions, key: string, contents: string | Buffer): Promise<string> {
  validateStorage(options);
  const contentType = objectContentType(key);
  const bytes = Buffer.isBuffer(contents) ? contents : Buffer.from(contents, 'utf8');
  const client = createStorageClient(options);
  try {
    await client.send(new PutObjectCommand({
      Bucket: options.bucket, Key: key, Body: bytes, ContentType: contentType, ACL: 'public-read',
      ...(contentType.startsWith('text/html') ? { ContentDisposition: 'inline' } : {}),
      CacheControl: key.startsWith('profiles/') ? 'no-store' : 'no-cache',
    }), { abortSignal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch {
    throw new UserError('Не удалось загрузить объект в S3. Проверьте ключи, права, endpoint и доступность сети; локальные файлы сохранены.');
  } finally { client.destroy(); }
  const url = objectUrl(options, key);
  const downloaded = await requestBytes(url, { headers: { 'Cache-Control': 'no-cache' } }, 'Проверка публичного объекта S3');
  if (!downloaded.bytes.equals(bytes)) throw new UserError('Проверка S3: скачанное содержимое не совпадает с загруженным.');
  return url;
}

export function objectUrl(options: StorageOptions, key: string): string {
  objectContentType(key);
  return `${options.endpoint.replace(/\/$/, '')}/${options.bucket}/${key}`;
}

export async function readObject(options: StorageOptions, key: string): Promise<Buffer> {
  validateStorage(options);
  const response = await requestBytes(objectUrl(options, key), {
    headers: { 'Cache-Control': 'no-cache' },
  }, `Скачивание S3 ${key}`);
  return response.bytes;
}
