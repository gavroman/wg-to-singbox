import { ListObjectsV2Command } from '@aws-sdk/client-s3';
import type { StorageOptions } from './types.js';
import { createStorageClient } from './client.js';
import { objectUrl, validateStorage } from './object.js';
import { UserError } from '../shared/errors.js';
import { requestText, REQUEST_TIMEOUT_MS } from '../shared/http.js';

export interface StoredProfile { name: string; key: string }

export async function listProfiles(options: StorageOptions): Promise<StoredProfile[]> {
  validateStorage(options);
  const client = createStorageClient(options);
  const profiles: StoredProfile[] = [];
  const seenTokens = new Set<string>();
  let token: string | undefined;
  try {
    do {
      const page = await client.send(new ListObjectsV2Command({
        Bucket: options.bucket, Prefix: 'profiles/',
        ...(token !== undefined ? { ContinuationToken: token } : {}),
      }), { abortSignal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      for (const item of page.Contents ?? []) {
        const match = /^profiles\/(sf-[A-Za-z0-9_-]{0,61})\/sing-box\.json$/.exec(item.Key ?? '');
        if (match) profiles.push({ name: match[1]!, key: item.Key! });
      }
      if (!page.IsTruncated) break;
      token = page.NextContinuationToken;
      if (!token || seenTokens.has(token)) throw new UserError('S3 вернул некорректную страницу списка профилей.');
      seenTokens.add(token);
    } while (true);
    return profiles;
  } catch (error) {
    if (error instanceof UserError) throw error;
    throw new UserError('Не удалось получить список профилей S3. Проверьте право ListBucket и доступность сети.');
  } finally { client.destroy(); }
}

export async function readProfile(options: StorageOptions, profile: StoredProfile): Promise<string> {
  const response = await requestText(objectUrl(options, profile.key), {
    headers: { 'Cache-Control': 'no-cache' },
  }, 'Чтение опубликованного профиля');
  return response.text;
}
