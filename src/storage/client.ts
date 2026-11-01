import { S3Client } from '@aws-sdk/client-s3';
import type { StorageOptions } from './types.js';

export function createStorageClient(options: StorageOptions): S3Client {
  return new S3Client({
    endpoint: options.endpoint, region: options.region, forcePathStyle: true, maxAttempts: 1,
    credentials: { accessKeyId: options.accessKeyId, secretAccessKey: options.secretAccessKey },
  });
}
