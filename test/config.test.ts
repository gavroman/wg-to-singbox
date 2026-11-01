import { afterEach, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadEnvironment, rulesSetting, storageSettings } from '../src/config/index.js';

const directories: string[] = [];
afterEach(async () => { for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true }); });

it('loads .env without overriding process values', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'libertd-env-')); directories.push(directory);
  const path = join(directory, '.env');
  await writeFile(path, 'S3_BUCKET=test-bucket\nS3_ACCESS_KEY_ID=file-key\nS3_SECRET_ACCESS_KEY="secret#with-hash"\nVPN_RULES_URL=https://example.com/rules.json\n');
  const env = loadEnvironment(path, { S3_ACCESS_KEY_ID: 'process-key' });
  expect(storageSettings(env)).toMatchObject({ accessKeyId: 'process-key', secretAccessKey: 'secret#with-hash' });
  expect(rulesSetting(env)).toBe('https://example.com/rules.json');
  expect(rulesSetting(env, 'https://override.example/rules.json')).toBe('https://override.example/rules.json');
});

it('requires an explicit S3 bucket instead of selecting a personal default', () => {
  const credentials = { S3_ACCESS_KEY_ID: 'test-key', S3_SECRET_ACCESS_KEY: 'test-secret' };
  expect(() => storageSettings(credentials)).toThrow('S3_BUCKET');
  expect(() => storageSettings({ ...credentials, S3_BUCKET: '' })).toThrow('S3_BUCKET');
  expect(() => storageSettings({ ...credentials, S3_BUCKET: '   ' })).toThrow('S3_BUCKET');
  expect(storageSettings({ ...credentials, S3_BUCKET: 'chosen-bucket' }).bucket).toBe('chosen-bucket');
});

it('requires a rules URL unless --rules explicitly supplies it', () => {
  expect(() => rulesSetting({})).toThrow('VPN_RULES_URL');
  expect(() => rulesSetting({ VPN_RULES_URL: '' })).toThrow('VPN_RULES_URL');
  expect(rulesSetting({}, 'https://example.com/rules.json')).toBe('https://example.com/rules.json');
});
