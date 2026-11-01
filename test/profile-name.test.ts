import { TEST_RULES_URL } from './fixtures/config.js';
import { expect, it } from 'vitest';
import { basename } from 'node:path';
import { profilePaths } from '../src/artifacts/paths.js';
import { makeImportUri } from '../src/connection/index.js';
import { buildSingBoxConfig, parseWireGuard } from '../src/conversion/index.js';
import { profileKey } from '../src/storage/index.js';
import { normalizeProfileName } from '../src/shared/profile-name.js';
import { wireGuard } from './fixtures/config.js';

it('uses the same prefixed name for paths, config, storage and import', () => {
  const wg = parseWireGuard(wireGuard());
  for (const input of ['iphone', 'sf-iphone']) {
    const paths = profilePaths(input);
    expect(basename(paths.wireGuard)).toBe('wireguard.conf');
    expect(basename(paths.singBox)).toBe('sing-box.json');
    expect(profileKey(input)).toBe('profiles/sf-iphone/sing-box.json');
    expect(buildSingBoxConfig(wg, TEST_RULES_URL, input).endpoints).toMatchObject([{ tag: 'sf-iphone' }]);
    expect(new URL(makeImportUri('https://example.com/config.json', input)).hash).toBe('#sf-iphone');
  }
  expect(profilePaths('iphone')).toEqual(profilePaths('sf-iphone'));
  expect(profilePaths('iPhone').root.toLowerCase()).not.toBe(profilePaths('iphone').root.toLowerCase());
});

it('limits the final name to 64 characters without changing case', () => {
  expect(normalizeProfileName('a'.repeat(61))).toHaveLength(64);
  expect(normalizeProfileName(`sf-${'a'.repeat(61)}`)).toHaveLength(64);
  expect(() => normalizeProfileName('a'.repeat(62))).toThrow('64');
  expect(normalizeProfileName('iPhone')).toBe('sf-iPhone');
  expect(normalizeProfileName('SF-iphone')).toBe('sf-SF-iphone');
  for (const input of ['', '-phone', '../iphone']) expect(() => normalizeProfileName(input)).toThrow('Имя');
});
