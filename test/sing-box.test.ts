import { TEST_RULES_URL } from './fixtures/config.js';
import { it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSingBoxConfig, parseWireGuard } from '../src/conversion/index.js';
import { RULES_TEMPLATE_PATH } from '../src/rules/source.js';
import { wireGuard } from './fixtures/config.js';

it('passes sing-box 1.14.4 validation', async () => {
  const exec = promisify(execFile);
  const binary = process.env.SING_BOX_BINARY ?? 'sing-box';
  const version = await exec(binary, ['version']); // Missing binary is a failure, never a skip.
  expect(version.stdout).toMatch(/^sing-box version 1\.14\.4\s/m);
  const directory = await mkdtemp(join(tmpdir(), 'libertd-core-'));
  try {
    await exec(binary, ['rule-set', 'compile', '--output', join(directory, 'rules.srs'), RULES_TEMPLATE_PATH]);
    for (const dualStack of [false, true]) {
      const path = join(directory, `config-${dualStack}.json`);
      const config = buildSingBoxConfig(parseWireGuard(wireGuard(dualStack)), TEST_RULES_URL, 'iphone');
      await writeFile(path, JSON.stringify(config));
      const checked = await exec(binary, ['check', '-c', path], { cwd: directory });
      expect(checked.stdout + checked.stderr).not.toContain('independent_cache');
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
}, 30_000);
