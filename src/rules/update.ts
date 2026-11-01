import { formatJson, readTextFile } from '../artifacts/files.js';
import { artifactRulesPath } from '../artifacts/paths.js';
import { UserError } from '../shared/errors.js';
import { parseJsonObject } from '../shared/json.js';
import { validateUrl } from '../shared/validation.js';
import { publishJson } from '../storage/index.js';
import { listProfiles, readProfile } from '../storage/profiles.js';
import { validateStorage } from '../storage/object.js';
import { pullConfigs } from '../configs/pull.js';
import { validateRules } from './validation.js';
import { formatRulesVersion, setRulesVersion } from './version.js';
import type { RulesUpdateOptions, RulesUpdateResult } from './types.js';

export async function updateRules(options: RulesUpdateOptions): Promise<RulesUpdateResult> {
  validateStorage(options.storage);
  validateUrl(options.storage.endpoint, 'S3_ENDPOINT для remote profile', true);
  let contents: string;
  try { contents = await readTextFile(options.rulesPath ?? artifactRulesPath(options.outputDirectory)); }
  catch { throw new UserError('Не удалось прочитать rules. Выполните configs:pull или укажите --input <file> для rules:update.'); }
  validateRules(contents);
  const profiles = await listProfiles(options.storage);
  const rulesUrl = await publishJson(options.storage, 'rules/vpn_rules.json', contents);
  const version = formatRulesVersion();
  const result: RulesUpdateResult = { rulesUrl, version, updated: [], skipped: [], failed: [], pull: null };

  for (const profile of profiles) {
    try {
      const config = parseJsonObject(await readProfile(options.storage, profile));
      if (!setRulesVersion(config, rulesUrl, version)) {
        result.skipped.push(profile.name);
        continue;
      }
      await publishJson(options.storage, profile.key, formatJson(config));
      result.updated.push(profile.name);
    } catch (error) {
      result.failed.push({ name: profile.name, error: safeError(error) });
    }
  }
  // Even after a partial update, pull the actual S3 state rather than patching local copies.
  try {
    result.pull = await pullConfigs({ storage: options.storage,
      ...(options.outputDirectory !== undefined ? { outputDirectory: options.outputDirectory } : {}) });
  } catch (error) { result.pullError = safeError(error); }
  return result;
}

function safeError(error: unknown): string {
  return error instanceof UserError ? error.message : 'Не удалось обновить или скачать профиль.';
}
