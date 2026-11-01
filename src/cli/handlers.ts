import { join, resolve } from 'node:path';
import { PACKAGE_ROOT, rulesSetting, storageSettings, wgSettings } from '../config/index.js';
import { formatJson, readTextFile, writePrivateFile } from '../artifacts/files.js';
import { conversionOutput } from '../artifacts/paths.js';
import { buildSingBoxConfig, parseWireGuard } from '../conversion/index.js';
import { connectProfile, downloadProfile, provision } from '../provision/index.js';
import { uploadProfile } from '../provision/upload.js';
import { pullConfigs } from '../configs/pull.js';
import { updateRules } from '../rules/update.js';
import { UserError } from '../shared/errors.js';
import { validateUrl } from '../shared/validation.js';
import { normalizeProfileName } from '../shared/profile-name.js';

interface Named { name: string }
interface WgArgs extends Named { clientId?: string }
interface ProvisionArgs extends WgArgs { rules?: string }
interface ConvertArgs extends Named { input: string; output: string; rules?: string }

export function handlers(env: NodeJS.ProcessEnv, print: (value: unknown) => void) {
  return {
    async provision(args: ProvisionArgs) {
      const name = normalizeProfileName(args.name);
      const result = await provision({
        wg: wgSettings(env, name, args.clientId), storage: storageSettings(env),
        rulesUrl: rulesSetting(env, args.rules), outputDirectory: join(PACKAGE_ROOT, 'artifacts'),
      });
      print(result);
    },
    async wg(args: WgArgs) {
      const name = normalizeProfileName(args.name);
      const result = await downloadProfile(wgSettings(env, name, args.clientId));
      print({ name, clientId: result.clientId, created: result.created, wireGuardPath: result.paths.wireGuard });
    },
    async convert(args: ConvertArgs) {
      const name = normalizeProfileName(args.name);
      const input = resolve(args.input);
      const output = await conversionOutput(input, args.output);
      const config = buildSingBoxConfig(parseWireGuard(await readTextFile(input)), rulesSetting(env, args.rules), name);
      await writePrivateFile(output, formatJson(config));
      print({ name, singBoxPath: output });
    },
    async upload(args: Named & { input: string; wireguard?: string }) {
      const name = normalizeProfileName(args.name);
      const settings = storageSettings(env);
      validateUrl(settings.endpoint, 'S3_ENDPOINT для remote profile', true);
      print(await uploadProfile({ name, input: resolve(args.input), storage: settings,
        ...(args.wireguard !== undefined ? { wireGuardInput: resolve(args.wireguard) } : {}) }));
    },
    async connect(args: Named & { url: string }) { print(await connectProfile(args.url, args.name)); },
    async configsPull() { print(await pullConfigs({ storage: storageSettings(env) })); },
    async rulesUpdate(args: { input?: string }) {
      const result = await updateRules({ storage: storageSettings(env),
        ...(args.input !== undefined ? { rulesPath: resolve(args.input) } : {}) });
      print(result);
      if (result.failed.length || result.pullError) {
        throw new UserError('Публикация выполнена с ошибками обновления или скачивания. Подробности выведены выше.');
      }
    },
  };
}
