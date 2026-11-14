import { join, resolve } from 'node:path';
import { PACKAGE_ROOT } from '../config/index.js';
import { loadVpnConfig, requireConfig } from '../config/private.js';
import { formatJson, readTextFile, writePrivateFile } from '../artifacts/files.js';
import { conversionOutput } from '../artifacts/paths.js';
import { ConnectionConverter, convertInput } from '../conversion/connections.js';
import { connectProfile } from '../provision/index.js';
import { provisionManaged, describeProfiles, updateProfiles, uploadConnections } from '../provision/managed.js';
import { collectConnections, checkPanels } from '../panels/index.js';
import { pullConfigs } from '../configs/pull.js';
import { updateRules } from '../rules/update.js';
import { UserError } from '../shared/errors.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { parseJsonObject } from '../shared/json.js';

interface ConfigArgs { config?: string }
interface Named extends ConfigArgs { name: string }
interface WgArgs extends Named { clientId?: string; connection?: string }
interface ProvisionArgs extends WgArgs { rules?: string; createOnly?: boolean }
interface ConvertArgs extends Named { input: string; output: string; rules?: string }

export function handlers(env: NodeJS.ProcessEnv, print: (value: unknown) => void) {
  const load = (args: ConfigArgs) => loadVpnConfig(args.config, env);
  return {
    async configCheck(args: ConfigArgs) {
      const config = await load(args);
      print({ valid: true, connections: Object.keys(config.connections ?? {}), panels: Object.keys(config.panels ?? {}) });
    },
    async panelsCheck(args: ConfigArgs) { print(await checkPanels(await load(args))); },
    async provision(args: ProvisionArgs) {
      print(await provisionManaged(await load(args), args.name, {
        ...(args.rules ? { rulesUrl: args.rules } : {}),
        ...(args.clientId ? { clientId: args.clientId } : {}),
        ...(args.createOnly !== undefined ? { createOnly: args.createOnly } : {}),
      }));
    },
    async wg(args: WgArgs) {
      const name = normalizeProfileName(args.name);
      const connections = await collectConnections(await load(args), name, { wireguardOnly: true,
        ...(args.connection ? { onlyConnection: args.connection } : {}),
        ...(args.clientId ? { clientId: args.clientId } : {}),
      });
      const directory = join(PACKAGE_ROOT, 'exports', `${name}--${Buffer.from(name).toString('hex')}`);
      const connectionsPath = join(directory, 'connections.json');
      await writePrivateFile(connectionsPath, formatJson(connections));
      print({ name, connections: Object.keys(connections), connectionsPath });
    },
    async convert(args: ConvertArgs) {
      const name = normalizeProfileName(args.name);
      const config = await load(args);
      const rulesUrl = args.rules ?? config.routing?.rulesUrl;
      if (!rulesUrl) throw new UserError('Для команды требуется routing.rulesUrl или --rules.');
      const input = resolve(args.input);
      const output = await conversionOutput(input, args.output);
      const connections = convertInput(await readTextFile(input), name);
      const result = new ConnectionConverter({ name, rulesUrl, urltest: config.urltest,
        ...(config.dns ? { dns: config.dns } : {}),
      }).convert(connections);
      await writePrivateFile(output, formatJson(result));
      print({ name, singBoxPath: output });
    },
    async upload(args: Named & { input: string; connections?: string; createOnly?: boolean }) {
      const config = await load(args);
      const document = parseJsonObject(await readTextFile(resolve(args.input)));
      const map = args.connections ? parseJsonObject(await readTextFile(resolve(args.connections))) : undefined;
      print(await uploadConnections(config, args.name, document, map,
        args.createOnly !== undefined ? { createOnly: args.createOnly } : {}));
    },
    async profilesList(args: ConfigArgs) { print(await describeProfiles(await load(args))); },
    async profilesUpdate(args: ConfigArgs & { all?: boolean; rules?: string }) {
      if (!args.all) throw new UserError('Для массового обновления укажите --all.');
      const results = await updateProfiles(await load(args), args.rules ? { rulesUrl: args.rules } : {});
      print(results);
      if (results.some(result => !result.updated)) throw new UserError('Некоторые профили не обновлены; результаты выведены выше.');
    },
    async connect(args: Named & { url: string }) { print(await connectProfile(args.url, args.name)); },
    async configsPull(args: ConfigArgs) {
      const config = await load(args); requireConfig(config, ['s3']);
      print(await pullConfigs({ storage: config.s3! }));
    },
    async rulesUpdate(args: ConfigArgs & { input?: string }) {
      const config = await load(args); requireConfig(config, ['s3']);
      const result = await updateRules({ storage: config.s3!,
        ...(args.input !== undefined ? { input: args.input, rulesPath: resolve(args.input) } : {}) });
      print(result);
      if (result.failed.length || result.pullError) throw new UserError('Публикация выполнена с ошибками; подробности выведены выше.');
    },
  };
}
