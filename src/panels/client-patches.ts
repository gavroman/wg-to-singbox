import { isDeepStrictEqual } from 'node:util';
import type { JsonValue } from '../types.js';
import { UserError } from '../shared/errors.js';
import type { ThreeXClient, ThreeXInbound } from './three-x.js';

export interface ClientPatchContext {
  client?: ThreeXClient;
  targets: readonly ThreeXInbound[];
  inbounds: readonly ThreeXInbound[];
}

export interface ClientPatchTransport {
  request(path: string, body?: unknown): Promise<unknown>;
  getClient(email: string): Promise<ThreeXClient | undefined>;
}

/** Fields are both creation defaults and the postcondition checked after applying a patch. */
export interface ClientPatch {
  id: string;
  fields: Readonly<Record<string, JsonValue>>;
  apply(transport: ClientPatchTransport, email: string): Promise<void>;
}

export type ClientPatchHandler = (context: ClientPatchContext) => readonly ClientPatch[];

function satisfied(client: ThreeXClient | undefined, patch: ClientPatch): boolean {
  return client !== undefined && Object.entries(patch.fields).every(([field, value]) =>
    isDeepStrictEqual(client.client[field], value));
}

export class ClientPatchRegistry {
  private readonly handlers = new Map<string, ClientPatchHandler>();

  register(protocol: string, handler: ClientPatchHandler): void {
    if (!protocol || this.handlers.has(protocol)) throw new UserError('Обработчик патчей протокола уже зарегистрирован или имя пусто.');
    this.handlers.set(protocol, handler);
  }

  requirements(context: ClientPatchContext): ClientPatch[] {
    const patches = new Map<string, ClientPatch>();
    const fields = new Map<string, JsonValue>();
    for (const protocol of new Set(context.targets.map(inbound => inbound.protocol))) {
      const handler = this.handlers.get(protocol);
      if (!handler) throw new UserError('Для протокола inbound не определены правила патчей клиента.');
      for (const patch of handler(context)) {
        if (!patch.id || !Object.keys(patch.fields).length) throw new UserError('Некорректное описание патча клиента.');
        const previous = patches.get(patch.id);
        if (previous && !isDeepStrictEqual(previous.fields, patch.fields)) throw new UserError('Конфликт описаний патча клиента.');
        for (const [field, value] of Object.entries(patch.fields)) {
          if (fields.has(field) && !isDeepStrictEqual(fields.get(field), value)) {
            throw new UserError('Протоколы требуют несовместимые значения полей клиента.');
          }
          fields.set(field, value);
        }
        if (!previous) patches.set(patch.id, patch);
      }
    }
    return [...patches.values()];
  }

  plan(context: ClientPatchContext): ClientPatch[] {
    return this.requirements(context).filter(patch => !satisfied(context.client, patch));
  }

  creationFields(context: ClientPatchContext): Record<string, JsonValue> {
    return Object.fromEntries(this.requirements(context).flatMap(patch => Object.entries(patch.fields)));
  }
}

const visionPatch: ClientPatch = {
  id: 'vless-vision-flow',
  fields: { flow: 'xtls-rprx-vision' },
  async apply(transport, email) {
    await transport.request('clients/bulkAdjust', {
      emails: [email], addDays: 0, addBytes: 0, flow: 'xtls-rprx-vision',
    });
  },
};

export function createClientPatchRegistry(): ClientPatchRegistry {
  const registry = new ClientPatchRegistry();
  registry.register('wireguard', () => []);
  registry.register('vless', context => {
    // Flow is stored on the shared client: changing it must be compatible with
    // every VLESS binding, including those outside the selected profile.
    if (!satisfied(context.client, visionPatch)) {
      const attachedIds = new Set(context.client?.inboundIds ?? []);
      const affected = [...context.targets, ...context.inbounds.filter(inbound => attachedIds.has(inbound.id))];
      if (affected.filter(inbound => inbound.protocol === 'vless').some(inbound => {
        const network = String(inbound.streamSettings.network ?? inbound.streamSettings.method ?? 'tcp').toLowerCase();
        return !['tcp', 'raw'].includes(network) || !['reality', 'tls'].includes(String(inbound.streamSettings.security));
      })) throw new UserError('3x-ui: патч Vision несовместим с VLESS-привязками клиента; изменения не выполнялись.');
    }
    return [visionPatch];
  });
  return registry;
}

/** Re-read after every attempt, including failed/ambiguous POST; never blindly replay it. */
export async function applyClientPatches(
  registry: ClientPatchRegistry,
  context: ClientPatchContext & { client: ThreeXClient },
  transport: ClientPatchTransport,
  readOnly = false,
): Promise<ThreeXClient> {
  let client = context.client;
  const requirements = registry.requirements(context);
  const pending = requirements.filter(patch => !satisfied(client, patch));
  if (pending.length && readOnly) throw new UserError('3x-ui: нужны патчи клиента (только чтение).');
  for (const patch of pending) {
    if (satisfied(client, patch)) continue;
    try { await patch.apply(transport, client.client.email); }
    catch { /* The read-back is authoritative; a lost response may still mean success. */ }
    const after = await transport.getClient(client.client.email);
    if (!after || after.client.email !== client.client.email || !satisfied(after, patch)) {
      throw new UserError('3x-ui: патч клиента не подтверждён; повторная запись не выполнялась.');
    }
    client = after;
  }
  if (requirements.some(patch => !satisfied(client, patch))) {
    throw new UserError('3x-ui: после патчей не выполнены требования протоколов клиента.');
  }
  return client;
}
