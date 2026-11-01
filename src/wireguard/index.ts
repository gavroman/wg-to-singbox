import type { WgDownload, WgOptions } from '../types.js';
import { UserError } from '../shared/errors.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { WgEasyClient } from './client.js';
import type { WgClient } from './client.js';

export interface SelectedClient { clientId: string; created: boolean }
export type OnClientSelected = (client: SelectedClient) => Promise<void>;

export async function obtainWireGuard(options: WgOptions, onSelected?: OnClientSelected): Promise<WgDownload> {
  options = { ...options, name: normalizeProfileName(options.name) };
  if (options.clientId !== undefined && !/^[A-Za-z0-9_-]+$/.test(options.clientId)) throw new UserError('Некорректный ID клиента.');
  const api = new WgEasyClient(options);
  await api.login();
  const before = await api.listClients();
  let selected = findExisting(before, options);
  let created = false;
  if (!selected) {
    await api.createClient(options.name);
    const after = await api.listClients();
    const oldIds = new Set(before.map(client => client.id));
    const matches = after.filter(client => client.name === options.name);
    if (matches.length !== 1 || oldIds.has(matches[0]!.id)) {
      throw new UserError('Не удалось однозначно определить созданного клиента. Укажите --client-id; клиенты не удалялись.');
    }
    selected = matches[0]!;
    created = true;
  }
  const identity = { clientId: selected.id, created };
  await onSelected?.(identity);
  if (selected.enabled === false) throw new UserError('WG-клиент отключён. Включите его в wg-easy.');
  try { return { ...identity, text: await api.configuration(selected.id) }; }
  catch { throw new UserError(`Не удалось скачать WG-конфиг. ID клиента: ${selected.id}. Повторите с --client-id.`); }
}

function findExisting(clients: WgClient[], options: WgOptions): WgClient | undefined {
  if (options.clientId) {
    const client = clients.find(item => item.id === options.clientId);
    if (!client) throw new UserError('Клиент с указанным ID не найден.');
    if (client.name !== options.name) throw new UserError('Имя WG-клиента не совпадает с --name.');
    return client;
  }
  const matches = clients.filter(client => client.name === options.name);
  if (matches.length > 1) throw new UserError('Несколько WG-клиентов с таким именем. Укажите --client-id.');
  return matches[0];
}
