import type { VpnConfig, ConnectionConfig } from '../config/private.js';
import { requireConfig, subnetsOverlap } from '../config/private.js';
import { parseWireGuard } from '../conversion/parser.js';
import { wireGuardToUri } from '../conversion/connections.js';
import { obtainWireGuard } from '../wireguard/index.js';
import { WgEasyClient } from '../wireguard/client.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { UserError } from '../shared/errors.js';
import { ThreeXClientApi } from './three-x.js';
export { ClientPatchRegistry, createClientPatchRegistry, applyClientPatches } from './client-patches.js';
export type { ClientPatch, ClientPatchHandler, ClientPatchContext, ClientPatchTransport } from './client-patches.js';

export interface CollectOptions { clientId?: string; onlyConnection?: string; wireguardOnly?: boolean; readOnly?: boolean }

function selectedConnections(config: VpnConfig, options: CollectOptions): [string, ConnectionConfig][] {
  requireConfig(config, ['panels']);
  if (options.onlyConnection && !config.connections?.[options.onlyConnection]) throw new UserError('Указанное подключение не найдено в конфиге.');
  const selected = Object.entries(config.connections ?? {}).filter(([name, item]) =>
    (!options.onlyConnection || name === options.onlyConnection) && (!options.wireguardOnly || item.type === 'wireguard'));
  if (!selected.length) throw new UserError('Нет подходящих подключений.');
  const wgPanels = new Set(selected.filter(([, item]) => config.panels?.[item.panel]?.type === 'wg-easy').map(([, item]) => item.panel));
  if (options.clientId && wgPanels.size !== 1) throw new UserError('--client-id требует ровно одну выбранную панель wg-easy.');
  return selected;
}

export async function collectConnections(config: VpnConfig, name: string, options: CollectOptions = {}): Promise<Record<string, string>> {
  name = normalizeProfileName(name);
  const selected = selectedConnections(config, options);
  const obtained = new Map<string, string>();
  const panelNames = [...new Set(selected.map(([, connection]) => connection.panel))].sort((a, b) =>
    Number(config.panels![b]!.type === 'wg-easy') - Number(config.panels![a]!.type === 'wg-easy'));
  const knownWgNetworks: string[] = [];
  for (const panelName of panelNames) {
    const panel = config.panels![panelName]!;
    const group = selected.filter(([, connection]) => connection.panel === panelName);
    if (panel.type === 'wg-easy') {
      const settings = { baseUrl: panel.url, password: panel.password, name, ...(options.clientId ? { clientId: options.clientId } : {}) };
      let text: string;
      if (options.readOnly) {
        const api = new WgEasyClient(settings);
        await api.login();
        const clients = (await api.listClients()).filter(x => x.name === name && (!options.clientId || x.id === options.clientId));
        if (clients.length !== 1 || clients[0]!.enabled === false) throw new UserError('wg-easy: клиент не найден однозначно или отключён (только чтение).');
        text = await api.configuration(clients[0]!.id);
      } else text = (await obtainWireGuard(settings)).text;
      knownWgNetworks.push(...parseWireGuard(text).addresses);
      const uri = wireGuardToUri(text);
      for (const [connectionName] of group) obtained.set(connectionName, uri);
    } else {
      for (const [connectionName, connection] of group) {
        if (connection.type === 'wireguard' && connection.inbound && knownWgNetworks.some(network => subnetsOverlap(network, connection.inbound!.subnet))) {
          throw new UserError(`Подключение ${connectionName}: подсеть пересекается с адресной сетью wg-easy.`);
        }
      }
      const api = new ThreeXClientApi(panel.url, panel.apiToken);
      const inbounds = await api.listInbounds();
      const targets = [];
      for (const [connectionName, connection] of group) {
        const inbound = await api.ensureInbound(connectionName, connection, inbounds, options.readOnly);
        targets.push({ name: connectionName, config: connection, inbound });
      }
      const client = await api.ensureClient(name, targets, inbounds, options.readOnly);
      const links = await api.links(name);
      for (const target of targets) obtained.set(target.name, api.selectLink(links, client, target.inbound, target.config, target.name));
    }
  }
  return Object.fromEntries(selected.map(([name]) => [name, obtained.get(name)!]));
}

export async function checkPanels(config: VpnConfig): Promise<unknown> {
  const selected = selectedConnections(config, {});
  const reports: Record<string, unknown>[] = [];
  for (const panelName of new Set(selected.map(([, connection]) => connection.panel))) {
    const panel = config.panels![panelName]!;
    if (panel.type === 'wg-easy') {
      const api = new WgEasyClient({ baseUrl: panel.url, password: panel.password, name: 'sf-check' });
      await api.login();
      const clients = await api.listClients();
      reports.push({ panel: panelName, type: panel.type, accessible: true, apiVersion: 14, clients: clients.length });
    } else {
      const api = new ThreeXClientApi(panel.url, panel.apiToken);
      const status = await api.status();
      const inbounds = await api.listInbounds();
      const connections = selected.filter(([, x]) => x.panel === panelName).map(([name, connection]) => {
        const inbound = api.findInbound(inbounds, name);
        if (inbound) api.validateInbound(inbound, connection, name);
        return { name, status: inbound ? 'exists' : 'will-create', ...(inbound ? { inboundId: inbound.id } : {}) };
      });
      const xray = status.xray !== null && typeof status.xray === 'object' ? status.xray as Record<string, unknown> : {};
      reports.push({ panel: panelName, type: panel.type, accessible: true,
        ...(typeof status.panelVersion === 'string' ? { panelVersion: status.panelVersion } : {}),
        ...(typeof xray.version === 'string' ? { xrayVersion: xray.version } : {}), connections });
    }
  }
  return reports;
}
