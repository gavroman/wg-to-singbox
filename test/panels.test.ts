import { afterEach, describe, expect, it, vi } from 'vitest';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { parseVpnConfig } from '../src/config/private.js';
import { collectConnections, checkPanels } from '../src/panels/index.js';
import { allocateAddress, ThreeXClientApi, type ThreeXInbound } from '../src/panels/three-x.js';

const key = (n: number) => Buffer.alloc(32, n).toString('base64');
const publicFromSecret = (secret: string) => Buffer.from(String(createPublicKey(createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(secret, 'base64')]),
  format: 'der', type: 'pkcs8',
})).export({ format: 'jwk' }).x), 'base64url').toString('base64');
const realityPrivate = Buffer.alloc(32, 9).toString('base64url');
const realityPublic = Buffer.from(publicFromSecret(key(9)), 'base64').toString('base64url');
const uuid = '11111111-2222-4333-8444-555555555555';
const TOKEN = 'test-api-token-not-for-output';
const config = () => parseVpnConfig({
  version: 1, panels: { '3x-main': { type: '3x-ui', url: 'https://panel.test/custom/', apiToken: TOKEN } },
  connections: {
    '3x-wg': { type: 'wireguard', panel: '3x-main', inbound: { port: 51822, subnet: '10.20.0.0/24', mtu: 1420 } },
    '3x-vless': { type: 'vless-reality', panel: '3x-main', inbound: { port: 443, reality: { target: 'example.com:443', serverNames: ['example.com'] } } },
  },
});
type Row = Record<string, any>;
function mockPanel() {
  const state = { inbounds: [] as Row[], client: undefined as Row | undefined, requests: [] as { path: string; body?: Row }[],
    failAfterCreate: false, failAfterAttach: false, failAfterPatch: false, ignorePatch: false,
    invalidLinks: false, extraLinks: [] as string[] };
  vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init: RequestInit = {}) => {
    const path = new URL(String(url)).pathname;
    expect(path.startsWith('/custom/panel/api/')).toBe(true);
    expect((init.headers as Row).Authorization).toBe(`Bearer ${TOKEN}`);
    const route = path.slice('/custom/panel/api/'.length);
    const body: Row | undefined = init.body ? JSON.parse(String(init.body)) : undefined;
    state.requests.push({ path: route, ...(body ? { body } : {}) });
    let obj: unknown = null, success = true, msg = '';
    if (route === 'server/status') obj = { panelVersion: '3.11.0', xray: { version: '26.6.27' } };
    else if (route === 'inbounds/list') obj = state.inbounds;
    else if (route === 'server/getNewX25519Cert') obj = { privateKey: realityPrivate, publicKey: realityPublic };
    else if (route === 'inbounds/add') {
      state.inbounds.push({ ...body!, id: state.inbounds.length + 1 });
      obj = state.inbounds.at(-1);
      if (state.failAfterCreate) { success = false; msg = 'sensitive-server-message'; }
    } else if (route.startsWith('clients/get/')) {
      if (!state.client) { success = false; msg = 'Obtain (record not found)'; }
      else obj = state.client;
    } else if (route === 'clients/add') {
      const input = body!.client;
      const firstInbound = state.inbounds.find(x => x.id === body!.inboundIds[0])!;
      const vlessFirst = firstInbound.protocol === 'vless';
      state.client = { client: { ...input, id: 11, uuid: vlessFirst ? uuid : '',
        flow: vlessFirst ? input.flow : '',
        privateKey: vlessFirst ? '' : key(1), publicKey: vlessFirst ? '' : publicFromSecret(key(1)),
        allowedIPs: input.allowedIPs?.join(',') ?? '' }, inboundIds: [...body!.inboundIds] };
      if (state.failAfterCreate) { success = false; msg = 'sensitive-server-message'; }
    } else if (route.endsWith('/attach')) {
      state.client!.inboundIds.push(...body!.inboundIds);
      if (body!.inboundIds.some((id: number) => state.inbounds.find(x => x.id === id)?.protocol === 'vless')) state.client!.client.uuid = uuid;
      if (body!.inboundIds.some((id: number) => state.inbounds.find(x => x.id === id)?.protocol === 'wireguard')) {
        state.client!.client.privateKey ||= key(1);
        state.client!.client.publicKey ||= publicFromSecret(key(1));
        // The panel allocates a missing tunnel address when attaching to WG.
        const wgInbound = state.inbounds.find(x => body!.inboundIds.includes(x.id) && x.protocol === 'wireguard')!;
        state.client!.client.allowedIPs ||= `${String(wgInbound.settings.subnetIp).replace(/\.0$/, '.2')}/32`;
      }
      if (state.failAfterAttach) { success = false; msg = 'partial attach'; }
    } else if (route === 'clients/bulkAdjust') {
      if (!state.ignorePatch) state.client!.client.flow = body!.flow;
      if (state.failAfterPatch) throw new Error('synthetic lost patch response');
    }
    else if (route.startsWith('clients/links/')) {
      obj = state.inbounds.filter(x => state.client?.inboundIds.includes(x.id)).map(x => {
        if (x.protocol === 'wireguard') {
          const params = new URLSearchParams({ address: state.client!.client.allowedIPs, publickey: publicFromSecret(x.settings.secretKey), mtu: '1420' });
          return `wireguard://${encodeURIComponent(key(1))}@vpn.test:${x.port}?${params}#exporter-name`;
        }
        const params = new URLSearchParams({ security: 'reality', flow: 'xtls-rprx-vision', type: 'tcp', sni: 'example.com', pbk: state.invalidLinks ? 'invalid-public-key' : realityPublic, sid: x.streamSettings.realitySettings.shortIds[0] });
        return `vless://${uuid}@vpn.test:${x.port}?${params}#unrelated-fragment`;
      }).concat(state.extraLinks);
    } else throw new Error(`Unexpected mocked route ${route}`);
    return new Response(JSON.stringify({ success, msg, obj }), { headers: { 'Content-Type': 'application/json' } });
  }));
  return state;
}
afterEach(() => vi.unstubAllGlobals());

describe('panel adapters', () => {
  it('creates named inbound/client attachments once and returns exactly configured links through a custom panel path', async () => {
    const state = mockPanel();
    state.extraLinks = ['trojan://unused@example.org:443#foreign'];
    const first = await collectConnections(config(), 'iphone');
    expect(Object.keys(first)).toEqual(['3x-wg', '3x-vless']);
    expect(first['3x-wg']).toMatch(/^wireguard:\/\//);
    expect(first['3x-vless']).toMatch(/^vless:\/\//);
    expect(state.inbounds.map(x => x.remark)).toEqual(['3x-wg', '3x-vless']);
    expect(state.client!.client).toMatchObject({ email: 'sf-iphone', allowedIPs: '10.20.0.2/32', flow: 'xtls-rprx-vision' });
    expect(state.requests.find(x => x.path === 'clients/add')!.body!.inboundIds).toEqual([state.inbounds.find(x => x.protocol === 'vless')!.id]);
    expect(state.requests.find(x => x.path.endsWith('/attach'))!.body!.inboundIds).toEqual([state.inbounds.find(x => x.protocol === 'wireguard')!.id]);
    const writes = state.requests.filter(x => x.body).length;
    expect(await collectConnections(config(), 'sf-iphone')).toEqual(first);
    expect(state.requests.filter(x => x.body)).toHaveLength(writes);
    expect(state.requests.some(x => /del|detach|bulkAdjust/.test(x.path))).toBe(false);
  });
  it('reads state after partial/unknown POST results rather than creating duplicates', async () => {
    const state = mockPanel(); state.failAfterCreate = true; state.failAfterAttach = true;
    const result = await collectConnections(config(), 'iphone');
    expect(Object.keys(result)).toHaveLength(2);
    expect(state.requests.filter(x => x.path === 'inbounds/add')).toHaveLength(2);
    expect(state.requests.filter(x => x.path === 'clients/add')).toHaveLength(1);
    expect(state.requests.filter(x => x.path.endsWith('/attach'))).toHaveLength(1);
  });
  it('checks access and reports missing inbound without mutations; readOnly does not provision', async () => {
    const state = mockPanel();
    expect(await checkPanels(config())).toMatchObject([{ panel: '3x-main', connections: [{ status: 'will-create' }, { status: 'will-create' }] }]);
    await expect(collectConnections(config(), 'iphone', { readOnly: true })).rejects.toThrow('только чтение');
    expect(state.requests.some(x => x.body)).toBe(false);
  });
  it('does not reuse an unrelated inbound by port or create another matching remark with a wrong protocol', async () => {
    const state = mockPanel();
    state.inbounds = [{ id: 1, remark: '3x-wg', protocol: 'vless', port: 51822, enable: true, settings: {}, streamSettings: {} }];
    await expect(collectConnections(config(), 'iphone')).rejects.toThrow('protocol');
    expect(state.requests.some(x => x.body)).toBe(false);
    state.inbounds[0] = { ...state.inbounds[0], remark: 'test-other', protocol: 'wireguard' };
    await expect(collectConnections(config(), 'iphone')).rejects.toThrow('порт занят');
    expect(state.requests.some(x => x.body)).toBe(false);
  });
  it('matches returned links using inbound keys, not exporter fragments, and hides API credentials', async () => {
    const state = mockPanel(); state.invalidLinks = true;
    const error = await collectConnections(config(), 'iphone').catch(e => e as Error);
    expect(String(error)).toContain('подходящая ссылка не найдена');
    expect(String(error)).not.toContain(TOKEN);
    expect(String(error)).not.toContain(key(1));
    expect(String(error)).not.toContain('vless://');
  });
  it('rejects ambiguous remarks before any mutation', async () => {
    const state = mockPanel();
    state.inbounds = [1, 2].map(id => ({ id, remark: '3x-wg', protocol: 'wireguard', port: 51822, enable: true, settings: { mtu: 1420 }, streamSettings: {} }));
    await expect(collectConnections(config(), 'iphone')).rejects.toThrow('неоднозначное');
    expect(state.requests.some(x => x.body)).toBe(false);
  });
});

it('allocates within the explicit WG pool, skips occupied ranges, and fails on exhaustion', () => {
  const inbound = (allowedIPs: string[]): ThreeXInbound => ({ id: 1, remark: 'other', protocol: 'wireguard', port: 5000, enable: true,
    settings: { clients: [{ email: 'another', allowedIPs }] }, streamSettings: {} });
  expect(allocateAddress('10.20.0.0/24', [inbound(['10.20.0.0/28'])], 'sf-new')).toBe('10.20.0.16/32');
  expect(() => allocateAddress('10.20.0.0/30', [inbound(['10.20.0.2/32'])], 'sf-new')).toThrow('исчерпан');
  expect(() => allocateAddress('8.8.8.0/24', [], 'sf-new')).toThrow('подсеть');
});

it('rejects API error bodies without disclosing raw server messages', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ success: false, msg: TOKEN, obj: null }))));
  const api = new ThreeXClientApi('https://panel.test', TOKEN);
  await expect(api.listInbounds()).rejects.toThrow('операция не выполнена');
  try { await api.listInbounds(); } catch (error) { expect(String(error)).not.toContain(TOKEN); }
});

it('checks wg-easy address networks before any 3x creation regardless of config order', async () => {
  const { wireGuard } = await import('./fixtures/config.js');
  const state = mockPanel();
  const threeFetch = globalThis.fetch;
  vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init: RequestInit = {}) => {
    const parsed = new URL(String(url));
    if (parsed.hostname !== 'wg.test') return threeFetch(url, init);
    if (parsed.pathname === '/api/session') return new Response('{}', { headers: { 'set-cookie': 'connect.sid=synthetic; Path=/' } });
    if (parsed.pathname === '/api/wireguard/client') return new Response(JSON.stringify([{ id: 'existing', name: 'sf-iphone', enabled: true }]));
    if (parsed.pathname.endsWith('/configuration')) return new Response(wireGuard());
    throw new Error('Unexpected wg-easy route');
  }));
  const input = config();
  input.panels!['wg-main'] = { type: 'wg-easy', url: 'https://wg.test', password: 'test' };
  input.connections!['wg-easy'] = { type: 'wireguard', panel: 'wg-main' };
  const conn = input.connections!['3x-wg']!;
  if (conn.type === 'wireguard') conn.inbound!.subnet = '10.8.0.0/24';
  await expect(collectConnections(input, 'iphone')).rejects.toThrow('пересекается');
  expect(state.requests.some(x => x.body)).toBe(false);
});

it('derives REALITY public key from privateKey when the panel omits the exported public field', async () => {
  const state = mockPanel();
  const expected = await collectConnections(config(), 'iphone');
  const inbound = state.inbounds.find(x => x.protocol === 'vless')!;
  delete inbound.streamSettings.realitySettings.settings.publicKey;
  expect(await collectConnections(config(), 'iphone')).toEqual(expected);
});

it('plans the VLESS flow patch for an existing WG client and leaves other fields and repeated runs unchanged', async () => {
  const state = mockPanel();
  const wgOnly = config(); delete wgOnly.connections!['3x-vless'];
  await collectConnections(wgOnly, 'iphone');
  expect(state.client!.client.flow).toBe('');
  Object.assign(state.client!.client, { totalGB: 1234, expiryTime: 1900000000000, password: 'preserved-test-password', subId: 'preserved-test-sub' });
  const firstPrivateKey = state.client!.client.privateKey;
  await collectConnections(config(), 'iphone');
  expect(state.client!.client.privateKey).toBe(firstPrivateKey);
  expect(state.client!.client.uuid).toBe(uuid);
  expect(state.client!.client.flow).toBe('xtls-rprx-vision');
  expect(state.requests.filter(x => x.path === 'clients/add')).toHaveLength(1);
  expect(state.requests.filter(x => x.path === 'clients/bulkAdjust')).toHaveLength(1);
  const patch = state.requests.find(x => x.path === 'clients/bulkAdjust')!;
  expect(patch.body).toEqual({ emails: ['sf-iphone'], addDays: 0, addBytes: 0, flow: 'xtls-rprx-vision' });
  expect(state.requests.findIndex(x => x.path.endsWith('/attach'))).toBeLessThan(state.requests.indexOf(patch));
  expect(state.client!.client).toMatchObject({ totalGB: 1234, expiryTime: 1900000000000, password: 'preserved-test-password', subId: 'preserved-test-sub' });
  const writes = state.requests.filter(x => x.body).length;
  await collectConnections(config(), 'iphone');
  expect(state.requests.filter(x => x.body)).toHaveLength(writes);
});

it('applies no client patches when adding WG to an existing VLESS client', async () => {
  const state = mockPanel();
  const vlessOnly = config(); delete vlessOnly.connections!['3x-wg'];
  await collectConnections(vlessOnly, 'iphone');
  const originalUuid = state.client!.client.uuid;
  await collectConnections(config(), 'iphone');
  expect(state.client!.client.uuid).toBe(originalUuid);
  expect(state.client!.client.flow).toBe('xtls-rprx-vision');
  expect(state.requests.filter(x => x.path === 'clients/bulkAdjust')).toHaveLength(0);
  expect(state.requests.filter(x => x.path.endsWith('/attach'))).toHaveLength(1);
});

it('validates protocol patch compatibility before attaching to the new VLESS inbound', async () => {
  const state = mockPanel();
  await collectConnections(config(), 'iphone');
  const targetId = state.inbounds.find(x => x.remark === '3x-vless')!.id;
  state.client!.inboundIds = [state.inbounds.find(x => x.protocol === 'wireguard')!.id, 99];
  state.client!.client.flow = '';
  state.inbounds.push({ id: 99, remark: 'external-vless', protocol: 'vless', port: 8443,
    enable: true, settings: {}, streamSettings: { network: 'ws', security: 'tls' } });
  const before = state.requests.length;
  await expect(collectConnections(config(), 'iphone')).rejects.toThrow('несовместим');
  expect(state.requests.slice(before).filter(x => x.body)).toHaveLength(0);
  expect(state.client!.inboundIds).not.toContain(targetId);
});

it('confirms a lost patch response by re-reading and never repeats the mutation', async () => {
  const state = mockPanel();
  const wgOnly = config(); delete wgOnly.connections!['3x-vless'];
  await collectConnections(wgOnly, 'iphone');
  state.failAfterPatch = true;
  await collectConnections(config(), 'iphone');
  expect(state.requests.filter(x => x.path === 'clients/bulkAdjust')).toHaveLength(1);
  expect(state.client!.client.flow).toBe('xtls-rprx-vision');
});

it('does not return links when a required patch was not applied', async () => {
  const state = mockPanel();
  const wgOnly = config(); delete wgOnly.connections!['3x-vless'];
  await collectConnections(wgOnly, 'iphone');
  state.ignorePatch = true;
  const before = state.requests.length;
  await expect(collectConnections(config(), 'iphone')).rejects.toThrow('патч клиента не подтверждён');
  expect(state.requests.slice(before).filter(x => x.path.startsWith('clients/links/'))).toHaveLength(0);
});
