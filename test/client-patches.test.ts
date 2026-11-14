import { describe, expect, it, vi } from 'vitest';
import type { JsonValue } from '../src/types.js';
import type { ThreeXClient, ThreeXInbound } from '../src/panels/three-x.js';
import {
  ClientPatchRegistry, createClientPatchRegistry, applyClientPatches,
  type ClientPatch, type ClientPatchContext, type ClientPatchTransport,
} from '../src/panels/client-patches.js';

const VISION = 'xtls-rprx-vision';
function inbound(id: number, protocol = 'vless', network = 'tcp', security = 'reality'): ThreeXInbound {
  return { id, remark: `connection-${id}`, protocol, port: 4000 + id, enable: true,
    settings: {}, streamSettings: { network, security } };
}
function client(flow = ''): ThreeXClient {
  return { client: { email: 'sf-test', flow, uuid: '11111111-2222-4333-8444-555555555555',
    privateKey: 'preserved-private-key', totalGB: 1234 }, inboundIds: [1] };
}
function context(current = client()): ClientPatchContext & { client: ThreeXClient } {
  const wg = inbound(1, 'wireguard');
  const vless = inbound(2);
  return { client: current, targets: [vless], inbounds: [wg, vless] };
}
function patch(id: string, fields: Record<string, JsonValue>): ClientPatch {
  return { id, fields,
    async apply(transport, email) { await transport.request(`clients/custom/${encodeURIComponent(email)}`, fields); },
  };
}
function transport(initial = client(), mode: 'ok' | 'lost-response' | 'unchanged' = 'ok') {
  const stored = structuredClone(initial);
  const request = vi.fn(async (_path: string, body?: unknown): Promise<unknown> => {
    if (mode !== 'unchanged') {
      const fields = body as Record<string, unknown>;
      // bulkAdjust includes routing metadata; only its flow is a client field.
      if ('emails' in fields) stored.client.flow = String(fields.flow);
      else Object.assign(stored.client, fields);
    }
    if (mode === 'lost-response') throw new Error('private-response-must-not-leak');
    return {};
  });
  const getClient = vi.fn(async (_email: string) => structuredClone(stored));
  return { api: { request, getClient } satisfies ClientPatchTransport, stored, request, getClient };
}

describe('protocol-specific client patch planning', () => {
  it('WireGuard explicitly requires no patches or creation fields', () => {
    const wg = inbound(1, 'wireguard');
    const ctx = { client: client(), targets: [wg], inbounds: [wg] };
    const registry = createClientPatchRegistry();
    expect(registry.plan(ctx)).toEqual([]);
    expect(registry.creationFields(ctx)).toEqual({});
  });

  it('VLESS requires Vision and derives the same field for client creation', () => {
    const registry = createClientPatchRegistry();
    const ctx = context();
    expect(registry.plan(ctx).map(item => item.fields)).toEqual([{ flow: VISION }]);
    expect(registry.creationFields({ targets: ctx.targets, inbounds: ctx.inbounds })).toEqual({ flow: VISION });
  });

  it('already-correct VLESS needs no patch, while creation still has the required flow', async () => {
    const registry = createClientPatchRegistry();
    const ctx = context(client(VISION));
    expect(registry.plan(ctx)).toEqual([]);
    const remote = transport(ctx.client);
    expect(await applyClientPatches(registry, ctx, remote.api)).toEqual(ctx.client);
    expect(remote.request).not.toHaveBeenCalled();
  });

  it('deduplicates the same Vision requirement across multiple selected VLESS inbounds', () => {
    const registry = createClientPatchRegistry();
    const ctx = context();
    const second = inbound(3, 'vless', 'raw', 'tls');
    expect(registry.plan({ ...ctx, targets: [...ctx.targets, second], inbounds: [...ctx.inbounds, second] })).toHaveLength(1);
  });

  it('rejects a flow change that would affect an incompatible existing VLESS attachment', () => {
    const registry = createClientPatchRegistry();
    const ctx = context();
    ctx.client.inboundIds.push(3);
    const websocket = inbound(3, 'vless', 'ws', 'tls');
    expect(() => registry.plan({ ...ctx, inbounds: [...ctx.inbounds, websocket] })).toThrow();
  });

  it('does not treat an unrelated unattached VLESS inbound as a patch conflict', () => {
    const registry = createClientPatchRegistry();
    const ctx = context();
    const websocket = inbound(3, 'vless', 'ws', 'tls');
    expect(registry.plan({ ...ctx, inbounds: [...ctx.inbounds, websocket] })).toHaveLength(1);
  });

  it('rejects an unknown protocol instead of assuming that no patch is needed', () => {
    const target = inbound(1, 'future-protocol');
    expect(() => createClientPatchRegistry().plan({ client: client(), targets: [target], inbounds: [target] })).toThrow();
  });

  it('rejects duplicate protocol registration', () => {
    const registry = createClientPatchRegistry();
    expect(() => registry.register('wireguard', () => [])).toThrow();
  });

  it('rejects different requirements for the same client field before executing them', () => {
    const registry = new ClientPatchRegistry();
    registry.register('one', () => [patch('one-mode', { mode: 'one' })]);
    registry.register('two', () => [patch('two-mode', { mode: 'two' })]);
    const targets = [inbound(1, 'one'), inbound(2, 'two')];
    expect(() => registry.plan({ client: client(), targets, inbounds: targets })).toThrow();
  });
});

describe('client patch execution', () => {
  it('supports a newly registered protocol without changes to the executor', async () => {
    const registry = createClientPatchRegistry();
    registry.register('future-protocol', () => [patch('future-auth', { auth: 'synthetic-password' })]);
    const target = inbound(2, 'future-protocol');
    const ctx = { client: client(), targets: [target], inbounds: [target] };
    const remote = transport(ctx.client);
    const result = await applyClientPatches(registry, ctx, remote.api);
    expect(result.client.auth).toBe('synthetic-password');
    expect(result.client.privateKey).toBe(ctx.client.client.privateKey);
    expect(result.client.totalGB).toBe(1234);
    expect(remote.request).toHaveBeenCalledExactlyOnceWith('clients/custom/sf-test', { auth: 'synthetic-password' });
    expect(remote.getClient).toHaveBeenCalledWith('sf-test');
    await applyClientPatches(registry, { ...ctx, client: result }, remote.api);
    expect(remote.request).toHaveBeenCalledTimes(1);
  });

  it('sets only the missing VLESS flow and preserves credentials and limits', async () => {
    const ctx = context();
    const remote = transport(ctx.client);
    const result = await applyClientPatches(createClientPatchRegistry(), ctx, remote.api);
    expect(remote.request).toHaveBeenCalledExactlyOnceWith('clients/bulkAdjust', {
      emails: ['sf-test'], addDays: 0, addBytes: 0, flow: VISION,
    });
    expect(result.client).toEqual({ ...ctx.client.client, flow: VISION });
    expect(remote.getClient).toHaveBeenCalledWith('sf-test');
  });

  it('accepts a lost POST response only after rereading the applied fields, without retrying', async () => {
    const ctx = context();
    const remote = transport(ctx.client, 'lost-response');
    const result = await applyClientPatches(createClientPatchRegistry(), ctx, remote.api);
    expect(result.client.flow).toBe(VISION);
    expect(remote.request).toHaveBeenCalledTimes(1);
    expect(remote.getClient).toHaveBeenCalledTimes(1);
  });

  it('rejects an unconfirmed patch after a successful POST and does not retry it', async () => {
    const ctx = context();
    const remote = transport(ctx.client, 'unchanged');
    await expect(applyClientPatches(createClientPatchRegistry(), ctx, remote.api)).rejects.toThrow();
    expect(remote.request).toHaveBeenCalledTimes(1);
    expect(remote.getClient).toHaveBeenCalledTimes(1);
  });

  it('read-only mode refuses required patches without sending POST', async () => {
    const ctx = context();
    const remote = transport(ctx.client);
    await expect(applyClientPatches(createClientPatchRegistry(), ctx, remote.api, true)).rejects.toThrow();
    expect(remote.request).not.toHaveBeenCalled();
  });
});
