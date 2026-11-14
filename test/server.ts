import { createServer } from 'node:https';
import type { IncomingHttpHeaders } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { wireGuard } from './fixtures/config.js';

let credentials: Promise<{ key: Buffer; cert: Buffer }> | undefined;

async function createTestCredentials() {
  const directory = await mkdtemp(join(tmpdir(), 'libertd-test-tls-'));
  try {
    const keyPath = join(directory, 'localhost.key');
    const certPath = join(directory, 'localhost.crt');
    await promisify(execFile)('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', '/CN=localhost', '-keyout', keyPath, '-out', certPath,
    ], { timeout: 10_000 });
    const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
    return { key, cert };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

export async function mockServices() {
  const state = {
    clients: [] as { id: string; name: string; enabled?: boolean }[],
    requests: [] as { method: string; path: string; headers: IncomingHttpHeaders; body: string; bytes: Buffer }[],
    objects: new Map<string, Buffer>(), creation: 'ok' as 'ok' | 'lost' | 'duplicate',
    objectHeaders: new Map<string, IncomingHttpHeaders>(),
    failUpload: false, failUploadKey: '', failDownload: false, corruptRead: false, privateRead: false,
    failList: false, listPageSize: 1000,
  };
  // Reuse the in-memory pair within this test worker; temporary files are already removed.
  const server = createServer(await (credentials ??= createTestCredentials()), async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const bytes = Buffer.concat(chunks);
    const body = bytes.toString();
    const path = req.url!;
    state.requests.push({ method: req.method!, path, headers: req.headers, body, bytes });
    const json = (value: unknown) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(value)); };
    const url = new URL(path, 'https://mock.invalid');
    if (req.method === 'GET' && url.searchParams.get('list-type') === '2') {
      if (state.failList || !req.headers.authorization) { res.writeHead(403); res.end(); return; }
      const bucketPrefix = `${url.pathname.replace(/\/$/, '')}/`;
      const prefix = url.searchParams.get('prefix') ?? '';
      const keys = [...state.objects.keys()].filter(key => key.startsWith(bucketPrefix + prefix))
        .map(key => key.slice(bucketPrefix.length)).sort();
      const start = Number(url.searchParams.get('continuation-token') ?? 0);
      const selected = keys.slice(start, start + state.listPageSize);
      const next = start + selected.length;
      const truncated = next < keys.length;
      res.setHeader('Content-Type', 'application/xml');
      res.end(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
        `<IsTruncated>${truncated}</IsTruncated>` +
        selected.map(key => `<Contents><Key>${escapeXml(key)}</Key></Contents>`).join('') +
        (truncated ? `<NextContinuationToken>${next}</NextContinuationToken>` : '') + '</ListBucketResult>');
      return;
    }
    if (path === '/api/session') {
      res.setHeader('Set-Cookie', 'connect.sid=test-session; HttpOnly; Path=/'); json({ success: true }); return;
    }
    if (path.startsWith('/api/') && req.headers.cookie !== 'connect.sid=test-session') { res.writeHead(401); res.end(); return; }
    if (path === '/api/wireguard/client') {
      if (req.method === 'GET') { json(state.clients); return; }
      const { name } = JSON.parse(body);
      state.clients.push({ id: `client-${state.clients.length + 1}`, name });
      if (state.creation === 'duplicate') state.clients.push({ id: 'concurrent-client', name });
      if (state.creation === 'lost') { req.socket.destroy(); return; }
      json({ success: true }); return;
    }
    if (path.endsWith('/configuration')) {
      if (state.failDownload) res.writeHead(503);
      res.end(state.failDownload ? 'secret-server-error' : wireGuard()); return;
    }
    if (req.method === 'PUT') {
      if (state.failUpload || path.split('?')[0] === state.failUploadKey) { res.writeHead(403); res.end(); return; }
      if (req.headers['if-none-match'] === '*' && state.objects.has(path.split('?')[0]!)) {
        res.writeHead(412); res.end(); return;
      }
      state.objects.set(path.split('?')[0]!, bytes);
      state.objectHeaders.set(path.split('?')[0]!, req.headers);
      res.setHeader('ETag', '"test"'); res.end(); return;
    }
    if (req.method === 'GET') {
      if (state.privateRead) { res.writeHead(403); res.end(); return; }
      const content = state.objects.get(path);
      const headers = state.objectHeaders.get(path);
      for (const key of ['content-type', 'content-disposition']) {
        if (headers?.[key]) res.setHeader(key, headers[key]);
      }
      if (content === undefined) res.writeHead(404);
      res.end(state.corruptRead ? '{}' : content); return;
    }
    res.writeHead(404); res.end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { state, url: `https://127.0.0.1:${(server.address() as AddressInfo).port}`,
    async close() { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); } };
}

function escapeXml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}
