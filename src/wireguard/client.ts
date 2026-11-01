import type { WgOptions } from '../types.js';
import { UserError } from '../shared/errors.js';
import { requestText } from '../shared/http.js';
import { validateUrl } from '../shared/validation.js';

export interface WgClient { id: string; name: string; enabled?: boolean }

export class WgEasyClient {
  private readonly baseUrl: string;
  private readonly cookies = new Map<string, string>();

  constructor(private readonly options: WgOptions) {
    const url = validateUrl(options.baseUrl, 'WG_EASY_URL');
    if (url.search || url.hash) throw new UserError('WG_EASY_URL не должен содержать query или fragment.');
    this.baseUrl = url.href.replace(/\/$/, '');
  }

  private async request(path: string, method = 'GET', body?: object): Promise<string> {
    const headers: Record<string, string> = {};
    if (this.cookies.size) headers.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    if (body) headers['Content-Type'] = 'application/json';
    const response = await requestText(`${this.baseUrl}/api/${path}`, {
      method, headers, ...(body ? { body: JSON.stringify(body) } : {}),
    }, 'wg-easy');
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';')[0]!;
      const separator = pair.indexOf('=');
      if (separator > 0) this.cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
    return response.text;
  }

  async login(): Promise<void> {
    if (!this.options.password) throw new UserError('Не задан WG_EASY_PASSWORD.');
    await this.request('session', 'POST', { password: this.options.password });
    if (!this.cookies.has('connect.sid')) throw new UserError('wg-easy не вернул session cookie. Нужен API версии 14.');
  }

  async listClients(): Promise<WgClient[]> {
    const text = await this.request('wireguard/client');
    let data: unknown;
    try { data = JSON.parse(text); } catch { throw new UserError('wg-easy вернул некорректный список клиентов.'); }
    if (!Array.isArray(data) || !data.every(isClient) || new Set(data.map(c => c.id)).size !== data.length) {
      throw new UserError('wg-easy вернул некорректный список клиентов.');
    }
    return data;
  }

  async createClient(name: string): Promise<void> {
    // A lost response may still mean success. Never retry this POST.
    try { await this.request('wireguard/client', 'POST', { name }); }
    catch { throw new UserError('Результат создания WG-клиента неизвестен. Проверьте список и повторите запуск; POST не повторялся.'); }
  }

  async configuration(id: string): Promise<string> {
    return this.request(`wireguard/client/${encodeURIComponent(id)}/configuration`);
  }
}

function isClient(value: unknown): value is WgClient {
  if (typeof value !== 'object' || value === null) return false;
  const client = value as Record<string, unknown>;
  return typeof client.id === 'string' && /^[A-Za-z0-9_-]+$/.test(client.id) &&
    typeof client.name === 'string' && (client.enabled === undefined || typeof client.enabled === 'boolean');
}
