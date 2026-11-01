import { UserError } from './errors.js';

export const REQUEST_TIMEOUT_MS = 30_000;

export interface TextResponse { text: string; headers: Headers }

export async function requestText(url: string | URL, init: RequestInit, label: string): Promise<TextResponse> {
  const response = await requestBytes(url, init, label);
  return { text: response.bytes.toString('utf8'), headers: response.headers };
}

export async function requestBytes(url: string | URL, init: RequestInit, label: string): Promise<{ bytes: Buffer; headers: Headers }> {
  try {
    const response = await fetch(url, {
      ...init, redirect: 'error', signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) throw new UserError(`${label}: HTTP ${response.status}.`);
    return { bytes: Buffer.from(await response.arrayBuffer()), headers: response.headers };
  } catch (error) {
    if (error instanceof UserError) throw error;
    throw new UserError(`${label}: ошибка сети или таймаут 30 секунд.`);
  }
}
