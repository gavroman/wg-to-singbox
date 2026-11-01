import { expect, it } from 'vitest';
import { renderProfilePage } from '../src/connection/page.js';
import { makeImportUri } from '../src/connection/index.js';

it('renders the profile name, QR, two actions and four platform downloads', () => {
  const profileUrl = 'https://example.com/profiles/sf-phone/sing-box.json';
  const qrUrl = 'https://example.com/profiles/sf-phone/qr.png';
  const html = renderProfilePage({ name: 'phone', profileUrl, qrUrl });
  expect(html).toContain('<h1>sf-phone</h1>');
  expect(html).toContain(`<img src="${qrUrl}"`);
  const links = [...html.matchAll(/<a\b[^>]*href="([^"]+)"/g)].map(match => match[1]);
  expect(links).toEqual([
    makeImportUri(profileUrl, 'phone'), profileUrl,
    'https://apps.apple.com/app/sing-box-mt/id6785326793',
    'https://play.google.com/store/apps/details?id=io.nekohasekai.sfa',
    'https://sing-box.sagernet.org/clients/apple/#download-macos-standalone-version',
    'https://sing-box.sagernet.org/clients/desktop/#download',
  ]);
  expect(html).toContain('Открыть в sing-box');
  expect(html).toContain('Открыть профиль');
  expect(html).toContain('name="viewport"');
  expect(html).not.toContain('QR открывает тот же профиль');
  expect(html).not.toContain('Профиль загружается по ссылке и обновляется в приложении');
  expect(html).not.toContain('<script');
});

it('escapes URL attributes and rejects unsafe URL schemes', () => {
  const profileUrl = 'https://example.com/config.json?value="><script>alert(1)</script>&v=2';
  const qrUrl = 'https://example.com/qr.png?value=" onerror="alert(1)';
  const html = renderProfilePage({ name: 'phone', profileUrl, qrUrl });
  expect(html).not.toContain('<script');
  expect(html).not.toContain('onerror="');
  expect(html).toContain('&quot;&gt;&lt;script&gt;');
  expect(html).toContain('&amp;v=2');
  expect(() => renderProfilePage({ name: 'phone', profileUrl: 'javascript:alert(1)', qrUrl })).toThrow('HTTPS');
  expect(() => renderProfilePage({ name: 'phone', profileUrl, qrUrl: 'javascript:alert(1)' })).toThrow('HTTPS');
});
