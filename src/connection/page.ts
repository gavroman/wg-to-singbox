import { normalizeProfileName } from '../shared/profile-name.js';
import { validateUrl } from '../shared/validation.js';
import { makeImportUri } from './index.js';

interface ProfilePageOptions {
  name: string;
  profileUrl: string;
  qrUrl: string;
}

export function renderProfilePage(options: ProfilePageOptions): string {
  const name = normalizeProfileName(options.name);
  validateUrl(options.qrUrl, 'URL QR', true);
  const importUri = makeImportUri(options.profileUrl, name);
  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta name="robots" content="noindex, nofollow">
  <title>${escapeHtml(name)} · sing-box</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, -apple-system, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100svh; display: grid; place-items: center;
      padding: 24px 16px; background: #10141d; color: #f3f5fa; }
    main { width: 100%; max-width: 420px; padding: 28px; border: 1px solid #303a4c;
      border-radius: 24px; background: #192130; box-shadow: 0 16px 48px #0003; }
    .eyebrow { margin: 0 0 10px; font-size: 12px; font-weight: 650;
      letter-spacing: .12em; text-transform: uppercase; color: #a9bce0; }
    h1 { margin: 0; font-size: clamp(24px, 7vw, 32px); line-height: 1.2; overflow-wrap: anywhere; }
    .hint { margin: 12px 0 24px; color: #bcc6d8; font-size: 15px; line-height: 1.5; }
    figure { margin: 0 0 24px; }
    img { display: block; width: 100%; height: auto; aspect-ratio: 1;
      border: 10px solid #fff; border-radius: 16px; background: #fff; }
    .actions { display: grid; gap: 12px; }
    .actions a { display: flex; min-height: 52px; align-items: center; justify-content: center;
      padding: 14px 16px; border-radius: 12px; font-size: 16px; font-weight: 650;
      text-align: center; text-decoration: none; }
    .primary { background: #a8c8ff; color: #10223e; }
    .secondary { border: 1px solid #60718c; color: #e4edff; }
    a:hover { filter: brightness(1.1); }
    a:focus-visible { outline: 3px solid #fff; outline-offset: 4px; }
    .downloads { margin-top: 24px; padding-top: 16px; border-top: 1px solid #303a4c; }
    .downloads p { margin: 0; font-size: 13px; color: #a9b5ca; }
    .platform-links { display: flex; flex-wrap: wrap; gap: 4px 16px; }
    .platform-links a { display: inline-flex; align-items: center; min-height: 44px;
      color: #c6d9ff; font-size: 14px; text-underline-offset: 4px; }
    @media (max-width: 360px) { main { padding: 20px; } }
  </style>
</head>
<body>
  <main>
    <p class="eyebrow">sing-box · Remote Profile</p>
    <h1>${escapeHtml(name)}</h1>
    <p class="hint">Подключите профиль на этом устройстве или отсканируйте QR с другого.</p>
    <figure>
      <img src="${escapeHtml(options.qrUrl)}" width="320" height="320" alt="QR для импорта ${escapeHtml(name)}">
    </figure>
    <nav class="actions" aria-label="Подключение профиля">
      <a class="primary" href="${escapeHtml(importUri)}">Открыть в sing-box</a>
      <a class="secondary" href="${escapeHtml(options.profileUrl)}">Открыть профиль</a>
    </nav>
    <footer class="downloads">
      <p>Установить sing-box</p>
      <div class="platform-links">
        <a href="https://apps.apple.com/app/sing-box-mt/id6785326793" target="_blank" rel="noopener noreferrer">iOS</a>
        <a href="https://play.google.com/store/apps/details?id=io.nekohasekai.sfa" target="_blank" rel="noopener noreferrer">Android</a>
        <a href="https://sing-box.sagernet.org/clients/apple/#download-macos-standalone-version" target="_blank" rel="noopener noreferrer">macOS</a>
        <a href="https://sing-box.sagernet.org/clients/desktop/#download" target="_blank" rel="noopener noreferrer">Windows</a>
      </div>
    </footer>
  </main>
</body>
</html>
`;
}

function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
