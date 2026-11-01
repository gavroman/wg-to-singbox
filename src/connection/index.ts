import QRCode from 'qrcode';
import { validateUrl } from '../shared/validation.js';
import { normalizeProfileName } from '../shared/profile-name.js';
import { writePrivateFile } from '../artifacts/files.js';

export function makeImportUri(profileUrl: string, name: string): string {
  name = normalizeProfileName(name);
  validateUrl(profileUrl, 'URL профиля', true);
  return `sing-box://import-remote-profile?url=${encodeURIComponent(profileUrl)}#${encodeURIComponent(name)}`;
}

export async function writeQr(importUri: string, outputPath: string): Promise<void> {
  const png = await QRCode.toBuffer(importUri, { type: 'png', errorCorrectionLevel: 'M', margin: 4, scale: 6 });
  await writePrivateFile(outputPath, png);
}
