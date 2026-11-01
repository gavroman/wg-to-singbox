import type { WgOptions } from '../wireguard/types.js';
import type { StorageOptions } from '../storage/types.js';

export interface ProvisionOptions {
  wg: WgOptions;
  storage: StorageOptions;
  rulesUrl: string;
  outputDirectory: string;
}

export interface ProfileData {
  name: string;
  clientId?: string;
  profileUrl: string;
  wireGuardUrl: string;
  qrUrl: string;
  pageUrl: string;
  importUri: string;
}

export interface PublishProfileOptions {
  name: string;
  storage: StorageOptions;
  singBoxPath: string;
  wireGuardPath: string;
  clientId?: string;
  outputDirectory?: string;
}

export interface PublishProfileResult extends ProfileData {
  wireGuardPath: string;
  singBoxPath: string;
  qrPath: string;
  pagePath: string;
  dataPath: string;
  dataUrl: string;
}

export interface ProvisionResult extends PublishProfileResult { clientId: string }
