import type { StorageOptions } from '../storage/types.js';
import type { ConfigsPullResult } from '../configs/types.js';

export interface RulesUpdateOptions {
  storage: StorageOptions;
  rulesPath?: string;
  outputDirectory?: string;
}

export interface ProfileUpdateFailure { name: string; error: string }

export interface RulesUpdateResult {
  rulesUrl: string;
  version: string;
  updated: string[];
  skipped: string[];
  failed: ProfileUpdateFailure[];
  pull: ConfigsPullResult | null;
  pullError?: string;
}
