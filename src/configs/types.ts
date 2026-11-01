import type { StorageOptions } from '../storage/types.js';

export interface ConfigsPullOptions { storage: StorageOptions; outputDirectory?: string }
export interface ConfigsPullResult { directory: string; profiles: string[]; rulesPath: string }
