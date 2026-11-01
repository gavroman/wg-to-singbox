import { join } from 'node:path';
import { PACKAGE_ROOT } from '../config/index.js';

// Optional initial input; published state and subsequent working copies come from S3.
export const RULES_TEMPLATE_PATH = join(PACKAGE_ROOT, 'rules/vpn_rules.json');
