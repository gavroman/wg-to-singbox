export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export type JsonObject = { [key: string]: JsonValue };

export type * from './wireguard/types.js';
export type * from './storage/types.js';
export type * from './provision/types.js';
export type * from './rules/types.js';
export type * from './configs/types.js';
