export { parseWireGuard } from './parser.js';
export { buildSingBoxConfig } from './builder.js';
export { ConnectionConverter, parseConnectionMap, wireGuardToUri, parseWireGuardUri, convertInput, connectionParts, registerConnectionProtocol } from './connections.js';
export type { ConnectionMap, ConverterOptions, ConnectionHandler, ParsedConnection } from './connections.js';
