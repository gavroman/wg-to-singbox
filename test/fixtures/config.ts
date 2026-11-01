export const TEST_RULES_URL = 'https://example.com/rules/vpn_rules.json';

export const key = (byte: number): string => Buffer.alloc(32, byte).toString('base64');

export function wireGuard(dualStack = false): string {
  return `[Interface]
PrivateKey = ${key(1)}
Address = 10.8.0.2/24${dualStack ? ', fd00::2/64' : ''}
DNS = 10.8.0.1${dualStack ? ', fd00::1' : ''}
MTU = 1420
ListenPort = 0
[Peer]
PublicKey = ${key(2)}
PresharedKey = ${key(3)}
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0${dualStack ? ', ::/0' : ''}
PersistentKeepalive = 25
`;
}
