export interface WgPeer {
  publicKey: string;
  endpoint: { address: string; port: number };
  allowedIps: string[];
  presharedKey?: string;
  keepalive?: number;
}

export interface WireGuardConfig {
  privateKey: string;
  addresses: string[];
  dns: string[];
  peers: WgPeer[];
  mtu?: number;
  listenPort?: number;
}

export interface WgOptions {
  baseUrl: string;
  password: string;
  name: string;
  clientId?: string;
}

export interface WgDownload {
  clientId: string;
  created: boolean;
  text: string;
}

