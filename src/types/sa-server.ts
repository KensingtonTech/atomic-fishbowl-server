export interface SaServer {
  id: string; // this is a uuid
  friendlyName: string;
  host: string;
  port: number;
  ssl: boolean;
  user: string;
  password: string;
}

export type SaServers = Record<string, SaServer>;