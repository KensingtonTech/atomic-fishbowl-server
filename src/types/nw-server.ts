export interface NwServer {
  id: string; // this is a uuid
  friendlyName: string;
  host: string;
  port: number;
  ssl: boolean;
  user: string;
  deviceNumber: number;
  password: string;
}

export type NwServers = Record<string, NwServer>;

export type NwServerTest = Omit<Optional<NwServer, 'id' | 'password'>, 'friendlyName' | 'deviceNumber'>;
