import { CollectionType, HashValue } from './collection';
import { Feed } from './feed';

export interface WorkerConfigBase {
  id: string,
  collectionId: string, // we include this to disambiguate a difference in monitoring collections between id and collectionId
  state: string,
  timeBegin?: number,
  timeEnd?: number,
  contentLimit: number,
  minX: number,
  minY: number,
  gsPath: string,
  pdftotextPath: string,
  sofficePath: string,
  sofficeProfilesDir: string,
  unrarPath: string,
  collectionsDir: string,
  privateKeyFile: string,
  useHashFeed: boolean,
  type: CollectionType,
  onlyContentFromArchives: boolean
  queryTimeout: number;
  contentTimeout: number;
  maxContentErrors: number;
  sessionLimit: number;

  query: string;
  contentTypes: string[];
  distillationEnabled: boolean;
  distillationTerms?: string[];
  regexDistillationEnabled: boolean;
  regexDistillationTerms?: string[];

  md5Enabled: boolean;
  sha1Enabled: boolean;
  sha256Enabled: boolean;
  md5Hashes?: HashValue[];
  sha1Hashes?: HashValue[];
  sha256Hashes?: HashValue[];
  
  hashFeed?: Feed;
  hashFeederSocket?: string;

  host: string;
  port: number;
  ssl: boolean;
  user: string;
  password: string;
}

export interface NwWorkerConfig extends WorkerConfigBase {
  serviceType: 'nw';
}

export interface SaWorkerConfig extends WorkerConfigBase {
  serviceType: 'sa';
}

export type WorkerConfig = NwWorkerConfig | SaWorkerConfig;