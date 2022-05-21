export type CollectionType = 'fixed' | 'rolling' | 'monitoring';

export interface CollectionBase {
  id: string;
  name: string;
  type: CollectionType;
  state: string;
  query: string;
  serviceType: 'nw' | 'sa';
  contentTypes: string[];
  contentLimit: number;
  bound: boolean;
  usecase: string;
  minX: number;
  minY: number;
  distillationEnabled: boolean;
  distillationTerms: string[];
  regexDistillationEnabled: boolean;
  regexDistillationTerms: string[];
  useHashFeed: boolean; // whether to use a hash feed
  hashFeed?: string; // the uuid of the feed
  sha1Enabled?: boolean;
  sha1Hashes?: HashValue[];
  sha256Enabled?: boolean;
  sha256Hashes?: HashValue[];
  md5Enabled?: boolean;
  md5Hashes?: HashValue[];
  lastHours?: number;
  timeBegin?: number;
  timeEnd?: number;
  creator: CollectionMeta;
  modifier?: CollectionMeta;
  executeTime: number;
  onlyContentFromArchives: boolean;
}

export interface NwCollection extends CollectionBase {
  serviceType: 'nw';
  nwserver:  string;
  nwserverName: string;
  deviceNumber: number;
}

export interface SaCollection extends CollectionBase {
  serviceType: 'sa';
  saserver: string;
  saserverName: string;
}

export type Collection = NwCollection | SaCollection;

export type Collections = Record<string, Collection>;

export interface HashValue {
  hash: string;
  friendly?: string;
}

export type ContentType = 'image' | 'pdf' | 'office' | 'hash' | 'unsupportedZipEntry' | 'encryptedZipEntry' | 'encryptedRarEntry' | 'encryptedRarTable';

export type ContentSubType = 'word' | 'excel' | 'powerpoint';

export type HashType = 'sha1' | 'sha256' | 'md5';

export type ArchiveType = 'zip' | 'rar';

export interface ContentItem {
  id: string;
  session: number;
  contentType: ContentType;
  contentSubType: ContentSubType;
  /**
   * The image or office or pdf or exe filename
   */
  contentFile: string;
  /**
   * This is a pdf document which we may substitute for a converted original office doc.  This will be rendered by the client instead
   */
  proxyContentFile?: string;
  /**
   * The PDF gs-generated image filename
   */
  pdfImage?: string;
  /**
   * Thumbnail image file - only used for images, not pdf's or office
   */
  thumbnail?: string;
  archiveFilename?: string;
  hashType?: HashType;
  hashValue?: string;
  /**
   * friendly name of hash, if there is one
   */
  hashFriendly?: string;

  fromArchive: boolean;
  archiveType: ArchiveType;
  isArchive: boolean;

  textDistillationEnabled: boolean;
  regexDistillationEnabled: boolean;
  textTermsMatched?: string[];
  regexTermsMatched?: string[];
  [key: string]: any;
}

export type ContentItems = Record<string, ContentItem>;

export type Meta = Record<string, string[] | number[]>;

export interface Session {
  id: number;
  meta: Meta;
}

export type Sessions = Record<string, Session>;

export interface Search {
  session: number;
  id: string; // uuid
  contentFile: string;
  searchString: string;
}

export interface CollectionData {
  id: string;
  images: ContentItem[];
  sessions: Record<string, Session>; // key is "session id"
  search?: Search[];
}

export interface CollectionDataRecord {
  id: string;
  data: CollectionData;
}

/**
 * The DB representation of CollectionData.  'data' is string-serialised in JSON format
 */
export interface CollectionDataEntry {
  id: string;
  data: string;
}

export interface CollectionMeta {
  username: string;
  id: string;
  fullname: string;
  timestamp: number;
}

export interface CollectionUpdate {
  session: Session;
  search?: Search[];
  images: ContentItem[];
}

export interface WorkerData {
  collectionUpdate?: CollectionUpdate;
  state?: 'monitoring' | 'error' | 'complete' | string;
  error?: string;
  queryResultsCount?: number;
  workerProgress?: string;
  label?: string;
}

export type CollectionState = 'monitoring' | 'querying' | 'complete' | 'error';
