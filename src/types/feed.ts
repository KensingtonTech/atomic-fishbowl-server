import { CollectionMeta } from './collection';

export type FeedType = 'manual' | 'scheduled';

export interface FeedBase {
  id: string;
  name: string;
  // type: FeedType; // 'manual' or 'scheduled'
  creator: CollectionMeta;
  modifier?: CollectionMeta;
  version: number;
  delimiter: string;
  headerRow: boolean; // treat first CSV row as a header or not
  valueColumn: number;
  typeColumn: number;
  friendlyNameColumn: number;
}

export interface ManualFeed extends FeedBase {
  // manual feeds
  type: 'manual';
  filename: string;
  internalFilename: string;
}

export type FeedScheduleInterval = 'hours' | 'minutes' | 'day';

export interface FeedSchedule {
  interval: FeedScheduleInterval; // hours, minutes, day
  value: number; // string | number
}

export interface ScheduledFeed extends FeedBase {
  // scheduled feeds
  type: 'scheduled';
  url: string;
  authentication: boolean;
  username: string;
  password: string;
  schedule: FeedSchedule;
  authChanged: boolean; // indicates whether user / password changed when editing a scheduled feed
}

export type Feed = ManualFeed | ScheduledFeed;

export type Feeds = Record<string, Feed>;

export interface FeedState {
  good: boolean;
  time: number;
}


export interface FeedTestParams {
  url: string;
  authentication: boolean;
  useCollectionCredentials?: string; // the feed id
  username?: string;
  password?: string;
}
