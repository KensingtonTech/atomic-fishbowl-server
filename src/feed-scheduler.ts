import log from './logging.js';
import { ConfigurationManager } from './configuration-manager.js';
import { Server as SocketServer } from 'socket.io';
import { FeedState, ScheduledFeed } from './types/feed';
import * as utils from './utils.js';
import { AxiosRequestConfig } from 'axios';
import { TokenManager } from 'token-manager.js';


export class FeedScheduler {
  // the purpose of this class is to update feeds on a schedule

  afbConfig: ConfigurationManager;
  io: SocketServer;
  scheduledFeeds: Record<string, ScheduledFeed> = {};
  schedule: Record<string, NodeJS.Timer> = {};
  callback: (id: string) => void;
  state: Record<string, FeedState> = {};  // stores the state of jobs.  id : { 'message': string, 'time' : number }

  tokenMgr: TokenManager;

  constructor(afbConfig: ConfigurationManager, io: SocketServer, callback: (id: string) => void) {
    this.afbConfig = afbConfig;
    this.callback = callback;
    this.io = io;
    this.tokenMgr = this.afbConfig.getTokenManager();
  }



  updateSchedule(feeds: Record<string, ScheduledFeed>) {
    log.debug('FeedScheduler: updateSchedule(): received update');
    // this method helps initialise the scheduler.  It should only be run once when the application starts up
    Object.entries(feeds)
      .filter( ([,feed]) => feed.type === 'scheduled')
      .forEach( ([id, feed]) => {
        this.addScheduledFeed(feed);
        setTimeout( () => this.updateFeedCallback(id), 10000 ); // delay pulling feeds 10 seconds to avoid race condition with feed_server not having enough time to read feeds at startup
      });
  }



  updateScheduledFeed(feed: ScheduledFeed) {
    const id = feed.id;
    log.debug('FeedScheduler: updateScheduledFeed(): id', id);
    const existingFeed = this.scheduledFeeds[id];
    if (!existingFeed) {
      this.addScheduledFeed(feed);
      return;
    }

    const scheduleTypeChanged = feed.schedule.interval !== existingFeed.schedule.interval;
    const scheduleValueChanged = feed.schedule.value !== existingFeed.schedule.value;
    if (
      feed.type === 'scheduled'
      && (scheduleTypeChanged || scheduleValueChanged)
    ) {
      this.removeScheduledFeed(id);
      this.addScheduledFeed(feed);
    }
  }



  removeScheduledFeed(id: string) {
    // used when a feed is deleted
    log.debug('FeedScheduler: removeScheduledFeed(): id', id);
    clearInterval(this.schedule[id]);
    delete this.schedule[id];
    delete this.scheduledFeeds[id];
    delete this.state[id];
    this.tokenMgr.authSocketsEmit('feedStatus', this.getStatus() );
  }



  addScheduledFeed(feed: ScheduledFeed) {
    const id = feed.id;
    log.debug('FeedScheduler: addScheduledFeed(): id', id);
    this.scheduledFeeds[id] = feed;
    if (feed.schedule.interval === 'hours') {
      const hours = feed.schedule.value;
      const ms = hours * 60 * 60 * 1000;
      const job = setInterval( () => this.updateFeedCallback(id), ms );
      this.schedule[id] = job;
    }

    if (feed.schedule.interval === 'minutes') {
      const minutes = feed.schedule.value;
      const ms = minutes * 60 * 1000;
      const job = setInterval( () => this.updateFeedCallback(id), ms );
      this.schedule[id] = job;
    }

    if (feed.schedule.interval === 'day') {
      const days = feed.schedule.value;
      const ms = days * 24 * 60 * 60 * 1000;
      const job = setInterval( () => this.updateFeedCallback(id), ms );
      this.schedule[id] = job;
    }
  }



  async updateFeedCallback(id: string) {
    // this actually updates the feed, and triggers the callback from the caller

    if (!(id in this.scheduledFeeds)) {
      log.error(`FeedScheduler: updateFeedCallback(): feed ${id} was not found in scheduledFeeds.  This may be harmless.  Returning`);
      return;
    }

    const feed = this.scheduledFeeds[id];
    if (!feed.url) {
      throw new Error(`'url' property is not defined in feed`);
    }

    const axiosOptions: AxiosRequestConfig = {};
    if (feed.authentication && feed.username && feed.password) {
      axiosOptions.auth = {
        username: feed.username,
        password: this.afbConfig.decrypt(feed.password)
      };
    }

    try {
      // fetch the file and write it to disk
      await utils.downloadFile(feed.url, `${this.afbConfig.feedsDir}/${id}.feed`, axiosOptions);
      const timestamp = new Date().getTime();
      this.state[id] = { good: true, time: timestamp };
      this.tokenMgr.authSocketsEmit('feedStatus', this.getStatus() );
      this.callback(id);
    }
    catch (error: any) {
      const timestamp = new Date().getTime();
      log.error(`FeedScheduler: updateFeedCallback(): caught error updating feed ${id}:`, error.message ?? error);
      this.state[id] = { good: false, time: timestamp };
      this.tokenMgr.authSocketsEmit('feedStatus', this.getStatus() );
    }
  }



  getStatus() {
    return this.state;
  }

}
