const request = require('request');
const fs = require('fs');

var winston = null;

module.exports = class {

  // the purpose of this class is to update feeds on a schedule

  constructor(feedsDir, winst, decryptor, callback, io) {
    this.scheduledFeeds = {};
    this.schedule = {};
    this.callback = callback;
    this.feedsDir = feedsDir;
    this.decryptor = decryptor;
    this.state = {};  // stores the state of jobs.  id : { 'message': string, 'time' : number }
    this.io = io; // socket.io
    winston = winst;
  }



  updateSchedule(feeds) {
    winston.debug('updateSchedule(): received update');
    // this method helps initialise the scheduler.  It should only be run once when the application starts up
    for (let id in feeds) {
      if (feeds.hasOwnProperty(id)) {
        
        let feed = feeds[id];
        
        if (feed.type != 'scheduled') {
          // we only care about scheduled feeds
          continue;
        }

        this.addFeed(feed);
        setTimeout( () => this.updateFeedCallback(id), 10000 ); // delay pulling feeds 10 seconds to avoid race condition with feed_server not having enough time to read feeds at startup

      }
    }
  }



  updateFeed(feed) {
    let id = feed.id;
    winston.debug('updateFeed(): id', id);

    if (!(id in this.scheduledFeeds)) {
      this.addFeed(feed);
      return;
    }

    if (feed.schedule.type != this.scheduledFeeds[id].schedule.type || feed.schedule.value != this.scheduledFeeds[id].schedule.value) {
      this.delFeed(id);
      this.addFeed(feed);
    }

  }



  delFeed(id) {
    // used when a feed is deleted
    winston.debug('delFeed(): id', id);
    clearInterval(this.schedule[id]);
    delete this.schedule[id];
    delete this.scheduledFeeds[id];
    delete this.state[id];
    this.io.emit('feedStatus', this.status() );
  }



  addFeed(feed) {
    let id = feed.id;
    winston.debug('addFeed(): id', id);
    this.scheduledFeeds[id] = feed;
    if (feed.schedule.type == 'hours') {
      let hours = feed.schedule.value;
      let ms = hours * 60 * 60 * 1000;
      let job = setInterval( () => this.updateFeedCallback(id), ms );
      this.schedule[id] = job;
    }

    if (feed.schedule.type == 'minutes') {
      let minutes = feed.schedule.value;
      let ms = minutes * 60 * 1000;
      let job = setInterval( () => this.updateFeedCallback(id), ms );
      this.schedule[id] = job;
    }

    if (feed.schedule.type == 'day') {
      let days = feed.schedule.value;
      let ms = days * 24 * 60 * 60 * 1000;
      let job = setInterval( () => this.updateFeedCallback(id), ms );
      this.schedule[id] = job;
    }

  }



  updateFeedCallback(id) {
    // this actually updates the feed, and triggers the callback from the caller

    // winston.debug('updateFeedCallback(): updating feed', id);

    let feed = this.scheduledFeeds[id];
    // now we need to fetch the file and write it to disk
    let options = { url: feed.url, method: 'GET', gzip: true };
    if (feed.authentication) {
      options['auth'] = { user: feed.username, pass: this.decryptor.decrypt(feed.password, 'utf8'), sendImmediately: true };
    }
    
    // let tempName = path.basename(temp.path({suffix: '.scheduled'}));

    let myRequest = request(options, (error, result, body) => { // get the feed
      // callback
      let timestamp = new Date().getTime();

      if (error) {
        winston.error('updateFeedCallback(): caught error updating feed ' + id + ':', error);
        this.state[id] = { good : false, time: timestamp };
        this.io.emit('feedStatus', this.status() );
        return;
      }

      if (result.statusCode != 200) {
        winston.error('updateFeedCallback(): non-success HTTP status code received whilst updating feed ' + id + ': received', result.statusCode);
        this.state[id] = { good : false, time: timestamp };
        this.io.emit('feedStatus', this.status() );
        return;
      }

      // winston.debug('updateFeedCallback(): myRequest callback()');
      this.state[id] = { good : true, time: timestamp };
      this.io.emit('feedStatus', this.status() );
      this.callback(id);

    })
    .on('error', (err) => {
      let timestamp = new Date().getTime();
      winston.debug('updateFeedCallback(): caught error updating feed file' + id + '.feed :', err);
      this.state[id] = { good : false, time: timestamp };
      this.io.emit('feedStatus', this.status() );
    })
    .pipe(fs.createWriteStream(this.feedsDir + '/' + id + '.feed'));
  }



  status() {
    // winston.debug('status(): state:', this.state)
    return this.state;
  }

}