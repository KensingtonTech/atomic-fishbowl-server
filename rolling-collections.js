class RollingCollectionHandler {

  // The purpose of this class is to manage connections to API requests for rolling collections

  constructor(dbUpdateCallback, collections, collectionsDir, feeds, feederSocketFile, gsPath, pdftotextPath, sofficePath, sofficeProfilesDir, unrarPath, internalPrivateKeyFile, useCasesObj, preferences, nwservers, saservers, collectionsUrl, channel) {

    this.cfg = {
      collections: collections,
      collectionsDir: collectionsDir,
      feeds: feeds,
      feederSocketFile: feederSocketFile,
      gsPath: gsPath,
      pdftotextPath: pdftotextPath,
      sofficePath: sofficePath,
      sofficeProfilesDir: sofficeProfilesDir,
      unrarPath: unrarPath,
      internalPrivateKeyFile: internalPrivateKeyFile,
      useCasesObj: useCasesObj,
      preferences: preferences,
      nwservers: nwservers,
      saservers: saservers,
      collectionsUrl: collectionsUrl
    };
    this.rollingCollectionManagers = {};
    this.dbUpdateCallback = dbUpdateCallback;

    // socket.io
    this.channel = channel;
    this.channel.on('connection', (socket) => this.onChannelConnect(socket) );
  }



  onChannelConnect(socket) {
    winston.debug('RollingCollectionHandler: onChannelConnect()');
    socket.on('disconnect', () => this.onChannelDisconnect(socket) );
    socket.on('join', (data) => this.onJoinCollection(socket, data) );
    socket.on('leave', () => this.onLeaveCollection(socket) );
    socket.on('pause', () => this.onPauseCollection(socket) );
    socket.on('unpause', () => this.onUnpauseCollection(socket) );
  }



  onJoinCollection(socket, data) {
    // this is the equivalent of onHttpConnection(), but for socket connections
    // data must contain properties collectionID and sessionId
    // sessionId should be null if a standard rolling collection
    winston.debug('RollingCollectionHandler: onJoinCollection()');
    // winston.debug('RollingCollectionHandler: onJoinCollection(): socket', socket);
    
    let collectionId = data['collectionId'];
    let collection = this.cfg.collections[collectionId];

    let rollingId = collectionId;
    let sessionId = data['sessionId'];

    if (collection.type === 'monitoring') {
      rollingId = collectionId + '_' + sessionId;
    }
    socket['rollingId'] = rollingId; // add the rolling id to our socket so we can later identify it
    socket['collectionId'] = collectionId;
    socket['collectionName'] = collection.name;
    socket['collectionType'] = collection.type;

    winston.debug('RollingCollectionHandler: onJoinCollection(): collectionId:', collectionId);
    winston.debug('RollingCollectionHandler: onJoinCollection(): rollingId:', rollingId);
    winston.info(`User '${socket.conn.user.username}' has connected to ${collection.type} collection '${collection.name}'`);

    socket.join(rollingId); // this joins a room for rollingId

    let rollingCollectionManager = null;
    if ( !(rollingId in this.rollingCollectionManagers) ) {
      // there is no RollingCollectionManager yet for the chosen collection.  So create one
      rollingCollectionManager = new RollingCollectionManager(collection, collectionId, rollingId, (id) => this.rollingCollectionManagerRemovalCallback(id), this.dbUpdateCallback, this.cfg, this.channel);
      this.rollingCollectionManagers[rollingId] = { collectionId: collectionId, manager: rollingCollectionManager };
    }
    else {
      // there's already a manager for the chosen collection
      rollingCollectionManager = this.rollingCollectionManagers[rollingId]['manager'];
    }
    
    socket['rollingCollectionManager'] = rollingCollectionManager;
    socket['rollingId'] = rollingId;
    rollingCollectionManager.addSocketClient(socket);

  }



  onLeaveCollection(socket) {
    // when a socket disconnects gracefully
    winston.debug('RollingCollectionHandler: onLeaveCollection()');

    
    if ('rollingId' in socket) {
      let rollingId = socket['rollingId'];
      let collectionId = socket.collectionId;
      winston.info(`User '${socket.conn.user.username}' has disconnected from ${socket.collectionType} collection '${socket.collectionName}'`)
      socket.leave(rollingId);
      delete socket['rollingId'];
      delete socket['collectionId'];
      delete socket['collectionName'];
      delete socket['collectionType'];
    }

    if ('rollingCollectionManager' in socket) {
      let manager = socket['rollingCollectionManager'];
      manager.removeSocketClient();
      delete socket['rollingCollectionManager'];
    }

  }



  onChannelDisconnect(socket) {
    // when a socket disconnects un-gracefully
    winston.debug('RollingCollectionHandler: onChannelDisconnect()');
      
    if ('rollingId' in socket) {
      let rollingId = socket['rollingId'];
      let collectionId = socket.collectionId;
      winston.debug('RollingCollectionHandler: onChannelDisconnect(): matched collection id:', collectionId);
      winston.info(`User '${socket.conn.user.username}' has disconnected from ${this.cfg.collections[collectionId].type} collection '${this.cfg.collections[collectionId].name}'`);
      socket.leave(rollingId);
      delete socket['rollingId'];
      delete socket['collectionId'];
    }

    if ('rollingCollectionManager' in socket) {
      let manager = socket['rollingCollectionManager'];
      // winston.debug(manager);
      manager.removeSocketClient();
      delete socket['rollingCollectionManager'];
    }

  }



  onPauseCollection(socket) {
    winston.debug('RollingCollectionHandler: onPauseCollection()');
    
    if ('rollingCollectionManager' in socket) {
      let rollingId = socket['rollingId'].substring(0,36);
      winston.info(`User '${socket.conn.user.username}' has paused monitoring collection '${this.cfg.collections[rollingId].name}'`)
      // winston.info(`User '${socket.conn.user.username}' has paused monitoring collection '${rollingId}'`)
      // winston.info(`this.collections[rollingId]:`, this.cfg.collections)
      let manager = socket['rollingCollectionManager'];
      manager.pause();
    }

  }



  onUnpauseCollection(socket) {
    winston.debug('RollingCollectionHandler: onUnpauseCollection()');

    if ('rollingCollectionManager' in socket) {
      let rollingId = socket['rollingId'].substring(0,36);
      winston.info(`User '${socket.conn.user.username}' has unpaused monitoring collection '${this.cfg.collections[rollingId].name}'`)
      // winston.info(`User '${socket.conn.user.username}' has unpaused monitoring collection '${rollingId}'`)
      let manager = socket['rollingCollectionManager'];
      manager.unpause();
    }

  }
  

  
  onHttpConnection(req, res) {
    // Builds and streams a rolling or monitoring collection back to the client.  Handles the client connection and kicks off the process
    
    let collectionId = req.params.collectionId;
    let clientSessionId = req.headers['afbsessionid'];
    
    winston.debug('RollingCollectionHandler: onHttpConnection(): collectionId:', collectionId);
    // winston.debug('preferences:', this.cfg.preferences);
    
    let rollingId = collectionId;
    // rollingId is either the collectionId (for rolling collections), or the clientSessionId (for monitoring collections).
    // our classes will refer to this id when accessing the rollingCollections object
    if ( this.cfg.collections[collectionId].type === 'monitoring' ) {
      rollingId = clientSessionId;
    }
    let collection = this.cfg.collections[collectionId];

    winston.debug('RollingCollectionHandler: onHttpConnection(): rollingId:', rollingId);
    winston.info(`User '${req.user.username}' has connected to ${collection.type} collection '${collection.name}'`);
    
    // create a client connection handler for this connection
    // does a manager for the requested rolling collection exist?
    // if not, create a new rolling collection manager
    // add new or existing rolling collection manager to the client connection handler
    
    let clientConnection = new HttpConnection(req, res, collectionId, rollingId, this.cfg);
    if ( !clientConnection.onConnect(collection) ) {
      return;
    }
    
    let rollingCollectionManager = null;
    if ( !(rollingId in this.rollingCollectionManagers)) {
      // there is no RollingCollectionManager yet for the chosen collection.  So create one
      rollingCollectionManager = new RollingCollectionManager(collection, collectionId, rollingId, (id) => this.rollingCollectionManagerRemovalCallback(id), this.dbUpdateCallback, this.cfg, this.channel);
      this.rollingCollectionManagers[rollingId] = { collectionId: collectionId, manager: rollingCollectionManager };
    }
    else {
      // there's already a manager for the chosen collection
      rollingCollectionManager = this.rollingCollectionManagers[rollingId]['manager'];
    }

    // give the client connection object the rolling collection manager to attach itself to
    clientConnection.addManager(rollingCollectionManager);
    
  }



  pauseMonitoringCollectionHttp(req, res) {
    let clientSessionId = req.headers['afbsessionid'];
    winston.debug(`RollingCollectionHandler pauseMonitoringCollectionHttp(): Pausing monitoring collection ${clientSessionId}`);
    // winston.info(`User '${req.user.username}' has paused monitoring collection '${this.cfg.collections[rollingId].name}'`)
    let manager = this.rollingCollectionManagers[clientSessionId]['manager'];
    manager.pause();
    res.status(202).send( JSON.stringify( { success: true } ) );
  }



  unpauseMonitoringCollectionHttp(req, res) {
    // This only gets used by the client if a monitoring collection is paused and then resumed within the minute the run is permitted to continue executing
    // Otherwise, the client will simply call /api/collection/rolling/:id again
    let clientSessionId = req.headers['afbsessionid'];
    winston.debug(`RollingCollectionHandler: unpauseMonitoringCollectionHttp(): Resuming monitoring collection ${clientSessionId}`);
    // winston.info(`User '${req.user.username}' has unpaused monitoring collection '${this.cfg.collections[rollingId].name}'`)
    let manager = this.rollingCollectionManagers[clientSessionId]['manager'];
    manager.unpause();
    res.status(202).send( JSON.stringify( { success: true } ) );
  }



  collectionEdited(collectionId, collection) {
    winston.debug('RollingCollectionHandler: collectionEdited()');
    let managers = []
    if (collectionId in this.rollingCollectionManagers) {
      // manager = { rollingId: { collectionId: collectionId, manager: manager } }
      let manager = this.rollingCollectionManagers[collectionId]['manager'];
      managers.push(manager);
    }
    else {
      // didn't find the collectionId, but it could still be in there if it's a monitoring collection
      for (let i in this.rollingCollectionManagers) {
        if (this.rollingCollectionManagers.hasOwnProperty(i) && this.rollingCollectionManagers[i]['collectionId'] == collectionId ) {
          let manager = this.rollingCollectionManagers[i]['manager'];
          managers.push(manager);
        }
      }
    }
    for (let i = 0; i < managers.length; i++) {
      // there should only be one unless it's a monitoring collection with multiple clients
      let manager = managers[i];
      manager.onCollectionEdited(collection);
    }
  }


  
  collectionDeleted(collectionId, user) {
    winston.debug('RollingCollectionHandler: collectionDeleted()');
    let managers = []
    if (collectionId in this.rollingCollectionManagers) {
      // manager = { rollingId: { collectionId: collectionId, manager: manager } }
      let manager = this.rollingCollectionManagers[collectionId]['manager'];
      managers.push(manager);
    }
    else {
      // didn't find the collectionId, but it could still be in there if it's a monitoring collection
      for (let i in this.rollingCollectionManagers) {
        if (this.rollingCollectionManagers.hasOwnProperty(i) && this.rollingCollectionManagers[i]['collectionId'] == collectionId ) {
          let manager = this.rollingCollectionManagers[i]['manager'];
          managers.push(manager);
        }
      }
    }
    for (let i = 0; i < managers.length; i++) {
      // there should only be one unless it's a monitoring collection with multiple clients
      let manager = managers[i];
      manager.onCollectionDeleted(user);
    }
  }


  
  rollingCollectionManagerRemovalCallback(id) {
    winston.debug('RollingCollectionHandler: rollingCollectionManagerRemovalCallback()');
    delete this.rollingCollectionManagers[id];
  }



  killall() {
    winston.debug('RollingCollectionHandler: killall()');
    for (let rollingId in this.rollingCollectionManagers) {
      if (this.rollingCollectionManagers.hasOwnProperty(rollingId)) {
        let manager = this.rollingCollectionManagers[rollingId].manager;
        manager.abort();
      }
    }
  }



  updateFeederSocketFile(filename) {
    this.cfg.feederSocketFile = filename;
  }

}
  
  
  
  
  
  
  
  
  
  
  
  

  
  

class HttpConnection {

  constructor(req, res, collectionId, rollingId, cfg) {
    winston.debug('HttpConnection: constructor()');
    this.cfg = cfg;
    this.id = uuidV4();
    this.req = req;
    this.res = res;
    this.collectionId = collectionId;
    this.rollingId = rollingId;
    
    this.manager = null;
    this.heartbeatInterval = null;
    this.disconnected = false;
  }



  onConnect(collection) {

    winston.debug('HttpConnection: onConnect():');

    ////////////////////////////////////////////////////
    //////////////////RESPONSE HEADERS//////////////////
    ////////////////////////////////////////////////////
  
    try {
      // Write the response headers
      if (collection.bound && !( 'usecase' in collection )) {
        throw(`Bound collection ${this.collectionId} does not have a use case defined`);
      }
      if (collection.bound && !(collection.usecase in this.cfg.useCasesObj) ) {
        throw(`Use case ${collection.usecase} in bound collection ${this.collectionId} is not a valid use case`);
      }
      if (collection.type === 'rolling' || collection.type === 'monitoring') {
        this.res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': 'inline' } );
        this.res.write('['); // Open the array so that oboe can see it
      }
      else {
        throw("Collection " + this.collectionId + " is not of type 'rolling' or 'monitoring'");
      }
    }
    catch (e) {
      winston.error('HttpConnection: onConnect():', e);
      this.res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
      return false;
    }
  

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////CLIENT DISCONNECT HANDLER///////////////////////
    ///////////////////////////////////////////////////////////////////////
    
    this.req.on('close', () => this.onClientClosedConnection() );

    this.heartbeatInterval = setInterval( () => {
      this.send( { heartbeat : true } );
    }, 15000 );
    
    return true;

  }



  onClientClosedConnection() {
    winston.debug('HttpConnection: onClientClosedConnection()');
    winston.info(`User '${this.req.user.username}' has disconnected from ${this.cfg.collections[this.collectionId].type} collection '${this.cfg.collections[this.collectionId].name}'`);
    this.disconnected = true;
    // This block runs when the client disconnects from the session
    // But NOT when we terminate the session from the server
    
    if (this.heartbeatInterval) {
      // stop sending heartbeats to client
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    
    this.manager.removeHttpClient(this.id);

    this.end();
  }



  addManager(manager) {
    winston.debug('HttpConnection: addManager()');
    this.manager = manager;
    this.manager.addHttpClient(this.id, this);
  }



  send(data) {
    // winston.debug('HttpConnection: send()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( JSON.stringify(data) + ',');
      this.res.flush();
    }
  }



  sendRaw(data) {
    winston.debug('HttpConnection: sendRaw()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( data );
      this.res.flush();
    }
  }



  end() {
    winston.debug('HttpConnection: end()');
    if (this.heartbeatInterval) {
      // stop sending heartbeats to client
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    this.sendRaw('{"close":true}]'); // Close the array so that oboe knows we're done
    this.manager = null;
    this.res.end() // not sure if this will work if already disconnected
    if (!this.disconnected) {
    }
  }


}


















class RollingCollectionManager {

  constructor(collection, collectionId, rollingId, removalCallback, dbUpdateCallback, cfg, channel = null) {
    winston.debug('RollingCollectionManager: constructor()');
    this.cfg = cfg;
    this.channel = channel; // a handle to our socket.io /collections namespace
    
    // callbacks
    this.removalCallback = removalCallback;
    this.dbUpdateCallback = dbUpdateCallback; // this callback will trigger a db update of the collection
    
    // client-related
    this.observers = 0; // the number of clients that are currently connected to the collection, both http and socket.io
    this.httpClients = {};  // holds references to http connection objects
    
    // collections
    this.rollingId = rollingId;
    this.collectionId = collectionId;
    this.collection = collection;
    this.monitoringCollection = false;
    this.sessions = [];
    this.content = [];
    this.search = [];
    this.lastEnd = null; // the end time of the last query to run
    this.lastRun = null; // the last time that the worker actually ran
    if (this.collection.type === 'monitoring') {
      this.paused = false;
      this.monitoringCollection = true;
      this.timeOfPause = 0;
      this.pauseTimeout = null;
    }
    
    // worker
    this.workerProcess = []; // holds process handles for the workers
    this.workInterval = null; // holds the interval handle for the ongoing work loop
    this.workerSocket = []; // holds the unix sockets for connections back from the workers
    this.runs = 0; // the number of times that a worker has been run
    this.runContent = {};  // This holds the content generated by each invidual run of the worker.  The key is the run number.  Only used for SA monitoring collections, because more than one worker is allowed to run
    this.resumed = false; // this indicates that work() has already run but it was killed, therefore collection data is still in memory.  Use this to direct the query timeframe on subsequent work() runs
    this.restartWorkLoopOnExit = false;  // this will cause an already-killed workLoop() to restart when the worker exits, if there was a residual worker still running

    // destruction
    this.destroyThreshold = 3600; // wait one hour to destroy
    this.destroyTimeout;  // holds setTimeout for destroy().  Cancel if we get another connection within timeframe
    this.destroyed = false;

  }



  run() {
    winston.debug('RollingCollectionManager: run()');
    // Now schedule workLoop() to run every 60 seconds and store a reference to it in this.workInterval
    // which we can later use to terminate the timer and prevent future execution.
    // This will not initially execute work() until the first 60 seconds have elapsed, which is why we run workLoop() immediately after
    this.workInterval = setInterval( () => this.workLoop(), 60000);
    this.workLoop();
  }



  selfDestruct() {
    winston.debug('RollingCollectionManager: selfDestruct()');
    /*if (isDestroyed) {
      winston.debug('Not self-destructing as we\'re already being deleted');
      return;
    }*/
    this.collection['state'] = 'stopped';
    if (!this.monitoringCollection) {
      winston.debug("RollingCollectionManager: selfDestruct(): No clients have reconnected to rolling collection " + this.rollingId + " within " + this.destroyThreshold + " seconds. Self-destructing");
    }
    else {
      winston.debug("RollingCollectionManager: selfDestruct(): Client disconnected from monitoring collection " + this.rollingId + ".  Self-destructing");
    }
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = null;
    }
    this.killWorker();
    try {
      winston.debug("RollingCollectionManager: selfDestruct(): Deleting output directory for rolling collection", this.rollingId);
      rimraf( this.cfg.collectionsDir + '/' + this.rollingId, () => {} ); // Delete output directory
    }
    catch(exception) {
      winston.error('RollingCollectionManager: selfDestruct(): ERROR deleting output directory ' + this.cfg.collectionsDir + '/' + this.rollingId, exception);
    }
    this.removalCallback(this.rollingId);
  }



  addHttpClient(id, client) {
    winston.debug('RollingCollectionManager: addHttpClient()');
    this.httpClients[id] = client;
    this.observers += 1;
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = null;
    }

    if (this.monitoringCollection) {
      client.send('paused', this.paused);
    }
    
    if (this.runs == 0) {
      this.run();
    }
    
    if (this.runs > 0) {
      winston.debug(`RollingCollectionManager: addHttpClient(): This is not the first client to have connected to rolling collection ${this.rollingId}.  Playing back existing collection`);
      let resp = null;

      let sessions = {};
      for (let i = 0; i < this.sessions.length; i++) {
        // Play back sessions
        // We must do it this way because the client expects an object
        // We store sessions internally as an array of objects
        let session = this.sessions[i];
        sessions[session.id] = session;
      }

      client.send( { wholeCollection: { images: this.content, sessions: sessions, search: this.search } } );

      if (this.observers == 1) {
        // If all clients have disconnected, and then one reconnects, the worker should start immediately
        this.resumed = true;
        // clearInterval(this.workInterval);
        // this.workInterval = null;
        // if (!this.workerProcess) {
        if (this.workerProcess.length === 0) {
          this.run();
        }
        else {
          this.restartWorkLoopOnExit = true;
        }
      }

    }

  }



  addSocketClient(socket) {
    winston.debug('RollingCollectionManager: addSocketClient()');
    this.observers += 1;
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = null;
    }

    if (this.monitoringCollection) {
      socket.emit('paused', this.paused);
    }
    
    if (this.runs == 0) {
      this.run();
    }
    
    if (this.runs > 0) {
      winston.debug(`This is not the first client to have connected to rolling collection ${this.rollingId}.  Playing back existing collection`);

      let sessions = {};
      for (let i = 0; i < this.sessions.length; i++) {
        // Play back sessions
        // We must do it this way because the client expects an object
        // We store sessions internally as an array of objects
        let session = this.sessions[i];
        sessions[session.id] = session;
      }
      socket.emit('sessions', sessions );

      // play back images
      socket.emit('content', this.content);

      // Play back search text
      socket.emit('searches', this.search);

      winston.debug(`Current number of observers: ${this.observers}`);

      if (this.observers == 1) {
        // If all clients have disconnected, and then one reconnects, the worker should start immediately
        this.resumed = true;
        // clearInterval(this.workInterval);
        // this.workInterval = null;
        // if (!this.workerProcess) {
        winston.debug(`workerProcess.length: ${this.workerProcess.length}`);
        if (this.workerProcess.length === 0) {
          this.run();
        }
        else {
          this.restartWorkLoopOnExit = true;
        }
      }

    }

  }



  onCollectionEdited(collection) {
    // If the collection gets edited, we must assume that some critical element has changed...
    // and that we must blow away the existing data and work jobs, and start over

    winston.debug('RollingCollectionManager: onCollectionEdited()');
    
    // stop the work loop
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = null;
    }
    
    // stop any running workers
    this.killWorker();
    
    this.collection = collection;

    this.sessions = [];
    this.content = [];
    this.search = [];
    this.runs = 0;
    this.lastEnd = null;
    this.lastRun = null;
    this.resumed = false;

    this.sendToChannel('clear', true);
    this.sendToHttpClients( { wholeCollection: { images: [], sessions: {}, search: [] } } );
    

    // don't re-run.  The clients will cause this themselves when they reconnect.  Stick with this as it otherwise causes issues later on.
    // this.run();

  }



  onCollectionDeleted(user) {
    winston.debug('RollingCollectionManager: onCollectionDeleted()');
    this.destroyed = true;

    // stop the work loop
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = null;
    }
    
    // stop any running workers
    this.killWorker();
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = null;
    }

    if (this.monitoringCollection) {
      // we only do this for monitoring collections as this helps us to...
      // clean up after all the different client instances of a particular monitoring collection
      // the collection delete handler will otherwise handle deletion
      try {
        winston.debug("Deleting output directory for collection", this.rollingId);
        rimraf( this.cfg.collectionsDir + '/' + this.rollingId, () => {} ); // Delete output directory
      }
      catch(exception) {
        winston.error('ERROR deleting output directory ' + this.cfg.collectionsDir + '/' + this.rollingId, exception);
      }
    }

    this.sendToChannel('deleted', user);
    this.sendToHttpClients( { collectionDeleted: true, user: user } );
    this.endAllClients();

    this.removalCallback(this.rollingId);
  }



  abort() {
    winston.debug('RollingCollectionManager: abort()');

    // we only get here if the program is exiting, either gracefully or due to an error

    // stop the work loop
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = null;
    }

    this.killWorker();

    try {
      winston.debug("Deleting output directory for collection", this.collectionId);
      rimraf.sync( this.cfg.collectionsDir + '/' + this.rollingId ); // Delete output directory
    }
    catch(exception) {
      winston.error('ERROR deleting output directory ' + this.cfg.collectionsDir + '/' + this.collectionId, exception);
    }
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = null;
    }
    
    // this.sendToChannel('clear', true);
    // this.sendToHttpClients( { collectionDeleted: this.collectionId } ); // don't think this belongs here
    this.endAllClients();
    // this.removalCallback(this.collectionId);
  }



  killWorker() {

    winston.debug('RollingCollectionManager: killWorker()');

    if (this.workerSocket.length !== 0) {
      for (let i = 0; i < this.workerSocket.length; i++) {
        this.workerSocket[i].removeAllListeners();
      }
      this.workerSocket = [];
    }

    if (this.workerProcess.length !== 0){
      for (let i = 0; i < this.workerProcess.length; i++) {
        this.workerProcess[i].removeAllListeners(); // not sure whether we need this or not - probably do
        this.workerProcess[i].kill('SIGINT');
      }
      this.workerProcess = [];
    }
  }



  removeHttpClient(id) {
    winston.debug('RollingCollectionManager: removeHttpClient()');
    this.observers -= 1;

    if (this.observers != 0) {
      winston.debug("RollingCollectionManager: removeHttpClient(): Client disconnected from rolling collection with rollingId", this.rollingId);
    }

    else {
      winston.debug("RollingCollectionManager: removeHttpClient(): Last client disconnected from rolling collection with rollingId " + this.rollingId + '.  Waiting for ' + this.destroyThreshold + ' seconds before self-destructing');
      this.destroyTimeout = setTimeout( () => this.selfDestruct(), this.destroyThreshold * 1000); // trigger the countdown to self-destruct
      this.restartWorkLoopOnExit = false;
      clearInterval(this.workInterval);
      this.workInterval = null;
      // we want any running workers to finish, so that we have complete data if someone rejoins
      // this.killWorker();
    }

    delete this.httpClients[id];
  }



  removeSocketClient() {
    winston.debug('RollingCollectionManager: removeSocketClient()');

    this.observers -= 1;

    if (this.monitoringCollection) {
      // this.selfDestruct();
      winston.debug("RollingCollectionManager: removeSocketClient(): Client disconnected from monitoring collection with rollingId " + this.rollingId + '.  Waiting for 5 seconds before self-destructing');
      this.destroyTimeout = setTimeout( () => this.selfDestruct(), 5000); // trigger the countdown to self-destruct
      this.restartWorkLoopOnExit = false;
      // clearInterval(this.workInterval);
      // this.workInterval = null;
      return;
    }
   

    if (this.observers != 0) {
      winston.debug("RollingCollectionManager: removeSocketClient(): Socket client disconnected from rolling collection with rollingId", this.rollingId);
    }

    else {
      winston.debug("RollingCollectionManager: removeSocketClient(): Last client disconnected from rolling collection with rollingId " + this.rollingId + '.  Waiting for ' + this.destroyThreshold + ' seconds before self-destructing');
      this.destroyTimeout = setTimeout( () => this.selfDestruct(), this.destroyThreshold * 1000); // trigger the countdown to self-destruct
      this.restartWorkLoopOnExit = false;
      clearInterval(this.workInterval);
      this.workInterval = null;
      // we want any running workers to finish, so that we have complete data if someone rejoins
      // this.killWorker();
    }

  }



  pause() {
    winston.debug('RollingCollectionManager: pause()');
    this.paused = true;
    this.timeOfPause = moment().unix();
    this.sendToChannel('paused', true);
    /*if (this.workInterval) {
      // stop workLoop from running any more, but allow present worker to finish.
      clearInterval(this.workInterval);
      this.workInterval = null;
    }
    if (this.pauseTimeout) {
      clearTimeout(this.pauseTimeout);
      this.pauseTimeout = null;
    }*/

  }



  unpause() {
    winston.debug('RollingCollectionManager: unpause()');
    this.paused = false;
    
    let timeOfResume = moment().unix();
    let difference = timeOfResume - this.timeOfPause;
    winston.debug('RollingCollectionManager: unpause(): difference:', difference);
    
    /*if (difference <= 60) {
      // less than a minute has elapsed or exactly 1 minute has elapsed since the collection was paused
      let resumeInXSeconds = 60 - difference;
      winston.debug('RollingCollectionManager: unpause(): resumeInXSeconds:', resumeInXSeconds);

      this.pauseTimeout = setTimeout( () => {
        winston.debug('RollingCollectionManager: unpause(): resuming work');
        this.pauseTimeout = null;
        this.workInterval = setInterval( () => this.workLoop(), 60000);
        this.workLoop();
      }, resumeInXSeconds * 1000);
    }*/

    if (difference >= 60) {
      // more than a minute has elapsed since pause. Resume immediately and restart loop
      clearInterval(this.workInterval);
      this.workInterval = setInterval( () => this.workLoop(), 60000);
      this.workLoop();
    }

    this.timeOfPause = 0;

    this.sendToChannel('paused', false);

  }



  sendToWorker(data, workerSocket) {
    winston.debug('RollingCollectionManager: sendToWorker()');
    workerSocket.write( JSON.stringify(data) + '\n' );
  }



  sendToHttpClients(data) {
    // winston.debug('RollingCollectionManager: sendToHttpClients()');
    for (let id in this.httpClients) {
      if (this.httpClients.hasOwnProperty(id)) {
        let client = this.httpClients[id];
        client.send(data);
      }
    }
  }



  sendToHttpClientsRaw(data) {
    winston.debug('RollingCollectionManager: sendToHttpClientsRaw()');
    for (let id in this.httpClients) {
      if (this.httpClients.hasOwnProperty(id)) {
        let client = this.httpClients[id];
        client.sendRaw(data);
      }
    }
  }



  sendToChannel(type, data) {
    if (this.channel) {
      this.channel.to(this.rollingId).emit( type, data );
    }
  }



  endAllClients() {
    winston.debug('RollingCollectionManager: endAllClients()');
    for (let id in this.httpClients) {
      if (this.httpClients.hasOwnProperty(id)) {
        let client = this.httpClients[id];
        client.end();
      }
    }
    this.sendToChannel('disconnect', true);
  }


  
  endHttpClients() {
    winston.debug('RollingCollectionManager: endHttpClients()');
    for (let id in this.httpClients) {
      if (this.httpClients.hasOwnProperty(id)) {
        let client = this.httpClients[id];
        client.end();
      }
    }
  }



  workLoop() {
    // Main body of worker execution
    winston.debug('RollingCollectionManager: workLoop()');

    try {

      winston.debug("workLoop(): Starting run for rollingId", this.rollingId);


      if (this.monitoringCollection && this.paused) {
        winston.debug(`workLoop(): Collection ${this.rollingId} is paused.  Skipping worker run for this cycle`);
        return;
      }

      if ( !this.monitoringCollection && this.workerProcess.length !== 0 && this.runs === 1) {
        // If we're a rolling collection still on our first run, let it continue running until it completes
        winston.debug('workLoop(): First run of rolling collection is still running.  Delaying next run by 60 seconds');
        return;
      }
      
      // if ( this.workerProcess && ( this.runs > 1 || this.monitoringCollection ) ) {
      if ( ( !this.monitoringCollection && this.workerProcess.length !== 0 && this.runs > 1 ) ||
           ( this.monitoringCollection && this.collection.serviceType === 'nw' && this.workerProcess.length !== 0 )
         ) {
        // If not a monitoring collection, check if there's already a python worker process already running which has overrun the 60 second mark, and if so, kill it
        winston.debug('workLoop(): Timer expired for running worker.  Terminating worker');
        this.workerProcess.shift().kill('SIGINT');
      }

      if ( this.monitoringCollection && this.collection.serviceType === 'sa' && this.workerProcess.length === 2 ) {
        // If an SA monitoring collection, check if there are already two python workers already running.  If so, kill the older worker.  We want to allow two workers to run simultaneously in SA's case
        winston.debug('workLoop(): Timer expired for running worker 1.  Terminating worker');
        let wProcess = this.workerProcess.shift();
        wProcess.kill('SIGINT');
        /*
        let wSocket = wProcess.workerSocket;
        let wContent = wSocket.content;
        winston.debug('workLoop(): Deleting content of running worker 1');
        for (let i = 0; i < wContent.length; i++) {
          let contentItem = wContent[i];
          if ('contentFile' in contentItem && contentItem.contentFile) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.contentFile, () => {} );
          }
          if ('proxyContentFile' in contentItem && contentItem.proxyContentFile) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.proxyContentFile, () => {} );
          }
          if ('pdfImage' in contentItem && contentItem.pdfImage) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.pdfImage, () => {} );
          }
          if ('thumbnail' in contentItem && contentItem.thumbnail) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.thumbnail, () => {} );
          }
          if ('archiveFilename' in contentItem && contentItem.archiveFilename) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.archiveFilename, () => {} );
          }
          wSocket.content = null;
          wProcess.workerSocket = null;
        }*/
      }




      // Create temp file to be used as our UNIX domain socket
      let tempName = temp.path({suffix: '.socket'});

      // Now open the UNIX domain socket that will talk to the worker script by creating a handler (or server) to handle communications
      let workerSocket = null;
      let socketServer = net.createServer( (wSocket) => { 
        workerSocket = wSocket;
        if (this.collection.serviceType === 'sa') {
          // this is a temp space for content for this run of the worker, so that we can delete it later
          workerSocket['content'] = [];
        }
        this.workerSocket.push(workerSocket);
        this.onConnectionFromWorker(tempName, workerSocket);
        // We won't write any more data to the socket, so we will call close() on socketServer.  This prevents the server from accepting any new connections
        socketServer.close();
      });


      
      socketServer.listen(tempName, () => {
        // Tell the server to listen for communication from the not-yet-started worker

        winston.debug('workLoop(): listen(): Rolling Collection: Listening for worker communication');
        winston.debug("workLoop(): listen(): Rolling Collection: Spawning worker with socket file " + tempName);
        
        // Start the worker process and assign a reference to it to 'worker'
        // Notice that we don't pass any configuration to the worker on the command line.  It's all done through the UNIX socket for security.
        let workerProcess = spawn('./worker_stub.py', [tempName, '2>&1'], { shell: false, stdio: 'inherit'});
        workerProcess['workerSocket'] = this.workerSocket;
        workerProcess.on('exit', (code, signal) => this.onWorkerExit(code, signal, workerProcess.pid) );
        this.workerProcess.push(workerProcess);
      });
    }

    catch(e) {
      winston.error("workLoop(): work(): Caught unhandled error:", e);
    }
    
  }



  onWorkerExit(code, signal, pid) {
    // This is where we handle the exiting of the worker process
    // this.workerProcess = null;
    winston.debug(`onWorkerExit(): pid: ${pid}`)
    for (let i = 0; i < this.workerProcess.length; i++) {
      if (this.workerProcess[i].pid == pid) {
        winston.debug(`onWorkerExit(): matched process with pid ${pid},  Removing process from workerProcess table`);
        this.workerProcess.splice(i, 1);
        break;
      }
    }

    if (signal) {
      winston.debug('onWorkerExit(): Worker process was terminated by signal', signal);
      // Tell client that we're resting
      this.collection['state'] = 'resting';
      this.sendToChannel('state', 'resting');
      this.sendToHttpClients( { collection: { id: this.collectionId, state: 'resting' } } );
    }

    /*else if (!code) {
      // Handle really abnormal worker exit with no error code - maybe because we couldn't spawn it at all?  We likely won't ever enter this block
      winston.debug('workLoop(): listen(): onExit(): Worker process exited abnormally without an exit code');

      this.collection['state'] = 'error';
      this.sendToChannel('state', 'error');
      this.sendToHttpClients( { collection: { id: this.collectionId, state: 'error' } } );
    }*/

    // Handle normal worker exit code 0
    else if (!code || code === 0) {
      winston.debug('onWorkerExit(): Worker process exited normally with exit code 0');
      // Tell clients that we're resting
      this.collection['state'] = 'resting';
      this.sendToChannel('state', 'resting');
      this.sendToHttpClients( { collection: { id: this.collectionId, state: 'resting' } } );
    }

    else if (code && code !== 0) {
      // Handle worker exit with non-zero (error) exit code
      winston.debug('onWorkerExit(): Worker process exited in bad state with non-zero exit code', code );
      this.collection['state'] = 'error';
      this.sendToChannel('state', 'error');
      this.sendToHttpClients( { collection: { id: this.collectionId, state: 'error' } } );
    }


    if (this.monitoringCollection && this.paused) {
      // Monitoring collection is paused
      // Now we end and delete this monitoring collection, except for its files (which still may be in use on the client)
      winston.debug('onWorkerExit(): Completing work for paused monitoring collection', this.rollingId);
      this.dbUpdateCallback(this.collectionId);
      return;
    }

    // Save the collection to the DB
    this.dbUpdateCallback(this.collectionId);

    if (this.restartWorkLoopOnExit && this.workerProcess.length === 0) {
      this.restartWorkLoopOnExit = false;
      this.workInterval = setInterval( () => this.workLoop(), 60000);
    }
  }



  onConnectionFromWorker(tempName, workerSocket) {
    winston.debug('RollingCollectionManager: onConnectionFromWorker()');
    // For rolling and monitoring collections
    // Handles all dealings with the worker process after it has been spawned, including sending it its configuration, and sending data received from it to the onDataFromWorker() function
    // It also purges old data from the collection as defined by the type of collection and number of hours back to retain
    
    this.runs++;
    
    winston.debug("onConnectionFromWorker(): Connection received from worker to build rolling or monitoring collection", this.rollingId);
    
    if (this.monitoringCollection && !this.paused && this.collection.serviceType === 'nw') {
      // clean up nw monitoring collection files from last run
      rimraf(this.cfg.collectionsDir + '/' + this.rollingId + '/*', () => {} );
    }

    else if (this.monitoringCollection && !this.paused && this.collection.serviceType === 'sa') {

      // create an entry in runContent for this run
      this.runContent[this.runs] = [];

      // winston.debug(`onConnectionFromWorker(): this.runContent:`, this.runContent);
      
      // clean up sa monitoring collection files from five runs ago
      if ( (this.runs - 5) in this.runContent ) {
        winston.debug(`onConnectionFromWorker(): Deleting content from worker run ${this.runs - 5}`);
        // clean up collection from 5 runs ago
        let content = this.runContent[this.runs - 5];
        for (let i = 0; i < content.length; i++) {
          let contentItem = content[i];
          if ('contentFile' in contentItem && contentItem.contentFile) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.contentFile, () => {} );
          }
          if ('proxyContentFile' in contentItem && contentItem.proxyContentFile) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.proxyContentFile, () => {} );
          }
          if ('pdfImage' in contentItem && contentItem.pdfImage) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.pdfImage, () => {} );
          }
          if ('thumbnail' in contentItem && contentItem.thumbnail) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.thumbnail, () => {} );
          }
          if ('archiveFilename' in contentItem && contentItem.archiveFilename) {
            fs.unlink(this.cfg.collectionsDir + '/' + contentItem.archiveFilename, () => {} );
          }
        }
        delete this.runContent[this.runs - 5];
      }
    }

    let ourState = '';
    // Tell our subscribed clients that we're rolling, so they can start their spinny icon and whatnot
    if (this.monitoringCollection) {
      ourState = 'monitoring';
    }
    else if (!this.monitoringCollection) {
      ourState = 'rolling';
    }
    this.collection['state'] = ourState;
    if ( !(this.collection.serviceType === 'sa' && this.monitoringCollection) ) { // we do not want the client to clear the screen if it is an SA monitoring collection as it takes a long time to build.  let the client send it instead when it has data to send
      this.sendToChannel('state', ourState);
      this.sendToHttpClients( { collection: { id: this.collectionId, state: ourState}} );
    }
  
  
    ///////////////////////////
    //PURGE AGED-OUT SESSIONS//
    ///////////////////////////
  
    if (this.monitoringCollection) {
      this.sessions = [];
      this.content = [];
      this.search = [];
    }
    else if (!this.monitoringCollection && this.runs > 1) {
      // Purge events older than this.collection.lastHours
  
      winston.debug('Running purge routine');
      let sessionsToPurge = [];
  
      // Calculate the maximum age a given session is allowed to be before purging it
      let maxTime = this.lastEnd - this.collection.lastHours * 60 * 60;
      if (purgeHack) { maxTime = this.lastRun - 60 * purgeHackMinutes; } // 5 minute setting used for testing
  
      for (let i = 0; i < this.sessions.length; i++) {
        // Look at each session and determine whether it is older than maxtime
        // If so, add it to purgedSessionPositions and sessionsToPurge
        let session = this.sessions[i];
        // winston.debug('session:', session);
        let sid = session.id;
        if ( this.collection.serviceType == 'nw' && session.meta.time < maxTime ) {
          sessionsToPurge.push(sid);
        }
        else if ( this.collection.serviceType == 'sa' && this.convertSATime(session.meta.stop_time[0]) < maxTime ) {
          sessionsToPurge.push(sid);
        }
      }
  
      this.purgeSessions(sessionsToPurge.slice());
     
      // Notify the client of our purged sessions
      if (sessionsToPurge.length > 0) {
        let update = { collectionPurge: sessionsToPurge };
        this.sendToChannel('purge', sessionsToPurge);
        this.sendToHttpClients(update);
      }
      
    }
  
    //////////////////////////////////
    //Build the worker configuration//
    //////////////////////////////////
  
    let cfg = {
      // id: id,
      id: this.rollingId,
      collectionId: this.collectionId, // original collection ID
      state: ourState,
      contentLimit: this.collection.contentLimit,
      minX: this.collection.minX,
      minY: this.collection.minY,
      gsPath: this.cfg.gsPath,
      pdftotextPath: this.cfg.pdftotextPath,
      sofficePath: this.cfg.sofficePath,
      sofficeProfilesDir: this.cfg.sofficeProfilesDir,
      unrarPath: this.cfg.unrarPath,
      collectionsDir: this.cfg.collectionsDir,
      privateKeyFile: this.cfg.internalPrivateKeyFile,
      useHashFeed: this.collection.useHashFeed,
      serviceType: this.collection.serviceType,
      type: this.collection.type,
      onlyContentFromArchives: this.collection.onlyContentFromArchives || false
    };
  
    if (this.collection.serviceType == 'nw') {
      cfg['summaryTimeout'] = this.cfg.preferences.nw.summaryTimeout;
      cfg['queryTimeout'] = this.cfg.preferences.nw.queryTimeout;
      cfg['contentTimeout'] = this.cfg.preferences.nw.contentTimeout;
      cfg['maxContentErrors'] = this.cfg.preferences.nw.maxContentErrors;
      cfg['sessionLimit'] = this.cfg.preferences.nw.sessionLimit;
    }
  
    if (this.collection.serviceType == 'sa') {
      cfg['queryTimeout'] = this.cfg.preferences.sa.queryTimeout;
      cfg['contentTimeout'] = this.cfg.preferences.sa.contentTimeout;
      cfg['maxContentErrors'] = this.cfg.preferences.sa.maxContentErrors;
      cfg['sessionLimit'] = this.cfg.preferences.sa.sessionLimit;
    }
  
    if (this.collection.bound) {
      // This is an OOTB use case
      let useCaseName = this.collection.usecase;
      let useCase = this.cfg.useCasesObj[useCaseName];

      if (this.collection.serviceType == 'nw') {
        cfg['query'] = useCase.nwquery;
      }
      else {
        cfg['query'] = useCase.saquery;
      }
      cfg['contentTypes'] = useCase.contentTypes;
      cfg['distillationEnabled'] = false;
      if ('distillationTerms' in useCase) {
        cfg['distillationEnabled'] = true;
        cfg['distillationTerms'] = useCase.distillationTerms;
      }
      cfg['regexDistillationEnabled'] = false;
      if ('regexTerms' in useCase) {
        cfg['regexDistillationEnabled'] = true;
        cfg['regexDistillationTerms'] = useCase.regexTerms;
      }
      cfg['onlyContentFromArchives'] = useCase.onlyContentFromArchives;
      // we don't yet support any hashing in OOTB use cases
    }
    else {
      // This is not an OOTB use case
      cfg['distillationEnabled'] = this.collection.distillationEnabled;
      cfg['regexDistillationEnabled'] = this.collection.regexDistillationEnabled;
      
      if (!this.collection.useHashFeed) {
        // we're not using a hash feed
        cfg['md5Enabled'] = this.collection.md5Enabled;
        cfg['sha1Enabled'] = this.collection.sha1Enabled;
        cfg['sha256Enabled'] = this.collection.sha256Enabled;
        if ('md5Hashes' in this.collection) {
          cfg['md5Hashes'] = this.collection.md5Hashes;
        }
        if ('sha1Hashes' in this.collection) {
          cfg['sha1Hashes'] = this.collection.sha1Hashes;
        }
        if ('sha256Hashes' in this.collection) {
          cfg['sha256Hashes'] = this.collection.sha256Hashes;
        }
      }
      else {
        // we're using a hash feed
        cfg['hashFeed'] = this.cfg.feeds[this.collection.hashFeed]; // pass the hash feed definition
        cfg['hashFeederSocket'] = this.cfg.feederSocketFile;
      }
  
      cfg['query'] = this.collection.query;
      cfg['contentTypes'] = this.collection.contentTypes;
    
      if ('distillationTerms' in this.collection) {
        cfg['distillationTerms'] = this.collection.distillationTerms;
      }
      if ('regexDistillationTerms' in this.collection) {
        cfg['regexDistillationTerms'] = this.collection.regexDistillationTerms;
      } 
    }
  
    let queryDelaySeconds = null;
    if (this.collection.serviceType == 'nw') {
      queryDelaySeconds = this.cfg.preferences.nw.queryDelayMinutes * 60;
    }
    else if (this.collection.serviceType == 'sa') {
      queryDelaySeconds = this.cfg.preferences.sa.queryDelayMinutes * 60;
    }
    if (queryDelaySeconds < 60) {
      queryDelaySeconds = 60;
    }

    winston.debug('The time is:', moment.utc().format('YYYY-MMMM-DD HH:mm:ss') );
    if (this.lastRun) {
      let mom = moment.utc(this.lastRun * 1000);
      winston.debug('The time of lastRun is:', mom.format('YYYY-MMMM-DD HH:mm:ss') );
    }
    if (this.lastEnd) {
      let mom = moment.utc(this.lastEnd * 1000);
      winston.debug('The time of lastEnd is:', mom.format('YYYY-MMMM-DD HH:mm:ss') );
    }

    if (this.monitoringCollection) {
      // If this is a monitoring collection, then set timeEnd and timeBegin to be a one minute window
      cfg['timeEnd'] = moment().startOf('minute').unix() - 1 - queryDelaySeconds;
      cfg['timeBegin'] = ( cfg['timeEnd'] - 60) + 1;
    }

    else if (this.runs == 1) {
      // This is the first run of a rolling collection
      // winston.debug('got to 1');
      winston.debug('onConnectionFromWorker(): Got first run');
      cfg['timeBegin'] = moment().startOf('minute').unix() - 1 - ( this.collection.lastHours * 60 * 60 ) - queryDelaySeconds ;
      cfg['timeEnd'] = moment().startOf('minute').unix() - 1 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler

      // cfg['timeEnd'] = moment().startOf('minute').unix() - 61 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
      // cfg['timeBegin'] = ( cfg['timeEnd'] - (this.collection.lastHours * 60 * 60) ) + 1;
    }
    
    else if ( ( !this.resumed && this.runs == 2 && ( moment().unix() - this.lastRun > 60 ) ) ) {
      // winston.debug('got to 2');
      // This is the second run of a non-resumed rolling collection - this allows the first run to exceed one minute of execution and will take up whatever excess time has elapsed
      // It will only enter this block if more than 61 seconds have elapsed since the last run
      winston.debug('onConnectionFromWorker(): Got second run');
      cfg['timeBegin'] = this.lastEnd + 1; // one second after the last run
      cfg['timeEnd'] = moment().startOf('minute').unix() - 1 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
      // cfg['timeEnd'] = moment().startOf('minute').unix() - 61 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
    }
  
    else if ( !this.resumed && this.runs >= 2) {
      // winston.debug('got to 3');
      // This is the third or greater run of a non-resumed rolling collection
      winston.debug('onConnectionFromWorker(): Got subsequent run');
      cfg['timeBegin'] = this.lastEnd + 1; // one second after the last run
      cfg['timeEnd'] = cfg['timeBegin'] + 60; // add one minute to cfg[timeBegin]
    }

    else if ( this.resumed && ( moment().unix() - this.lastRun < 60 ) ) { // resumed and less than 60 seconds have elapsed since last run
      winston.debug('onConnectionFromWorker(): Resumed collection and less than 60 seconds since last run');
      cfg['timeBegin'] = this.lastEnd + 1; // one second after the last run
      let secondsSinceLastRun = moment().unix() - this.lastRun;
      cfg['timeEnd'] = cfg['timeBegin'] + secondsSinceLastRun;
    }

    else if ( this.resumed && ( moment().unix() - this.lastRun >= 60 ) ) { // resumed and 60 seconds or more have elapsed since last run
      winston.debug('onConnectionFromWorker(): Resumed collection and greater than 60 seconds since last run');
      cfg['timeBegin'] = this.lastEnd + 1; // one second after the last run
      cfg['timeEnd'] = moment().startOf('minute').unix() - 1 - queryDelaySeconds;
    }
    
    this.resumed = false;

    let momBegin = moment.utc(cfg['timeBegin'] * 1000);
    winston.debug('The time of timeBegin is:', momBegin.format('YYYY-MMMM-DD HH:mm:ss') );

    let momEnd = moment.utc(cfg['timeEnd'] * 1000);
    winston.debug('The time of timeEnd is:', momEnd.format('YYYY-MMMM-DD HH:mm:ss') );
    
    this.lastRun = moment.utc().unix();
    this.lastEnd = cfg['timeEnd']; // store the time of last run so that we can reference it the next time we loop


    if ('distillationTerms' in this.collection) {
      cfg['distillationTerms'] = this.collection.distillationTerms;
    }
    if ('regexDistillationTerms' in this.collection) {
      cfg['regexDistillationTerms'] = this.collection.regexDistillationTerms;
    }
    if ('md5Hashes' in this.collection) {
      cfg['md5Hashes'] = this.collection.md5Hashes;
    }
    if ('sha1Hashes' in this.collection) {
     cfg['sha1Hashes'] = this.collection.sha1Hashes;
    }
    if ('sha256Hashes' in this.collection) {
     cfg['sha256Hashes'] = this.collection.sha256Hashes;
    }
  
    if (this.collection.serviceType == 'nw') {
      let nwserver = this.cfg.nwservers[this.collection.nwserver];
      for (let k in nwserver) {
        if (nwserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
          cfg[k] = nwserver[k];  // assign properties of nwserver to the collection cfg
        }
      }
    }
    if (this.collection.serviceType == 'sa') {
      let saserver = this.cfg.saservers[this.collection.saserver];
      for (let k in saserver) {
        if (saserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
          cfg[k] = saserver[k];  // assign properties of saserver to the collection cfg
        }
      }
    }
    let outerCfg = { workerConfig: cfg };
  
  
  
    ////////////////////////
    //DEAL WITH THE SOCKET//
    ////////////////////////
  
    // Buffer for worker data
    var data = '';
  
    //Set socket options
    workerSocket.setEncoding('utf8');
    
    let runnum = this.runs; // just making sure we resolve the correct run number in the below 'data' callback.  primitive numbers are copied by value and not by reference
    // Handle data received from the worker over the socket (this really builds the collection)
    workerSocket.on('data', chunk => data = this.onDataFromWorker(data, chunk, runnum) );
    // this.onDataFromWorkerFunc = (chunk) => this.onDataFromWorker(data, chunk);
    // this.workerSocket.on('data', this.onDataFromWorkerFunc );
                                
                                
    // Once the worker has exited, delete the socket temporary file
    workerSocket.on('end', () => this.onWorkerDisconnected(tempName) );
    
    // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
    this.sendToWorker(outerCfg, workerSocket);
    
  }

  

  onWorkerDisconnected(tempName) {
    winston.debug('onWorkerDisconnected(): Worker disconnected.  Rolling collection update cycle complete');
    for (let i = 0; i < this.workerSocket.length; i++) {
      if (tempName === this.workerSocket[i].server._pipeName) {
        winston.debug('onWorkerDisconnected: found workerSocket.  Deleting it');
        fs.unlink(tempName, () => {} ); // Delete the temporary UNIX socket file
        this.workerSocket.splice(i, 1);
        break;
      }
    }
  }



  purgeSessions(sessionsToPurge) {
    // winston.debug('purgeSessions(): sessionsToPurge.length: ', sessionsToPurge.length)
    winston.debug('RollingCollectionManager: purgeSessions(): ' + sessionsToPurge);
    while (sessionsToPurge.length > 0) {
      let sessionToPurge = sessionsToPurge.shift(); // a session ID
      // winston.debug('purgeSessions(): purge for session', sessionToPurge);
  
      // for (let i = 0; i < this.sessions.length; i++) {
      for (let i = this.sessions.length - 1; i != -1 ; i--) {
        // Remove purged sessions from this.sessions
        let session = this.sessions[i];
        if (session.id == sessionToPurge) {
          // winston.debug('purgeSessions(): purging session', session.id);
          this.sessions.splice(i, 1);
          break;
        }
      }
  
      let searchesToPurge = [];
      // for (let i = 0; i < this.search.length; i++) {
      for (let i = this.search.length - 1; i != -1; i--) {
        // Identify search items to purge from this.search
        let search = this.search[i];
        if (search.session == sessionToPurge) {
          // searchesToPurge.push(search);
          winston.debug('purgeSessions(): purging search', search.session);
          this.search.splice(i, 1);
        }
      }
      /*while (searchesToPurge.length != 0) {
        // Remove purged search items from this.search
        let searchToPurge = searchesToPurge.shift();
        for (let i = 0; i < this.search.length; i++) {
          let search = this.search[i];
          if (searchToPurge.session == search.session && searchToPurge.contentFile == search.contentFile) {
            // Purge search
            winston.debug('purgeSessions(): purging search', search.session);
            this.search.splice(i, 1);
            break;
          }
        }
      }*/
      
      let contentsToPurge = [];
      // for (let i = 0; i < this.content.length; i++) {
      for (let i = this.content.length - 1; i != -1; i--) {
        // Purge content
        let content = this.content[i];
        if (content.session == sessionToPurge) {
          winston.debug('purgeSessions(): purging content', content.session);
          // contentsToPurge.push(content);
          if ('contentFile' in content) {
            fs.unlink(content.contentFile, () => {});
          }
          if ('proxyContentFile' in content) {
            fs.unlink(content.proxyContentFile, () => {});
          }
          if ('thumbnail' in content) {
            fs.unlink(content.thumbnail, () => {});
          }
          if ('pdfImage' in content) {
            fs.unlink(content.pdfImage, () => {});
          }
          this.content.splice(i, 1);
        }
      }

      /*while (contentsToPurge.length != 0) {
        let contentToPurge = contentsToPurge.shift();
        for (let i = 0; i < this.content.length; i++) {
          let content = this.content[i];
          if (contentToPurge.session == content.session && contentToPurge.contentFile == content.contentFile && contentToPurge.contentType == content.contentType) {
            // Purge content
            winston.debug('purgeSessions(): purging content', content.session);
            this.content.splice(i, 1);
            if ('contentFile' in content) {
              fs.unlink(content.contentFile, () => {});
            }
            if ('proxyContentFile' in content) {
              fs.unlink(content.proxyContentFile, () => {});
            }
            if ('thumbnail' in content) {
              fs.unlink(content.thumbnail, () => {});
            }
            if ('pdfImage' in content) {
              fs.unlink(content.pdfImage, () => {});
            }
            break;
          }
        }
      }*/

    }
  }


  
  onDataFromWorker(data, chunk, runNumber) {
  // onDataFromWorker(chunk) {
  // onDataFromWorker = (chunk) => {
    // Handles socket data received from the worker process
    // This actually builds the collection data structures and sends updates to the client
    winston.debug('RollingCollectionManager: onDataFromWorker(): Processing update from worker');
     data += chunk

    var splt = data.split("\n").filter( (el) => {return el.length != 0}) ;

    if ( splt.length == 1 && data.indexOf("\n") === -1 ) {
      // this case means the split resulted in only one element and that doesn't contain the newline delimiter, which means we haven't received an entire update yet...
      // we'll continue and wait for the next update which will hopefully contain the delimiter
      return data;
    }
    var d = []
    if ( splt.length == 1 && data.endsWith("\n") ) {
      // this case means the split resulted in only one element and that it does contain the newline delimiter.  This means we received a single complete update.
      d.push(splt.shift() );
      data='';
    }
    else if ( splt.length > 1 ) {
      // This case means the split resulted in multiple elements and that it does contain a newline delimiter...
      // This means we have at least one complete update, and possibly more.
      if (data.endsWith("\n")) {  // the last element is a full update as data ends with a newline
        while (splt.length > 0) {
          d.push(splt.shift());
        }
        data = '';
      }
      else { // the last element is only a partial update, meaning that more data must be coming
        while (splt.length > 1) {
          d.push(splt.shift());
        }
        data = splt.shift();  // this should be the last partial update, which should be appended to in the next update
      }
    }

    while (d.length > 0) {
      let u = d.shift();
      let update = JSON.parse(u);

      if ('collectionUpdate' in update) {

        this.sessions.push(update.collectionUpdate.session);
        
        if (update.collectionUpdate.search) {
          if (!this.search) {
            this.search = [];
          }
          for (var i = 0; i < update.collectionUpdate.search.length; i++) {
            
            this.search.push(update.collectionUpdate.search[i]);
          }
        }

        for (let i = 0; i < update.collectionUpdate.images.length; i++) {
          let image = update.collectionUpdate.images[i];
          this.content.push(image);
          if (this.monitoringCollection && this.collection.serviceType === 'sa') {
            this.runContent[runNumber].push(image);
          }
        }
      }
      
      // winston.debug('update:', update);
      if ('state' in update) {
        this.sendToChannel('state', update.state);
        this.sendToHttpClients( { collection: { id: this.collectionId, state: update.state } } );
      }
      else {
        this.sendToChannel('update', update);
        this.sendToHttpClients(update);
      }
    }

    return data;
  };


  convertSATime(value) {
    return parseInt(value.substring(0, value.indexOf(':')), 10);
  }


}

module.exports = RollingCollectionHandler;
