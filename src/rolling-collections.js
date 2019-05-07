class RollingCollectionHandler {

  // The purpose of this class is to manage connections to API requests for rolling collections

  constructor(afbconfig, feederSocketFile, channel) {

    this.afbconfig = afbconfig;
    this.feederSocketFile = feederSocketFile,
    this.rollingCollectionManagers = {};

    // socket.io
    this.channel = channel;
    this.channel.on('connection', (socket) => this.onChannelConnect(socket) ); // channel is the /collections socket.io namespace,  It gets further segmented into per-collection rooms.  For monitoring collections, each client connection gets its own room, so that it can be controlled independently of other users.
    this.roomSockets = {}; // tracks which sockets are joined to which rooms
  }



  onChannelConnect(socket) {
    winston.debug('RollingCollectionHandler: onChannelConnect()');
    if (!('jwtuser' in socket.conn)) {
      // socket is not authenticated - disconnect it
      socket.disconnect(false);
      return;
    }
    socket.on('disconnect', () => this.onChannelDisconnect(socket) );
    socket.on('join', (data) => this.onSocketJoinCollection(socket, data) );
    socket.on('leave', () => this.onLeaveCollection(socket) );
    socket.on('pause', () => this.onPauseCollection(socket) );
    socket.on('unpause', () => this.onUnpauseCollection(socket) );
  }



  onSocketJoinCollection(socket, data) {
    // this is the equivalent of onHttpConnection(), but for socket connections
    // data must contain properties collectionID and sessionId
    // sessionId should be null if a standard rolling collection
    winston.debug('RollingCollectionHandler: onSocketJoinCollection()');
    // winston.debug('RollingCollectionHandler: onSocketJoinCollection(): socket', socket);

    let collectionId = data['collectionId'];
    let collection = this.afbconfig.collections[collectionId];

    let rollingId = collectionId;
    let sessionId = data['sessionId'];

    winston.debug('RollingCollectionHandler: onSocketJoinCollection(): collectionId:', collectionId);
    winston.debug('RollingCollectionHandler: onSocketJoinCollection(): rollingId:', rollingId);
    winston.info(`User '${socket.conn.jwtuser.username}' has connected to ${collection.type} collection '${collection.name}'`);

    if (!license.valid) {
      winston.info(`License is invalid.  Aborting attempt to connect to rolling or monitoring collection '${collection.name}'`);
      return;
    }

    if (collection.type === 'monitoring') {
      rollingId = collectionId + '_' + sessionId;
    }
    socket['rollingId'] = rollingId; // add the rolling id to our socket so we can later identify it
    socket['collectionId'] = collectionId;
    socket['collectionName'] = collection.name;
    socket['collectionType'] = collection.type;

    socket.join(rollingId); // this joins a room for rollingId
    if (!(rollingId in this.roomSockets)) {
      this.roomSockets[rollingId] = [];
    }
    this.roomSockets[rollingId].push(socket);

    // we leave out the licensing code here as it is handled by the client or when the collection is killed

    let rollingCollectionManager = null;
    if ( !(rollingId in this.rollingCollectionManagers) ) {
      // there is no RollingCollectionManager yet for the chosen collection.  So create one
      rollingCollectionManager = new RollingCollectionManager(this, collection, collectionId, rollingId);
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
      winston.info(`A user has disconnected from ${socket.collectionType} collection '${socket.collectionName}'`)
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
      if (collectionId in this.afbconfig.collections) {
        winston.info(`A user has disconnected from ${this.afbconfig.collections[collectionId].type} collection '${this.afbconfig.collections[collectionId].name}'`);
      }
      else {
        winston.info(`A user has disconnected from rolling collections`);
      }
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
      winston.info(`User '${socket.conn.jwtuser.username}' has paused monitoring collection '${this.afbconfig.collections[rollingId].name}'`)
      // winston.info(`User '${socket.conn.jwtuser.username}' has paused monitoring collection '${rollingId}'`)
      // winston.info(`this.afbconfig.collections[rollingId]:`, this.afbconfig.collections)
      let manager = socket['rollingCollectionManager'];
      manager.pause();
    }

  }



  onUnpauseCollection(socket) {
    winston.debug('RollingCollectionHandler: onUnpauseCollection()');

    if ('rollingCollectionManager' in socket) {
      let rollingId = socket['rollingId'].substring(0,36);
      winston.info(`User '${socket.conn.jwtuser.username}' has unpaused monitoring collection '${this.afbconfig.collections[rollingId].name}'`)
      // winston.info(`User '${socket.conn.jwtuser.username}' has unpaused monitoring collection '${rollingId}'`)
      let manager = socket['rollingCollectionManager'];
      manager.unpause();
    }

  }
  

  
  onHttpConnection(req, res) {
    // Builds and streams a rolling or monitoring collection back to the client.  Handles the client connection and kicks off the process
    
    let collectionId = req.params.collectionId;
    let clientSessionId = req.headers['afbsessionid'];
    
    winston.debug('RollingCollectionHandler: onHttpConnection(): collectionId:', collectionId);
    // winston.debug('preferences:', this.afbconfig.preferences);
    
    let rollingId = collectionId;
    // rollingId is either the collectionId (for rolling collections), or the clientSessionId (for monitoring collections).
    // our classes will refer to this id when accessing the rollingCollections object
    if ( this.afbconfig.collections[collectionId].type === 'monitoring' ) {
      rollingId = clientSessionId;
    }
    let collection = this.afbconfig.collections[collectionId];

    winston.debug('RollingCollectionHandler: onHttpConnection(): rollingId:', rollingId);
    winston.info(`User '${req.user.username}' has connected to ${collection.type} collection '${collection.name}'`);
    
    // create a client connection handler for this connection
    // does a manager for the requested rolling collection exist?
    // if not, create a new rolling collection manager
    // add new or existing rolling collection manager to the client connection handler
    
    let clientConnection = new HttpConnection(this, collectionId, rollingId, req, res);
    if ( !clientConnection.onConnect(collection) ) {
      return;
    }
    
    let rollingCollectionManager = null;
    if ( !(rollingId in this.rollingCollectionManagers)) {
      // there is no RollingCollectionManager yet for the chosen collection.  So create one
      rollingCollectionManager = new RollingCollectionManager(this, collection, collectionId, rollingId);
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
    // winston.info(`User '${req.user.username}' has paused monitoring collection '${this.afbconfig.collections[rollingId].name}'`)
    let manager = this.rollingCollectionManagers[clientSessionId]['manager'];
    manager.pause();
    res.status(202).send( JSON.stringify( { success: true } ) );
  }



  unpauseMonitoringCollectionHttp(req, res) {
    // This only gets used by the client if a monitoring collection is paused and then resumed within the minute the run is permitted to continue executing
    // Otherwise, the client will simply call /api/collection/rolling/:id again
    let clientSessionId = req.headers['afbsessionid'];
    winston.debug(`RollingCollectionHandler: unpauseMonitoringCollectionHttp(): Resuming monitoring collection ${clientSessionId}`);
    // winston.info(`User '${req.user.username}' has unpaused monitoring collection '${this.afbconfig.collections[rollingId].name}'`)
    let manager = this.rollingCollectionManagers[clientSessionId]['manager'];
    manager.unpause();
    res.status(202).send( JSON.stringify( { success: true } ) );
  }



  collectionEdited(collectionId, collection) {
    winston.debug('RollingCollectionHandler: collectionEdited()');
    let managers = []
    if (collectionId in this.rollingCollectionManagers) {
      let manager = this.rollingCollectionManagers[collectionId]['manager'];
      managers.push(manager);
    }
    else {
      // didn't find the collectionId yet, but it could still be in there if it's a monitoring collection
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


  
  async removeRollingCollectionManager(id) { // id is rollingId
    winston.debug('RollingCollectionHandler: removeRollingCollectionManager()');
    delete this.rollingCollectionManagers[id];
    // disconnect all client sockets from this collection's room
    if (!(id in this.roomSockets)) {
      winston.error('No sockets could be found for fixed collection', id);
    }
    try {
      winston.debug("Deleting output directory for collection", id);
      await rmfr( this.afbconfig.collectionsDir + '/' + id ); // Delete output directory
    }
    catch(error) {
      winston.error('ERROR deleting output directory ' + this.afbconfig.collectionsDir + '/' + id, error);
      throw(error);
    }
    for (let i = 0; i < this.roomSockets[id].slice(0).length; i++) {
      let socket = this.roomSockets[id][i];
      this.onLeaveCollection(socket);
    }
    delete this.roomSockets[id];
  }



  killall() {
    // we get here during server shutdown, and when the license expires
    winston.debug('RollingCollectionHandler: killall()');
    Object.values(this.rollingCollectionManagers).forEach( manager => {
      manager.manager.abort();
    });
  }



  restartRunningCollections() {
    // we get here during server shutdown, and when the license expires
    winston.debug('RollingCollectionHandler: restartRunningCollections()');
    Object.values(this.rollingCollectionManagers).forEach( manager => {
      manager.manager.restart();
    });
  }



  updateFeederSocketFile(filename) {
    this.feederSocketFile = filename;
  }

}
  
  
  
  
  
  
  
  
  
  
  
  

  
  

class HttpConnection {

  constructor(handler, collectionId, rollingId, req, res) {
    winston.debug('HttpConnection: constructor()');
    this.handler = handler;
    this.afbconfig = this.handler.afbconfig;
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
      if (collection.bound && !(collection.usecase in this.afbconfig.useCases.useCasesObj) ) {
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
    winston.info(`User '${this.req.user.username}' has disconnected from ${this.afbconfig.collections[this.collectionId].type} collection '${this.afbconfig.collections[this.collectionId].name}'`);
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

  constructor(handler, collection, collectionId, rollingId) {
    winston.debug('RollingCollectionManager: constructor()');
    this.handler = handler;
    this.afbconfig = this.handler.afbconfig;
    this.channel = this.handler.channel; // a handle to our socket.io /collections namespace
    
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
    this.lastQueryEndTime = null; // the end time of the last query to run
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



  async selfDestruct() {
    winston.debug('RollingCollectionManager: selfDestruct()');
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
    this.handler.removeRollingCollectionManager(this.rollingId);
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
        if (this.workerProcess.length === 0) {
          winston.debug('RollingCollectionManager: addHttpClient(): there is a workerProcess.  Setting restartWorkLoopOnExit to false');
          this.restartWorkLoopOnExit = false;
          this.run();
        }
        else {
          winston.debug('RollingCollectionManager: addHttpClient(): there is already a workerProcess.  Setting restartWorkLoopOnExit to true');
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
      winston.debug(`RollingCollectionManager: addSocketClient(): This is not the first client to have connected to rolling collection ${this.rollingId}.  Playing back existing collection`);

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

      // Emit collection state
      socket.emit('state', this.collection.state);

      winston.debug(`RollingCollectionManager: addSocketClient(): Current number of observers: ${this.observers}`);

      if (this.workInterval) {
        // workInterval is already running - just let it continue
        winston.debug('RollingCollectionManager: addSocketClient(): there is an existing workInterval running.  Not starting workLoop');
      }

      else if (!this.workInterval) {
        // there is no existing workInterval.  Better check for a running worker in case there's an old one still floating about
        if (this.workerProcess.length !== 0) {
          // there's already a worker running.  When it exits, instruct it to restart the workLoop
          winston.debug('RollingCollectionManager: addSocketClient(): there is an existing workerProcess.  The workLoop will be restarted when it exits.  Setting restartWorkLoopOnExit to true');
          this.restartWorkLoopOnExit = true;
        }
        else if (this.workerProcess.length === 0) {
          // no worker is running and there is no work interval.  Start the workLoop
          winston.debug('RollingCollectionManager: addSocketClient(): there is no existing workerProcess.  Starting workLoop');
          this.restartWorkLoopOnExit = false;
          this.run();
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
    this.lastQueryEndTime = null;
    this.lastRun = null;
    this.resumed = false;

    this.sendToRoom('clear', true); // this only triggers when a collection is edited.  no other time
    this.sendToHttpClients( { wholeCollection: { images: [], sessions: {}, search: [] } } );
    

    if (this.observers !== 0) {
      this.run();
    }

  }



  async onCollectionDeleted(user) {
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

    this.sendToHttpClients( { collectionDeleted: true, user: user } );
    this.endAllClients();

    this.handler.removeRollingCollectionManager(this.rollingId);
  }



  async abort() {
    winston.debug('RollingCollectionManager: abort()');

    // we only get here in these cases:
    //   1. the program is exiting, either gracefully or due to an error
    //   2. license expired

    // stop the work loop
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = null;
    }

    this.killWorker();
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = null;
    }

    let state = 'stopped';
    this.collection['state'] = state;
    this.sendToRoom('state', state);
    this.endAllClients(); // disconnects socket and http clients
    
    await this.afbconfig.updateRollingCollection(this.collectionId) // save collection state
    
    this.handler.removeRollingCollectionManager(this.collectionId);
  }



  async restart() {
    winston.debug('RollingCollectionManager: restart()');

    // we only get here in this case:
    //   1. query delay minutes has been updated
    
    // stop the work loop
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = null;
    }
    
    // stop any running workers
    this.killWorker();
    
    this.sessions = [];
    this.content = [];
    this.search = [];
    this.runs = 0;
    this.lastQueryEndTime = null;
    this.lastRun = null;
    this.resumed = false;

    this.sendToRoom('clear', true); // this only triggers when a collection is edited.  no other time
    this.sendToHttpClients( { wholeCollection: { images: [], sessions: {}, search: [] } } );

    if (this.observers !== 0) {
      this.run();
    }

   
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
    this.sendToRoom('paused', true);
  }



  unpause() {
    winston.debug('RollingCollectionManager: unpause()');
    this.paused = false;
    
    let timeOfResume = moment().unix();
    let difference = timeOfResume - this.timeOfPause;
    winston.debug('RollingCollectionManager: unpause(): difference:', difference);

    if (difference >= 60) {
      // more than a minute has elapsed since pause. Resume immediately and restart loop
      clearInterval(this.workInterval);
      this.workInterval = setInterval( () => this.workLoop(), 60000);
      this.workLoop();
    }

    this.timeOfPause = 0;

    this.sendToRoom('paused', false);

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
    // sends RAW data to all connected HTTP clients
    winston.debug('RollingCollectionManager: sendToHttpClientsRaw()');
    for (let id in this.httpClients) {
      if (this.httpClients.hasOwnProperty(id)) {
        let client = this.httpClients[id];
        client.sendRaw(data);
      }
    }
  }



  sendToRoom(type, data) {
    // sends data to all connected socket.io clients
    if (this.channel) {
      this.channel.to(this.rollingId).emit( type, data );
    }
  }



  endAllClients() {
    // disconnects socket and http clients
    winston.debug('RollingCollectionManager: endAllClients()');
    for (let id in this.httpClients) {
      if (this.httpClients.hasOwnProperty(id)) {
        let client = this.httpClients[id];
        client.end();
      }
    }
    this.sendToRoom('disconnect', true);
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

      ///////////////////////////
      //PURGE AGED-OUT SESSIONS//
      ///////////////////////////
      this.calculateSessionsToPurge();

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
        let workerProcess = spawn('./worker/worker_stub.py', [tempName, '2>&1'], { shell: false, stdio: 'inherit'});
        workerProcess['workerSocket'] = this.workerSocket;
        workerProcess.on('exit', (code, signal) => this.onWorkerExit(code, signal, workerProcess.pid, tempName) );
        this.workerProcess.push(workerProcess);
      });
    }

    catch(e) {
      winston.error("workLoop(): work(): Caught unhandled error:", e);
    }
    
  }



  onWorkerExit(code, signal, pid, tempName) {
    // This is where we handle the exiting of the worker process
    // this.workerProcess = null;
    winston.debug(`onWorkerExit(): Worker with PID ${pid} exited.  Rolling collection update cycle is complete`);
    for (let i = 0; i < this.workerProcess.length; i++) {
      if (this.workerProcess[i].pid == pid) {
        winston.debug(`onWorkerExit(): matched process with pid ${pid},  Removing process from workerProcess table`);
        this.workerProcess.splice(i, 1);
        break;
      }
    }

    for (let i = 0; i < this.workerSocket.length; i++) {
      if (tempName === this.workerSocket[i].server._pipeName) {
        winston.debug('onWorkerExit(): matched workerSocket.  Deleting it');
        fs.unlink(tempName, () => {} ); // Delete the temporary UNIX socket file
        this.workerSocket.splice(i, 1);
        break;
      }
    }

    if (signal) {
      winston.debug('onWorkerExit(): Worker process was terminated by signal', signal);
      // Tell client that we're resting
      this.collection['state'] = 'resting';
      this.sendToRoom('state', 'resting');
      this.sendToHttpClients( { collection: { id: this.collectionId, state: 'resting' } } );
    }

    // Handle normal worker exit code 0
    else if (!code || code === 0) {
      winston.debug('onWorkerExit(): Worker process exited normally with exit code 0');
      // Tell clients that we're resting
      this.collection['state'] = 'resting';
      this.sendToRoom('state', 'resting');
      this.sendToHttpClients( { collection: { id: this.collectionId, state: 'resting' } } );
    }

    else if (code && code !== 0) {
      // Handle worker exit with non-zero (error) exit code
      winston.debug('onWorkerExit(): Worker process exited in bad state with non-zero exit code', code );
      this.collection['state'] = 'error';
      this.sendToRoom('state', 'error');
      this.sendToHttpClients( { collection: { id: this.collectionId, state: 'error' } } );
    }


    if (this.monitoringCollection && this.paused) {
      // Monitoring collection is paused
      // Now we end and delete this monitoring collection, except for its files (which still may be in use on the client)
      winston.debug('onWorkerExit(): Completing work for paused monitoring collection', this.rollingId);
      this.afbconfig.updateRollingCollection(this.collectionId);
      return;
    }

    // Save the collection to the DB
    this.afbconfig.updateRollingCollection(this.collectionId);

    if (this.restartWorkLoopOnExit && this.workerProcess.length === 0) {
      winston.debug('onWorkerExit(): restartWorkLoopOnExit is true.  Triggering new workLoop() interval')
      this.restartWorkLoopOnExit = false;
      this.workInterval = setInterval( () => this.workLoop(), 60000);
    }
  }



  async onConnectionFromWorker(tempName, workerSocket) {
    winston.debug('RollingCollectionManager: onConnectionFromWorker()');
    // For rolling and monitoring collections
    // Handles all dealings with the worker process after it has been spawned, including sending it its configuration, and sending data received from it to the onDataFromWorker() function
    // It also purges old data from the collection as defined by the type of collection and number of hours back to retain
    
    this.runs++;
    
    winston.debug("onConnectionFromWorker(): Connection received from worker to build rolling or monitoring collection", this.rollingId);
    
    if (this.monitoringCollection && !this.paused && this.collection.serviceType === 'nw') {
      // clean up nw monitoring collection files from last run
      await rmfr(this.afbconfig.collectionsDir + '/' + this.rollingId + '/*');
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
            fs.unlink(this.afbconfig.collectionsDir + '/' + contentItem.contentFile, () => {} );
          }
          if ('proxyContentFile' in contentItem && contentItem.proxyContentFile) {
            fs.unlink(this.afbconfig.collectionsDir + '/' + contentItem.proxyContentFile, () => {} );
          }
          if ('pdfImage' in contentItem && contentItem.pdfImage) {
            fs.unlink(this.afbconfig.collectionsDir + '/' + contentItem.pdfImage, () => {} );
          }
          if ('thumbnail' in contentItem && contentItem.thumbnail) {
            fs.unlink(this.afbconfig.collectionsDir + '/' + contentItem.thumbnail, () => {} );
          }
          if ('archiveFilename' in contentItem && contentItem.archiveFilename) {
            fs.unlink(this.afbconfig.collectionsDir + '/' + contentItem.archiveFilename, () => {} );
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
      this.sendToRoom('state', ourState);
      this.sendToHttpClients( { collection: { id: this.collectionId, state: ourState}} );
    }
  
  
  
    //////////////////////////////////
    //Build the worker configuration//
    //////////////////////////////////
  
    let cfg = {
      id: this.rollingId,
      collectionId: this.collectionId, // original collection ID
      state: ourState,
      contentLimit: this.collection.contentLimit,
      minX: this.collection.minX,
      minY: this.collection.minY,
      gsPath: this.afbconfig.gsPath,
      pdftotextPath: this.afbconfig.pdftotextPath,
      sofficePath: this.afbconfig.sofficePath,
      sofficeProfilesDir: this.afbconfig.sofficeProfilesDir,
      unrarPath: this.afbconfig.unrarPath,
      collectionsDir: this.afbconfig.collectionsDir,
      privateKeyFile: this.afbconfig.internalPrivateKeyFile,
      useHashFeed: this.collection.useHashFeed,
      serviceType: this.collection.serviceType,
      type: this.collection.type,
      onlyContentFromArchives: this.collection.onlyContentFromArchives || false
    };
  
    try {
      if (this.collection.serviceType === 'nw') {
        cfg['summaryTimeout'] = this.afbconfig.preferences.nw.summaryTimeout;
        cfg['queryTimeout'] = this.afbconfig.preferences.nw.queryTimeout;
        cfg['contentTimeout'] = this.afbconfig.preferences.nw.contentTimeout;
        cfg['maxContentErrors'] = this.afbconfig.preferences.nw.maxContentErrors;
        cfg['sessionLimit'] = this.afbconfig.preferences.nw.sessionLimit;
      }
    
      if (this.collection.serviceType === 'sa') {
        cfg['queryTimeout'] = this.afbconfig.preferences.sa.queryTimeout;
        cfg['contentTimeout'] = this.afbconfig.preferences.sa.contentTimeout;
        cfg['maxContentErrors'] = this.afbconfig.preferences.sa.maxContentErrors;
        cfg['sessionLimit'] = this.afbconfig.preferences.sa.sessionLimit;
      }
    }
    catch(error) {
      /*
      On 3/21/19, the server crashed with this when connecting to a NW rolling collection.  Could not reproduce:
      2019-03-21 10:01:27,691 afb_server    DEBUG      RollingCollectionManager: onConnectionFromWorker()
      2019-03-21 10:01:27,691 afb_server    DEBUG      onConnectionFromWorker(): Connection received from worker to build rolling or monitoring collection ad3a7b05-801e-4220-fca4-1d631dbc0f52
      TypeError: Cannot read property 'summaryTimeout' of undefined
          at RollingCollectionManager.onConnectionFromWorker (/Users/tunderhay/src/afb-server/rolling-collections.js:1302:55)
          at Server.net.createServer (/Users/tunderhay/src/afb-server/rolling-collections.js:1072:14)
          at Server.emit (events.js:197:13)
          at Pipe.onconnection (net.js:1501:8)
      2019-03-21 10:01:27,694 afb_server    DEBUG      onCleanup(): exitCode: 1
      2019-03-21 10:01:27,695 afb_server    DEBUG      onCleanup(): signal:
      2019-03-21 10:01:27,704 afb_worker    INFO       Exiting afb_worker with code 0
      */
      winston.error('Caught error trying to read preferences.  Exiting with code 1.');
      process.exit(1);
    }
  
    if (this.collection.bound) {
      // This is an OOTB use case
      let useCaseName = this.collection.usecase;
      let useCase = this.afbconfig.useCases.useCasesObj[useCaseName];

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
        cfg['hashFeed'] = this.afbconfig.feeds[this.collection.hashFeed]; // pass the hash feed definition
        cfg['hashFeederSocket'] = this.handler.feederSocketFile;
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
      queryDelaySeconds = this.afbconfig.preferences.nw.queryDelayMinutes * 60;
    }
    else if (this.collection.serviceType == 'sa') {
      queryDelaySeconds = this.afbconfig.preferences.sa.queryDelayMinutes * 60;
    }
    if (queryDelaySeconds < 60) {
      queryDelaySeconds = 60;
    }

    winston.debug('The time is:', moment.utc().format('YYYY-MMMM-DD HH:mm:ss') );
    if (this.lastRun) {
      let mom = moment.utc(this.lastRun * 1000);
      winston.debug('The time of lastRun is:', mom.format('YYYY-MMMM-DD HH:mm:ss') );
    }
    if (this.lastQueryEndTime) {
      let mom = moment.utc(this.lastQueryEndTime * 1000);
      winston.debug('The time of lastQueryEndTime is:', mom.format('YYYY-MMMM-DD HH:mm:ss') );
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
    }
    
    else if ( ( !this.resumed && this.runs == 2 && ( moment().unix() - this.lastRun > 60 ) ) ) {
      // winston.debug('got to 2');
      // This is the second run of a non-resumed rolling collection - this allows the first run to exceed one minute of execution and will take up whatever excess time has elapsed
      // It will only enter this block if more than 61 seconds have elapsed since the last run
      winston.debug('onConnectionFromWorker(): Got second run');
      cfg['timeBegin'] = this.lastQueryEndTime + 1; // one second after the last run
      cfg['timeEnd'] = moment().startOf('minute').unix() - 1 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
    }
  
    else if ( !this.resumed && this.runs >= 2) {
      // winston.debug('got to 3');
      // This is the third or greater run of a non-resumed rolling collection
      winston.debug('onConnectionFromWorker(): Got subsequent run');
      cfg['timeBegin'] = this.lastQueryEndTime + 1; // one second after the last run
      cfg['timeEnd'] = cfg['timeBegin'] + 60; // add one minute to cfg[timeBegin]
    }

    else if ( this.resumed && ( moment().unix() - this.lastRun < 60 ) ) { // resumed and less than 60 seconds have elapsed since last run
      winston.debug('onConnectionFromWorker(): Resumed collection and less than 60 seconds since last run');
      cfg['timeBegin'] = this.lastQueryEndTime + 1; // one second after the last run
      let secondsSinceLastRun = moment().unix() - this.lastRun;
      cfg['timeEnd'] = cfg['timeBegin'] + secondsSinceLastRun;
    }

    else if ( this.resumed && ( moment().unix() - this.lastRun >= 60 ) ) { // resumed and 60 seconds or more have elapsed since last run
      winston.debug('onConnectionFromWorker(): Resumed collection and greater than 60 seconds since last run');
      cfg['timeBegin'] = this.lastQueryEndTime + 1; // one second after the last run
      cfg['timeEnd'] = moment().startOf('minute').unix() - 1 - queryDelaySeconds;
    }
    
    this.resumed = false;

    let momBegin = moment.utc(cfg['timeBegin'] * 1000);
    winston.debug('The time of timeBegin is:', momBegin.format('YYYY-MMMM-DD HH:mm:ss') );

    let momEnd = moment.utc(cfg['timeEnd'] * 1000);
    winston.debug('The time of timeEnd is:', momEnd.format('YYYY-MMMM-DD HH:mm:ss') );
    
    this.lastRun = moment.utc().unix();
    this.lastQueryEndTime = cfg['timeEnd']; // store the time of last run so that we can reference it the next time we loop


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
      let nwserver = this.afbconfig.nwservers[this.collection.nwserver];
      for (let k in nwserver) {
        if (nwserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
          cfg[k] = nwserver[k];  // assign properties of nwserver to the collection cfg
        }
      }
    }
    if (this.collection.serviceType == 'sa') {
      let saserver = this.afbconfig.saservers[this.collection.saserver];
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
    
    // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
    this.sendToWorker(outerCfg, workerSocket);
    
  }



  calculateSessionsToPurge() {

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
      let maxTime = this.lastQueryEndTime - this.collection.lastHours * 60 * 60;
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
        this.sendToRoom('purge', sessionsToPurge);
        this.sendToHttpClients(update);
      }
      
    }
  }



  purgeSessions(sessionsToPurge) {
    // winston.debug('purgeSessions(): sessionsToPurge.length: ', sessionsToPurge.length)
    winston.debug('RollingCollectionManager: purgeSessions(): ' + sessionsToPurge);

    while (sessionsToPurge.length > 0) {
      let sessionToPurge = sessionsToPurge.shift(); // a session ID
      // winston.debug('purgeSessions(): purge for session', sessionToPurge);
  
      for (let i = this.sessions.length - 1; i != -1 ; i--) {
        // Remove purged sessions from this.sessions
        let session = this.sessions[i];
        if (session.id == sessionToPurge) {
          // winston.debug('purgeSessions(): purging session', session.id);
          this.sessions.splice(i, 1);
          break;
        }
      }
  
      for (let i = this.search.length - 1; i != -1; i--) {
        // Identify search items to purge from this.search
        let search = this.search[i];
        if (search.session == sessionToPurge) {
          winston.debug('purgeSessions(): purging search', search.session);
          this.search.splice(i, 1);
        }
      }
      
      for (let i = this.content.length - 1; i != -1; i--) {
        // Purge content
        let content = this.content[i];
        if (content.session == sessionToPurge) {
          winston.debug('purgeSessions(): purging content', content.session);
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

    }
  }


  
  onDataFromWorker(data, chunk, runNumber) {
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
        this.sendToRoom('state', update.state);
        this.sendToHttpClients( { collection: { id: this.collectionId, state: update.state } } );
      }
      else {
        this.sendToRoom('update', update);
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
