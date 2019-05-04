class FixedCollectionHandler {

  // The purpose of this class is to manage connections to API requests for fixed collections

  constructor(afbconfig, feederSocketFile, channel) {

    this.afbconfig = afbconfig;
    this.feederSocketFile = feederSocketFile;
    this.collectionManagers = {};

    // socket.io
    this.channel = channel; // channel is the /collections socket.io namespace
    this.channel.on('connection', (socket) => this.onChannelConnect(socket) );

    this.roomSockets = {}; // tracks which sockets are joined to which rooms
  }



  onChannelConnect(socket) {
    winston.debug('FixedCollectionHandler: onChannelConnect()');
    if (!('jwtuser' in socket.conn)) {
      // socket is not authenticated - disconnect it
      socket.disconnect(false);
      return;
    }
    // start listening for messages from a client after it has connected
    socket.on('joinFixed', (collectionId) => this.onSocketJoinCollection(socket, collectionId) );
    socket.on('leaveFixed', (id) => this.onLeaveCollection(socket) );
    socket.on('disconnect', () => this.onChannelDisconnect(socket) );
  }



  onSocketJoinCollection(socket, collectionId) {
    // this is the equivalent of onHttpConnection(), but for socket connections
    winston.debug('FixedCollectionHandler: onSocketJoinCollection()');

    socket['collectionId'] = collectionId; // add the collection id to our socket so we can later identify it
    let collection = this.afbconfig.collections[collectionId];
    socket['collectionName'] = collection.name;

    winston.debug('FixedCollectionHandler: onSocketJoinCollection(): collectionId:', collectionId);
    winston.info(`User '${socket.conn.jwtuser.username}' has connected to fixed collection '${collection.name}'`);

    socket.join(collectionId); // this joins a room for collectionId
    if (!(collectionId in this.roomSockets)) {
      this.roomSockets[collectionId] = [];
    }
    this.roomSockets[collectionId].push(socket);

    // here's where we want to decide if collection is complete (so return it)...
    // or if we need to build it
    if (this.afbconfig.collections[collectionId].state === 'initial' || this.afbconfig.collections[collectionId].state === 'building' || this.afbconfig.collections[collectionId].state === 'error') {
      winston.debug('FixedCollectionHandler: onSocketJoinCollection(): joining a collection manager');
      // build the collection or join the building collection
      
      // winston.debug('FixedCollectionHandler: onSocketJoinCollection(): this socket is in rooms:', socket.rooms);

      if (!license.valid && !this.afbconfig.collections[collectionId]['state'] == 'building') {
        winston.info(`License is invalid.  Aborting attempt to build fixed collection '${collection.name}'`);
        return;
      }
  
      let fixedCollectionManager = null;
      if ( !(collectionId in this.collectionManagers)) {
        // there is no FixedCollectionManager yet for the chosen collection.  So create one
        fixedCollectionManager = new FixedCollectionManager(this, collection, collectionId);
        this.collectionManagers[collectionId] = fixedCollectionManager;
      }
      else {
        // there's already a manager for the chosen collection
        fixedCollectionManager = this.collectionManagers[collectionId]
      }  
      fixedCollectionManager.addSocketClient(socket);

    }

    else {
      winston.debug('FixedCollectionHandler: onSocketJoinCollection(): playing back complete collection');
      // play back the complete collection
      let collectionsData = this.afbconfig.collectionsData[collectionId]
      // winston.debug('collectionsData:', collectionsData);

      socket.emit('sessions', collectionsData.sessions );

      // play back images
      socket.emit('content', collectionsData.images);

      // Play back search text
      socket.emit('searches', collectionsData.search);
    }
  }



  onLeaveCollection(socket) {
    // when a socket disconnects gracefully or when the collection is done building through its handler.removeFixedCollectionManager
    winston.debug('FixedCollectionHandler: onLeaveCollection()');

    if (!('collectionId' in socket)) {
      return;
    }

    let collectionId = socket['collectionId'];
    let socketId = socket.id;

    if (collectionId in socket.rooms) {
      socket.leave(collectionId);
      winston.info(`A user has disconnected from fixed collection '${socket.collectionName}'`)
      delete socket['collectionId'];
      delete socket['collectionName'];
    }

    if (collectionId in this.roomSockets) {
      for (let i = 0; i < this.roomSockets[collectionId].length; i++) {
        // remove this socket from the room to client mapping
        let sock = this.roomSockets[collectionId][i];
        if (sock.id === socket.id) {
          this.roomSockets[collectionId].splice(i, 1);
          break;
        }
      }
    }
  
    if ( collectionId in this.collectionManagers ) {
      let manager = this.collectionManagers[collectionId];
      manager.removeSocketClient();
    }
  }



  onChannelDisconnect(socket) {
    // when a socket disconnects - either ungracefully or when the user has logged out
    winston.debug('FixedCollectionHandler: onChannelDisconnect()');

    if (!('collectionId' in socket)) {
      return;
    }

    let collectionId = socket['collectionId'];
    winston.debug('FixedCollectionHandler: onChannelDisconnect(): matched collectionId:', collectionId);

    if (collectionId in this.afbconfig.collections) {
      winston.info(`A user has disconnected from fixed collection '${this.afbconfig.collections[collectionId].name}'`);
    }
    else {
      winston.info(`A user has disconnected from fixed collections`);
    }

    if (collectionId in socket.rooms) {
      socket.leave(collectionId);  
    }

    if ( collectionId in this.collectionManagers ) {
      let manager = this.collectionManagers[collectionId];
      manager.removeSocketClient();
    }
  }



  async removeFixedCollectionManager(id) {
    winston.debug('FixedCollectionHandler: removeFixedCollectionManager()');
    delete this.collectionManagers[id];
    // disconnect all client sockets from this collection's room
    if (!(id in this.roomSockets)) {
      throw('No sockets could be found for fixed collection', id);
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
  

  
  onHttpConnection(req, res) {
    // Builds and streams a fixec collection back to the client.  Handles the client connection and kicks off the process
    
    let collectionId = req.params.id;
    let collection = this.afbconfig.collections[collectionId];
    
    winston.debug('FixedCollectionHandler: onHttpConnection(): collectionId:', collectionId);
    winston.info(`User '${req.user.username}' has connected to fixed collection '${collection.name}'`);
    
    // create a client connection handler for this connection
    // does a manager for the requested collection exist?
    // if not, create a new collection manager
    // add new or existing collection manager to the client connection handler
    
    let clientConnection = new FixedHttpConnection(this, collectionId, req, res);
    if ( !clientConnection.onConnect(collection) ) {
      return;
    }
    
    let fixedCollectionManager = null;
    if ( !(collectionId in this.collectionManagers)) {
      // there is no fixedCollectionManager yet for the chosen collection.  So create one
      fixedCollectionManager = new FixedCollectionManager(this, collection, collectionId);
      this.collectionManagers[collectionId] = fixedCollectionManager;
    }
    else {
      // there's already a manager for the chosen collection
      fixedCollectionManager = this.collectionManagers[collectionId];
    }

    // give the client connection object the collection manager to attach itself to
    clientConnection.addManager(fixedCollectionManager);
    
  }



  collectionDeleted(collectionId, user) {
    // we should only get here if someone deletes a fixed collection...
    // which is in the process of building
    winston.debug('FixedCollectionHandler: collectionDeleted()');
    if (collectionId in this.collectionManagers) {
      let manager = this.collectionManagers[collectionId];
      manager.onCollectionDeleted(user);
    }
  }



  killall() {
    // we should only ever get here during shutdown of the server
    for (let collectionId in this.collectionManagers) {
      if (this.collectionManagers.hasOwnProperty(collectionId)) {
        let manager = this.collectionManagers[collectionId];
        manager.abort();
      }
    }
  }



  updateFeederSocketFile(filename) {
    this.feederSocketFile = filename;
  }

}
  
  
  
  
  
  
  
  
  
  
  
  

  
  

class FixedHttpConnection {

  constructor(handler, collectionId, req, res) {
    this.handler = handler;
    this.afbconfig = this.handler.afbconfig;
    winston.debug('FixedHttpConnection: constructor()');
    this.id = uuidV4();
    this.req = req;
    this.res = res;
    this.collectionId = collectionId;
    this.manager = null;
    this.heartbeatInterval = null;
    this.disconnected = false;
  }



  onConnect(collection) {

    winston.debug('FixedHttpConnection: onConnect():');

    ////////////////////////////////////////////////////
    //////////////////RESPONSE HEADERS//////////////////
    ////////////////////////////////////////////////////
  
    try {
      if (collection.bound && !('usecase' in collection )) {
        throw(`Bound collection ${this.collectionId} does not have a use case defined`);
      }
      if (collection.bound && !(collection.usecase in this.afbconfig.useCases.useCasesObj) ) {
        throw(`Use case ${collection.usecase} in bound collection ${id} is not a valid use case`);
      }
      if (collection.state !== 'complete') {
        this.res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': 'inline' } );
        this.res.write('['); // Open the array so that oboe can see it
      }
      else {
        throw(`Collection ${this.collectionId} is in a complete state.  We really shouldn't have got here`);
      }
    }
    catch (e) {
      winston.error(`FixedHttpConnection: onConnect():`, e);
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
    winston.debug('FixedHttpConnection: onClientClosedConnection()');
    winston.info(`User '${this.req.user.username}' has disconnected from ${this.afbconfig.collections[this.collectionId].type} collection '${this.afbconfig.collections[this.collectionId].name}'`);
    this.disconnected = true;
    // This block runs when the client disconnects from the session
    // It doesn't run when we end the session ourselves
    
    if (this.heartbeatInterval) {
      // stop sending heartbeats to client
      clearInterval(this.heartbeatInterval);
    }
    
    this.manager.removeHttpClient(this.id);

    // we will allow a collection to continue building even after clients have disconnected from it
  }



  addManager(manager) {
    winston.debug('FixedHttpConnection: addManager()');
    this.manager = manager;
    this.manager.addHttpClient(this.id, this);
  }



  send(data) {
    // winston.debug('FixedHttpConnection: send()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( JSON.stringify(data) + ',');
    }
  }


  
  sendRaw(data) {
    winston.debug('FixedHttpConnection: sendRaw()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( data );
    }
  }



  end() {
    winston.debug('FixedHttpConnection: end()');
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














class FixedCollectionManager {

  constructor(handler, collection, collectionId) {
    winston.debug('FixedCollectionManager: constructor()');
    this.handler = handler;
    this.afbconfig = this.handler.afbconfig;
    this.httpClients = {}; // holds http clients
    this.workerSocket = null; // used for communication with worker
    this.workerProcess = null; // the handle for the worker process
    this.channel = this.handler.channel; // channel is the /collections socket.io namespace (and all clients connected to it)
    this.observers = 0; // tracks how many clients are connected to this collection
    this.collection = collection;
    this.collectionId = collectionId;
    this.sessions = [];
    this.content = [];
    this.search = [];
    this.hasRun = false;
  }



  run() {
    winston.debug('FixedCollectionManager: run()');
    this.buildFixedCollection();
  }



  addHttpClient(id, client) {
    winston.debug('FixedCollectionManager: addHttpClient()');
    this.httpClients[id] = client;
    this.observers += 1;
    
    if (!this.hasRun) {
      this.run();
    }
    
    if (this.hasRun) {
      winston.debug(`This is not the first client connected to fixed collection ${this.collectionId}.  Playing back existing collection`);

      // client.send( { collection: { id: this.collectionId, state: 'building' } } );

      let sessions = {};
      for (let i = 0; i < this.sessions.length; i++) {
        // Play back sessions
        // We must do it this way because the client expects an object
        // we store sessions internally as an array of objects
        let session = this.sessions[i];
        sessions[session.id] = session;
      }

      client.send( { wholeCollection: { images: this.content, sessions: sessions, search: this.search } } );

    }

  }



  addSocketClient(socket) {
    winston.debug('FixedCollectionManager: addSocketClient()');
    this.observers += 1;
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = null;
    }

    if (!this.hasRun) {
      this.run();
    }
    
    if (this.hasRun) {
      winston.debug(`This is not the first client connected to fixed collection ${this.collectionId}.  Playing back existing collection`);
      let resp = null;

      // client.send( { collection: { id: this.collectionId, state: 'building' } } );
      // socket.emit('state', this.collection['state']);

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

    }

  }



  onCollectionDeleted(user) {
    winston.debug('FixedCollectionManager: onCollectionDeleted()');
    // stop any running workers
    this.killWorker();
    this.sendToHttpClients( { collectionDeleted: this.collectionId, user: user } );
    this.endHttpClients();
    // this is handled for IO clients in the outer express collection delete method
    this.handler.removeFixedCollectionManager(this.collectionId); // this is necessary as onWorkerExit won't trigger after killall()
  }



  async abort() {
    // we should only ever get here during shutdown of the server
    winston.debug('FixedCollectionManager: abort()');
    this.killWorker();
    this.endHttpClients();
    this.handler.removeFixedCollectionManager(this.collectionId);
  }



  killWorker() {
    if (this.workerSocket) {
      this.workerSocket.removeAllListeners();
      this.workerSocket = null;
    }

    if (this.workerProcess){
      this.workerProcess.removeAllListeners(); // prevents collection state from getting written and to prevent the collection from getting saved in onWorkerExit()
      this.workerProcess.kill('SIGINT');
      this.workerProcess = null;
    }
  }




  removeHttpClient(id) {
    winston.debug('FixedCollectionManager: removeHttpClient()');
    this.observers -= 1;
    if (this.observers != 0) {
      winston.debug("Client disconnected from fixed collection with collectionId", this.collectionId);
    }
    delete this.httpClients[id];
  }



  removeSocketClient() {
    winston.debug('FixedCollectionManager: removeSocketClient()');
    this.observers -= 1;
    if (this.observers != 0) {
      winston.debug("FixedCollectionManager: removeSocketClient(): Socket client disconnected from collection with collectionId", this.collectionId);
    }
  }



  sendToWorker(data) {
    winston.debug('FixedCollectionManager: sendToWorker()');
    this.workerSocket.write( JSON.stringify(data) + '\n' );
  }



  sendToHttpClients(data) {
    // winston.debug('FixedCollectionManager: sendToHttpClients()');
    for (let id in this.httpClients) {
      if (this.httpClients.hasOwnProperty(id)) {
        let client = this.httpClients[id];
        client.send(data);
      }
    }
  }



  sendToHttpClientsRaw(data) {
    winston.debug('FixedCollectionManager: sendToHttpClientsRaw()');
    for (let id in this.httpClients) {
      if (this.httpClients.hasOwnProperty(id)) {
        let client = this.httpClients[id];
        client.sendRaw(data);
      }
    }
  }



  sendToRoom(type, data) {
    if (this.channel) {
      this.channel.to(this.collectionId).emit( type, data );
    }
  }



  endHttpClients() {
    winston.debug('FixedCollectionManager: endHttpClients()');
    for (let id in this.httpClients) {
      if (this.httpClients.hasOwnProperty(id)) {
        let client = this.httpClients[id];
        client.end();
      }
    }
  } 



  buildFixedCollection() {
    // Main body of worker execution
    winston.debug('FixedCollectionManager: buildFixedCollection()');

    try {
    
      var tempName = temp.path({suffix: '.socket'});
      
      // Open a UNIX domain socket for the worker to connect back to
      var socketServer = net.createServer( (socket) => {
        this.workerSocket = socket;
        this.onConnectionFromWorker(tempName); });
        socketServer.close();

      socketServer.listen(tempName, () => {
        winston.debug('Listening for worker communication');
        winston.debug("Spawning worker with socket file " + tempName);
        
        // Start the worker process.  It won't do anything until we send it a config
        this.workerProcess = spawn('./worker/worker_stub.py', [tempName], { shell: false, stdio: 'inherit' });
        
        this.workerProcess.on('exit', (code) => this.onWorkerExit(code, tempName) );

      });
    }
    catch(e) {
      winston.error("buildFixedCollection(): Caught error:", e);
    }
     
  }




  async onWorkerExit(code, tempName) {
    if (!code || code === 0) {
      winston.debug('Worker process exited normally with exit code 0');
      this.collection['state'] = 'complete'; 
    }
    else {
      winston.debug('Worker process exited abnormally with exit code',code);
      this.collection['state'] = 'error';
    }
    if (this.collectionId in this.afbconfig.collectionsData) { // if statement needed in case the collection has been deleted whilst still building
      winston.debug('Merging temporary collection into permanent collection');
      // updates the collectionsData with the final content, search, and sessions
      // no need to tell clients as they will have already received all content updates
      let sessions = {};
      for (let e in this.sessions) {
        let s = this.sessions[e];
        let sid = s.id;
        sessions[sid] = s;
      }
      let update = { id: this.collectionId, images: this.content, search: this.search, sessions: sessions};
      await this.afbconfig.addCollectionsData(update);
    }
    winston.debug('Temporary collection merged into main branch');
    await fs.promises.unlink(tempName);
    this.sendToRoom('state', this.collection['state']);
    this.sendToHttpClients( { collection: { id: this.collectionId, state: this.collection['state'] } } );
    this.endHttpClients();
    await this.afbconfig.saveFixedCollection(this.collectionId, this.collection); // saves the collection state
    this.handler.removeFixedCollectionManager(this.collectionId); // time to die - causes this class instance to be deleted and the collection will then be served from afbconfig
  }

  


  onConnectionFromWorker(tempName) {
    // This is called when the worker connects back to us through the UNIX socket
    // Its purpose is to build a configuration for the worker and send it
    // Once the config has been sent, the worker will do its magic and send results back here

    this.hasRun = true;
  
    winston.debug("onConnectionFromWorker(): Connection received from worker to build collection", this.collectionId);
    
    //////////////////////////////////
    //Build the worker configuration//
    //////////////////////////////////
  
    let cfg = { 
      id: this.collectionId,
      collectionId: this.collectionId, // we include this to disambiguate a difference in monitoring collections between id and collectionId
      state: 'building',
      timeBegin: this.collection.timeBegin,
      timeEnd: this.collection.timeEnd,
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
      if (this.collection.serviceType == 'nw') {
        cfg['summaryTimeout'] = this.afbconfig.preferences.nw.summaryTimeout;
        cfg['queryTimeout'] = this.afbconfig.preferences.nw.queryTimeout;
        cfg['contentTimeout'] = this.afbconfig.preferences.nw.contentTimeout;
        cfg['maxContentErrors'] = this.afbconfig.preferences.nw.maxContentErrors;
        cfg['sessionLimit'] = this.afbconfig.preferences.nw.sessionLimit;
      }
    
      if (this.collection.serviceType == 'sa') {
        cfg['queryTimeout'] = this.afbconfig.preferences.sa.queryTimeout;
        cfg['contentTimeout'] = this.afbconfig.preferences.sa.contentTimeout;
        cfg['maxContentErrors'] = this.afbconfig.preferences.sa.maxContentErrors;
        cfg['sessionLimit'] = this.afbconfig.preferences.sa.sessionLimit;
      }
    }
    catch(error) {
      /*
      On 3/24/19, the server crashed with this when connecting to a NW rolling collection.  Could not reproduce:
      2019-03-24 09:01:13,210 afb_server    DEBUG      onConnectionFromWorker(): Connection received from worker to build collection 93c443b9-0859-58a7-9a8f-d212c5da1783
      TypeError: Cannot read property 'summaryTimeout' of undefined
          at FixedCollectionManager.onConnectionFromWorker (/Users/tunderhay/src/afb-server/fixed-collections.js:701:55)
          at Server.net.createServer (/Users/tunderhay/src/afb-server/fixed-collections.js:620:14)
          at Server.emit (events.js:197:13)
          at Pipe.onconnection (net.js:1501:8)


      */
      winston.error('Caught error trying to read preferences.  Exiting with code 1');
      process.exit(1);
    }
  
    if (this.collection.bound) {
      // This is an OOTB use case
      let useCaseName = this.collection.usecase;
      let useCase = this.afbconfig.useCases.useCasesObj[useCaseName];
      cfg['query'] = useCase.query;
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
      // This is a custom use case, not an OOTB use case
  
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
  
    if (this.collection.serviceType == 'nw') {
      let nwserver = this.afbconfig.nwservers[this.collection.nwserver];
      for (var k in nwserver) {
  
        if (nwserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
          cfg[k] = nwserver[k];  // assign properties of nwserver to the collection cfg
        }
      }
    }
    if (this.collection.serviceType == 'sa') {
      let saserver = this.afbconfig.saservers[this.collection.saserver];
      for (var k in saserver) {
        if (saserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
          cfg[k] = saserver[k];  // assign properties of saserver to the collection cfg
        }
      }
    }
  
    let outerCfg = { workerConfig: cfg };
  
    
  
    ////////////////////////
    //DEAL WITH THE SOCKET//
    ////////////////////////
  
    // Tell our subscribers that we're building, so they can start their spinny icon
    this.collection['state'] = 'building';
    this.sendToRoom('state', this.collection['state']);
    this.sendToHttpClients( { collection: { id: this.collectionId, state: this.collection['state']} } );
  
    // Buffer for worker data
    var data = '';
    
    // Set socket options
    this.workerSocket.setEncoding('utf8');
  
    // Handle data sent from the worker via the UNIX socket (collection results)
    this.workerSocket.on('data', chunk => data = this.onDataFromWorker(data, chunk) );
    
    // Now that we've finished building the new collection, emit a finished signal, and merge the new collection into the this.cfg.collectionsData object, and delete the object from buildingFixedCollections
                            
    // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
    this.sendToWorker(outerCfg);
    
  }



  onDataFromWorker(data, chunk) {
    // Handles socket data received from the worker process
    // This actually builds the collection data structures and sends updates to the client
    // winston.debug('FixedCollectionManager: onDataFromWorker(): Processing update from worker');
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
          this.content.push(update.collectionUpdate.images[i]);
        }
      }
      
      this.sendToRoom('update', update);
      this.sendToHttpClients(update);
    }

    return data;
  }


}


module.exports = FixedCollectionHandler;