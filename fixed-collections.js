const temp = require('temp');
const uuidV4 = require('uuid/v4');
const net = require('net'); //for unix sockets
const spawn = require('child_process').spawn;
const moment = require('moment');
const fs = require('fs');



class FixedCollectionHandler {

  // The purpose of this class is to manage connections to API requests for fixed collections

  constructor(dbUpdateCallback, winston, collections, collectionsData, collectionsDir, feeds, feederSocketFile, gsPath, pdftotextPath, sofficePath, sofficeProfilesDir, unrarPath, internalPrivateKeyFile, useCasesObj, preferences, nwservers, saservers, collectionsUrl, channel) {

    this.cfg = {
      winston: winston,
      collections: collections,
      feeds: feeds,
      feederSocketFile: feederSocketFile,
      collectionsData: collectionsData,
      collectionsDir: collectionsDir,
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
    this.winston = winston;

    this.collectionManagers = {};
    this.dbUpdateCallback = dbUpdateCallback;

    // socket.io
    this.channel = channel;
    this.channel.on('connection', (socket) => this.onChannelConnect(socket) );
  }



  onChannelConnect(socket) {
    this.winston.debug('FixedCollectionHandler: onChannelConnect()');
    socket.on('joinFixed', (data) => this.onJoinCollection(socket, data) );
    socket.on('leaveFixed', (id) => this.onLeaveCollection(socket) );
    socket.on('disconnect', () => this.onChannelDisconnect(socket) );
  }



  onJoinCollection(socket, collectionId) {
    // this is the equivalent of onHttpConnection(), but for socket connections
    this.winston.debug('FixedCollectionHandler: onJoinCollection()');

    socket['collectionId'] = collectionId; // add the collection id to our socket so we can later identify it
    let collection = this.cfg.collections[collectionId];

    this.winston.info('FixedCollectionHandler: onJoinCollection(): collectionId:', collectionId);

    socket.join(collectionId); // this joins a room for collectionId

    // here's where we want to decide if collection is complete (so return it)...
    // or if we need to build it
    if (this.cfg.collections[collectionId]['state'] == 'initial' || this.cfg.collections[collectionId]['state'] == 'building' || this.cfg.collections[collectionId]['state'] == 'error') {
      this.winston.debug('FixedCollectionHandler: onJoinCollection(): joining a collection manager');
      // build the collection or join the building collection
      
      // this.winston.debug('FixedCollectionHandler: onJoinCollection(): this socket is in rooms:', socket.rooms);
  
      let fixedCollectionManager = null;
      if ( !(collectionId in this.collectionManagers)) {
        // there is no FixedCollectionManager yet for the chosen collection.  So create one
        fixedCollectionManager = new FixedCollectionManager(collection, collectionId, (id) => this.fixedCollectionManagerRemovalCallback(id), this.dbUpdateCallback, this.cfg, this.channel);
        this.collectionManagers[collectionId] = fixedCollectionManager;
      }
      else {
        // there's already a manager for the chosen collection
        fixedCollectionManager = this.collectionManagers[collectionId]
      }  
      fixedCollectionManager.addSocketClient(socket);

    }

    else {
      this.winston.debug('FixedCollectionHandler: onJoinCollection(): playing back complete collection');
      // play back the complete collection
      let collectionsData = this.cfg.collectionsData[collectionId]
      // this.winston.debug('collectionsData:', collectionsData);

      socket.emit('sessions', collectionsData.sessions );

      // play back images
      socket.emit('content', collectionsData.images);

      // Play back search text
      socket.emit('searches', collectionsData.search);

    }

  }



  onLeaveCollection(socket) {
    // when a socket disconnects gracefully
    this.winston.debug('FixedCollectionHandler: onLeaveCollection()');

    let collectionId = socket['collectionId'];
    delete socket['collectionId'];

    if (collectionId in socket.rooms) {
      socket.leave(collectionId);  
    }
  
    if ( collectionId in this.collectionManagers ) {
      let manager = this.collectionManagers[collectionId];
      manager.removeSocketClient();
    }

  }



  onChannelDisconnect(socket) {
    // when a socket disconnects un-gracefully
    this.winston.debug('FixedCollectionHandler: onChannelDisconnect()');

    if ('collectionId' in socket) {
      let collectionId = socket['collectionId'];
      this.winston.debug('FixedCollectionHandler: onChannelDisconnect(): matched collectionId:', collectionId);
  
      if (collectionId in socket.rooms) {
        socket.leave(collectionId);  
      }

      if ( collectionId in this.collectionManagers ) {
        let manager = this.collectionManagers[collectionId];
        manager.removeSocketClient();
      }
    }

  }
  

  
  onHttpConnection(req, res) {
    // Builds and streams a fixec collection back to the client.  Handles the client connection and kicks off the process
    
    let collectionId = req.params.id;
    let collection = this.cfg.collections[collectionId];
    
    this.winston.info('FixedCollectionHandler: onHttpConnection(): collectionId:', collectionId);
    
    // create a client connection handler for this connection
    // does a manager for the requested collection exist?
    // if not, create a new collection manager
    // add new or existing collection manager to the client connection handler
    
    let clientConnection = new HttpConnection(req, res, collectionId, this.cfg);
    if ( !clientConnection.onConnect(collection) ) {
      return;
    }
    
    let fixedCollectionManager = null;
    if ( !(collectionId in this.collectionManagers)) {
      // there is no fixedCollectionManager yet for the chosen collection.  So create one
      fixedCollectionManager = new FixedCollectionManager(collection, collectionId, () => this.fixedCollectionManagerRemovalCallback, this.dbUpdateCallback, this.cfg);
      this.collectionManagers[collectionId] = fixedCollectionManager;
    }
    else {
      // there's already a manager for the chosen collection
      fixedCollectionManager = this.collectionManagers[collectionId];
    }

    // give the client connection object the collection manager to attach itself to
    clientConnection.addManager(fixedCollectionManager);
    
  }
  

  
  fixedCollectionManagerRemovalCallback(id) {
    this.winston.debug('FixedCollectionHandler: fixedCollectionManagerRemovalCallback()');
    delete this.collectionManagers[id];
  }



  abortBuildingCollection(collectionId) {
    let collectionManager = this.collectionManagers[collectionId];
    this.collectionManager.abort();
  }



  collectionDeleted(collectionId, user) {
    // we should only get here if someone deletes a fixed collection...
    // which is in the process of building
    this.winston.info('FixedCollectionHandler: collectionDeleted()');
    if (collectionId in this.collectionManagers) {
      let manager = this.collectionManagers[collectionId];
      manager.onCollectionDeleted(user);
    }
  }



  killall() {
    for (let collectionId in this.collectionManagers) {
      if (this.collectionManagers.hasOwnProperty(collectionId)) {
        let manager = this.collectionManagers[collectionId];
        manager.abort();
      }
    }
  }



  updateFeederSocketFile(filename) {
    this.cfg.feederSocketFile = filename;
  }

}
  
  
  
  
  
  
  
  
  
  
  
  

  
  

class HttpConnection {

  constructor(req, res, collectionId, cfg) {
    this.cfg = cfg;
    this.winston = this.cfg.winston;
    this.winston.info('HttpConnection: constructor()');
    this.id = uuidV4();
    this.req = req;
    this.res = res;
    this.collectionId = collectionId;
    this.manager = null;
    this.heartbeatInterval = null;
    this.disconnected = false;
  }



  onConnect(collection) {

    this.winston.info('HttpConnection: onConnect():');
    this.winston.debug('got to 0');

    ////////////////////////////////////////////////////
    //////////////////RESPONSE HEADERS//////////////////
    ////////////////////////////////////////////////////
  
    try {
      if (collection.bound && !('usecase' in collection )) {
        throw(`Bound collection ${this.collectionId} does not have a use case defined`);
      }
      if (collection.bound && !(collection.usecase in this.cfg.useCasesObj) ) {
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
      this.winston.error(`HttpConnection: onConnect():`, e);
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
    this.winston.info('HttpConnection: onClientClosedConnection()');
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
    this.winston.info('HttpConnection: addManager()');
    this.manager = manager;
    this.manager.addClient(this.id, this);
  }



  send(data) {
    // this.winston.info('HttpConnection: send()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( JSON.stringify(data) + ',');
    }
  }


  
  sendRaw(data) {
    this.winston.info('HttpConnection: sendRaw()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( data );
    }
  }



  end() {
    this.winston.info('HttpConnection: end()');
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

  constructor(collection, collectionId, removalCallback, dbUpdateCallback, cfg, channel = null) {
    this.cfg = cfg;
    this.winston = this.cfg.winston;

    this.winston.info('FixedCollectionManager: constructor()');
    this.clients = {};
    this.socket = null;
    this.removalCallback = removalCallback;
    this.dbUpdateCallback = dbUpdateCallback;
    this.collection = collection;
    this.collectionId = collectionId;
    this.observers = 0;
    this.workerProcess = null;
    this.sessions = [];
    this.content = [];
    this.search = [];
    this.hasRun = false;
    this.channel = channel;
  }



  run() {
    this.winston.info('FixedCollectionManager: run()');
    this.buildFixedCollection();
  }



  addClient(id, client) {
    this.winston.info('FixedCollectionManager: addClient()');
    this.clients[id] = client;
    this.observers += 1;
    
    if (!this.hasRun) {
      this.run();
    }
    
    if (this.hasRun) {
      this.winston.info(`This is not the first client connected to fixed collection ${this.collectionId}.  Playing back existing collection`);

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
    this.winston.info('FixedCollectionManager: addClient()');
    this.observers += 1;
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = null;
    }

    if (!this.hasRun) {
      this.run();
    }
    
    if (this.hasRun) {
      this.winston.info(`This is not the first client connected to fixed collection ${this.collectionId}.  Playing back existing collection`);
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
    this.winston.debug('FixedCollectionManager: onCollectionDeleted()');
    this.destroyed = true;
    
    // stop any running workers
    this.killWorker();
    
    this.sendToChannel('deleted', user);
    this.sendToHttpClients( { collectionDeleted: this.collectionId, user: user } );
    this.endClients();

    this.removalCallback(this.collectionId);
  }



  abort() {
    this.winston.info('FixedCollectionManager: abort()');

    try {
      this.winston.debug("Deleting output directory for collection", this.collectionId);
      rimraf.sync( this.cfg.collectionsDir + '/' + this.collectionId ); // Delete output directory
    }
    catch(exception) {
      this.winston.error('ERROR deleting output directory ' + this.cfg.collectionsDir + '/' + this.collectionId, exception);
    }

    this.killWorker();

    // this.sendToChannel('clear', true);
    // this.sendToHttpClients( { collectionDeleted: this.collectionId } );
    this.endClients();
    // this.removalCallback(this.collectionId);
  }



  killWorker() {

    if (this.socket) {
      this.socket.removeAllListeners();
      this.socket = null;
    }

    if (this.workerProcess){
      this.workerProcess.removeAllListeners(); // not sure whether we need this or not - probably do
      this.workerProcess.kill('SIGINT');
      this.workerProcess = null;
    }
  }




  removeHttpClient(id) {
    this.winston.info('FixedCollectionManager: removeHttpClient()');
    this.observers -= 1;
    if (this.observers != 0) {
      this.winston.debug("Client disconnected from fixed collection with collectionId", this.collectionId);
    }
    delete this.clients[id];
  }



  removeSocketClient() {
    this.winston.info('FixedCollectionManager: removeSocketClient()');
    this.observers -= 1;
    if (this.observers != 0) {
      this.winston.debug("FixedCollectionManager: removeSocketClient(): Socket client disconnected from collection with collectionId", this.collectionId);
    }
  }



  sendToWorker(data) {
    this.winston.info('FixedCollectionManager: sendToWorker()');
    this.socket.write( JSON.stringify(data) + '\n' );
  }



  sendToHttpClients(data) {
    // this.winston.info('FixedCollectionManager: sendToHttpClients()');
    for (let id in this.clients) {
      if (this.clients.hasOwnProperty(id)) {
        let client = this.clients[id];
        client.send(data);
      }
    }
  }



  sendToHttpClientsRaw(data) {
    this.winston.info('FixedCollectionManager: sendToHttpClientsRaw()');
    for (let id in this.clients) {
      if (this.clients.hasOwnProperty(id)) {
        let client = this.clients[id];
        client.sendRaw(data);
      }
    }
  }



  sendToChannel(type, data) {
    if (this.channel) {
      this.channel.to(this.collectionId).emit( type, data );
    }
  }



  endClients() {
    this.winston.info('FixedCollectionManager: endClients()');
    for (let id in this.clients) {
      if (this.clients.hasOwnProperty(id)) {
        let client = this.clients[id];
        client.end();
      }
    }
  }



  buildFixedCollection() {
    // Main body of worker execution
    this.winston.info('FixedCollectionManager: buildFixedCollection()');

    try {
    
      var tempName = temp.path({suffix: '.socket'});
      
      // Open a UNIX domain socket for the worker to connect back to
      var socketServer = net.createServer( (socket) => {
        this.socket = socket;
        this.onConnectionFromWorker(tempName); });
        socketServer.close();

      socketServer.listen(tempName, () => {
        this.winston.debug('Listening for worker communication');
        this.winston.debug("Spawning worker with socket file " + tempName);
        
        // Start the worker process.  It won't do anything until we send it a config
        this.workerProcess = spawn('./worker_stub.py', [tempName], { shell: false, stdio: 'inherit' });
        
        this.workerProcess.on('exit', (code) => this.onWorkerExit(code) );

      });
    }
    catch(e) {
      this.winston.error("buildFixedCollection(): Caught error:", e);
    }
     
  }



  onWorkerExit(code) {
    if (!code) {
      this.winston.debug('Worker process exited abnormally without an exit code');
      this.collection['state'] = 'error';
    }
    else if (code !== 0) {
      this.winston.debug('Worker process exited abnormally with exit code',code);
      this.collection['state'] = 'error';
    }
    else {
      this.winston.debug('Worker process exited normally with exit code', code);
      this.collection['state'] = 'complete';
      
    }
    this.sendToChannel('state', this.collection['state']);
    this.sendToHttpClients( { collection: { id: this.collectionId, state: this.collection['state'] } } );

    this.dbUpdateCallback(this.collectionId, this.collection);
    this.endClients();
  }

  


  onConnectionFromWorker(tempName) {
    // This is called when the worker connects back to us through the UNIX socket
    // Its purpose is to build a configuration for the worker and send it
    // Once the config has been sent, the worker will do its magic and send results back here

    this.hasRun = true;
  
    this.winston.info("onConnectionFromWorker(): Connection received from worker to build collection", this.collectionId);
    
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
      gsPath: this.cfg.gsPath,
      pdftotextPath: this.cfg.pdftotextPath,
      sofficePath: this.cfg.sofficePath,
      sofficeProfilesDir: this.cfg.sofficeProfilesDir,
      unrarPath: this.cfg.unrarPath,
      collectionsDir: this.cfg.collectionsDir,
      privateKeyFile: this.cfg.internalPrivateKeyFile,
      useHashFeed: this.collection.useHashFeed,
      serviceType: this.collection.serviceType
    };
  
    if (this.collection.serviceType == 'nw') {
      cfg['summaryTimeout'] = this.cfg.preferences.nw.summaryTimeout;
      cfg['queryTimeout'] = this.cfg.preferences.nw.queryTimeout;
      cfg['contentTimeout'] = this.cfg.preferences.nw.contentTimeout;
      cfg['maxContentErrors'] = this.cfg.preferences.nw.maxContentErrors;
    }
  
    if (this.collection.serviceType == 'sa') {
      cfg['queryTimeout'] = this.cfg.preferences.sa.queryTimeout;
      cfg['contentTimeout'] = this.cfg.preferences.sa.contentTimeout;
      cfg['maxContentErrors'] = this.cfg.preferences.sa.maxContentErrors;
    }
  
    if (this.collection.bound) {
      // This is an OOTB use case
      let useCaseName = this.collection.usecase;
      let useCase = this.cfg.useCasesObj[useCaseName];
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
        cfg['hashFeed'] = this.cfg.feeds[this.collection.hashFeed] // pass the hash feed definition
        cfg['hashFeederSocket'] = this.cfg.feederSocketFile
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
      let nwserver = this.cfg.nwservers[this.collection.nwserver];
      for (var k in nwserver) {
  
        if (nwserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
          cfg[k] = nwserver[k];  // assign properties of nwserver to the collection cfg
        }
      }
    }
    if (this.collection.serviceType == 'sa') {
      let saserver = this.cfg.saservers[this.collection.saserver];
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
    this.sendToChannel('state', this.collection['state']);
    this.sendToHttpClients( { collection: { id: this.collectionId, state: this.collection['state']} } );
  
    // Buffer for worker data
    var data = '';
    
    // Set socket options
    this.socket.setEncoding('utf8');
  
    // Handle data sent from the worker via the UNIX socket (collection results)
    this.socket.on('data', chunk => data = this.onDataFromWorker(data, chunk) );
    
    // Now that we've finished building the new collection, emit a finished signal, and merge the new collection into the this.cfg.collectionsData object, and delete the object from buildingFixedCollections
    this.socket.on('end', () => this.onWorkerDisconnected(tempName) );
                            
    // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
    this.sendToWorker(outerCfg);
    
  }


  onWorkerDisconnected(tempName) {
    this.winston.debug('Worker has disconnected from the server.  Merging temporary collection into permanent collection');
    if (this.collectionId in this.cfg.collectionsData) { // needed in case the collection has been deleted whilst still building
      this.cfg.collectionsData[this.collectionId].images = this.content;
      this.cfg.collectionsData[this.collectionId].search = this.search;
      for (var e in this.sessions) {
        let s = this.sessions[e];
        let sid = s.id;
        this.cfg.collectionsData[this.collectionId].sessions[sid] = s;
      }
    }
    /*else {
      // just for debugging
      this.winston.debug('!!!Couldn\' find collection in this.cfg.collectionsData!!!');
    }*/
    this.winston.debug('Temporary collection merged into main branch');
    fs.unlink(tempName, () => {} );
    this.removalCallback(this.collectionId); // time to die
  }



  onDataFromWorker(data, chunk) {
    // Handles socket data received from the worker process
    // This actually builds the collection data structures and sends updates to the client
    // this.winston.debug('FixedCollectionManager: onDataFromWorker(): Processing update from worker');
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

        // modify image paths to point to /collections/:collectionId
        for (let i = 0; i < update.collectionUpdate.images.length; i++) {
          
          update.collectionUpdate.images[i].contentFile = this.cfg.collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].contentFile;
          
          if ('proxyContentFile' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].proxyContentFile = this.cfg.collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].proxyContentFile;
          }

          if ('thumbnail' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].thumbnail = this.cfg.collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].thumbnail;
          }
          if ('pdfImage' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].pdfImage = this.cfg.collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].pdfImage;
          }
          if ('archiveFilename' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].archiveFilename = this.cfg.collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].archiveFilename;
          }
          this.content.push(update.collectionUpdate.images[i]);
        }
      }
      
      this.sendToChannel('update', update);
      this.sendToHttpClients(update);
    }

    return data;
  }


}


module.exports = FixedCollectionHandler;