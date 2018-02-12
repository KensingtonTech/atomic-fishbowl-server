const temp = require('temp');
const uuidV4 = require('uuid/v4');
const net = require('net'); //for unix sockets
const spawn = require('child_process').spawn;
const moment = require('moment');
const fs = require('fs');

var winston = null;
var collections = null;
var feederSocketFile = null;
var collectionsDir = null;
var gsPath = null;
var pdftotextPath = null;
var sofficePath = null;
var sofficeProfilesDir = null;
var unrarPath = null;
var internalPrivateKeyFile = null;
var useCasesObj = null;
var preferences = null;
var nwservers = null;
var saservers = null;
var collectionsUrl = null;
var collectionsData = null;

module.exports = class {

  // The purpose of this class is to manage connections to API requests for fixed collections

  constructor(dbUpdateCallback, winstoN, collectionS, collectionsDatA, collectionsDiR, feederSocketFilE, gsPatH, pdftotextPatH, sofficePatH, sofficeProfilesDiR, unrarPatH, internalPrivateKeyFilE, useCasesObJ, preferenceS, nwserverS, saserverS, collectionsUrL) {
    this.collectionManagers = {};
    this.dbUpdateCallback = dbUpdateCallback;
    winston = winstoN;
    collections = collectionS;
    feederSocketFile = feederSocketFilE;
    collectionsDir = collectionsDiR;
    gsPath = gsPatH;
    pdftotextPath = pdftotextPatH;
    sofficePath = sofficePatH;
    sofficeProfilesDir = sofficeProfilesDiR;
    unrarPath = unrarPatH;
    internalPrivateKeyFile = internalPrivateKeyFilE;
    useCasesObj = useCasesObJ;
    preferences = preferenceS;
    nwservers = nwserverS;
    saservers = saserverS;
    collectionsUrl = collectionsUrL;
    collectionsData = collectionsDatA;
  }
  
  
  handleFixedConnection(req, res) {
    // Builds and streams a fixec collection back to the client.  Handles the client connection and kicks off the process
    
    let collectionId = req.params.id;
    let collection = collections[collectionId];
    
    winston.info('handleFixedConnection(): collectionId:', collectionId);
    
    // create a client connection handler for this connection
    // does a manager for the requested rolling collection exist?
    // if not, create a new rolling collection manager
    // add new or existing rolling collection manager to the client connection handler
    
    let clientConnection = new ClientConnection(req, res, collectionId);
    if ( !clientConnection.onConnect(collection) ) {
      return;
    }
    
    let fixedCollectionManager = null;
    if ( !(collectionId in this.collectionManagers)) {
      // there is no fixedCollectionManager yet for the chosen collection.  So create one
      fixedCollectionManager = new FixedCollectionManager(collection, collectionId, () => this.fixedCollectionManagerRemovalCallback, this.dbUpdateCallback);
      this.collectionManagers[collectionId] = fixedCollectionManager;
    }
    else {
      // there's already a manager for the chosen collection
      fixedCollectionManager = this.collectionManagers[collectionId];
    }

    // give the client connection object the rolling collection manager to attach itself to
    clientConnection.addManager(fixedCollectionManager);
    
  }
  

  
  fixedCollectionManagerRemovalCallback(id) {
    winston.info('fixedCollectionManagerRemovalCallback()');
    delete this.collectionManagers[id];
  }



  abortBuildingCollection(collectionId) {
    let collectionManager = this.collectionManagers[collectionId];
    this.collectionManager.abort();
  }



  collectionDeleted(collectionId, user) {
    // we should only get here if someone deletes a fixed collection...
    // which is in the process of building
    winston.info('collectionDeleted()');
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

}
  
  
  
  
  
  
  
  
  
  
  
  

  
  

class ClientConnection {

  constructor(req, res, collectionId) {
    winston.info('ClientConnection: constructor()');
    this.id = uuidV4();
    this.req = req;
    this.res = res;
    this.collectionId = collectionId;
    this.manager = null;
    this.heartbeatInterval = null;
    this.disconnected = false;
  }



  addManager(manager) {
    winston.info('ClientConnection: addManager()');
    this.manager = manager;
    this.manager.addClient(this.id, this);
  }



  send(data) {
    // winston.info('ClientConnection: send()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( JSON.stringify(data) + ',');
      this.res.flush();
    }
  }


  
  sendRaw(data) {
    winston.info('ClientConnection: sendRaw()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( data );
      this.res.flush();
    }
  }



  end() {
    winston.info('ClientConnection: end()');
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

  onConnect(collection) {

    winston.info('ClientConnection: onConnect():');

    ////////////////////////////////////////////////////
    //////////////////RESPONSE HEADERS//////////////////
    ////////////////////////////////////////////////////
  
    try {
      if (collection.bound && !('usecase' in collection )) {
        throw(`Bound collection ${this.collectionId} does not have a use case defined`);
      }
      if (collection.bound && !(collection.usecase in useCasesObj) ) {
        throw(`Use case ${collection.usecase} in bound collection ${id} is not a valid use case`);
      }
      if (collection.state !== 'complete') {
        this.res.writeHead(200, {'Content-Type': 'application/json','Content-Disposition': 'inline' });
        this.res.write('['); // Open the array so that oboe can see it
        this.res.flush();
      }
      else {
        throw(`Collection ${this.collectionId} is in a complete state.  We really shouldn't have got here`);
      }
    }
    catch (e) {
      winston.error(`ClientConnection: onConnect():`, e);
      this.res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
      return false;
    }
  

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////CLIENT DISCONNECT HANDLER///////////////////////
    ///////////////////////////////////////////////////////////////////////
    
    this.req.on('close', () => {
      winston.info('ClientConnection: close()');
      this.disconnected = true;
      // This block runs when the client disconnects from the session
      // It doesn't run when we end the session ourselves
      
      if (this.heartbeatInterval) {
        // stop sending heartbeats to client
        clearInterval(this.heartbeatInterval);
      }
      
      this.manager.removeClient(this.id);

      // we will allow a collection to continue building even after clients have disconnected from it
    });

    this.heartbeatInterval = setInterval( () => {
      this.send( { heartbeat : true } );
    }, 15000 );
    
    return true;

  }

}













class FixedCollectionManager {

  constructor(collection, collectionId, removalCallback, dbUpdateCallback) {
    winston.info('FixedCollectionManager: constructor()');
    this.clients = {};
    this.socket = null;
    this.removalCallback = removalCallback;
    this.dbUpdateCallback = dbUpdateCallback;
    this.collection = collection;
    this.collectionId = collectionId;
    this.observers = 0;
    this.workerProcess = null;
    this.sessions = [];
    this.images = [];
    this.search = [];
    this.hasRun = false;
  }



  run() {
    winston.info('FixedCollectionManager: run()');
    this.buildFixedCollection();
  }



  addClient(id, client) {
    winston.info('FixedCollectionManager: addClient()');
    this.clients[id] = client;
    this.observers += 1;
    
    if (!this.hasRun) {
      this.run();
    }
    
    if (this.hasRun) {
      winston.info(`This is not the first client connected to fixed collection ${this.collectionId}.  Playing back existing collection`);
      let resp = null;

      client.send( { collection: { id: this.collectionId, state: 'building' } } );

      for (let i = 0; i < this.sessions.length; i++) {
        // Play back sessions
        resp = {
          collectionUpdate: {
            session: this.sessions[i]
          }
        };
        client.send(resp);
      }

      // play back images
      resp = {
        collectionUpdate: {
          images: this.images
        }
      };
      client.send(resp);

      resp = {
        // Play back search text
        collectionUpdate: {
          search: this.search
        }
      }
      client.send(resp);

    }

  }



  onCollectionDeleted(user) {
    winston.debug('FixedCollectionManager: onCollectionDeleted()');
    this.destroyed = true;
    
    // stop any running workers
    this.killWorker();
    
    this.sendToClients( { collectionDeleted: this.collectionId, user: user } );
    this.endClients();

    this.removalCallback(this.rollingId);
  }



  abort() {
    winston.info('FixedCollectionManager: abort()');

    try {
      winston.debug("Deleting output directory for collection", this.collectionId);
      rimraf( collectionsDir + '/' + this.collectionId, () => {} ); // Delete output directory
    }
    catch(exception) {
      winston.error('ERROR deleting output directory ' + collectionsDir + '/' + this.collectionId, exception);
    }

    this.killWorker();

    this.sendToClients( { collectionDeleted: this.collectionId } );
    this.endClients();
    this.removalCallback(this.collectionId);
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




  removeClient(id) {
    winston.info('FixedCollectionManager: removeClient()');
    this.observers -= 1;
    if (this.observers != 0) {
      winston.debug("Client disconnected from fixed collection with collectionId", this.collectionId);
    }
    delete this.clients[id];
  }



  sendToWorker(data) {
    winston.info('FixedCollectionManager: sendToWorker()');
    this.socket.write( JSON.stringify(data) + '\n' );
  }



  sendToClients(data) {
    // winston.info('FixedCollectionManager: sendToClients()');
    for (let id in this.clients) {
      if (this.clients.hasOwnProperty(id)) {
        let client = this.clients[id];
        client.send(data);
      }
    }
  }

  sendToClientsRaw(data) {
    winston.info('FixedCollectionManager: sendToClientsRaw()');
    for (let id in this.clients) {
      if (this.clients.hasOwnProperty(id)) {
        let client = this.clients[id];
        client.sendRaw(data);
      }
    }
  }

  endClients() {
    winston.info('FixedCollectionManager: endClients()');
    for (let id in this.clients) {
      if (this.clients.hasOwnProperty(id)) {
        let client = this.clients[id];
        client.end();
      }
    }
  }


  buildFixedCollection() {
    // Main body of worker execution
    winston.info('FixedCollectionManager: buildFixedCollection()');

    try {
      this.collection['state'] = 'building';
      this.sendToClients( { collection: { id: this.collectionId, state: 'building' } } );
    
      var tempName = temp.path({suffix: '.socket'});
      
      // Open a UNIX domain socket for the worker to connect back to
      var socketServer = net.createServer( (socket) => {
        this.socket = socket;
        this.onConnectionFromWorker(tempName); });
        socketServer.close();

      socketServer.listen(tempName, () => {
        winston.debug('Listening for worker communication');
        winston.debug("Spawning worker with socket file " + tempName);
        
        // Start the worker process.  It won't do anything until we send it a config
        this.workerProcess = spawn('./worker_stub.py', [tempName], { shell: false, stdio: 'inherit' });
        
        this.workerProcess.on('exit', (code) => this.onWorkerExit(code) );

      });
    }
    catch(e) {
      winston.error("buildFixedCollection(): Caught error:", e);
    }
     
  }



  onWorkerExit(code) {
    if (typeof code === 'undefined') {
      winston.debug('Worker process exited abnormally without an exit code');
      this.collection['state'] = 'error';
      this.sendToClients( { collection: { id: this.collectionId, state: 'error' } } );
    }
    else if (code != 0) {
      winston.debug('Worker process exited abnormally with exit code',code.toString());
      this.collection['state'] = 'error';
      this.sendToClients( { collection: { id: this.collectionId, state: 'error' } } );
    }
    else {
      winston.debug('Worker process exited normally with exit code', code.toString());
      this.collection['state'] = 'complete';
      this.sendToClients( { collection: { id: this.collectionId, state: 'complete' } } );
    }
    this.dbUpdateCallback(this.collectionId, this.collection);
    this.endClients();
  }

  


  onConnectionFromWorker(tempName) {
    // This is called when the worker connects back to us through the UNIX socket
    // Its purpose is to build a configuration for the worker and send it
    // Once the config has been sent, the worker will do its magic and send results back here

    this.hasRun = true;
  
    winston.info("onConnectionFromWorker(): Connection received from worker to build collection", this.collectionId);
    
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
      gsPath: gsPath,
      pdftotextPath: pdftotextPath,
      sofficePath: sofficePath,
      sofficeProfilesDir: sofficeProfilesDir,
      unrarPath: unrarPath,
      collectionsDir: collectionsDir,
      privateKeyFile: internalPrivateKeyFile,
      useHashFeed: this.collection.useHashFeed,
      serviceType: this.collection.serviceType
    };
  
    if (this.collection.serviceType == 'nw') {
      cfg['summaryTimeout'] = preferences.nw.summaryTimeout;
      cfg['queryTimeout'] = preferences.nw.queryTimeout;
      cfg['contentTimeout'] = preferences.nw.contentTimeout;
      cfg['maxContentErrors'] = preferences.nw.maxContentErrors;
    }
  
    if (this.collection.serviceType == 'sa') {
      cfg['queryTimeout'] = preferences.sa.queryTimeout;
      cfg['contentTimeout'] = preferences.sa.contentTimeout;
      cfg['maxContentErrors'] = preferences.sa.maxContentErrors;
    }
  
    if (this.collection.bound) {
      // This is an OOTB use case
      let useCaseName = this.collection.usecase;
      let useCase = useCasesObj[useCaseName];
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
        cfg['hashFeed'] = feeds[this.collection.hashFeed] // pass the hash feed definition
        cfg['hashFeederSocket'] = feederSocketFile
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
      let nwserver = nwservers[this.collection.nwserver];
      for (var k in nwserver) {
  
        if (nwserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
          cfg[k] = nwserver[k];  // assign properties of nwserver to the collection cfg
        }
      }
    }
    if (this.collection.serviceType == 'sa') {
      let saserver = saservers[this.collection.saserver];
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
    this.sendToClients( { collection: { id: this.collectionId, state: 'building'} } );
  
    // Buffer for worker data
    var data = '';
    
    // Set socket options
    this.socket.setEncoding('utf8');
  
    // Handle data sent from the worker via the UNIX socket (collection results)
    this.socket.on('data', chunk => data = this.onDataFromWorker(data, chunk) );
    
    // Now that we've finished building the new collection, emit a finished signal, and merge the new collection into the collectionsData object, and delete the object from buildingFixedCollections
    this.socket.on('end', () => this.onWorkerDisconnected(tempName) );
                            
    // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
    this.sendToWorker(outerCfg);
    
  }


  onWorkerDisconnected(tempName) {
    winston.debug('Worker has disconnected from the server.  Merging temporary collection into permanent collection');
    if (this.collectionId in collectionsData) { // needed in case the collection has been deleted whilst still building
      collectionsData[this.collectionId].images = this.images;
      collectionsData[this.collectionId].search = this.search;
      for (var e in this.sessions) {
        let s = this.sessions[e];
        let sid = s.id;
        collectionsData[this.collectionId].sessions[sid] = s;
      }
    }
    /*else {
      // just for debugging
      winston.debug('!!!Couldn\' find collection in collectionsData!!!');
    }*/
    winston.debug('Temporary collection merged into main branch');
    fs.unlink(tempName, () => {} );
    this.removalCallback(this.collectionId); // time to die
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

        // modify image paths to point to /collections/:collectionId
        for (let i = 0; i < update.collectionUpdate.images.length; i++) {
          
          update.collectionUpdate.images[i].contentFile = collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].contentFile;
          
          if ('proxyContentFile' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].proxyContentFile = collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].proxyContentFile;
          }

          if ('thumbnail' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].thumbnail = collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].thumbnail;
          }
          if ('pdfImage' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].pdfImage = collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].pdfImage;
          }
          if ('archiveFilename' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].archiveFilename = collectionsUrl + '/' + this.collectionId + '/' + update.collectionUpdate.images[i].archiveFilename;
          }
          this.images.push(update.collectionUpdate.images[i]);
        }
      }
      
      this.sendToClients(update);
    }

    return data;
  }


}