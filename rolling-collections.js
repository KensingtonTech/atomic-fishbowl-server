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

module.exports = class {

  // The purpose of this class is to manage connections to API requests for rolling collections

  constructor(dbUpdateCallback, winstoN, collectionS, collectionsDiR, feederSocketFilE, gsPatH, pdftotextPatH, sofficePatH, sofficeProfilesDiR, unrarPatH, internalPrivateKeyFilE, useCasesObJ, preferenceS, nwserverS, saserverS, collectionsUrL) {
    this.rollingCollectionManagers = {};
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
    
  }
  
  
  handleRollingConnection(req, res) {
    // Builds and streams a rolling or monitoring collection back to the client.  Handles the client connection and kicks off the process
    
    let collectionId = req.params.collectionId;
    let clientSessionId = req.headers['afbsessionid'];
    
    winston.info('handleRollingConnection(): collectionId:', collectionId);
    // winston.debug('preferences:', preferences);
    
    let rollingId = collectionId;
    // rollingId is either the collectionId (for rolling collections), or the clientSessionId (for monitoring collections).
    // our classes will refer to this id when accessing the rollingCollections object
    if ( collections[collectionId].type === 'monitoring' ) {
      rollingId = clientSessionId;
    }
    let collection = collections[collectionId];

    winston.info('handleRollingConnection(): rollingId:', rollingId);
    
    // create a client connection handler for this connection
    // does a manager for the requested rolling collection exist?
    // if not, create a new rolling collection manager
    // add new or existing rolling collection manager to the client connection handler
    
    let clientConnection = new ClientConnection(req, res, collectionId, rollingId);
    if ( !clientConnection.onConnect(collection) ) {
      return;
    }
    
    let rollingCollectionManager = null;
    if ( !(rollingId in this.rollingCollectionManagers)) {
      // there is no RollingCollectionManager yet for the chosen collection.  So create one
      rollingCollectionManager = new RollingCollectionManager(collection, collectionId, rollingId, () => this.rollingCollectionManagerRemovalCallback, this.dbUpdateCallback);
      this.rollingCollectionManagers[rollingId] = { collectionId: collectionId, manager: rollingCollectionManager };
    }
    else {
      // there's already a manager for the chosen collection
      rollingCollectionManager = this.rollingCollectionManagers[rollingId]['manager'];
    }

    // give the client connection object the rolling collection manager to attach itself to
    clientConnection.addManager(rollingCollectionManager);
    
  }



  collectionEdited(collectionId, collection) {
    winston.info('collectionEdited()');
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
    winston.info('collectionDeleted()');
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
    winston.info('rollingCollectionManagerRemovalCallback()');
    delete this.rollingCollectionManagers[id];
  }



  pauseMonitoringCollection(req, res) {
    let clientSessionId = req.headers['afbsessionid'];
    winston.info(`handlePauseMonitoringCollection(): Pausing monitoring collection ${clientSessionId}`);
    let manager = this.rollingCollectionManagers[clientSessionId]['manager'];
    manager.pause();
    res.status(202).send( JSON.stringify( { success: true } ) );
  }



  unpauseMonitoringCollection(req, res) {
    // This only gets used by the client if a monitoring collection is paused and then resumed within the minute the run is permitted to continue executing
    // Otherwise, the client will simply call /api/collection/rolling/:id again
    let clientSessionId = req.headers['afbsessionid'];
    winston.info(`handleUnpauseMonitoringCollection(): Resuming monitoring collection ${clientSessionId}`);
    let manager = this.rollingCollectionManagers[clientSessionId]['manager'];
    manager.unpause();
    res.status(202).send( JSON.stringify( { success: true } ) );
  }



  killall() {
    for (let rollingId in this.collectionManagers) {
      if (this.collectionManagers.hasOwnProperty(rollingId)) {
        let manager = this.collectionManagers[rollingId];
        manager.abort();
      }
    }
  }

}
  
  
  
  
  
  
  
  
  
  
  
  

  
  

class ClientConnection {

  constructor(req, res, collectionId, rollingId) {
    winston.info('ClientConnection: constructor()');
    this.id = uuidV4();
    this.req = req;
    this.res = res;
    this.collectionId = collectionId;
    this.rollingId = rollingId;
    
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
      // Write the response headers
      if (collection.bound && !( 'usecase' in collection )) {
        throw(`Bound collection ${this.collectionId} does not have a use case defined`);
      }
      if (collection.bound && !(collection.usecase in useCasesObj) ) {
        throw(`Use case ${collection.usecase} in bound collection ${this.collectionId} is not a valid use case`);
      }
      if (collection.type === 'rolling' || collection.type === 'monitoring') {
        this.res.writeHead(200, {'Content-Type': 'application/json','Content-Disposition': 'inline' });
        this.res.write('['); // Open the array so that oboe can see it
        this.res.flush();
      }
      else {
        throw("Collection " + this.collectionId + " is not of type 'rolling' or 'monitoring'");
      }
    }
    catch (e) {
      winston.error('ClientConnection: onConnect():', e);
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
      // But NOT when we terminate the session from the server
      
      if (this.heartbeatInterval) {
        // stop sending heartbeats to client
        clearInterval(this.heartbeatInterval);
        this.heartbeatInterval = null;
      }
      
      this.manager.removeClient(this.id);

      this.end();
    });

    this.heartbeatInterval = setInterval( () => {
      this.send( { heartbeat : true } );
    }, 15000 );
    
    return true;

  }

}


















class RollingCollectionManager {

  constructor(collection, collectionId, rollingId, removalCallback, dbUpdateCallback) {
    winston.info('RollingCollectionManager: constructor()');
    this.clients = {};
    this.socket = null;
    this.removalCallback = removalCallback;
    this.dbUpdateCallback = dbUpdateCallback;
    this.collection = collection;
    this.collectionId = collectionId;
    this.rollingId = rollingId;
    this.observers = 0;
    this.workInterval = null;
    this.workerProcess = null;
    this.destroyThreshold = 3600; // wait one hour to destroy
    this.destroyTimeout;  // holds setTimeout for destroy().  Cancel if we get another connection within timeframe
    this.runs = 0;
    this.sessions = [];
    this.images = [];
    this.search = [];
    this.monitoringCollection = false;
    this.lastrun = null;
    this.destroyed = false;
  }



  run() {
    winston.info('RollingCollectionManager: run()');
    this.workLoop();
    // Now schedule workLoop() to run every 60 seconds and store a reference to it in this.workInterval
    // which we can later use to terminate the timer and prevent future execution.
    // This will not initially execute work() until the first 60 seconds have elapsed, which is why we run workLoop() once before this
    this.workInterval = setInterval( () => this.workLoop(), 60000);
  }



  setMonitoring() {
    winston.info('RollingCollectionManager: setMonitoring()');
    this.monitoring = false;
    this.paused = false;
    this.monitoringCollection = true;
  }



  selfDestruct() {
    winston.info('RollingCollectionManager: selfDestruct()');
    /*if (isDestroyed) {
      winston.debug('Not self-destructing as we\'re already being deleted');
      return;
    }*/
    this.collection['state'] = 'disconnected';
    winston.debug("No clients reconnected to rolling collection " + this.rollingId + " within " + this.destroyThreshold + " seconds. Self-destructing");
    clearInterval(this.workInterval);
    this.killWorker();
    try {
      winston.debug("Deleting output directory for collection", this.rollingId);
      rimraf( collectionsDir + '/' + this.rollingId, () => {} ); // Delete output directory
    }
    catch(exception) {
      winston.error('ERROR deleting output directory ' + collectionsDir + '/' + this.rollingId, exception);
    }
    this.removalCallback(this.rollingId);
  }



  addClient(id, client) {
    winston.info('RollingCollectionManager: addClient()');
    this.clients[id] = client;
    this.observers += 1;
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = null;
    }
    
    if (this.runs == 0) {
      this.run();
    }
    
    if (this.runs > 0) {
      winston.info(`This is not the first client connected to rolling collection ${this.rollingId}.  Playing back existing collection`);
      let resp = null;

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

      if (this.observers == 1) {
        // If all clients have disconnected, and then one reconnects, the worker should start immediately
        clearInterval(this.workInterval);
        this.workInterval = null;
        this.run();
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
    
    this.collection = collection

    this.sessions = [];
    this.images = [];
    this.search = [];
    this.runs = 0;

    this.sendToClients( { wholeCollection: { images: [], sessions: {}, search: [] } } );

    // don't re-run.  The clients will cause this themselves when they reconnect
    // this d.run();

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

    if (this.monitoring) {
      // we only do this for monitoring collections as this helps us to...
      // clean up after all the different client instances of a particular monitoring collection
      // the collection delete handler will otherwise handle deletion
      try {
        winston.debug("Deleting output directory for collection", this.rollingId);
        rimraf( collectionsDir + '/' + this.rollingId, () => {} ); // Delete output directory
      }
      catch(exception) {
        winston.error('ERROR deleting output directory ' + collectionsDir + '/' + this.rollingId, exception);
      }
    }

    this.sendToClients( { collectionDeleted: this.collectionId, user: user } );
    this.endClients();

    this.removalCallback(this.rollingId);
  }



  abort() {
    winston.info('RollingCollectionManager: abort()');

    try {
      winston.debug("Deleting output directory for collection", this.collectionId);
      rimraf( collectionsDir + '/' + this.collectionId, () => {} ); // Delete output directory
    }
    catch(exception) {
      winston.error('ERROR deleting output directory ' + collectionsDir + '/' + this.collectionId, exception);
    }

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
    winston.info('RollingCollectionManager: removeClient()');
    this.observers -= 1;
    if (this.observers != 0) {
      winston.debug("Client disconnected from rolling collection with rollingId", this.rollingId);
    }
    else {
      winston.debug("Last client disconnected from rolling collection with rollingId " + this.rollingId + '.  Waiting for ' + this.destroyThreshold + ' seconds before self-destructing');
      this.destroyTimeout = setTimeout( () => this.selfDestruct(), this.destroyThreshold * 1000); // trigger the countdown to self-destruct
    }
    delete this.clients[id];
  }



  pause() {
    winston.info('RollingCollectionManager: pause()');
    this.paused = true;
  }



  unpause() {
    winston.info('RollingCollectionManager: unpause()');
    this.paused = false;
  }



  sendToWorker(data) {
    winston.info('RollingCollectionManager: sendToWorker()');
    this.socket.write( JSON.stringify(data) + '\n' );
  }



  sendToClients(data) {
    winston.info('RollingCollectionManager: sendToClients()');
    for (let id in this.clients) {
      if (this.clients.hasOwnProperty(id)) {
        let client = this.clients[id];
        client.send(data);
      }
    }
  }



  sendToClientsRaw(data) {
    winston.info('RollingCollectionManager: sendToClientsRaw()');
    for (let id in this.clients) {
      if (this.clients.hasOwnProperty(id)) {
        let client = this.clients[id];
        client.sendRaw(data);
      }
    }
  }



  endClients() {
    winston.info('RollingCollectionManager: endClients()');
    for (let id in this.clients) {
      if (this.clients.hasOwnProperty(id)) {
        let client = this.clients[id];
        client.end();
      }
    }
  }



  workLoop() {
    // Main body of worker execution
    winston.info('RollingCollectionManager: workLoop()');

    try {

      winston.debug("workLoop(): Starting run for rollingId", this.rollingId);

      if ( !this.monitoringCollection && this.workerProcess && this.runs == 1) {
        // If we're a rolling collection still on our first run, let it continue running until it completes
        winston.info('workLoop(): First run of rolling collection is still running.  Delaying next run 60 seconds');
        return;
      }
      
      if ( this.workerProcess && this.runs > 1) {
        // Check if there's already a python worker process already running which has overrun the 60 second mark, and if so, kill it
        winston.info('workLoop(): Timer expired for running worker.  Terminating worker');
        this.workerProcess.kill('SIGINT');
      }

      if (this.monitoringCollection && this.paused === true) {
        winston.debug(`workLoop(): Collection ${this.rollingId} is paused.  Returning`);
        return;
      }

      // Create temp file to be used as our UNIX domain socket
      let tempName = temp.path({suffix: '.socket'});

      // Now open the UNIX domain socket that will talk to worker script by creating a handler (or server) to handle communications
      let socketServer = net.createServer( (socket) => { 
        this.socket = socket;
        this.onConnectionFromWorker(tempName);
        // We won't write any more data to the socket, so we will call close() on socketServer.  This prevents the server from accepting any new connections
        socketServer.close();
      });

      
      socketServer.listen(tempName, () => {
        // Tell the server to listen for communication from the not-yet-started worker

        winston.debug('workLoop(): listen(): Rolling Collection: Listening for worker communication');
        winston.debug("workLoop(): listen(): Rolling Collection: Spawning worker with socket file " + tempName);
        
        // Start the worker process and assign a reference to it to 'worker'
        // Notice that we don't pass any configuration to the worker on the command line.  It's all done through the UNIX socket for security.
        this.workerProcess = spawn('./worker_stub.py', [tempName, '2>&1'], { shell: false, stdio: 'inherit'});

        this.workerProcess.on('exit', (code, signal) => this.onWorkerExit(code, signal) );
      });
    }

    catch(e) {
      winston.error("workLoop(): work(): Caught unhandled error:", e);
    }
    
  }



  onWorkerExit(code, signal) {
    // This is where we handle the exiting of the worker process

    if (this.workerProcess) {
      this.workerProcess = null;
    }

    if (typeof code === 'undefined') {
      // Handle really abnormal worker exit with no error code - maybe because we couldn't spawn it at all?  We likely won't ever enter this block
      winston.debug('workLoop(): listen(): onExit(): Worker process exited abnormally without an exit code');

      this.collection['state'] = 'error';
      this.sendToClients( { collection: { id: this.collectionId, state: 'error' } } );
    }

    else if (code !== null || signal !== null) {

      // Handle normal worker exit code 0
      if (code !== null && code === 0) {
        winston.debug('workLoop(): listen(): onExit(): Worker process exited normally with exit code 0');
        // Tell clients that we're resting
        this.collection['state'] = 'resting';
        this.sendToClients( { collection: { id: this.collectionId, state: 'resting' } } );
      }

      else if (code !== null && code !== 0) {
        // Handle worker exit with non-zero (error) exit code
        winston.debug('workLoop(): listen(): onExit(): Worker process exited in bad state with non-zero exit code', code.toString() );
        this.collection['state'] = 'error';
        this.sendToClients( { collection: { id: this.collectionId, state: 'error' } } );
      }

      else {
        winston.debug('workLoop(): listen(): onExit(): Worker process was terminated by signal', signal);
        // Tell client that we're resting
        this.collection['state'] = 'resting';
        this.sendToClients( { collection: { id: this.collectionId, state: 'resting' } } );
      }

      if (this.monitoring && this.paused) {
        // Monitoring collection is paused
        // Now we end and delete this monitoring collection, except for its files (which still may be in use on the client)
        winston.debug('workLoop(): listen(): onExit(): Completing work for paused monitoring collection', this.rollingId);
        clearInterval(this.workInterval); // stop work() from being called again
        this.workInterval = null;
        this.endClients();
        this.dbUpdateCallback(this.collectionId);
        return;
      }
    }

    // Save the collection to the DB
    this.dbUpdateCallback(this.collectionId);
  }



  onConnectionFromWorker(tempName) {
    winston.info('RollingCollectionManager: onConnectionFromWorker()');
    // For rolling and monitoring collections
    // Handles all dealings with the worker process after it has been spawned, including sending it its configuration, and sending data received from it to the onDataFromWorker() function
    // It also purges old data from the collection as defined by the type of collection and number of hours back to retain
    
    this.runs++;
    
    winston.debug("onConnectionFromWorker(): Connection received from worker to build rolling or monitoring collection", this.rollingId);
    
    let ourState = '';
    // Tell our subscribed clients that we're rolling, so they can start their spinny icon and whatnot
    if (this.monitoring) {
      ourState = 'monitoring';
    }
    else if (!this.monitoring) {
      ourState = 'rolling';
    }
    this.collection['state'] = ourState;
    this.sendToClients( { collection: { id: this.collectionId, state: ourState}} );
  
  
    ///////////////////////////
    //PURGE AGED-OUT SESSIONS//
    ///////////////////////////
  
    if (this.monitoring) {
      this.sessions = [];
      this.images = [];
      this.search = [];
    }
    else if (!this.monitoring && this.runs > 1) {
      // Purge events older than this.collection.lastHours
  
      winston.debug('Running purge routine');
      let sessionsToPurge = [];
  
      // Calculate the maximum age a given session is allowed to be
      let maxTime = this.lastRun - this.collection.lastHours * 60 * 60;
      // if (purgeHack) { maxTime = thisRollingCollectionSubject.lastRun - 60 * 5; } // 5 minute setting used for testing
  
  
      for (let i = 0; i < this.sessions.length; i++) {
        // Look at each session and determine whether it is older than maxtime
        // If so, add it to purgedSessionPositions and sessionsToPurge
        let session = this.sessions[i];
        let sid = session.id;
        if ( session.meta.time < maxTime ) {
          sessionsToPurge.push(sid);
        }
      }
  
      this.purgeSessions(sessionsToPurge.slice());
     
      // Notify the client of our purged sessions
      if (sessionsToPurge.length > 0) {
        let update = { collectionPurge: sessionsToPurge };
        this.sendToClients(update);
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
      gsPath: gsPath,
      pdftotextPath: pdftotextPath,
      sofficePath: sofficePath,
      sofficeProfilesDir: sofficeProfilesDir,
      unrarPath: unrarPath,
      collectionsDir: collectionsDir,
      privateKeyFile: internalPrivateKeyFile,
      useHashFeed: this.collection.useHashFeed,
      serviceType: this.collection.serviceType
  
      // query: this.collection.query,
      // regexDistillationEnabled: this.collection.regexDistillationEnabled,
      // md5Enabled: this.collection.md5Enabled,
      // sha1Enabled: this.collection.sha1Enabled,
      // sha256Enabled: this.collection.sha256Enabled,
      // contentTypes: collections[id].contentTypes,
      // distillationEnabled: this.collection.distillationEnabled
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
  
    let queryDelaySeconds = null;
    if (this.collection.serviceType == 'nw') {
      queryDelaySeconds = preferences.nw.queryDelayMinutes * 60;
    }
    else if (this.collection.serviceType == 'sa') {
      queryDelaySeconds = preferences.sa.queryDelayMinutes * 60;
    }
  
    if (this.monitoring) {
      // If this is a monitoring collection, then set timeEnd and timeBegin to be a one minute window
      cfg['timeEnd'] = moment().startOf('minute').unix() - 61 - queryDelaySeconds;
      cfg['timeBegin'] = ( cfg['timeEnd'] - 60) + 1;
    }
    
    else if (this.runs == 1) {
      // This is the first run of a rolling collection
      winston.debug('onConnectionFromWorker(): Got first run');
      cfg['timeEnd'] = moment().startOf('minute').unix() - 61 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
      cfg['timeBegin'] = ( cfg['timeEnd'] - (this.collection.lastHours * 60 * 60) ) + 1;
    }
    
    else if (this.runs == 2 && (moment().unix() - this.lastRun >= 61) ) {
      // This is the second run of a rolling collection - this allows the first run to exceed one minute of execution and will take up whatever excess time has elapsed
      // It will only enter this block if more than 61 seconds have elapsed since the last run
      winston.debug('onConnectionFromWorker(): Got second run');
      cfg['timeBegin'] = this.lastRun + 1; // one second after the last run
      cfg['timeEnd'] = moment().startOf('minute').unix() - 61 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
    }  
  
    else {
      // This is the third or greater run of a rolling collection
      winston.debug('onConnectionFromWorker(): Got subsequent run');
      cfg['timeBegin'] = this.lastRun + 1; // one second after the last run
      cfg['timeEnd'] = cfg['timeBegin'] + 60; //add one minute to cfg[timeBegin]
    }
  
    this.lastRun = cfg['timeEnd']; // store the time of last run so that we can reference it the next time we loop
  
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
      let nwserver = nwservers[this.collection.nwserver];
      for (let k in nwserver) {
        if (nwserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
          cfg[k] = nwserver[k];  // assign properties of nwserver to the collection cfg
        }
      }
    }
    if (this.collection.serviceType == 'sa') {
      let saserver = saservers[this.collection.saserver];
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
    this.socket.setEncoding('utf8');
    
    // Handle data received from the worker over the socket (this really builds the collection)
    this.socket.on('data', chunk => data = this.onDataFromWorker(data, chunk) );
    // this.onDataFromWorkerFunc = (chunk) => this.onDataFromWorker(data, chunk);
    // this.socket.on('data', this.onDataFromWorkerFunc );
                                
                                
    // Once the worker has exited, delete the socket temporary file
    this.socket.on('end', () => this.onWorkerDisconnected(tempName) );
    
    // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
    this.sendToWorker(outerCfg);
    
  }

  

  onWorkerDisconnected(tempName) {
    winston.debug('Worker disconnected.  Rolling collection update cycle complete.');
    fs.unlink(tempName, () => {} ); // Delete the temporary UNIX socket file
  }



  purgeSessions(sessionsToPurge) {
    // winston.debug('purgeSessions(): sessionsToPurge.length: ', sessionsToPurge.length)
    winston.info('RollingCollectionManager: purgeSessions()');
    while (sessionsToPurge.length > 0) {
      let sessionToPurge = sessionsToPurge.shift();
      // winston.debug('purgeSessions(): Trying to purge session', sessionToPurge);
  
      for (let i = 0; i < this.sessions.length; i++) {
        // Purge session
        let session = this.sessions[i];
        if (session.id == sessionToPurge) {
          // winston.debug('purgeSessions(): purging session', session.id);
          this.sessions.splice(i, 1);
          break;
        }
      }
  
      let searchesToPurge = [];
      for (let i = 0; i < this.search.length; i++) {
        let search = this.search[i];
        if (search.session == sessionToPurge) {
          searchesToPurge.push(search);
        }
      }
      while (searchesToPurge.length != 0) {
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
      }
  
  
      let contentsToPurge = [];
      for (let i = 0; i < this.images.length; i++) {
        // Purge content
        let content = this.images[i];
        if (content.session == sessionToPurge) {
          contentsToPurge.push(content);
        }
      }
      while (contentsToPurge.length != 0) {
        let contentToPurge = contentsToPurge.shift();
        for (let i = 0; i < this.images.length; i++) {
          let content = this.images[i];
          if (contentToPurge.session == content.session && contentToPurge.contentFile == content.contentFile && contentToPurge.contentType == content.contentType) {
            // Purge content
            winston.debug('purgeSessions(): purging content', content.session);
            this.images.splice(i, 1);
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
      }
    }
  }


  
  onDataFromWorker(data, chunk) {
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

        // modify image paths to point to /collections/:collectionId
        for (let i = 0; i < update.collectionUpdate.images.length; i++) {
          
          update.collectionUpdate.images[i].contentFile = collectionsUrl + '/' + this.rollingId + '/' + update.collectionUpdate.images[i].contentFile;
          
          if ('proxyContentFile' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].proxyContentFile = collectionsUrl + '/' + this.rollingId + '/' + update.collectionUpdate.images[i].proxyContentFile;
          }

          if ('thumbnail' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].thumbnail = collectionsUrl + '/' + this.rollingId + '/' + update.collectionUpdate.images[i].thumbnail;
          }
          if ('pdfImage' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].pdfImage = collectionsUrl + '/' + this.rollingId + '/' + update.collectionUpdate.images[i].pdfImage;
          }
          if ('archiveFilename' in update.collectionUpdate.images[i]) {
            update.collectionUpdate.images[i].archiveFilename = collectionsUrl + '/' + this.rollingId + '/' + update.collectionUpdate.images[i].archiveFilename;
          }
          this.images.push(update.collectionUpdate.images[i]);
        }
      }
      
      this.sendToClients(update);
    }

    return data;
  };


}