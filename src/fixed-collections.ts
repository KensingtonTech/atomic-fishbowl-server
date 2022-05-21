import { v4 as uuidV4 } from 'uuid';
import fs from 'fs';
import net from 'net';
import rmfr from 'rmfr';
import { spawn, ChildProcess } from 'child_process';
import temp from 'temp';
import log from './logging';
import { ConfigurationManager } from './configuration-manager';
import { Namespace, Socket } from 'socket.io';
import { Request, Response } from 'express';
import { JwtUser } from './types/jwt-user';
import {
  Collection,
  Session,
  Search,
  ContentItem
} from './types/collection';
import { WorkerConfig } from './types/worker';

export class FixedCollectionHandler {
  // The purpose of this class is to manage connections to API requests for fixed collections

  afbConfig: ConfigurationManager;
  feederSocketFilename: string;
  channel: Namespace;
  collectionManagers: Record<string, FixedCollectionManager> = {};
  roomSockets: Record<string, Socket[]> = {}; // key is collectionId.  tracks which sockets are joined to which rooms

  constructor(afbConfig: ConfigurationManager, feederSocketFilename: string, channel: Namespace) {
    this.afbConfig = afbConfig;
    this.feederSocketFilename = feederSocketFilename;

    // socket.io
    this.channel = channel; // channel is the /collections socket.io namespace
    this.channel.on('connection', (socket) => this.onChannelConnect(socket) );

    this.roomSockets = {}; 
  }



  onChannelConnect(socket: Socket) {
    log.debug('FixedCollectionHandler: onChannelConnect()');
    if (!socket.conn.jwtuser) {
      // socket is not authenticated - disconnect it
      socket.disconnect(false);
      return;
    }
    // start listening for messages from a client after it has connected
    socket.on('joinFixed', (collectionId) => this.onSocketJoinCollection(socket, collectionId) );
    socket.on('leaveFixed', () => this.onLeaveCollection(socket) );
    socket.on('disconnect', () => this.onChannelDisconnect(socket) );
  }



  onSocketJoinCollection(socket: Socket, collectionId: string) {
    // this is the equivalent of onHttpConnection(), but for socket connections
    log.debug('FixedCollectionHandler: onSocketJoinCollection()');

    socket.collectionId = collectionId; // add the collection id to our socket so we can later identify it
    const collection = this.afbConfig.getCollection(collectionId);
    socket.collectionName = collection.name;

    log.debug('FixedCollectionHandler: onSocketJoinCollection(): collectionId:', collectionId);
    log.info(`User '${socket.conn.jwtuser.username}' has connected to fixed collection '${collection.name}'`);

    socket.join(collectionId); // this joins a room for collectionId
    if (!(collectionId in this.roomSockets)) {
      this.roomSockets[collectionId] = [];
    }
    this.roomSockets[collectionId].push(socket);

    // here's where we want to decide if collection is complete (so return it)...
    // or if we need to build it
    if (['initial', 'building', 'error'].includes(collection.state)) {
      log.debug('FixedCollectionHandler: onSocketJoinCollection(): joining a collection manager');
      // build the collection or join the building collection
        
      let fixedCollectionManager = undefined;
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
      log.debug('FixedCollectionHandler: onSocketJoinCollection(): replaying complete collection');
      // play back the complete collection
      const collectionsData = this.afbConfig.getCollectionData(collectionId);
      // log.debug('collectionsData:', collectionsData);

      socket.emit('sessions', collectionsData.sessions );

      // play back images
      socket.emit('content', collectionsData.images);

      // Play back search text
      socket.emit('searches', collectionsData.search);
    }
  }



  onLeaveCollection(socket: Socket) {
    // when a socket disconnects gracefully or when the collection is done building through its handler.removeFixedCollectionManager
    log.debug('FixedCollectionHandler: onLeaveCollection()');

    if (!('collectionId' in socket)) {
      return;
    }

    const collectionId = socket.collectionId as string;

    if (socket.rooms.has(collectionId)) {
      socket.leave(collectionId);
      log.info(`A user has disconnected from fixed collection '${socket.collectionName}'`)
      delete socket.collectionId;
      delete socket.collectionName;
    }

    const roomSockets = this.roomSockets[collectionId];
    
    if (roomSockets) {
      roomSockets.forEachReverse( (sock, i) => {
        // remove this socket from the room to client mapping
        if (sock.id === socket.id) {
          roomSockets.splice(i, 1);
        }
      });
    }
  
    if ( collectionId in this.collectionManagers ) {
      const manager = this.collectionManagers[collectionId];
      manager.removeSocketClient();
    }
  }



  onChannelDisconnect(socket: Socket) {
    // when a socket disconnects from the room (channel) - either ungracefully or when the user has logged out
    log.debug('FixedCollectionHandler: onChannelDisconnect()');

    if (!('collectionId' in socket)) {
      return;
    }

    const collectionId = socket.collectionId as string;
    log.debug('FixedCollectionHandler: onChannelDisconnect(): matched collectionId:', collectionId);

    let existingCollection;
    try {
      existingCollection = this.afbConfig.getCollection(collectionId);
    }
    catch {}

    if (existingCollection) {
      log.info(`A user has disconnected from fixed collection '${existingCollection.name}'`);
    }
    else {
      log.info(`A user has disconnected from fixed collections`);
    }

    if (socket.rooms.has(collectionId)) {
      socket.leave(collectionId);  
    }

    if ( collectionId in this.collectionManagers ) {
      const manager = this.collectionManagers[collectionId];
      manager.removeSocketClient();
    }
    socket.removeAllListeners();
  }



  async removeFixedCollectionManager(id: string, deleteOutputDir = false) {
    // called from manager.onCollectionDeleted(), abort(), onWorkerExit()
    log.debug('FixedCollectionHandler: removeFixedCollectionManager()');
    delete this.collectionManagers[id];
    // disconnect all client sockets from this collection's room
    if (!(id in this.roomSockets)) {
      throw new Error(`No sockets could be found for fixed collection: ${id}`);
    }
    if (deleteOutputDir) {
      const dirName = `${this.afbConfig.collectionsDir}/${id}`;
      try {
        log.debug('Deleting output directory for collection', id);
        await rmfr( dirName ); // Delete output directory
      }
      catch (error: any) {
        log.error(`ERROR deleting output directory ${dirName}`, error);
        throw new Error(error);
      }
    }
    const roomSockets = this.roomSockets[id];
    if (roomSockets) {
      roomSockets.forEachReverse( (roomSocket) => this.onLeaveCollection(roomSocket) )
    }
    delete this.roomSockets[id];
  }
  

  
  onHttpConnection(req: Request, res: Response) {
    // Builds and streams a fixec collection back to the client.  Handles the client connection and kicks off the process
    
    const collectionId = req.params.id;
    const collection = this.afbConfig.getCollection(collectionId);
    const jwtUser = req.user as JwtUser;
    
    log.debug('FixedCollectionHandler: onHttpConnection(): collectionId:', collectionId);
    log.info(`User '${jwtUser.username}' has connected to fixed collection '${collection.name}'`);
    
    // create a client connection handler for this connection
    // does a manager for the requested collection exist?
    // if not, create a new collection manager
    // add new or existing collection manager to the client connection handler
    
    const clientConnection = new HttpConnection(this, collectionId, req, res);
    if ( !clientConnection.onConnect(collection) ) {
      return;
    }
    
    let fixedCollectionManager = undefined;
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



  collectionDeleted(collectionId: string, username: string) {
    // we should only get here if someone deletes a fixed collection...
    // which is in the process of building
    log.debug('FixedCollectionHandler: collectionDeleted()');
    if (collectionId in this.collectionManagers) {
      const manager = this.collectionManagers[collectionId];
      manager.onCollectionDeleted(username);
    }
  }



  killAll() {
    // we should only ever get here during shutdown of the server
    Object.values(this.collectionManagers).forEach(
      (manager) => manager.abort()
    );
  }



  updateFeederSocketFile(filename: string) {
    this.feederSocketFilename = filename;
  }

}
  
  
  
  
  
  
  
  
  
  
  
  

  
  

class HttpConnection {

  handler: FixedCollectionHandler;
  afbConfig: ConfigurationManager;
  id = uuidV4();
  req: Request;
  res: Response;
  collectionId: string;
  manager!: FixedCollectionManager;
  heartbeatInterval?: NodeJS.Timer;
  disconnected = false;

  constructor(handler: FixedCollectionHandler, collectionId: string, req: Request, res: Response) {
    log.debug('FixedHttpConnection: constructor()');
    this.handler = handler;
    this.afbConfig = this.handler.afbConfig;
    this.req = req;
    this.res = res;
    res.setHeader('transfer-encoding', 'chunked');
    this.collectionId = collectionId;
  }



  onConnect(collection: Collection) {
    log.debug('FixedHttpConnection: onConnect():');

    ////////////////////////////////////////////////////
    //////////////////RESPONSE HEADERS//////////////////
    ////////////////////////////////////////////////////
  
    try {
      if (collection.bound && !('usecase' in collection )) {
        throw new Error(`Bound collection ${this.collectionId} does not have a use case defined`);
      }
      if (collection.bound && !this.afbConfig.hasUseCase(collection.usecase)) {
        throw new Error(`Use case ${collection.usecase} in bound collection ${collection.id} is not a valid use case`);
      }
      if (collection.state !== 'complete') {
        this.res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': 'inline' } );
        this.res.write('['); // Open the array so that oboe can see it
      }
      else {
        throw new Error(`Collection ${this.collectionId} is in a complete state.  We really shouldn't have got here`);
      }
    }
    catch (error: any) {
      log.error(`FixedHttpConnection: onConnect():`, error);
      this.res.status(500).send( JSON.stringify( { success: false, error: error.message ?? error } ) );
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
    log.debug('FixedHttpConnection: onClientClosedConnection()');
    const jwtUser = this.req.user as JwtUser;
    const collection = this.afbConfig.getCollection(this.collectionId);
    log.info(`User '${jwtUser.username}' has disconnected from ${collection.type} collection '${collection.name}'`);
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



  addManager(manager: FixedCollectionManager) {
    log.debug('FixedHttpConnection: addManager()');
    this.manager = manager;
    this.manager.addHttpClient(this.id, this);
  }



  send(data: unknown) {
    // log.debug('FixedHttpConnection: send()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( `${JSON.stringify(data)},`);
    }
  }


  
  sendRaw(data: unknown) {
    log.debug('FixedHttpConnection: sendRaw()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( data );
    }
  }



  end() {
    log.debug('FixedHttpConnection: end()');
    if (this.heartbeatInterval) {
      // stop sending heartbeats to client
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = undefined;
    }
    this.sendRaw('{"close":true}]'); // Close the array so that oboe knows we're done
    this.manager = undefined as any;
    this.res.end() // not sure if this will work if already disconnected
  }
}














class FixedCollectionManager {

  handler: FixedCollectionHandler;
  channel: Namespace;
  afbConfig: ConfigurationManager;
  observers = 0; // tracks how many clients are connected to this collection
  collectionId: string;
  collection: Collection;
  hasRun = false;
  sessions: Session[] = [];
  content: ContentItem[] = [];
  search: Search[] = [];
  workerProcess!: ChildProcess; // the handle for the worker process
  workerNetSocket!: net.Socket; // used for communication with worker
  httpClients: Record<string, HttpConnection> = {}; // holds http clients
  destroyTimeout?: NodeJS.Timeout;

  constructor(handler: FixedCollectionHandler, collection: Collection, collectionId: string) {
    log.debug('FixedCollectionManager: constructor()');
    this.handler = handler;
    this.afbConfig = this.handler.afbConfig;
    this.channel = this.handler.channel; // channel is the /collections socket.io namespace (and all clients connected to it)
    this.collection = collection;
    this.collectionId = collectionId;
  }



  run() {
    log.debug('FixedCollectionManager: run()');
    this.buildFixedCollection();
  }



  addHttpClient(id: string, client: HttpConnection) {
    log.debug('FixedCollectionManager: addHttpClient()');
    this.httpClients[id] = client;
    this.observers += 1;
    
    if (!this.hasRun) {
      this.run();
    }
    
    if (this.hasRun) {
      log.debug(`This is not the first client connected to fixed collection ${this.collectionId}.  Replaying existing collection`);

      // Play back sessions
      // We must do it this way because the client expects an object
      // we store sessions internally as an array of objects
      const sessions: Record<string, Session> = {};
      this.sessions.forEach( (session) => sessions[session.id] = session );
      client.send({
        wholeCollection: {
          images: this.content,
          sessions: sessions,
          search: this.search
        }
      });
    }
  }



  addSocketClient(socket: Socket) {
    log.debug('FixedCollectionManager: addSocketClient()');
    this.observers += 1;
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = undefined;
    }

    if (!this.hasRun) {
      this.run();
    }
    
    if (this.hasRun) {
      log.debug(`This is not the first client connected to fixed collection ${this.collectionId}.  Replaying existing collection`);

      // Play back sessions
      // We must do it this way because the client expects an object
      // We store sessions internally as an array of objects
      const sessions: Record<string, Session> = {};
      this.sessions.forEach( session => sessions[session.id] = session);
      socket.emit('sessions', sessions );
      // play back images
      socket.emit('content', this.content);
      // Play back search text
      socket.emit('searches', this.search);
    }

  }



  onCollectionDeleted(username: string) {
    log.debug('FixedCollectionManager: onCollectionDeleted()');
    // stop any running workers
    this.killWorker();
    this.sendToHttpClients( {
      collectionDeleted: this.collectionId,
      user: username
    });
    this.endHttpClients();
    // this is handled for IO clients in the outer express collection delete method
    this.handler.removeFixedCollectionManager(this.collectionId, true); // this is necessary as onWorkerExit won't trigger after killall()
  }



  async abort() {
    // we should only ever get here during shutdown of the server
    log.debug('FixedCollectionManager: abort()');
    this.killWorker();
    this.endHttpClients();
    this.handler.removeFixedCollectionManager(this.collectionId, true);
  }



  killWorker() {
    if (this.workerNetSocket) {
      this.workerNetSocket.removeAllListeners();
      this.workerNetSocket = undefined as any;
    }

    if (this.workerProcess){
      this.workerProcess.removeAllListeners(); // prevents collection state from getting written and to prevent the collection from getting saved in onWorkerExit()
      this.workerProcess.kill('SIGINT');
      this.workerProcess = undefined as any;
    }
  }




  removeHttpClient(id: string) {
    log.debug('FixedCollectionManager: removeHttpClient()');
    this.observers -= 1;
    if (this.observers !== 0) {
      log.debug('Client disconnected from fixed collection with collectionId', this.collectionId);
    }
    delete this.httpClients[id];
  }



  removeSocketClient() {
    log.debug('FixedCollectionManager: removeSocketClient()');
    this.observers -= 1;
    if (this.observers !== 0) {
      log.debug('FixedCollectionManager: removeSocketClient(): Socket client disconnected from collection with collectionId', this.collectionId);
    }
  }



  sendToWorker(data: unknown) {
    log.debug('FixedCollectionManager: sendToWorker()');
    this.workerNetSocket.write( `${JSON.stringify(data)}\n` );
  }



  sendToHttpClients(data: unknown) {
    // log.debug('FixedCollectionManager: sendToHttpClients()');
    Object.values(this.httpClients)
      .forEach(
        (client) => client.send(data)
      );
  }



  sendToHttpClientsRaw(data: unknown) {
    log.debug('FixedCollectionManager: sendToHttpClientsRaw()');
    Object.values(this.httpClients)
      .forEach(
        (client) => client.sendRaw(data)
      );
  }



  sendToRoom(type: string, data: unknown) {
    if (this.channel) {
      this.channel.to(this.collectionId).emit( type, data );
    }
  }



  endHttpClients() {
    log.debug('FixedCollectionManager: endHttpClients()');
    Object.values(this.httpClients)
      .forEach(
        (client) => client.end()
      );
  } 



  buildFixedCollection() {
    // Main body of worker execution
    log.debug('FixedCollectionManager: buildFixedCollection()');

    try {
      const tempName = temp.path({suffix: '.socket'});
      
      // Open a UNIX domain socket for the worker to connect back to
      const socketServer = net.createServer( (workerSocket) => {
        this.workerNetSocket = workerSocket;
        this.onConnectionFromWorker();
      });
      socketServer.close();

      socketServer.listen(tempName, () => {
        log.debug('Listening for worker communication');
        log.debug(`Spawning worker with socket file ${tempName}`);
        
        // Start the worker process.  It won't do anything until we send it a config
        this.workerProcess = spawn('./worker/worker_stub.py', [tempName], { shell: false, stdio: 'inherit' });
        
        this.workerProcess.once('exit', (code) => this.onWorkerExit(code, tempName) );
      });
    }
    catch (error: any) {
      log.error('buildFixedCollection(): Caught error:', error);
    }
     
  }




  async onWorkerExit(code: number | null, tempName: string) {
    if (!code) {
      log.debug('Worker process exited normally with exit code 0');
      this.collection.state = 'complete'; 
    }
    else {
      log.debug('Worker process exited abnormally with exit code',code);
      this.collection.state = 'error'; 
    }
    if (this.afbConfig.hasCollectionData(this.collectionId)) { // if statement needed in case the collection has been deleted whilst still building
      log.debug('Merging temporary collection into permanent collection');
      // updates the collectionsData with the final content, search, and sessions
      // no need to tell clients as they will have already received all content updates
      const sessions: Record<string, Session> = {};
      this.sessions.forEach(
        (session) => sessions[session.id] = session
      );
      const update = {
        id: this.collectionId,
        images: this.content,
        search: this.search,
        sessions: sessions
      };
      await this.afbConfig.addCollectionsData(update);
    }
    log.debug('Temporary collection merged into main branch');
    await fs.promises.unlink(tempName);
    this.sendToRoom('state', this.collection.state);
    this.sendToHttpClients( { collection: { id: this.collectionId, state: this.collection.state } } );
    this.endHttpClients();
    await this.afbConfig.saveFixedCollection(this.collectionId, this.collection); // saves the collection state
    this.handler.removeFixedCollectionManager(this.collectionId); // time to die - causes this class instance to be deleted and the collection will then be served from afbConfig
  }

  


  onConnectionFromWorker() {
    // This is called when the worker connects back to us through the UNIX socket
    // Its purpose is to build a configuration for the worker and send it
    // Once the config has been sent, the worker will do its magic and send results back here

    this.hasRun = true;
  
    log.debug('onConnectionFromWorker(): Connection received from worker to build collection', this.collectionId);
    
    //////////////////////////////////
    //Build the worker configuration//
    //////////////////////////////////
  
    const preferences = this.afbConfig.getPreferences();
    let cfg: Partial<WorkerConfig> = { 
      id: this.collectionId,
      collectionId: this.collectionId, // we include this to disambiguate a difference in monitoring collections between id and collectionId
      state: 'building',
      timeBegin: this.collection.timeBegin,
      timeEnd: this.collection.timeEnd,
      contentLimit: this.collection.contentLimit,
      minX: this.collection.minX,
      minY: this.collection.minY,
      gsPath: this.afbConfig.gsPath,
      pdftotextPath: this.afbConfig.pdftotextPath,
      sofficePath: this.afbConfig.sofficePath,
      sofficeProfilesDir: this.afbConfig.sofficeProfilesDir,
      unrarPath: this.afbConfig.unrarPath,
      collectionsDir: this.afbConfig.collectionsDir,
      privateKeyFile: this.afbConfig.internalPrivateKeyFile,
      useHashFeed: this.collection.useHashFeed,
      serviceType: this.collection.serviceType,
      type: this.collection.type,
      onlyContentFromArchives: this.collection.onlyContentFromArchives ?? false
    };
  
    try {
      if (cfg.serviceType === 'nw') {
        cfg = {
          ...cfg,
          queryTimeout: preferences.nw.queryTimeout,
          contentTimeout: preferences.nw.contentTimeout,
          maxContentErrors: preferences.nw.maxContentErrors,
          sessionLimit: preferences.nw.sessionLimit
        }
      }
    
      if (cfg.serviceType === 'sa') {
        cfg = {
          ...cfg,
          queryTimeout: preferences.sa.queryTimeout,
          contentTimeout: preferences.sa.contentTimeout,
          maxContentErrors: preferences.sa.maxContentErrors,
          sessionLimit: preferences.sa.sessionLimit
        }
      }
    }
    catch (error: any) {
      log.error('Caught error trying to read preferences.  Exiting with code 1');
      process.exit(1);
    }
  
    if (this.collection.bound) {
      // This is an OOTB use case
      const useCaseName = this.collection.usecase;
      const useCase = this.afbConfig.getUseCase(useCaseName);
      cfg.query = cfg.serviceType === 'nw'
        ? useCase.nwquery
        : useCase.saquery;
      cfg.contentTypes = useCase.contentTypes;
      cfg.distillationEnabled = false;
      if ('distillationTerms' in useCase) {
        cfg.distillationEnabled = true;
        cfg.distillationTerms = useCase.distillationTerms;
      }
      cfg.regexDistillationEnabled = false;
      if ('regexTerms' in useCase) {
        cfg.regexDistillationEnabled = true;
        cfg.regexDistillationTerms = useCase.regexTerms;
      }
      cfg.onlyContentFromArchives = useCase.onlyContentFromArchives;
      // we don't yet support any hashing in OOTB use cases
    }
    else {
      // This is a custom use case, not an OOTB use case
      cfg.distillationEnabled = this.collection.distillationEnabled;
      cfg.regexDistillationEnabled = this.collection.regexDistillationEnabled;
  
      if (!this.collection.useHashFeed) {
        // we're not using a hash feed
        cfg.md5Enabled = this.collection.md5Enabled;
        cfg.sha1Enabled = this.collection.sha1Enabled;
        cfg.sha256Enabled = this.collection.sha256Enabled;
        if ('md5Hashes' in this.collection) {
          cfg.md5Hashes = this.collection.md5Hashes;
        }
        if ('sha1Hashes' in this.collection) {
          cfg.sha1Hashes = this.collection.sha1Hashes;
        }
        if ('sha256Hashes' in this.collection) {
          cfg.sha256Hashes = this.collection.sha256Hashes;
        }
      }
      else if (this.collection.hashFeed && this.handler.feederSocketFilename) {
        // we're using a hash feed
        cfg.hashFeed = this.afbConfig.getFeed(this.collection.hashFeed); // pass the hash feed definition
        cfg.hashFeederSocket = this.handler.feederSocketFilename;
      }
  
      cfg.query = this.collection.query;
      cfg.contentTypes = this.collection.contentTypes;
    
      if ('distillationTerms' in this.collection) {
        cfg.distillationTerms = this.collection.distillationTerms;
      }
      if ('regexDistillationTerms' in this.collection) {
        cfg.regexDistillationTerms = this.collection.regexDistillationTerms;
      }
    }
  
    if (cfg.serviceType === 'nw' && this.collection.serviceType === 'nw') {
      const nwserver = this.afbConfig.getNwServer(this.collection.nwserver);
      Object.entries(nwserver)
        .filter( ([key]) => !['_id', 'id'].includes(key))
        .forEach(
          ([key, value]) => (cfg as Record<string, any>)[key] = value
        );
    }
    if (cfg.serviceType === 'sa' && this.collection.serviceType === 'sa') {
      const saserver = this.afbConfig.getSaServer(this.collection.saserver);
      Object.entries(saserver)
        .filter( ([key]) => !['_id', 'id'].includes(key))
        .forEach(
          ([key, value]) => (cfg as Record<string, any>)[key] = value
        );
    }
  
    const outerCfg = { workerConfig: cfg };
  
    
  
    ////////////////////////
    //DEAL WITH THE SOCKET//
    ////////////////////////
  
    // Tell our subscribers that we're building, so they can start their spinny icon
    this.collection.state = 'building';
    this.sendToRoom('state', this.collection.state);
    this.sendToHttpClients({
      collection: {
        id: this.collectionId,
        state: this.collection.state
      }
    });
  
    // Buffer for worker data
    let data = '';
    
    // Set socket options
    this.workerNetSocket.setEncoding('utf8');
  
    // Handle data sent from the worker via the UNIX socket (collection results)
    this.workerNetSocket.on('data', chunk => data = this.onDataFromWorker(data, chunk) );
    
    // Now that we've finished building the new collection, emit a finished signal, and merge the new collection into the this.cfg.collectionsData object, and delete the object from buildingFixedCollections
                            
    // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
    this.sendToWorker(outerCfg); 
  }



  onDataFromWorker(data: string, chunk: Buffer) {
    // Handles socket data received from the worker process
    // This actually builds the collection data structures and sends updates to the client
    // log.debug('FixedCollectionManager: onDataFromWorker(): Processing update from worker');
    data += chunk.toString('utf8');

    const splt = data.split('\n').filter( (el) => el.length !== 0);

    if ( splt.length === 1 && data.indexOf('\n') === -1 ) {
      // this case means the split resulted in only one element and that doesn't contain the newline delimiter, which means we haven't received an entire update yet...
      // we'll continue and wait for the next update which will hopefully contain the delimiter
      return data;
    }
    const d: string[] = [];
    if ( splt.length === 1 && data.endsWith('\n') ) {
      // this case means the split resulted in only one element and that it does contain the newline delimiter.  This means we received a single complete update.
      d.push(splt.shift() as string);
      data='';
    }
    else if ( splt.length > 1 ) {
      // This case means the split resulted in multiple elements and that it does contain a newline delimiter...
      // This means we have at least one complete update, and possibly more.
      if (data.endsWith('\n')) {  // the last element is a full update as data ends with a newline
        while (splt.length > 0) {
          d.push(splt.shift() as string);
        }
        data = '';
      }
      else { // the last element is only a partial update, meaning that more data must be coming
        while (splt.length > 1) {
          d.push(splt.shift() as string);
        }
        data = splt.shift() as string;  // this should be the last partial update, which should be appended to in the next update
      }
    }

    while (d.length > 0) {
      const u = d.shift() as string;
      const update = JSON.parse(u);

      if ('collectionUpdate' in update) {
        this.sessions.push(update.collectionUpdate.session);
        
        if (update.collectionUpdate.search) {
          this.search = [
            ...this.search ?? [],
            ...update.collectionUpdate.search
          ];
        }

        this.content = [
          ...this.content ?? [],
          ...update.collectionUpdate.images
        ];
      }
      
      this.sendToRoom('update', update);
      this.sendToHttpClients(update);
    }

    return data;
  }
}
