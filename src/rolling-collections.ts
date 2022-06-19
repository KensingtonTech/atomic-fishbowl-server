import { v4 as uuidV4 } from 'uuid';
import fs from 'fs';
import net, { Socket as NetSocket } from 'net';
import rmfr from 'rmfr';
import { spawn, ChildProcess } from 'child_process';
import temp from 'temp';
import log from './logging.js';
import { ConfigurationManager } from './configuration-manager.js';
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
import moment from 'moment';
import * as utils from './utils.js';
import * as SocketMessages from './types/socket-messages';

/*
  What is the difference between collectionId and rollingId?
  They are usually the same uuid, except in the case of a monitoring
  collection, in which case the rollingId is unique.  This allows
  multiple clients to connect to the same monitoring collection,
  but in reality trigger two unique instances of it which can be
  controlled independently by each client.
*/

interface RollingCollectionManagersRecord {
  collectionId: string;
  rollingId: string;
  manager: RollingCollectionManager;
}

interface CollectionUpdate {
  session: Session;
  search?: Search[];
  images: ContentItem[];
}

interface WorkerData {
  collectionUpdate?: CollectionUpdate;
  state?: 'monitoring' | 'error' | 'complete' | string;
}



export class RollingCollectionHandler {
  // The purpose of this class is to manage connections to API requests for rolling collections

  afbConfig: ConfigurationManager;
  feederSocketFilename: string;
  channel: Namespace;
  
  /**
   * Key is collectionId.  tracks which sockets are joined to which rooms
   */
  roomSockets: Record<string, Socket[]> = {};
  purgeTest: boolean;
  purgeTestMinutes: number;

  /**
   * Key is rollingId
   */
  rollingCollectionManagers: Record<string, RollingCollectionManagersRecord> = {};

  constructor(afbConfig: ConfigurationManager, feederSocketFilename: string, channel: Namespace, purgeTest: boolean, purgeTestMinutes: number) {
    this.afbConfig = afbConfig;
    this.feederSocketFilename = feederSocketFilename,
    this.rollingCollectionManagers = {};

    // socket.io
    this.channel = channel;
    this.channel.on('connection', (socket) => this.onChannelConnect(socket) ); // channel is the /collections socket.io namespace,  It gets further segmented into per-collection rooms.  For monitoring collections, each client connection gets its own room, so that it can be controlled independently of other users.
    this.roomSockets = {}; // tracks which sockets are joined to which rooms
    this.purgeTest = purgeTest;
    this.purgeTestMinutes = purgeTestMinutes;
  }



  onChannelConnect(socket: Socket) {
    log.debug('RollingCollectionHandler: onChannelConnect()');
    if (!socket.conn.jwtuser) {
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



  onSocketJoinCollection(socket: Socket, data: SocketMessages.JoinCollection) {
    // this is the equivalent of onHttpConnection(), but for socket connections
    // data must contain properties collectionID and sessionId
    // sessionId should be undefined if a standard rolling collection
    log.debug('RollingCollectionHandler: onSocketJoinCollection()');

    const collectionId = data.collectionId;
    const collection = this.afbConfig.getCollection(collectionId);
    let rollingId = collectionId;
    const sessionId = data.sessionId;

    log.debug('RollingCollectionHandler: onSocketJoinCollection(): collectionId:', collectionId);
    log.debug('RollingCollectionHandler: onSocketJoinCollection(): rollingId:', rollingId);
    log.info(`User '${socket.conn.jwtuser.username}' has connected to ${collection.type} collection '${collection.name}'`);

    if (collection.type === 'monitoring') {
      rollingId = `${collectionId}_${sessionId}`;
    }
    socket.rollingId = rollingId; // add the rolling id to our socket so we can later identify it
    socket.collectionId = collectionId;
    socket.collectionName = collection.name;
    socket.collectionType = collection.type;

    socket.join(rollingId); // this joins a room for rollingId
    if (!(rollingId in this.roomSockets)) {
      this.roomSockets[rollingId] = [];
    }
    this.roomSockets[rollingId].push(socket);

    let rollingCollectionManager: RollingCollectionManager;
    if ( !(rollingId in this.rollingCollectionManagers) ) {
      // there is no RollingCollectionManager yet for the chosen collection.  So create one
      rollingCollectionManager = new RollingCollectionManager(this, collection, collectionId, rollingId);
      this.rollingCollectionManagers[rollingId] = {
        rollingId,
        collectionId,
        manager: rollingCollectionManager
      };
    }
    else {
      // there's already a manager for the chosen collection
      rollingCollectionManager = this.rollingCollectionManagers[rollingId].manager;
    }
    
    socket.rollingCollectionManager = rollingCollectionManager;
    rollingCollectionManager.addSocketClient(socket);
  }



  onLeaveCollection(socket: Socket) {
    // when a socket disconnects gracefully
    log.debug('RollingCollectionHandler: onLeaveCollection()');
    if (socket.rollingId) {
      const rollingId = socket.rollingId;
      log.info(`A user has disconnected from ${socket.collectionType} collection '${socket.collectionName}'`)
      socket.leave(rollingId);
      delete socket.rollingId;
      delete socket.collectionId;
      delete socket.collectionName;
      delete socket.collectionType;
    }

    const manager = socket.rollingCollectionManager;
    if (manager) {
      manager.removeSocketClient();
      delete socket.rollingCollectionManager;
    }
  }



  onChannelDisconnect(socket: Socket) {
    // when a socket disconnects un-gracefully
    log.debug('RollingCollectionHandler: onChannelDisconnect()');
      
    if ('rollingId' in socket) {
      const rollingId = socket.rollingId as string;
      const collectionId = socket.collectionId as string;
      log.debug('RollingCollectionHandler: onChannelDisconnect(): matched collection id:', collectionId);
      let collection;
      try {
        collection = this.afbConfig.getCollection(collectionId);
      }
      catch {}
      if (collection) {
        log.info(`A user has disconnected from ${collection.type} collection '${collection.name}'`);
      }
      else {
        log.info(`A user has disconnected from rolling collections`);
      }
      socket.leave(rollingId);
      delete (socket as any).rollingId;
      delete (socket as any).collectionId;
    }

    if (socket.rollingCollectionManager) {
      const manager = socket.rollingCollectionManager;
      manager.removeSocketClient();
      delete socket.rollingCollectionManager;
    }
    socket.removeAllListeners();
  }



  onPauseCollection(socket: Socket) {
    log.debug('RollingCollectionHandler: onPauseCollection()');
    
    if (socket.rollingCollectionManager) {
      const manager = socket.rollingCollectionManager;
      manager.pause();
    }
    if (socket.collectionId) {
      const collection = this.afbConfig.getCollection(socket.collectionId);
      log.info(`User '${socket.conn.jwtuser.username}' has paused monitoring collection '${collection.name}'`)
    }

  }



  onUnpauseCollection(socket: Socket) {
    log.debug('RollingCollectionHandler: onUnpauseCollection()');

    if (socket.rollingCollectionManager) {
      const manager = socket.rollingCollectionManager;
      manager.unpause();
    }
    if (socket.collectionId) {
      const collection = this.afbConfig.getCollection(socket.collectionId);
      log.info(`User '${socket.conn.jwtuser.username}' has unpaused monitoring collection '${collection.name}'`)
    }
  }
  

  
  onHttpConnection(req: Request, res: Response) {
    // Builds and streams a rolling or monitoring collection back to the client.  Handles the client connection and kicks off the process
    
    const collectionId: string = req.params.collectionId;
    const collection = this.afbConfig.getCollection(collectionId);
    const clientSessionId = req.headers.afbsessionid as string;
    const jwtUser = req.user as JwtUser;
    
    log.debug('RollingCollectionHandler: onHttpConnection(): collectionId:', collectionId);
    // log.debug('preferences:', this.afbConfig.preferences);
    
    let rollingId: string = collectionId;
    // rollingId is either the collectionId (for rolling collections), or the clientSessionId (for monitoring collections).
    // our classes will refer to this id when accessing the rollingCollections object
    if ( collection.type === 'monitoring' ) {
      rollingId = clientSessionId;
    }

    log.debug('RollingCollectionHandler: onHttpConnection(): rollingId:', rollingId);
    log.info(`User '${jwtUser.username}' has connected to ${collection.type} collection '${collection.name}'`);
    
    // create a client connection handler for this connection
    // does a manager for the requested rolling collection exist?
    // if not, create a new rolling collection manager
    // add new or existing rolling collection manager to the client connection handler
    
    const clientConnection = new HttpConnection(this, collectionId, rollingId, req, res);
    if ( !clientConnection.onConnect(collection) ) {
      return;
    }
    
    let rollingCollectionManager: RollingCollectionManager;
    if ( !(rollingId in this.rollingCollectionManagers)) {
      // there is no RollingCollectionManager yet for the chosen collection.  So create one
      rollingCollectionManager = new RollingCollectionManager(this, collection, collectionId, rollingId);
      this.rollingCollectionManagers[rollingId] = {
        rollingId,
        collectionId,
        manager: rollingCollectionManager
      };
    }
    else {
      // there's already a manager for the chosen collection
      rollingCollectionManager = this.rollingCollectionManagers[rollingId].manager;
    }

    // give the client connection object the rolling collection manager to attach itself to
    clientConnection.addManager(rollingCollectionManager);
    
  }



  pauseMonitoringCollectionHttp(req: Request, res: Response) {
    const clientSessionId = req.headers.afbsessionid as string;
    log.debug(`RollingCollectionHandler pauseMonitoringCollectionHttp(): Pausing monitoring collection ${clientSessionId}`);
    // log.info(`User '${req.user.username}' has paused monitoring collection '${this.afbConfig.collections[rollingId].name}'`)
    const manager = this.rollingCollectionManagers[clientSessionId].manager;
    manager.pause();
    res.status(202).send( JSON.stringify( { success: true } ) );
  }



  unpauseMonitoringCollectionHttp(req: Request, res: Response) {
    // This only gets used by the client if a monitoring collection is paused and then resumed within the minute the run is permitted to continue executing
    // Otherwise, the client will simply call /api/collection/rolling/:id again
    const clientSessionId = req.headers.afbsessionid as string;
    log.debug(`RollingCollectionHandler: unpauseMonitoringCollectionHttp(): Resuming monitoring collection ${clientSessionId}`);
    // log.info(`User '${req.user.username}' has unpaused monitoring collection '${this.afbConfig.collections[rollingId].name}'`)
    const manager = this.rollingCollectionManagers[clientSessionId].manager;
    manager.unpause();
    res.status(202).send( JSON.stringify( { success: true } ) );
  }



  collectionEdited(collectionId: string, editedCollection: Collection) {
    log.debug('RollingCollectionHandler: collectionEdited()');
    Object.values(this.rollingCollectionManagers)
      .filter( (manager) => manager.collectionId === collectionId)
      .forEach( (manager) => manager.manager.onCollectionEdited(editedCollection));
  }


  
  collectionDeleted(collectionId: string, username: string) {
    log.debug('RollingCollectionHandler: collectionDeleted()');
    Object.values(this.rollingCollectionManagers)
      .filter( (manager) => manager.collectionId === collectionId)
      .forEach( (manager) => manager.manager.onCollectionDeleted(username));
  }


  
  async removeRollingCollectionManager(rollingId: string) {
    log.debug('RollingCollectionHandler: removeRollingCollectionManager()');
    delete this.rollingCollectionManagers[rollingId];
    // disconnect all client sockets from this collection's room
    if (!(rollingId in this.roomSockets)) {
      log.error('No sockets could be found for fixed collection', rollingId);
    }
    else {
      this.roomSockets[rollingId].forEach( (socket) => this.onLeaveCollection(socket));
      delete this.roomSockets[rollingId];
    }
    try {
      log.debug('Deleting output directory for collection', rollingId);
      await rmfr( `${this.afbConfig.collectionsDir}/${rollingId}` ); // Delete output directory
    }
    catch (error: any) {
      log.error(`ERROR deleting output directory ${this.afbConfig.collectionsDir}/${rollingId}`, error);
      throw new Error(error);
    }
  }



  killAll() {
    // we get here during server shutdown
    log.debug('RollingCollectionHandler: killAll()');
    Object.values(this.rollingCollectionManagers).forEach( manager => {
      manager.manager.abort();
    });
  }



  restartRunningCollections() {
    // we get here during server shutdown
    log.debug('RollingCollectionHandler: restartRunningCollections()');
    Object.values(this.rollingCollectionManagers).forEach( manager => {
      manager.manager.restart();
    });
  }



  updateFeederSocketFile(filename: string) {
    this.feederSocketFilename = filename;
  }

}
  
  
  
  
  
  
  
  
  
  
  
  

  
  

class HttpConnection {

  handler: RollingCollectionHandler;
  collectionId: string;
  collection: Collection;
  rollingId: string;
  req: Request;
  res: Response;
  afbConfig: ConfigurationManager
  id = uuidV4();
  manager!: RollingCollectionManager;
  heartbeatInterval?: NodeJS.Timer;
  disconnected = false;
  jwtUser: JwtUser;

  constructor(handler: RollingCollectionHandler, collectionId: string, rollingId: string, req: Request, res: Response) {
    log.debug('HttpConnection: constructor()');
    this.handler = handler;
    this.afbConfig = this.handler.afbConfig;
    this.req = req;
    this.jwtUser = req.user as JwtUser;
    this.res = res;
    res.setHeader('transfer-encoding', 'chunked');
    this.collectionId = collectionId;
    this.rollingId = rollingId;
    this.collection = this.afbConfig.getCollection(collectionId);
  }



  onConnect(collection: Collection) {
    log.debug('HttpConnection: onConnect():');

    ////////////////////////////////////////////////////
    //////////////////RESPONSE HEADERS//////////////////
    ////////////////////////////////////////////////////
  
    try {
      // Write the response headers
      if (collection.bound && !( 'usecase' in collection )) {
        throw new Error(`Bound collection ${this.collectionId} does not have a use case defined`);
      }
      if (collection.bound && !(this.afbConfig.hasUseCase(collection.usecase)) ) {
        throw new Error(`Use case ${collection.usecase} in bound collection ${this.collectionId} is not a valid use case`);
      }
      if (collection.type === 'rolling' || collection.type === 'monitoring') {
        this.res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': 'inline' } );
        this.res.write('['); // Open the array so that oboe can see it
      }
      else {
        throw new Error(`Collection ${this.collectionId} is not of type 'rolling' or 'monitoring'`);
      }
    }
    catch (error: any) {
      log.error('HttpConnection: onConnect():', error);
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
    log.debug('HttpConnection: onClientClosedConnection()');
    log.info(`User '${this.jwtUser.username}' has disconnected from ${this.collection.type} collection '${this.collection.name}'`);
    this.disconnected = true;
    // This block runs when the client disconnects from the session
    // But NOT when we terminate the session from the server
    
    if (this.heartbeatInterval) {
      // stop sending heartbeats to client
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = undefined;
    }
    
    this.manager.removeHttpClient(this.id);

    this.end();
  }



  addManager(manager: RollingCollectionManager) {
    log.debug('HttpConnection: addManager()');
    this.manager = manager;
    this.manager.addHttpClient(this.id, this);
  }



  send(data: unknown) {
    // log.debug('HttpConnection: send()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( `${JSON.stringify(data)},` );
    }
  }



  sendRaw(data: unknown) {
    log.debug('HttpConnection: sendRaw()');
    // sends data to the client
    if (!this.disconnected) {
      this.res.write( data );
    }
  }



  end() {
    log.debug('HttpConnection: end()');
    if (this.heartbeatInterval) {
      // stop sending heartbeats to client
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = undefined;
    }
    this.sendRaw('{"close":true}]'); // Close the array so that oboe knows we're done
    this.res.end() // not sure if this will work if already disconnected
  }


}


















export class RollingCollectionManager {

  handler: RollingCollectionHandler;
  collection: Collection;
  collectionId: string;
  rollingId: string;
  afbConfig: ConfigurationManager;
  channel: Namespace;
  observers = 0; // the number of clients that are currently connected to the collection, both http and socket.io
  httpClients: Record<string, HttpConnection> = {};  // holds references to http connection objects
  sessions: Session[] = [];
  content: ContentItem[] = [];
  search: Search[] = [];
  lastQueryEndTime?: number; // the end time of the last query to run
  lastRun?: number; // the last time that the worker actually ran
    
  monitoringCollection = false;
  paused = false;
  timeOfPause = 0;
  pauseTimeout = undefined;

  // worker
  workerProcesses: ChildProcess[] = []; // holds process handles for the workers
  workInterval?: NodeJS.Timer; // holds the interval handle for the ongoing work loop
  workerSockets: NetSocket[] = []; // holds the unix sockets for connections back from the workers
  runs = 0; // the number of times that a worker has been run
  runContent: Record<number, ContentItem[]> = {};  // This holds the content generated by each invidual run of the worker.  The key is the run number.  Only used for SA monitoring collections, because more than one worker is allowed to run
  resumed = false; // this indicates that work() has already run but it was killed, therefore collection data is still in memory.  Use this to direct the query timeframe on subsequent work() runs
  restartWorkLoopOnExit = false;  // this will cause an already-killed workLoop() to restart when the worker exits, if there was a residual worker still running
  workLoopWaitingToStart = false; // this is set to true when onWorkerExit restarts the workLoop after restartWorkLoopOnExit is true, and fewer than 60 seconds has elapsed since the start of the last loop.  During the time when the workLoop is waiting to start again, this will prevent future clients from starting additional workLoops.  It's for an edge case.

  // destruction
  destroyThreshold = 3600; // wait one hour to destroy
  destroyTimeout?: NodeJS.Timeout;  // holds setTimeout for destroy().  Cancel if we get another connection within timeframe
  destroyed = false;
  
  purgeTest = false;
  purgeTestMinutes: number;


  constructor(handler: RollingCollectionHandler, collection: Collection, collectionId: string, rollingId: string) {
    log.debug('RollingCollectionManager: constructor()');
    this.handler = handler;
    this.afbConfig = this.handler.afbConfig;
    this.channel = this.handler.channel; // a handle to our socket.io /collections namespace
    
    // collections
    this.rollingId = rollingId;
    this.collectionId = collectionId;
    this.collection = collection;
    this.monitoringCollection = false;
    
    if (this.collection.type === 'monitoring') {
      this.paused = false;
      this.monitoringCollection = true;
      this.timeOfPause = 0;
      this.pauseTimeout = undefined;
    }
    this.purgeTest = this.handler.purgeTest;
    this.purgeTestMinutes = this.handler.purgeTestMinutes;
  }



  run() {
    log.debug('RollingCollectionManager: run()');
    // Now schedule workLoop() to run every 60 seconds and store a reference to it in this.workInterval
    // which we can later use to terminate the timer and prevent future execution.
    // This will not initially execute work() until the first 60 seconds have elapsed, which is why we run workLoop() immediately after
    this.workInterval = setInterval( () => this.workLoop(), 60000);
    this.workLoop();
  }



  async selfDestruct() {
    log.debug('RollingCollectionManager: selfDestruct()');
    this.collection.state = 'stopped';
    if (!this.monitoringCollection) {
      log.debug(`RollingCollectionManager: selfDestruct(): No clients have reconnected to rolling collection ${this.rollingId} within ${this.destroyThreshold} seconds. Self-destructing`);
    }
    else {
      log.debug(`RollingCollectionManager: selfDestruct(): Client disconnected from monitoring collection ${this.rollingId}.  Self-destructing`);
    }
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = undefined;
    }
    this.killWorker();
    this.handler.removeRollingCollectionManager(this.rollingId);
  }



  addHttpClient(id: string, client: HttpConnection) {
    log.debug('RollingCollectionManager: addHttpClient()');
    this.httpClients[id] = client;
    this.observers += 1;
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = undefined;
    }

    if (this.monitoringCollection) {
      client.send({paused: this.paused});
    }
    
    if (this.runs === 0) {
      this.run();
    }
    
    if (this.runs > 0) {
      log.debug(`RollingCollectionManager: addHttpClient(): This is not the first client to have connected to rolling collection ${this.rollingId}.  Replaying existing collection`);

      // Play back sessions
      // We must do it this way because the client expects an object
      // We store sessions internally as an array of objects
      const sessions: Record<string, Session> = {};
      this.sessions.forEach(session => sessions[session.id] = session)

      client.send({
        wholeCollection: {
          images: this.content,
          sessions: sessions,
          search: this.search
        }
      });

      if (this.workInterval) {
        // workInterval is already running - just let it continue
        log.debug('RollingCollectionManager: addHttpClient(): there is an existing workInterval running.  Not starting workLoop');
        return;
      }

      else if (this.workLoopWaitingToStart) {
        log.debug('RollingCollectionManager: addHttpClient(): workLoopWaitingToStart is true.  Not starting the workLoop');
        return;
      }

      else if (!this.workInterval) {
        // there is no existing workInterval.  Better check for a running worker in case there's an old one still floating about
        log.debug(`RollingCollectionManager: addHttpClient(): workerProcess.length: ${this.workerProcesses.length}`);

        if (this.workerProcesses.length !== 0) {
          // there's already a worker process running.  When it exits, instruct it to restart the workLoop
          log.debug('RollingCollectionManager: addHttpClient(): there is an existing workerProcess.  The workLoop will be restarted when it exits.  Setting restartWorkLoopOnExit to true');
          this.restartWorkLoopOnExit = true;
          return;
        }

        else if (this.workerProcesses.length === 0) {
          // no worker is running and there is no work interval.  Start the workLoop
          this.resumed = true;
          log.debug('RollingCollectionManager: addHttpClient(): there is no existing workerProcess.  Starting workLoop');
          this.restartWorkLoopOnExit = false;
          this.run();
        }
      }
    }
  }



  addSocketClient(socket: Socket) {
    log.debug('RollingCollectionManager: addSocketClient()');
    this.observers += 1;
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = undefined;
    }

    if (this.monitoringCollection) {
      socket.emit('paused', this.paused);
    }
    
    if (this.runs === 0) {
      this.run();
    }
    
    if (this.runs > 0) {
      log.debug(`RollingCollectionManager: addSocketClient(): This is not the first client to have connected to rolling collection ${this.rollingId}.  Replaying existing collection`);

      // Play back sessions
      // We must do it this way because the client expects an object
      // We store sessions internally as an array of objects
      const sessions: Record<string, Session> = {};
      this.sessions.forEach(session => sessions[session.id] = session);
      socket.emit('sessions', sessions );

      // play back images
      socket.emit('content', this.content);

      // Play back search text
      socket.emit('searches', this.search);

      // Emit collection state
      socket.emit('state', this.collection.state);

      log.debug(`RollingCollectionManager: addSocketClient(): Current number of observers: ${this.observers}`);

      if (this.workInterval) {
        // workInterval is already running - just let it continue
        log.debug('RollingCollectionManager: addSocketClient(): there is an existing workInterval running.  Not starting workLoop');
        return;
      }

      else if (this.workLoopWaitingToStart) {
        log.debug('RollingCollectionManager: addSocketClient(): workLoopWaitingToStart is true.  Not starting the workLoop');
        return;
      }

      else if (!this.workInterval) {
        // there is no existing workInterval.  Better check for a running worker in case there's an old one still floating about
        log.debug(`RollingCollectionManager: addSocketClient(): workerProcess.length: ${this.workerProcesses.length}`);

        if (this.workerProcesses.length !== 0) {
          // there's already a worker process running.  When it exits, instruct it to restart the workLoop
          log.debug('RollingCollectionManager: addSocketClient(): there is an existing workerProcess.  The workLoop will be restarted when it exits.  Setting restartWorkLoopOnExit to true');
          this.restartWorkLoopOnExit = true;
          return;
        }

        else if (this.workerProcesses.length === 0) {
          // no worker is running and there is no work interval.  Start the workLoop
          this.resumed = true;
          log.debug('RollingCollectionManager: addSocketClient(): there is no existing workerProcess.  Starting workLoop');
          this.restartWorkLoopOnExit = false;
          this.run();
        }
      }
    }
  }



  onCollectionEdited(collection: Collection) {
    // If the collection gets edited, we must assume that some critical element has changed...
    // and that we must blow away the existing data and work jobs, and start over
    log.debug('RollingCollectionManager: onCollectionEdited()');
    
    // stop the work loop
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = undefined;
    }
    
    // stop any running workers
    this.killWorker();
    
    this.collection = collection;
    this.sessions = [];
    this.content = [];
    this.search = [];
    this.runs = 0;
    this.lastQueryEndTime = undefined;
    this.lastRun = undefined;
    this.resumed = false;

    this.sendToRoom('clear', true); // this only triggers when a collection is edited.  no other time
    this.sendToHttpClients( { wholeCollection: { images: [], sessions: {}, search: [] } } );
   
    if (this.observers !== 0) {
      this.run();
    }
  }



  async onCollectionDeleted(username: string) {
    log.debug('RollingCollectionManager: onCollectionDeleted()');
    this.destroyed = true;

    // stop the work loop
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = undefined;
    }
    
    // stop any running workers
    this.killWorker();
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = undefined;
    }

    this.sendToHttpClients( { collectionDeleted: true, user: username } );
    this.endAllClients();
    this.handler.removeRollingCollectionManager(this.rollingId);
  }



  async abort() {
    // we only get here in this case:
    //   1. the program is exiting, either gracefully or due to an error
    log.debug('RollingCollectionManager: abort()');

    // stop the work loop
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = undefined;
    }

    this.killWorker();
    
    if (this.destroyTimeout) {
      clearTimeout(this.destroyTimeout);
      this.destroyTimeout = undefined;
    }

    const state = 'stopped';
    this.collection.state = state;
    this.sendToRoom('state', state);
    this.endAllClients(); // disconnects socket and http clients
    
    await this.afbConfig.updateRollingCollection(this.collectionId) // save collection state
    
    this.handler.removeRollingCollectionManager(this.collectionId);
  }



  async restart() {
    log.debug('RollingCollectionManager: restart()');

    // we only get here in this case:
    //   1. query delay minutes has been updated
    
    // stop the work loop
    if (this.workInterval) {
      clearInterval(this.workInterval);
      this.workInterval = undefined;
    }
    
    // stop any running workers
    this.killWorker();
    
    this.sessions = [];
    this.content = [];
    this.search = [];
    this.runs = 0;
    this.lastQueryEndTime = undefined;
    this.lastRun = undefined;
    this.resumed = false;

    this.sendToRoom('clear', true); // this only triggers when a collection is edited.  no other time
    this.sendToHttpClients( { wholeCollection: { images: [], sessions: {}, search: [] } } );

    if (this.observers !== 0) {
      this.run();
    }
  }



  killWorker() {
    log.debug('RollingCollectionManager: killWorker()');
    this.workerSockets.forEach(
      (workerSocket) => workerSocket.removeAllListeners()
    );
    this.workerSockets = [];

    this.workerProcesses.forEach( (workerProcess) => {
      workerProcess.removeAllListeners(); // not sure whether we need this or not - probably do
      workerProcess.kill('SIGINT');
    })
    this.workerProcesses = [];
  }



  removeHttpClient(id: string) {
    log.debug('RollingCollectionManager: removeHttpClient()');
    this.observers -= 1;

    if (this.observers !== 0) {
      log.debug('RollingCollectionManager: removeHttpClient(): Client disconnected from rolling collection with rollingId', this.rollingId);
    }

    else {
      log.debug(`RollingCollectionManager: removeHttpClient(): Last client disconnected from rolling collection with rollingId ${this.rollingId}.  Waiting for ${this.destroyThreshold} seconds before self-destructing`);
      this.destroyTimeout = setTimeout( () => this.selfDestruct(), this.destroyThreshold * 1000); // trigger the countdown to self-destruct
      this.restartWorkLoopOnExit = false;
      clearInterval(this.workInterval);
      this.workInterval = undefined;
      // we want any running workers to finish, so that we have complete data if someone rejoins
    }

    delete this.httpClients[id];
  }



  removeSocketClient() {
    log.debug('RollingCollectionManager: removeSocketClient()');
    this.observers -= 1;

    if (this.monitoringCollection) {
      log.debug(`RollingCollectionManager: removeSocketClient(): Client disconnected from monitoring collection with rollingId ${this.rollingId}.  Waiting for 5 seconds before self-destructing`);
      this.destroyTimeout = setTimeout( () => this.selfDestruct(), 5000); // trigger the countdown to self-destruct
      this.restartWorkLoopOnExit = false;
      return;
    }
   

    if (this.observers !== 0) {
      log.debug('RollingCollectionManager: removeSocketClient(): Socket client disconnected from rolling collection with rollingId', this.rollingId);
    }

    else {
      log.debug(`RollingCollectionManager: removeSocketClient(): Last client disconnected from rolling collection with rollingId ${this.rollingId}.  Waiting for ${this.destroyThreshold} seconds before self-destructing`);
      this.destroyTimeout = setTimeout( () => this.selfDestruct(), this.destroyThreshold * 1000); // trigger the countdown to self-destruct
      this.restartWorkLoopOnExit = false;
      clearInterval(this.workInterval);
      this.workInterval = undefined;
      // we want any running workers to finish, so that we have complete data if someone rejoins
    }
  }



  pause() {
    log.debug('RollingCollectionManager: pause()');
    this.paused = true;
    this.timeOfPause = moment().unix();
    this.sendToRoom('paused', true);
  }



  unpause() {
    log.debug('RollingCollectionManager: unpause()');
    this.paused = false;
    const timeOfResume = moment().unix();
    const difference = timeOfResume - this.timeOfPause;
    log.debug('RollingCollectionManager: unpause(): difference:', difference);

    if (difference >= 60) {
      // more than a minute has elapsed since pause. Resume immediately and restart loop
      clearInterval(this.workInterval);
      this.workInterval = setInterval( () => this.workLoop(), 60000);
      this.workLoop();
    }
    this.timeOfPause = 0;
    this.sendToRoom('paused', false);
  }



  sendToWorker(data: unknown, workerSocket: NetSocket) {
    log.debug('RollingCollectionManager: sendToWorker()');
    workerSocket.write( `${JSON.stringify(data)}\n` );
  }



  sendToHttpClients(data: unknown) {
    // log.debug('RollingCollectionManager: sendToHttpClients()');
    Object.values(this.httpClients).forEach(client => client.send(data));
  }



  sendToHttpClientsRaw(data: unknown) {
    // sends RAW data to all connected HTTP clients
    log.debug('RollingCollectionManager: sendToHttpClientsRaw()');
    Object.values(this.httpClients).forEach(client => client.sendRaw(data));
  }



  sendToRoom(type: string, data: unknown) {
    // sends data to all connected socket.io clients
    if (this.channel) {
      this.channel.to(this.rollingId).emit( type, data );
    }
  }



  endAllClients() {
    // disconnects socket and http clients
    log.debug('RollingCollectionManager: endAllClients()');
    this.endHttpClients();
    this.sendToRoom('disconnectClients', true);
  }


  
  endHttpClients() {
    log.debug('RollingCollectionManager: endHttpClients()');
    Object.values(this.httpClients).forEach(client => client.end());
  }



  workLoop() {
    // Main body of worker execution
    log.debug('RollingCollectionManager: workLoop()');

    if (!this.monitoringCollection && this.lastRun && this.resumed && (moment().unix() - this.lastRun < 60) ) {
      log.debug(`RollingCollectionManager: workLoop(): Fewer than 60 seconds have elapsed since the last cycle run for rollingId ${this.rollingId}.  Skipping this cycle`);
      return;
    }

    try {
      log.debug('workLoop(): Starting run for rollingId', this.rollingId);
      if (this.monitoringCollection && this.paused) {
        log.debug(`workLoop(): Collection ${this.rollingId} is paused.  Skipping worker run for this cycle`);
        return;
      }

      if ( !this.monitoringCollection && this.workerProcesses.length !== 0 && this.runs === 1) {
        // If we're a rolling collection still on our first run, let it continue running until it completes
        log.debug('workLoop(): First run of rolling collection is still running.  Delaying next run by 60 seconds');
        return;
      }

      ///////////////////////////
      //PURGE AGED-OUT SESSIONS//
      ///////////////////////////
      this.calculateSessionsToPurge();

      if ( ( !this.monitoringCollection && this.workerProcesses.length !== 0 && this.runs > 1 ) ||
           ( this.monitoringCollection && this.collection.serviceType === 'nw' && this.workerProcesses.length !== 0 )
         ) {
        // If not a monitoring collection, check if there's already a python worker process already running which has overrun the 60 second mark, and if so, kill it
        log.debug('workLoop(): Timer expired for running worker.  Terminating worker');
        (this.workerProcesses.shift() as ChildProcess).kill('SIGINT');
      }

      if ( this.monitoringCollection && this.collection.serviceType === 'sa' && this.workerProcesses.length === 2 ) {
        // If an SA monitoring collection, check if there are already two python workers already running.  If so, kill the older worker.  We want to allow two workers to run simultaneously in SA's case
        log.debug('workLoop(): Timer expired for running worker 1.  Terminating worker');
        (this.workerProcesses.shift() as ChildProcess).kill('SIGINT');
      }

      // Create temp file to be used as our UNIX domain socket
      const tempName = temp.path({suffix: '.socket'});

      // Now open the UNIX domain socket that will talk to the worker script by creating a handler (or server) to handle communications
      let workerSocket = undefined;
      const socketServer = net.createServer( (wSocket) => { 
        workerSocket = wSocket;
        /*if (this.collection.serviceType === 'sa') {
          // this is a temp space for content for this run of the worker, so that we can delete it later
          // 2022.05.28 -- Don't think this is relevant any more
          workerSocket.content = [];
        }*/
        this.workerSockets.push(workerSocket);
        this.onConnectionFromWorker(tempName, workerSocket);
        // We won't write any more data to the socket, so we will call close() on socketServer.  This prevents the server from accepting any new connections
        socketServer.close();
      });

      socketServer.listen(tempName, () => {
        // Tell the server to listen for communication from the not-yet-started worker

        log.debug('workLoop(): listen(): Rolling Collection: Listening for worker communication');
        log.debug(`workLoop(): listen(): Rolling Collection: Spawning worker with socket file ${tempName}`);
        
        // Start the worker process and assign a reference to it to 'worker'
        // Notice that we don't pass any configuration to the worker on the command line.  It's all done through the UNIX socket for security.
        const workerProcess = spawn('./worker/worker_stub.py', [tempName, '2>&1'], { shell: false, stdio: 'inherit'});
        workerProcess.workerSockets = this.workerSockets;
        workerProcess.on('exit', (code, signal) => this.onWorkerExit(code, signal, workerProcess.pid, tempName) );
        this.workerProcesses.push(workerProcess);
      });
    }

    catch (error: any) {
      log.error('workLoop(): work(): Caught unhandled error:', error);
    }
    
  }



  onWorkerExit(code: number | null, signal: NodeJS.Signals | null, pid: number | undefined, tempName: string) {
    // This is where we handle the exiting of the worker process
    log.debug(`onWorkerExit(): Worker with PID ${pid} exited.  Rolling collection update cycle is complete`);
    this.workerProcesses.forEachReverse(
      (workerProcess, i) => {
        log.debug(`onWorkerExit(): matched process with pid ${pid},  Removing process from workerProcess table`);
        this.workerProcesses.splice(i, 1);
      }
    );

    this.workerSockets.forEachReverse(
      (workerSocket, i) => {
        const address = (workerSocket as any)?.server?.address();
        if (address && tempName === address) {
          log.debug('onWorkerExit(): matched workerSocket.  Deleting it');
          fs.unlink(tempName, utils.noop ); // Delete the temporary UNIX socket file
          this.workerSockets.splice(i, 1);
        }
      }
    );

    if (signal) {
      log.debug('onWorkerExit(): Worker process was terminated by signal', signal);
      // Tell client that we're resting
      this.collection.state = 'resting';
      this.sendToRoom('state', this.collection.state);
      this.sendToHttpClients({
        collection: {
          id: this.collectionId,
          state: this.collection.state
        }
      });
    }
    // Handle normal worker exit code 0
    else if (!code) {
      log.debug('onWorkerExit(): Worker process exited normally with exit code 0');
      // Tell clients that we're resting
      this.collection.state = 'resting';
      this.sendToRoom('state', this.collection.state);
      this.sendToHttpClients({
        collection: {
          id: this.collectionId,
          state: this.collection.state
        }
      });
    }
    else if (code) {
      // Handle worker exit with non-zero (error) exit code
      log.debug('onWorkerExit(): Worker process exited in bad state with non-zero exit code', code );
      this.collection.state = 'error';
      this.sendToRoom('state', this.collection.state);
      this.sendToHttpClients( {
        collection: {
          id: this.collectionId,
          state: this.collection.state
        }
      });
    }

    if (this.monitoringCollection && this.paused) {
      // Monitoring collection is paused
      // Now we end and delete this monitoring collection, except for its files (which still may be in use on the client)
      log.debug('onWorkerExit(): Completing work for paused monitoring collection', this.rollingId);
      this.afbConfig.updateRollingCollection(this.collectionId);
      return;
    }

    // Save the collection to the DB
    this.afbConfig.updateRollingCollection(this.collectionId);

    if (this.restartWorkLoopOnExit && this.workerProcesses.length === 0 && this.lastRun) {
      log.debug('onWorkerExit(): restartWorkLoopOnExit is true.  Triggering new workLoop() interval')
      this.restartWorkLoopOnExit = false;
      // we could hit this block within a minute of the start of the last run.  If that happens, let's time the cycle to start at the one minute mark
      const mom = moment().unix();
      const secondsSinceLastRun = mom - this.lastRun;
      if ( secondsSinceLastRun < 60) {
        // if less than a minute has elapsed since the last run, time the cycle to start at the one minute mark
        log.debug(`onWorkerExit(): delaying start of next workLoop cycle by ${60 - secondsSinceLastRun} seconds`);
        this.workLoopWaitingToStart = true;
        setTimeout( () => {
          this.workLoopWaitingToStart = false;
          this.workInterval = setInterval( () => this.workLoop(), 60000);
          this.workLoop();
        }, (60 - secondsSinceLastRun) * 1000 );
      }
      else {
        // 60 or more seconds have elapsed since the last run - just start the work loop now
        this.workInterval = setInterval( () => this.workLoop(), 60000);
        this.workLoop();
      }
    }
  }



  async onConnectionFromWorker(tempName: string, workerSocket: NetSocket) {
    log.debug('RollingCollectionManager: onConnectionFromWorker()');
    // For rolling and monitoring collections
    // Handles all dealings with the worker process after it has been spawned, including sending it its configuration, and sending data received from it to the onDataFromWorker() function
    // It also purges old data from the collection as defined by the type of collection and number of hours back to retain
    
    this.runs++;
    
    log.debug('onConnectionFromWorker(): Connection received from worker to build rolling or monitoring collection', this.rollingId);
    
    if (this.monitoringCollection && !this.paused && this.collection.serviceType === 'nw') {
      // clean up nw monitoring collection files from last run
      await rmfr( `${this.afbConfig.collectionsDir}/${this.rollingId}/*`);
    }

    else if (this.monitoringCollection && !this.paused && this.collection.serviceType === 'sa') {

      // create an entry in runContent for this run
      this.runContent[this.runs] = [];
      
      // clean up sa monitoring collection files from five runs ago
      if ( (this.runs - 5) in this.runContent ) {
        log.debug(`onConnectionFromWorker(): Deleting content from worker run ${this.runs - 5}`);
        // clean up collection from 5 runs ago
        const content = this.runContent[this.runs - 5];
        content.forEach(
          (contentItem) => {
            if ('contentFile' in contentItem && contentItem.contentFile) {
              fs.unlink( `${this.afbConfig.collectionsDir}/${contentItem.contentFile}`, utils.noop );
            }
            if ('proxyContentFile' in contentItem && contentItem.proxyContentFile) {
              fs.unlink( `${this.afbConfig.collectionsDir}/${contentItem.proxyContentFile} `, utils.noop );
            }
            if ('pdfImage' in contentItem && contentItem.pdfImage) {
              fs.unlink( `${this.afbConfig.collectionsDir}/${contentItem.pdfImage} `, utils.noop );
            }
            if ('thumbnail' in contentItem && contentItem.thumbnail) {
              fs.unlink( `${this.afbConfig.collectionsDir}/${contentItem}.thumbnail` , utils.noop );
            }
            if ('archiveFilename' in contentItem && contentItem.archiveFilename) {
              fs.unlink( `${this.afbConfig.collectionsDir}/${contentItem.archiveFilename}`, utils.noop );
            }
          }
        );
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
    this.collection.state = ourState;
    if ( !(this.collection.serviceType === 'sa' && this.monitoringCollection) ) { // we do not want the client to clear the screen if it is an SA monitoring collection as it takes a long time to build.  let the client send it instead when it has data to send
      this.sendToRoom('state', ourState);
      this.sendToHttpClients( { collection: { id: this.collectionId, state: ourState}} );
    }
  
    //////////////////////////////////
    //Build the worker configuration//
    //////////////////////////////////
  
    const preferences = this.afbConfig.getPreferences();
    let cfg: Partial<WorkerConfig> = {
      id: this.rollingId,
      collectionId: this.collectionId, // original collection ID
      state: ourState,
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
      useHashFeed: this.collection.useHashFeed ?? false,
      serviceType: this.collection.serviceType,
      type: this.collection.type,
      onlyContentFromArchives: this.collection.onlyContentFromArchives || false
    };
  
    try {
      if (this.collection.serviceType === 'nw') {
        cfg = {
          ...cfg,
          queryTimeout: preferences.nw.queryTimeout,
          contentTimeout: preferences.nw.contentTimeout,
          maxContentErrors: preferences.nw.maxContentErrors,
          sessionLimit: preferences.nw.sessionLimit
        }
      }
    
      if (this.collection.serviceType === 'sa') {
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
      log.error('Caught error trying to read preferences.  Exiting with code 1.');
      process.exit(1);
    }
  
    if (this.collection.bound) {
      // This is an OOTB use case
      const useCaseName = this.collection.usecase;
      const useCase = this.afbConfig.getUseCase(useCaseName);
      cfg.query = this.collection.serviceType === 'nw'
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
      // This is not an OOTB use case
      cfg.distillationEnabled = this.collection.distillationEnabled;
      cfg.regexDistillationEnabled = this.collection.regexDistillationEnabled;
      
      if (!this.collection.useHashFeed) {
        // we're not using a hash feed
        cfg = {
          ...cfg,
          md5Enabled: this.collection.md5Enabled ?? false,
          sha1Enabled: this.collection.sha1Enabled ?? false,
          sha256Enabled: this.collection.sha256Enabled ?? false
        };

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
      else if (this.collection.useHashFeed && this.collection.hashFeed) {
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
  
    let queryDelaySeconds = this.collection.serviceType === 'nw'
      ? preferences.nw.queryDelayMinutes * 60
      : preferences.sa.queryDelayMinutes * 60;
    if (queryDelaySeconds < 60) {
      queryDelaySeconds = 60;
    }

    log.debug('The time is:', moment.utc().format('YYYY-MMMM-DD HH:mm:ss') );
    if (this.lastRun) {
      const mom = moment.utc(this.lastRun * 1000);
      log.debug('The time of lastRun is:', mom.format('YYYY-MMMM-DD HH:mm:ss') );
    }
    if (this.lastQueryEndTime) {
      const mom = moment.utc(this.lastQueryEndTime * 1000);
      log.debug('The time of lastQueryEndTime is:', mom.format('YYYY-MMMM-DD HH:mm:ss') );
    }

    if (this.monitoringCollection) {
      // If this is a monitoring collection, then set timeEnd and timeBegin to be a one minute window
      cfg.timeEnd = moment().startOf('minute').unix() - 1 - queryDelaySeconds;
      cfg.timeBegin = ( cfg.timeEnd - 60) + 1;
    }

    else if (this.runs === 1 && this.collection.lastHours !== undefined) {
      // This is the first run of a non-monitoring collection
      log.debug('onConnectionFromWorker(): Got first run');
      cfg.timeBegin = moment().startOf('minute').unix() - 1 - ( this.collection.lastHours * 60 * 60 ) - queryDelaySeconds ;
      cfg.timeEnd = moment().startOf('minute').unix() - 1 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
    }
    
    else if ( this.runs === 2 && !this.resumed && this.lastRun && this.lastQueryEndTime !== undefined && ( moment().unix() - this.lastRun > 60 ) ) {
      // This is the second run of a non-resumed non-monitoring collection - this allows the first run to exceed one minute of execution and will take up whatever excess time has elapsed during the first run's execution
      // It will only enter this block if 61 or more seconds have elapsed since the last run
      log.debug('onConnectionFromWorker(): Got second run');
      cfg.timeBegin = this.lastQueryEndTime + 1; // one second after the last run
      cfg.timeEnd = moment().startOf('minute').unix() - 1 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
    }
  
    else if ( this.runs >= 2 && !this.resumed && this.lastQueryEndTime !== undefined) {
      // This is the third or greater run of a non-resumed non-monitoring collection, or the second run of a non-resumed rolling collection for which the first run completed within the one minute threshold
      log.debug('onConnectionFromWorker(): Got subsequent run');
      cfg.timeBegin = this.lastQueryEndTime + 1; // one second after the last run
      cfg.timeEnd = cfg.timeBegin + 60; // add one minute to cfg[timeBegin]
    }

    else if ( this.resumed && this.lastQueryEndTime !== undefined && this.lastRun && ( moment().unix() - this.lastRun < 60 ) ) {
      // The non-monitoring collection has resumed and fewer than 60 seconds have elapsed since the last run
      // This happens when all clients disconnect from a non-monitoring collection, and the last workerProcess has finished, and then someone reconnects
      // shouldn't we just return here and wait for the next cycle to run? probably not, as the worker has already started by the time we get here.  This probably means we need to put a guard in somewhere else to prevent the worker from being launched if fewer than 60 seconds have elapsed since the last run.
      // A guard was added in workLoop() so we shouldn't enter this block anymore
      log.debug('onConnectionFromWorker(): Resumed collection and fewer than 60 seconds since last run');
      cfg.timeBegin = this.lastQueryEndTime + 1; // one second after the last run
      const secondsSinceLastRun = moment().unix() - this.lastRun;
      cfg.timeEnd = cfg.timeBegin + secondsSinceLastRun;
    }

    else if ( this.resumed && this.lastRun && this.lastQueryEndTime !== undefined && ( moment().unix() - this.lastRun >= 60 ) ) {
      // The non-monitoring collection has resumed and 60 seconds or more have elapsed since the last run
      log.debug('onConnectionFromWorker(): Resumed collection and greater than 60 seconds since last run');
      cfg.timeBegin = this.lastQueryEndTime + 1; // one second after the last run
      cfg.timeEnd = moment().startOf('minute').unix() - 1 - queryDelaySeconds;
    }
    
    this.resumed = false;

    const momBegin = moment.utc(cfg.timeBegin as number * 1000);
    log.debug('The time of timeBegin is:', momBegin.format('YYYY-MMMM-DD HH:mm:ss') );

    const momEnd = moment.utc(cfg.timeEnd as number * 1000);
    log.debug('The time of timeEnd is:', momEnd.format('YYYY-MMMM-DD HH:mm:ss') );
    
    this.lastRun = moment.utc().unix();
    this.lastQueryEndTime = cfg.timeEnd; // store the time of last run so that we can reference it the next time we loop


    if ('distillationTerms' in this.collection) {
      cfg.distillationTerms = this.collection.distillationTerms;
    }
    if ('regexDistillationTerms' in this.collection) {
      cfg.regexDistillationTerms = this.collection.regexDistillationTerms;
    }
    if ('md5Hashes' in this.collection) {
      cfg.md5Hashes = this.collection.md5Hashes;
    }
    if ('sha1Hashes' in this.collection) {
     cfg.sha1Hashes = this.collection.sha1Hashes;
    }
    if ('sha256Hashes' in this.collection) {
     cfg.sha256Hashes = this.collection.sha256Hashes;
    }
  
    // merge nw / sa server properties into cfg
    if (this.collection.serviceType === 'nw') {
      const nwserver = this.afbConfig.getNwServer(this.collection.nwserver);
      Object.entries(nwserver)
        .filter( ([key]) => ! ['id', '_id', 'deviceNumber', 'friendlyName'].includes(key))
        .forEach( ([key, value]) => (cfg as any)[key] = value);
    }
    if (this.collection.serviceType === 'sa') {
      const saserver = this.afbConfig.getSaServer(this.collection.saserver);
      Object.entries(saserver)
        .filter( ([key]) => ! ['id', '_id'].includes(key))
        .forEach( ([key, value]) => (cfg as any)[key] = value);
    }
    const outerCfg = { workerConfig: cfg };
    
    ////////////////////////
    //DEAL WITH THE SOCKET//
    ////////////////////////
  
    // Buffer for worker data
    let buffer = '';
  
    // Set socket options
    workerSocket.setEncoding('utf8');
    
    // Handle data received from the worker over the socket (this really builds the collection)
    workerSocket.on('data', (chunk) => buffer = this.onDataFromWorker(buffer, chunk, this.runs) );
    
    // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
    this.sendToWorker(outerCfg, workerSocket);
  }



  calculateSessionsToPurge() {
    if (this.monitoringCollection) {
      this.sessions = [];
      this.content = [];
      this.search = [];
    }
    else if (!this.monitoringCollection && this.runs > 1 && this.lastQueryEndTime !== undefined && this.collection.lastHours !== undefined && this.lastRun) {
      // Purge events older than this.collection.lastHours
  
      log.debug('Running purge routine');
      const sessionsIdsToPurge: number[] = [];
  
      // Calculate the maximum age a given session is allowed to be before purging it
      let maxTime = this.lastQueryEndTime - this.collection.lastHours * 60 * 60;
      if (this.purgeTest) { maxTime = this.lastRun - 60 * this.purgeTestMinutes; } // 5 minute setting used for testing
        
      this.sessions.forEach( (session) => {
        // Look at each session and determine whether it is older than maxtime
        // If so, add it to purgedSessionPositions and sessionsToPurge
        const sid = session.id;
        if ( this.collection.serviceType === 'nw' && session.meta.time && (session.meta.time as unknown as number) < maxTime ) {
          sessionsIdsToPurge.push(sid);
        }
        else if ( this.collection.serviceType === 'sa' && session?.meta?.stop_time?.length && this.convertSATime(session.meta.stop_time[0] as string) < maxTime ) {
          sessionsIdsToPurge.push(sid);
        }
      });
  
      this.purgeSessions(sessionsIdsToPurge.slice());
     
      // Notify the client of our purged sessions
      if (sessionsIdsToPurge.length > 0) {
        const update = { collectionPurge: sessionsIdsToPurge };
        this.sendToRoom('purge', sessionsIdsToPurge);
        this.sendToHttpClients(update);
      }
    }
  }



  purgeSessions(sessionsIdsToPurge: number[]) {
    log.debug('RollingCollectionManager: purgeSessions():', {sessionsIdsToPurge});

    while (sessionsIdsToPurge.length > 0) {
      const sessionToPurge = sessionsIdsToPurge.shift(); // a session ID
      this.sessions.forEachReverse(
        (session, i) => {
          // Remove purged sessions from this.sessions
          if (session.id === sessionToPurge) {
            this.sessions.splice(i, 1);
          }
        }
      );

      this.search.forEachReverse(
        (search, i) => {
          // Identify search items to purge from this.search
          if (search.session === sessionToPurge) {
            log.debug('purgeSessions(): purging search', search.session);
            this.search.splice(i, 1);
          }
        }
      );
      
      this.content.forEachReverse(
        (content, i) => {
          if (content.session === sessionToPurge) {
            // Purge content
            log.debug('purgeSessions(): purging content', content.session);
            if (content.contentFile) {
              fs.unlink(content.contentFile, utils.noop);
            }
            if (content.proxyContentFile) {
              fs.unlink(content.proxyContentFile, utils.noop);
            }
            if (content.thumbnail) {
              fs.unlink(content.thumbnail, utils.noop);
            }
            if (content.pdfImage) {
              fs.unlink(content.pdfImage, utils.noop);
            }
            this.content.splice(i, 1);
          }
        }
      );
    }
  }


  
  onDataFromWorker(buffer: string, chunk: Buffer, runNumber: number) {
    // Handles socket data received from the worker process
    // This actually builds the collection data structures and sends updates to the client
    log.debug('RollingCollectionManager: onDataFromWorker(): Processing update from worker');
    buffer += chunk.toString('utf8');

    const splt = buffer.split('\n').filter( (el) => el.length !== 0) ;

    if ( splt.length === 1 && buffer.indexOf('\n') === -1 ) {
      // this case means the split resulted in only one element and that doesn't contain the newline delimiter, which means we haven't received an entire update yet...
      // we'll continue and wait for the next update which will hopefully contain the delimiter
      return buffer;
    }
    const d = [];
    if ( splt.length === 1 && buffer.endsWith('\n') ) {
      // this case means the split resulted in only one element and that it does contain the newline delimiter.  This means we received a single complete update.
      d.push(splt.shift() );
      buffer='';
    }
    else if ( splt.length > 1 ) {
      // This case means the split resulted in multiple elements and that it does contain a newline delimiter...
      // This means we have at least one complete update, and possibly more.
      if (buffer.endsWith('\n')) {  // the last element is a full update as data ends with a newline
        while (splt.length > 0) {
          d.push(splt.shift());
        }
        buffer = '';
      }
      else {
        // the last element is only a partial update, meaning that more data must be coming
        while (splt.length > 1) {
          d.push(splt.shift());
        }
        buffer = splt.shift() as string;  // this should be the last partial update, which should be appended to in the next update
      }
    }

    while (d.length > 0) {
      const u = d.shift() as string;
      const update = JSON.parse(u) as WorkerData;

      if ('collectionUpdate' in update) {
        const collectionUpdate = update.collectionUpdate as CollectionUpdate
        this.sessions.push(collectionUpdate.session);
        
        if (collectionUpdate.search) {
          collectionUpdate.search.forEach( search =>this.search.push(search) );
        }

        collectionUpdate.images.forEach( (image) => {
          this.content.push(image);
          if (this.monitoringCollection && this.collection.serviceType === 'sa') {
            this.runContent[runNumber].push(image);
          }
        });
      }
      
      if ('state' in update) {
        this.sendToRoom('state', update.state);
        this.sendToHttpClients({
          collection: {
            id:
            this.collectionId,
            state: update.state
          }
        });
      }
      else {
        this.sendToRoom('update', update);
        this.sendToHttpClients(update);
      }
    }

    return buffer;
  }


  convertSATime(value: string): number {
    return parseInt(value.substring(0, value.indexOf(':')), 10);
  }
}
