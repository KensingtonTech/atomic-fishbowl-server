import sourceMapSupport from 'source-map-support';
sourceMapSupport.install();
import './types/global.js';
import './utils-prototype.js';
import dotenv from 'dotenv';
dotenv.config();
import passport from 'passport';
import jwt from 'jsonwebtoken';
import { Strategy as JwtStrategy, VerifiedCallback } from 'passport-jwt';
import { Strategy as LocalStrategy } from 'passport-local';
import { ExtractJwt } from 'passport-jwt';
import mongoose from 'mongoose';
import { UserModel, UserDoc } from './user-model.js';
import { v4 as uuidV4 } from 'uuid';
import fs from 'fs/promises';
import fssync from 'fs';
import net, { Socket as NetSocket } from 'net'; // for unix sockets
import rmfr from 'rmfr';
import { spawn, ChildProcess } from 'child_process';
import temp from 'temp';
import log from './logging.js';
import nodeCleanup from 'node-cleanup';
import * as utils from './utils.js';
import Express, { Request, Response, NextFunction } from 'express';
import Http from 'http';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import bodyParser from 'body-parser';
import { FixedCollectionHandler } from './fixed-collections.js';
import { RollingCollectionHandler } from './rolling-collections.js';
import { FeedScheduler } from './feed-scheduler.js';
import { BuildProperties } from './build-properties.js';
import { Server as SocketServer, Socket } from 'socket.io';
import { ConfigurationManager } from './configuration-manager.js';
import isDocker from 'is-docker';
import { JwtUser } from 'types/jwt-user';
import { Collection } from './types/collection';
import { AxiosRequestConfig } from 'axios';
import { SaServer } from 'types/sa-server';
import { NwServer } from 'types/nw-server';
import { Feed } from 'types/feed';

const app = Express();
const server = Http.createServer(app);
const listenPort = 3002;

const { Axios } = utils;
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());

// socket.io
const socketIoOptions = {
  pingTimeout: 25000,
  perMessageDeflate: false,
  httpCompression: false
};
const io = new SocketServer(server, socketIoOptions);
const collectionsChannel = io.of('/collections'); // create /collections namespace

// versioning
const version = `${BuildProperties.major}.${BuildProperties.minor}.${BuildProperties.patch}-${BuildProperties.level} Build ${BuildProperties.build}`;

// project file imports.  Handles native and minified cases
const devMode = utils.getStringEnvVar('NODE_ENV', 'development') === 'development';
const debugMode = utils.getBooleanEnvVar('AFB_DEBUG', true);
const purgeTest = utils.getBooleanEnvVar('PURGE_HACK', false); // causes sessions older than 5 minutes to be purged, if set to true.  Useful for testing purging without having to wait an hour
const purgeTestMinutes = utils.getNumberEnvVar('PURGE_HACK_MINUTES', 5);
const tokenSigningHack = utils.getBooleanEnvVar('TOKEN_SIGNING_HACK', false);
const tokenSigningHackSeconds = utils.getNumberEnvVar('TOKEN_SIGNING_HACK_SECONDS', 60);

log.info('Starting Atomic Fishbowl server version', version);
if (devMode) {
  log.level = 'debug';
  log.debug('Atomic Fishbowl Server is running in development mode');
}
else {
  log.level = 'info';
}
if (debugMode) {
  log.debug('Atomic Fishbowl Server debug logging is enabled');
  log.level = 'debug';
}

let feederSrvProcess: ChildProcess | undefined;
let rollingHandler: RollingCollectionHandler;
let fixedHandler: FixedCollectionHandler;


/// CONFIGURATION ///
let feederNetSocket: NetSocket;
let feederSocketFilename: string;
let feederInitialized = false;
let apiInitialized = false;

// Load config
const afbConfig = new ConfigurationManager(io, devMode);
const tokenMgr = afbConfig.getTokenManager();

// Multipart upload config
const upload = multer({ dest: afbConfig.tempDir });

// Set up feed scheduler
const scheduler = new FeedScheduler(afbConfig, io, (id: string) => schedulerUpdatedCallback(id));

// Create LibreOffice profiles dir
if ( !fssync.existsSync(afbConfig.dataDir) ) {
  log.info(`Creating data directory at ${afbConfig.dataDir}`);
  await fs.mkdir(afbConfig.dataDir);
}
if ( !fssync.existsSync(afbConfig.sofficeProfilesDir) ) {
  log.info(`Creating soffice profiles directory at ${afbConfig.sofficeProfilesDir}`);
  await fs.mkdir(afbConfig.sofficeProfilesDir);
}
if ( !fssync.existsSync(afbConfig.feedsDir) ) {
  log.info(`Creating feeds directory at ${afbConfig.feedsDir}`);
  await fs.mkdir(afbConfig.feedsDir);
}
if ( !fssync.existsSync(afbConfig.tempDir) ) {
  log.info(`Creating temp directory at ${afbConfig.tempDir}`);
  await fs.mkdir(afbConfig.tempDir);
}




/// STARTUP ///

(async function() {
  await afbConfig.connectToDB(); // this must come before mongoose user connection so that we know whether to create the default admin account
  await mongooseInit();
  tokenMgr.cleanBlackList();
  setInterval( () => tokenMgr.cleanBlackList(), 1000 * 60); // run every minute
  await cleanCollectionDirs();
  scheduler.updateSchedule( afbConfig.getScheduledFeeds() );
  try {
    startFeeder();
  }
  catch (error: any) {
    log.error('Caught error whilst starting feed server:', error);
    process.exit(1);
  }
})();



const logConnection = (req: Request, res: Response, next: NextFunction) => {
  log.info(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] ?? req.socket.remoteAddress}`);
  next();
}



const jwtAuth = (req: Request, res: Response, next: NextFunction) => passport.authenticate('jwt', { session: false } )(req, res, next);



/// LOGIN & LOGOUT ///

app.post(
  '/api/login',
  logConnection,
  passport.authenticate('local', { session: false }),
  async (req, res) => {
    let user;
    try {
      user = await UserModel.findOne({username: req.body.username, enabled: true});
    }
    catch (error: any) {
      log.info(`Error looking up user ${req.body.username}:`, error);
      res.json({ success: false, message: 'Authentication failed' });
    }

    if (!user) { // we likely will never enter this block as the validation is really already done by passport
      log.info(`Login failed for user ${req.body.username}.  User either not found or not enabled`);
      return res.json({ success: false, message: 'Authentication failed' });
    }
    
    log.info(`User ${req.body.username} has logged in`);
    log.debug(`Found user ${req.body.username}.  Signing token`);
    const tokenEpirySeconds = tokenSigningHack
      ? tokenSigningHackSeconds
      : afbConfig.tokenExpirationSeconds;
    log.debug('tokenExpirationSeconds:', tokenEpirySeconds);
    
    const token = jwt.sign(
      user.toObject({
        versionKey: false,
        transform: transformUser
      }),
      afbConfig.getJwtPrivateKey(),
      {
        subject: user.id,
        algorithm: 'RS256',
        expiresIn: tokenEpirySeconds,
        jwtid: uuidV4()
      }
    ); // expires in 24 hours

    if (req?.query?.socketId !== undefined) {
      // socketId is the socket.io socketID
      const socketId = req.query.socketId as string;
      const decoded = jwt.decode(token) as JwtUser;
      if (io.sockets.sockets.has(socketId)) {
        const socket = io.sockets.sockets.get(socketId);
        if (socket) {
          socket.conn.jwtuser = decoded; // write our token info to the socket so it can be accessed later
          tokenMgr.addSocketToken(socket); // decoded.jti, decoded.exp
          socket.once('clientReady', () => onClientReady(socket) );
          socket.emit('socketUpgrade');
        }
      }
      else {
        log.error(`User ${req.body.username} logged in with an invalid socket id: ${socketId}`);
      }
    }

    res.cookie(
      'access_token',
      token,
      {
        httpOnly: true,
        sameSite: 'none',
        secure: true
      }
    );
    res.json({
      success: true,
      user: user.toObject(),
      sessionId: uuidV4()
    });
  }
);



app.get(
  '/api/logout',
  logConnection,
  jwtAuth,
  async (req, res) => {
    const jwtUser = req.user as JwtUser;
    log.info(`User '${jwtUser.username}' has logged out`);
    const decoded = jwt.decode(req.cookies.access_token) as JwtUser; // we can use jwt.decode here without signature verification as it's already been verified during authentication
    const tokenId = decoded.jti; // store this
    tokenMgr.removeSocketTokensByJwt(tokenId); // downgrade sockets of token
    await tokenMgr.blacklistToken(tokenId); // blacklist the token
    res.clearCookie('access_token');
    res.status(200).json({ success: true });
  }
);



app.get(
  '/api/isloggedin',
  logConnection,
  jwtAuth,
  async (req, res) => {
    const jwtUser = req.user as JwtUser;
    const user = await UserModel.findOne({username: jwtUser.username});
    if (!user) {
      return res.status(401).send('Unauthorized');
    }
    log.info(`User '${user.username}' has logged in`);
    
    if ('query' in req && 'socketId' in req.query) {
      // socketId is the socket.io socketID
      const socketId = req.query.socketId as string;
      const decoded = jwt.decode(req.cookies.access_token)as JwtUser; // we can use jwt.decode here without signature verification as it's already been verified during authentication
    
      if (io.sockets.sockets.has(socketId)) {
        const socket = io.sockets.sockets.get(socketId);
        if (socket) {
          socket.conn.jwtuser = decoded; // write our token info to the socket so it can be accessed later
          tokenMgr.addSocketToken(socket); // decoded.jti, decoded.exp
          socket.once('clientReady', () => onClientReady(socket) );
          socket.emit('socketUpgrade');
        }
      }
      else {
        log.error(`User ${user.username} logged in with an invalid socket id: ${socketId}`);
      }
    }

    res.json({
      user: user.toObject(),
      sessionId: uuidV4()
    });
  }
);



/// USERS ///

const emitUsers = async (socket: SocketServer | Socket) => {
  try {
    const users = await UserModel.find({});
    socket.emit('users', users);
  }
  catch (error: any) {
    log.error('Error obtaining users:', error);
  }
}



app.get(
  '/api/user/:uname',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // get details of user uname
    const jwtUser = req.user as JwtUser;
    const uname = req.params.uname;
    log.info(`User '${jwtUser.username}' has requested info for user ${uname}`);
    try {
      const user = await UserModel.findOne( { username: uname } ).orFail();
      return res.json(user.toObject());
    }
    catch (error: any) {
      log.error(`ERROR finding user ${uname}:`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
    }
  }
);



app.post(
  '/api/user',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // add a new user
    const jwtUser = req.user as JwtUser;
    const newUser = req.body;
    try {
      if (!newUser.username) {
          throw new Error('\'username\' is not defined');
      }
      if (!newUser.password) {
        throw new Error('\'password\' is not defined');
      }
      if (!newUser.email) {
        throw new Error('\'email\' is not defined');
      }
      if (newUser.enabled === undefined) {
        throw new Error('\'enabled\' is not defined');
      }
    }
    catch (error: any) {
      return res.status(400).json({success: false, error: error.message ?? error})
    }
    newUser.password = afbConfig.decrypt(newUser.password);
    try {
      await UserModel.register(
        new UserModel({
          _id: uuidV4(),
          username: newUser.username,
          fullname: newUser.fullname,
          email: newUser.email,
          enabled: newUser.enabled
        }),
        newUser.password
      );
      log.info(`User '${jwtUser.username}' has added a new user '${newUser.username}'`);
      await emitUsers(io);
      return res.status(201).json({ success: true });
    }
    catch (error: any) {
      log.error(`Error adding user ${newUser.username} by user ${req.body.username} :`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
    }
  }
);



app.patch(
  '/api/user',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // edit an existing user
    const editedUser = req.body;
    if (!('password' in req.body)) {
      try {
        await UserModel.findOneAndUpdate( { id: editedUser.id }, editedUser);
        await emitUsers(io);
        return res.status(201).json({ success: true });
      }
      catch (error: any) {
        log.error(`ERROR modifying user with id ${editedUser.id}:`, error);
        return res.status(500).json({ success: false, error: error.message ?? error });
      }
    }
    else {
      log.debug(`Updating password for user with id ${editedUser.id}`);
      editedUser.password = afbConfig.decrypt(editedUser.password);

      // change password
      try {
        const newPassword = editedUser.password;
        delete editedUser.password;
        const user = await UserModel.findOneAndUpdate( { id: editedUser.id }, editedUser);
        if (!user) {
          throw new Error('User not found');
        }
        await user.setPassword(newPassword);
        await user.save();
        await emitUsers(io);
        return res.status(201).json({ success: true });
      }
      catch (error: any) {
        log.error('ERROR changing changing password:', error);
        res.status(500).json({ success: false, error: error.message ?? error });
        return;
      }
    }
  }
);



app.delete(
  '/api/user/:id',
  logConnection,
  jwtAuth,
  async(req, res) => {
    const id = req.params.id;
    try {
      const jwtUser = req.user as JwtUser;
      const user = await UserModel.findByIdAndRemove(id);
      if (!user) {
        return res.status(400).json({ success: false, error: 'Not found'});
      }
      log.info(`User '${jwtUser.username}' has deleted user ${user.username}`);
      await emitUsers(io);
      res.status(204).json({ success: true });
    }
    catch (error: any) {
      log.error('ERROR removing user:', error);
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
  }
);





//////////////////////COLLECTIONS//////////////////////
  

app.get(
  '/api/collection',
  logConnection,
  jwtAuth,
  (req, res) => {
    // Gets the configuration of all collections
    const jwtUser = req.user as JwtUser;
    log.info(`User '${jwtUser.username}' has requested the collections list`);
    try {
      res.json(afbConfig.getCollections());
    }
    catch (error: any) {
      log.error('ERROR GET /api/collection:', error);
      res.status(500).json({ success: false, error: error.message ?? error });
    }
  }
);



app.delete(
  '/api/collection/:id',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // Deletes a collection
    const jwtUser = req.user as JwtUser;
    const collectionId = req.params.id;
    let collection: Collection | undefined

    try {
      collection = afbConfig.getCollection(collectionId)
    }
    catch {
      log.info(`WARN DELETE /api/collection/${collectionId} : Collection not found` );
      return res.status(400).json({ success: false, error: `collection ${collectionId} not found`});
    }

    try {

      if (['rolling', 'monitoring'].includes(collection.type)) {
        rollingHandler.collectionDeleted(collectionId, jwtUser.username);
      }
      else if (collection.type === 'fixed' && collection.state !== 'complete') { // fixed
        fixedHandler.collectionDeleted(collectionId, jwtUser.username);
      }

      await afbConfig.deleteCollection(collectionId);
      tokenMgr.authSocketsEmit('collectionDeleted', { user: jwtUser.username, id: collectionId } ); // let socket clients know this has been deleted
    }
    catch (error: any) {
      res.status(500).json({ success: false, error: error.message ?? error });
      log.error(`Error deleting ${collection.type} collection with id ${collectionId}`);
      log.error(error);
      process.exit(1);
    }

    res.status(200).json({ success: true });
    log.info(`User '${jwtUser.username}' has deleted collection '${collection.name}'`);   
  }
);



app.get(
  '/api/collection/data/:id',
  logConnection,
  jwtAuth,
  (req, res) => {
    // Gets the collection data for a collection (content, sessions, and search)
    const jwtUser = req.user as JwtUser;
    const collectionId = req.params.id;
    let collection;
    let collectionData;

    try {
      collection = afbConfig.getCollection(collectionId)
      collectionData = afbConfig.getCollectionData(collectionId);
    }
    catch {
      log.info(`WARN DELETE /api/collection/${collectionId} : Collection not found` );
      return res.status(400).json({ success: false, error: `collection ${collectionId} not found`});
    }

    try {
      res.json(collectionData);
      log.info(`User '${jwtUser.username}' has requested the defintion of collection '${collection.name}'`);
    }
    catch (error: any) {
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
  }
);



app.post(
  '/api/collection',
  jwtAuth,
  async (req, res) => {
    // Adds a new collection
    // 'state' should always be at initial
    const jwtUser = req.user as JwtUser;
    try {
      const timestamp = new Date().getTime();
      const collection = req.body;
      if (!('type' in collection)) {
        throw new Error('\'type\' is not defined');
      }
      if (!('id' in collection)) {
        throw new Error('\'id\' is not defined');
      }
      if (!('name' in collection)) {
        throw new Error('\'name\' is not defined');
      }
      if (!('nwserver' in collection) && !('saserver' in collection) ) {
        throw new Error('Either \'nwserver\' or \'saserver\' is not defined');
      }
      if (!('nwserverName' in collection) && !('saserverName' in collection)) {
        throw new Error('Either \'nwserverName\' or \'saserverName\' is not defined');
      }
      if (!('bound' in collection)) {
        throw new Error('\'bound\' is not defined');
      }
      if (!('usecase' in collection)) {
        throw new Error('\'usecase\' is not defined');
      }
      if (collection.bound && collection.usecase === 'custom') {
        throw new Error('A bound collection must be associated with a non-custom use case')
      }
      else if (collection.bound && collection.usecase !== 'custom' && !afbConfig.hasUseCase(collection.usecase) ) {
        throw new Error(`Collection use case ${collection.usecase} is not a valid use case!`);
      }
      
      if (!collection.bound) {
        if (!('query' in collection)) {
          throw new Error('\'query\' is not defined');
        }
        if (!('contentTypes' in collection)) {
          throw new Error('\'contentTypes\' is not defined');
        }
      }

      collection.state = ['rolling', 'monitoring'].includes(collection.type)
        ? 'stopped'
        : 'initial';
      collection.creator = {
        username: jwtUser.username,
        id: jwtUser.sub,
        fullname: jwtUser.fullname,
        timestamp: timestamp
      };

      await afbConfig.addCollection(collection);
      log.info(`User '${jwtUser.username}' has added a new collection '${collection.name}'`);
      res.status(201).json({ success: true });   
    }
    catch (error: any) {
      log.error('POST /api/collection:', error);
      res.status(500).json({ success: false, error: error.message ?? error });
    }
  }
);



app.patch(
  '/api/collection',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // Edits an existing collection
    const jwtUser = req.user as JwtUser;
    try {
      const timestamp = new Date().getTime();
      const editedCollection = req.body as Collection;
      log.debug('collection:', editedCollection);
      const collectionId = editedCollection.id;
      let existingCollection;
      try {
        existingCollection= utils.deepCopy(afbConfig.getCollection(collectionId));
      }
      catch {
        return res.status(400).json({
          success: false,
          error: `Collection ${collectionId} does not exist`
        });
      }

      if (['rolling', 'monitoring'].includes(editedCollection.type)) {
        editedCollection.state = 'stopped';
      }
      else {
        editedCollection.state = 'initial';
      }
      // do something here to stop / reload an existing rolling collection

      editedCollection.modifier = {
        username: jwtUser.username,
        id: jwtUser.sub,
        fullname: jwtUser.fullname,
        timestamp: timestamp
      };

      rollingHandler.collectionEdited(collectionId, editedCollection);

      await afbConfig.editCollection(editedCollection);
      log.info(`User '${jwtUser.username}' has edited collection '${existingCollection.name}'`);
      res.status(205).json({ success: true });
    }
    catch (error: any) {
      res.status(500).json({ success: false, error: error.message ?? error } );
    }
  }
);



////////////////////// FEEDS //////////////////////

app.post(
  '/api/feed/manual',
  logConnection,
  jwtAuth,
  upload.single('file'),
  async (req, res) => {
    // Add a manual feed
    const jwtUser = req.user as JwtUser;
    const timestamp = new Date().getTime();
    if (!req.file) {
      return res.status(400).json({success: false, error: 'No file received'});
    }
    try {
      const feed = JSON.parse(req.body.model);
      
      if (!('id' in feed)) {
        throw new Error(`'id' is not defined`);
      }
      const id = feed.id;
      
      if (id in afbConfig.getFeeds()) {
        throw new Error(`Feed id ${id} already exists`)
      }

      if (!('name' in feed)) {
        throw new Error(`'name' is not defined`);
      }

      if (!('type' in feed)) {
        throw new Error(`'type' is not defined`);
      }

      if (!('delimiter' in feed)) {
        throw new Error(`'delimiter' is not defined`);
      }

      if (!('headerRow' in feed)) {
        throw new Error(`'headerRow' is not defined`);
      }

      if (!('valueColumn' in feed)) {
        throw new Error(`'valueColumn' is not defined`);
      }

      if (!('typeColumn' in feed)) {
        throw new Error(`'typeColumn' is not defined`);
      }

      if (!('friendlyNameColumn' in feed)) {
        throw new Error(`'friendlyNameColumn' is not defined`);
      }

      if (!('filename' in req.file)) {
        throw new Error(`'filename' not found in file definition`);
      }

      if (!('path' in req.file)) {
        throw new Error(`'path' not found in file definition`);
      }

      feed.version = 1;
      feed.creator = {
        username: jwtUser.username,
        id: jwtUser.sub,
        fullname: jwtUser.fullname,
        timestamp: timestamp
      };

      try {
        await fs.rename(req.file.path, `${afbConfig.feedsDir}/${id}.feed`);
      }
      catch (error: any) {
        log.error('Error moving file to feedsDir:', error);
        await fs.unlink(req.file.path);
        throw new Error(error);
      }

      await afbConfig.addFeed(feed);
      log.info(`User '${jwtUser.username}' has added a new manual feed '${feed.name}'`);
      writeToNetSocket( feederNetSocket, JSON.stringify( { new: true, feed: feed } ) );
      res.status(201).json({ success: true });
    }
    catch (error: any) {
      log.error(`POST /api/feed/manual:`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
  }
);



app.post(
  '/api/feed/scheduled',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // Add a scheduled feed
    const jwtUser = req.user as JwtUser;
    const timestamp = new Date().getTime();
    const feed = req.body;
    const id = feed?.id;
    try {
      if (!id) {
        throw new Error('\'id\' is not defined');
      }

      if (id in afbConfig.getFeeds()) {
        throw new Error(`Feed id ${id} already exists`)
      }

      if (!('name' in feed)) {
        throw new Error(`'name' property not found in feed definition`);
      }

      if (!('type' in feed)) {
        throw new Error(`'type' property not found in feed definition`);
      }

      if (!('delimiter' in feed)) {
        throw new Error(`'delimiter' property not found in feed definition`);
      }

      if (!('headerRow' in feed)) {
        throw new Error(`'headerRow' property not found in feed definition`);
      }

      if (!('valueColumn' in feed)) {
        throw new Error(`'valueColumn' property not found in feed definition`);
      }

      if (!('typeColumn' in feed)) {
        throw new Error(`'typeColumn' property not found in feed definition`);
      }

      if (!('friendlyNameColumn' in feed)) {
        throw new Error(`'friendlyNameColumn' property not found in feed definition`);
      }

      if (!('schedule' in feed)) {
        throw new Error(`'schedule' property not found in feed definition`);
      }

      if (!('url' in feed)) {
        throw new Error(`'url' property not found in feed definition`);
      }

      if (!('authentication' in feed)) {
        throw new Error(`'authentication' property not found in feed definition`);
      }

      if (feed.authentication && !('username' in feed && 'password' in feed)) {
        throw new Error('Credentials not found in feed definition');
      }

      feed.version = 1;
      feed.creator = {
        username: jwtUser.username,
        id: jwtUser.sub,
        fullname: jwtUser.fullname,
        timestamp
      };

      // fetch the file and write it to disk
      const axiosOptions: AxiosRequestConfig = {};
      if (feed.authentication && feed.password) {
        axiosOptions.auth = {
          username: feed.username,
          password: afbConfig.decrypt(feed.password)
        };
      }
      await utils.downloadFile(
        feed.url,
        `${afbConfig.feedsDir}/${id}.feed`,
        axiosOptions
      );
      await afbConfig.addFeed(feed);
      log.debug('/api/feed/scheduled: insertOne(): feed added to db');
      scheduler.addScheduledFeed(feed);
      log.info(`User '${jwtUser.username}' has added a new scheduled feed '${feed.name}'`);
      writeToNetSocket( feederNetSocket, JSON.stringify( { new: true, feed: feed } ) ); // let feeder server know of our update
      return res.status(201).json({ success: true });
    }
    catch (error: any) {
      log.error('POST /api/feed/scheduled:', error);
      res.status(500).json({ success: false, error: error.message ?? error });
    }
  }
);



app.patch(
  '/api/feed/withfile',
  logConnection,
  jwtAuth,
  upload.single('file'),
  async (req, res) => {
    // this is for editing of manual feeds which contain a new file
    const jwtUser = req.user as JwtUser;
    if (!req.file) {
      return res.status(400).json({success: false, error: 'No file received'});
    }
    try {
      const timestamp = new Date().getTime();
      const feed = JSON.parse(req.body.model);
      
      if (!('id' in feed)) {
        throw new Error('\'id\' parameter not found in feed');
      }

      const id = feed.id;

      // get creator from old feed
      const oldFeed = afbConfig.getFeed(id);
      const creator = oldFeed.creator
      const oldFeedName = oldFeed.name;
      feed.creator = creator;
      feed.version = oldFeed.version + 1;
      feed.modifier = {
        username: jwtUser.username,
        id: jwtUser.sub,
        fullname: jwtUser.fullname,
        timestamp: timestamp
      };

      try {
        await fs.rename(req.file.path, `${afbConfig.feedsDir}/${id}.feed`);
      }
      catch (error: any) {
        log.error('Error moving file to feedsDir:', error);
        await fs.unlink(req.file.path);
        throw new Error(error);
      }
      await afbConfig.editFeed(feed);
      log.info(`User '${jwtUser.username}' has edited feed '${oldFeedName}' and updated its CSV file`);
      writeToNetSocket( feederNetSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
      res.status(201).json({ success: true });
    }
    catch (error: any) {
      log.error(`PATCH /api/feed/withfile:` , error);
      res.status(500).json({ success: false, error: error.message ?? error } );
    }
  }
);




app.patch(
  '/api/feed/withoutfile',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // this is for editing of any feed which does not include a new file, both manual or scheduled
    const jwtUser = req.user as JwtUser;
    try {
      const timestamp = new Date().getTime();
      const feed = req.body as Feed;
      
      if (!('id' in feed)) {
        throw new Error('\'id\' parameter not found in feed');
      }

      const id = feed.id;

      // get creator from old feed
      const oldFeed = afbConfig.getFeed(id);
      const creator = oldFeed.creator
      const oldFeedName = oldFeed.name;
      feed.creator = creator;
      feed.version = oldFeed.version + 1;

      const modifier = {
        username: jwtUser.username,
        id: jwtUser.sub,
        fullname: jwtUser.fullname,
        timestamp: timestamp
      };
      feed.modifier = modifier;

      if (feed.type === 'manual' ) {
        await afbConfig.editFeed(feed);
        log.info(`User '${jwtUser.username}' has edited manual feed '${oldFeedName}' without updating its CSV file`);
        writeToNetSocket( feederNetSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
        res.status(201).json({ success: true });
        if (oldFeed.type === 'scheduled') {
          // tell scheduler to remove old feed
          scheduler.removeScheduledFeed(feed.id);
        }
      }
      if (feed.type === 'scheduled' && oldFeed.type === 'scheduled') {
        // scheduled feed
        // always pull feed anew.  this will save on funky logic
        const axiosOptions: AxiosRequestConfig = {};
        if (feed.authentication) {
          if (!feed.authChanged) {
            feed.username = oldFeed.username;
            feed.password = oldFeed.password; // if credentials haven't changed, then set the password to the old password
          }
          axiosOptions.auth = {
            username: feed.username,
            password: afbConfig.decrypt(feed.password)
          };
        }
        await utils.downloadFile(
          feed.url,
          `${afbConfig.feedsDir}/${id}.feed`,
          axiosOptions
        );
        try {
          await afbConfig.editFeed(feed);
        }
        catch (error: any) {
          log.error('PATCH /api/feed/withoutfile updateOne(): error updating feed in db:', error);
          throw new Error(error);
        }
        log.debug('PATCH /api/feed/withoutfile: updateOne(): feed modified in db');
        scheduler.updateScheduledFeed(feed);
        log.info(`User '${jwtUser.username}' has edited scheduled feed '${oldFeedName}' without updating its CSV file`);
        // calculate file hash for feed file
        writeToNetSocket( feederNetSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
        res.status(201).json({ success: true });
      }
    }
    catch (error: any) {
      log.error('PATCH /api/feed/withoutfile:', error);
      res.status(500).json({ success: false, error: error.message ?? error });
    }
  }
);




app.post(
  '/api/feed/testurl',
  logConnection,
  jwtAuth,
  async (req, res) => {
    const jwtUser = req.user as JwtUser;
    const axiosOptions: AxiosRequestConfig = {
      responseType: 'stream',
      validateStatus: () => true
    };
    const host = req.body;
    const url = host?.url;

    try {
      // log.debug('host:', host);
      switch (true) {
        case !url: {
          throw new Error('\'url\' property not defined in host definition');
        }
        case !('authentication' in host): {
          throw new Error('\'authentication\' property not found in host definition');
        }
        case ('useCollectionCredentials' in host): {
          const id = host.useCollectionCredentials;
          const feed = afbConfig.getFeed(id);
          if (feed.type === 'manual') {
            throw new Error('Feed does not contain authentication properties');
          }
          axiosOptions.auth = {
            username: feed.username,
            password: afbConfig.decrypt(feed.password)
          };
          break;
        }
        case (host.authentication && !('username' in host && 'password' in host)): {
          throw new Error('Credentials not found in host definition');
        }
        case (host.authentication): {
          axiosOptions.auth = {
            username: host.username,
            password: afbConfig.decrypt(host.password)
          };
        }
      }
    }
    catch (error: any) {
      log.error('POST /api/feed/testurl', error);
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
    
    try {
      const response = await Axios.get(url, axiosOptions);
      log.info(`User '${jwtUser.username}' has tested feed URL '${url}'.  Status Code: ${response.status}`);
      if (!(response.status >= 200 && response.status < 300)) {
        return res.status(200).json({
          success: false,
          error: 'Failure HTTP status code',
          statusCode: response.status
        });
      }
      let chunkHandler: ((chunk: string | Buffer) => void) | undefined = undefined;
      let closeHandler;
      const rawCSV = await new Promise( (resolve) => {
        let buffer = '';
        let resolved = false;
        chunkHandler = (chunk) => {
          // called when a chunk of data is received
          const dataStr = chunk.toString('utf8');
          log.debug('/api/feed/testurl: onData()');
          buffer += dataStr;
          let lines = buffer.split('\n');
  
          if (lines.length >= 6) {
            lines = lines.slice(0, lines.length > 6 ? 6 : lines.length);
            response.data.destroy();
            resolved = true;
            return resolve(
              lines.join('\n')
            );
          }
        };
        closeHandler = () => {
          if (!resolved) {
            response.data.off('data', chunkHandler);
            resolve(buffer);
          }
        };
        response.data.on('data', chunkHandler);
        response.data.on('close', closeHandler);
      });
      if (chunkHandler) {
        response.data.off('data', chunkHandler);
      }
      response.data.off('close', closeHandler);

      if (rawCSV) {
        return res.status(200).json({
          success: true,
          rawCSV
        });
      }
      log.debug('/api/feed/testurl: empty response');
      return res.status(200).json({
        success: false,
        error: 'Empty server response'
      });
    }
    catch (error: any) {
      log.debug(`User '${jwtUser.username}' caught an error whilst testing feed URL '${url}':`, error);
      const resValue = {
        success: false,
        error: error.message ?? error
      };
      return res.status(200).json(resValue);
    }
  }
);



app.get(
  '/api/feed/filehead/:id',
  logConnection,
  jwtAuth,
  (req, res) => {
    const jwtUser = req.user as JwtUser;
    try {
      const feedId = req.params.id;    
      
      const feed = afbConfig.getFeed(feedId);
      log.info(`User '${jwtUser.username}' has requested CSV file content for feed ${feed.name}`);
      let chunkSize = 1024;
      const maxBufSize = 262144;
      const buffer = new Buffer(maxBufSize);
      let bytesRead = 0;
      const fileSize = fssync.statSync(`${afbConfig.feedsDir}/${feedId}.feed`).size;
      if (chunkSize > fileSize) {
        chunkSize = fileSize;
      }

      fssync.open(`${afbConfig.feedsDir}/${feedId}.feed`, 'r', (err, fd) => {
        if (err) {
          throw err;
        }

        let rawCSV = '';

        const fsCallback = (err: any, read: number) => {
          bytesRead += read;
          const data = buffer.toString();
          let count = -1; // the number of newline chars we've found this time
          // eslint-disable-next-line no-empty
          for (let index = -2; index !== -1; count++, index = data.indexOf('\n', index + 1) ) {} // count newlines
          if (count >= 6) {
            const lines = data.split('\n');
            // console.debug(lines);
            while (lines.length > 6) {
              lines.pop();
            }
            rawCSV = lines.join('\n');
            finishCallback();
            return;
          }
          if (bytesRead < fileSize) {
            // there's still more to read
            if ( (fileSize - bytesRead) < chunkSize ) {
              chunkSize = fileSize - bytesRead;
            }
            fssync.read(fd, buffer, bytesRead, chunkSize, null, fsCallback);
            return;
          }
          // we've read everything
          finishCallback();
        };

        const finishCallback = () => {
          // reading finished
          if (rawCSV) {
            res.status(200).json({ success: true, rawCSV: rawCSV } );
          }
          else if (buffer.length > 0) {
            log.debug('/api/feed/filehead/:id : fewer than 6 lines were found in the CSV');
            res.status(200).json({ success: true, rawCSV: buffer.toString() });
          }
          else {
            log.debug('/api/feed/filehead/:id : empty file');
            res.status(200).json({ success: false, error: 'Empty response' });
          }
        }

        fssync.read(fd, buffer, bytesRead, chunkSize, null, fsCallback);
      });

    }
    catch (error: any) {
      log.error(`GET /api/feed/filehead/:id:`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
  }
);



app.delete(
  '/api/feed/:id',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // delete a feed
    const jwtUser = req.user as JwtUser;
    const feedId = req.params.id;
    let oldFeed;
    try {
      oldFeed = afbConfig.getFeed(feedId);
    }
    catch {
      return res.status(400).json({ success: false, error: 'Feed not found' });
    }
    
    try {
      await fs.unlink(`${afbConfig.feedsDir}/${feedId}.feed`);
      await afbConfig.deleteFeed(feedId); 
      log.info(`User '${jwtUser.username}' has deleted feed ${oldFeed.name}`);
      writeToNetSocket( feederNetSocket, JSON.stringify( { delete: true, id: feedId } ) ); // let feeder server know of our update
      scheduler.removeScheduledFeed(feedId);
      res.status(200).json({ success: true } );
    }
    catch (error: any) {
      log.error(`ERROR DELETE /api/feed/${feedId}:`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
    }
  }
);







//////////////////////NWSERVERS//////////////////////

app.delete(
  '/api/nwserver/:id',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // for deleting a netwitness server
    const jwtUser = req.user as JwtUser;
    let oldNwserver, id;
    try {
      if (!('id' in req.params)) {
        throw new Error('Could not find \'id\' in request parameters' );
      }
      id = req.params.id;
      oldNwserver = afbConfig.getNwServer(id);
      await afbConfig.deleteNwServer(id);
    }
    catch (error: any) {
      log.error(`ERROR DELETE /api/nwserver/${id} :`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
    log.info(`User '${jwtUser.username}' has deleted NetWitness server '${oldNwserver.user}@${oldNwserver.host}:${oldNwserver.port}'`);
    tokenMgr.authSocketsEmit('nwservers', redactApiServerPasswords(afbConfig.getNwServers()));
    res.status(200).json({ success: true });
  }
);



app.post(
  '/api/nwserver',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // for adding a netwitness server
    const jwtUser = req.user as JwtUser;
    const nwserver = req.body;
    try {
      if (!('id' in nwserver)) {
        throw new Error('\'id\' is not defined in nwserver');
      }
      if (!('friendlyName' in nwserver)) {
        throw new Error('\'friendlyName\' is not defined in nwserver');
      }
      if (!('host' in nwserver)) {
        throw new Error('\'host\' is not defined in nwserver');
      }
      if (!('port' in nwserver)) {
        throw new Error('\'port\' is not defined in nwserver');
      }
      if (!('user' in nwserver)) {
        throw new Error('\'user\' is not defined in nwserver');
      }
      if (!('password' in nwserver)) {
        throw new Error('\'password\' is not defined in nwserver'); // we don't decrypt here.  We only decrypt when we build a worker config
      }
      if (!('ssl' in nwserver)) {
        throw new Error('\'ssl\' is not defined in nwserver');
      }
      await afbConfig.addNwServer(nwserver);
    }
    catch (error: any) {
      log.error(`POST /api/nwserver:`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
  
    log.info(`User '${jwtUser.username}' has added NetWitness server '${nwserver.user}@${nwserver.host}:${nwserver.port}'`);
    tokenMgr.authSocketsEmit('nwservers', redactApiServerPasswords(afbConfig.getNwServers()));
    res.status(201).json({ success: true }); 
  });



app.patch(
  '/api/nwserver',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // for editing a netwitness server
    const jwtUser = req.user as JwtUser;
    let oldNwserver;
    try {
      const nwserver = req.body;
      if (!('id' in nwserver)) {
        throw new Error('\'id\' is not defined');
      }
      const id = nwserver.id;
      if (!('friendlyName' in nwserver)) {
        throw new Error('\'friendlyName\' is not defined in nwserver');
      }
      if (!('host' in nwserver)) {
        throw new Error('\'host\' is not defined in nwserver');
      }
      if (!('port' in nwserver)) {
        throw new Error('\'port\' is not defined in nwserver');
      }
      if (!('user' in nwserver)) {
        throw new Error('\'user\' is not defined in nwserver');
      }

      oldNwserver = utils.deepCopy(afbConfig.getNwServer(id));
      if (!('password' in nwserver)) {
        // use existing password
        nwserver.password = oldNwserver.password;
      }
      if (!('ssl' in nwserver)) {
        throw new Error('\'ssl\' is not defined  in nwserver');
      }
      await afbConfig.editNwServer(nwserver);
    }
    catch (error: any) {
      log.error(`PATCH /api/nwserver:`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
    log.info(`User '${jwtUser.username}' has edited NetWitness server '${oldNwserver.user}@${oldNwserver.host}:${oldNwserver.port}'`);
    tokenMgr.authSocketsEmit('nwservers', redactApiServerPasswords(afbConfig.getNwServers()));
    res.status(200).json({ success: true });
  }
);



app.post(
  '/api/nwserver/test',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // for testing a netwitness serveer
    const jwtUser = req.user as JwtUser;
    let uPassword: string;
    const testParams = req.body;
    try {
      if (!testParams.host) {
        throw new Error('\'host\' is not defined');
      }
      if (testParams.ssl === undefined) {
        throw new Error('\'ssl\' is not defined');
      }
      if (!testParams.port) {
        throw new Error('\'port\' is not defined');
      }
      if (!testParams.user) {
        throw new Error('\'user\' is not defined');
      }
      if (!testParams.id && !testParams.password) {
        throw new Error(`Either 'id' or 'password' must be defined`);
      }
    }
    catch (error: any) {
      return res.status(400).json({success: false, error: error.message ?? error})
    }
    if ('id' in testParams && !('password' in testParams)) {
      try {
        const nwserver = afbConfig.getNwServer(testParams.id);
        if (!nwserver.password) {
          throw new Error('Existing password not found');
        }
        uPassword = afbConfig.decrypt(nwserver.password);
      }
      catch (error: any) {
        return res.status(400).json({ success: false, error: error.message ?? error })
      }
    }
    else {
      uPassword = afbConfig.decrypt(testParams.password);
    }
    const {host, ssl, port, user} = testParams;
    const proto = ssl 
      ? 'https://'
      : 'http://';
    const url = `${proto}${host}:${port}`;
    
    try {
      const response = await Axios.get(url, {
        auth: {
          username: user,
          password: uPassword,
        },
        validateStatus: () => true
      });
      if (response.status >= 200 && response.status < 300) {
        log.info(`User '${jwtUser.username}' tested NetWitness server '${testParams.user}@${testParams.host}:${testParams.port}' with result success`);
      }
      else {
        log.info(`User '${jwtUser.username}' tested NetWitness server '${testParams.user}@${testParams.host}:${testParams.port}' with result failure.  STATUS CODE: ${response.status}`);
      }
      res.status(response.status).json({ error: response.statusText });
    }
    catch (error: any) {
      log.info(`User '${jwtUser.username}' tested NetWitness server '${testParams.user}@${testParams.host}:${testParams.port}' with result failure.  ${error.message ?? error}`);
      res.status(403).json({ error: error.message ?? error });
    }
  }
);



////////////////////// SA SERVERS //////////////////////

app.delete(
  '/api/saserver/:id',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // for deleting an sa server
    const jwtUser = req.user as JwtUser;
    let oldSaserver;
    const saServerId = req.params.id;
    try {
      if (!('id' in req.params)) {
        throw new Error('Could not find \'id\' in request parameters' );
      }
      oldSaserver = afbConfig.getSaServer(saServerId);
      await afbConfig.deleteSaServer(saServerId);
    }
    catch (error: any) {
      log.error(`ERROR DELETE /api/saserver/${saServerId} :`, error);
      res.status(500).json({ success: false, error: error.message ?? error } );
      return;
    }
    log.info(`User '${jwtUser.username}' has deleted SA server '${oldSaserver.user}@${oldSaserver.host}:${oldSaserver.port}'`);
    tokenMgr.authSocketsEmit('saservers', redactApiServerPasswords(afbConfig.getSaServers()));
    res.status(200).json({ success: true });
  }
);



app.post(
  '/api/saserver',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // for adding an sa server
    const jwtUser = req.user as JwtUser;
    let saserver;
    try {
      saserver = req.body;
      if (!('id' in saserver)) {
        throw new Error('\'id\' is not defined');
      }
      if (!('friendlyName' in saserver)) {
        throw new Error('\'friendlyName\' is not defined in saserver');
      }
      if (!('host' in saserver)) {
        throw new Error('\'host\' is not defined in saserver');
      }
      if (!('port' in saserver)) {
        throw new Error('\'port\' is not defined in saserver');
      }
      if (!('user' in saserver)) {
        throw new Error('\'user\' is not defined in saserver');
      }
      if (!('password' in saserver)) {
        throw new Error('\'password\' is not defined in saserver'); // we don't decrypt here.  We only decrypt when we build a worker config
      }
      if (!('ssl' in saserver)) {
        throw new Error('\'ssl\' is not defined in saserver');
      }
      await afbConfig.addSaServer(saserver);
    }
    catch (error: any) {
      log.error(`POST /api/saserver:`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
    log.info(`User '${jwtUser.username}' has added SA server '${saserver.user}@${saserver.host}:${saserver.port}'`);
    tokenMgr.authSocketsEmit('saservers', redactApiServerPasswords(afbConfig.getSaServers()));
    res.status(201).json({ success: true });
  }
);



app.patch(
  '/api/saserver',
  logConnection,
  jwtAuth,
  async (req, res) => {
    const jwtUser = req.user as JwtUser;
    let oldSaserver;
    try {
      const saserver = req.body;
      if (!('id' in saserver)) {
        throw new Error('\'id\' is not defined in saserver');
      }
      const id = saserver.id;
      oldSaserver = utils.deepCopy(afbConfig.getSaServer(id));
      if (!('friendlyName' in saserver)) {
        throw new Error('\'friendlyName\' is not defined in saserver');
      }
      if (!('host' in saserver)) {
        throw new Error('\'host\' is not defined in saserver');
      }
      if (!('port' in saserver)) {
        throw new Error('\'port\' is not defined in saserver');
      }
      if (!('user' in saserver)) {
        throw new Error('\'user\' is not defined in saserver');
      }
      if (!('password' in saserver)) {
        // use existing password
        saserver.password = oldSaserver.password;
      }
      if (typeof saserver.ssl === 'undefined') {
        throw new Error('\'ssl\' is not defined in saserver');
      }
      await afbConfig.editSaServer(saserver);
    }
    catch (error: any) {
      log.error(`PATCH /api/saserver:`, error);
      res.status(500).json({ success: false, error: error.message ?? error });
      return;
    }
    log.info(`User '${jwtUser.username}' has edited SA server '${oldSaserver.user}@${oldSaserver.host}:${oldSaserver.port}'`);
    tokenMgr.authSocketsEmit('saservers', redactApiServerPasswords(afbConfig.getSaServers()));
    res.status(200).json({ success: true });
  }
);



app.post(
  '/api/saserver/test',
  logConnection,
  jwtAuth,
  async (req, res) => {
    const jwtUser = req.user as JwtUser;
    const testParams = req.body;
    let uPassword = '';
    if ('id' in testParams && !('password' in testParams)) {
      try {
        const saserver = afbConfig.getSaServer(testParams.id);
        if (!saserver.password) {
          throw new Error('Existing password not found');
        }
        uPassword = afbConfig.decrypt(saserver.password);
      }
      catch (error: any) {
        return res.status(400).json({ success: false, error: error.message ?? error })
      }
    }
    else if ('id' in testParams && 'password' in testParams) {
      uPassword = afbConfig.decrypt(testParams.password);
    }
    else {
      uPassword = afbConfig.decrypt(testParams.password);
    }
    const {host, ssl, port, user} = testParams;
    const proto = ssl ? 'https://' : 'http://';
    const url = `${proto}${host}:${port}/api/v6/users/account_info`;

    try {
      // Perform test
      const response = await Axios.post(
        url,
        {
          _method: 'GET'
        },
        {
          auth: {
            username: user,
            password: uPassword,
          },
          headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
          },
          validateStatus: () => true
        }
      );
      if (response.status >= 200 && response.status < 300) {
        if (!('resultCode' in response.data) || response.data.resultCode !== 'API_SUCCESS_CODE') {
          log.info(`User '${jwtUser.username}' tested SA server '${testParams.user}@${testParams.host}:${testParams.port}' with result failure.  resultCode: ${response.data.resultCode ?? null}`);
          res.status(403).json({ success: false, error: response.data.resultCode });
          return;
        }
        log.info(`User '${jwtUser.username}' tested SA server '${testParams.user}@${testParams.host}:${testParams.port}' with result success`);
        res.status(200).json({ success: true } );
        return;
      }
      else {
        log.debug(`REST connection test to url ${url} failed.`);
        log.info(`User '${jwtUser.username}' tested SA server '${testParams.user}@${testParams.host}:${testParams.port}' with result failure.  STATUS CODE: ${response.status}`);
        res.status(403).json({ success: false, error: response.data.resultCode });
        return;
      }
    }
    catch (error: any) {
      log.info(`User '${jwtUser.username}' tested SA server '${testParams.user}@${testParams.host}:${testParams.port}' with result failure.  ${error.message ?? error}`);
      res.status(403).json({ error: error.message ?? error });
    }
  }
);



//////////////////////PING//////////////////////

app.get(
  '/api/ping',
  (req, res) => {
    res.status(200).json({ success: true } );
  }
);

//////////////////////PREFERENCES//////////////////////

app.post(
  '/api/preferences',
  logConnection,
  jwtAuth,
  async (req, res) => {
    // Set global preferences
    const jwtUser = req.user as JwtUser;
    try {
      const prefs = req.body;
      await afbConfig.updatePreferences(prefs);
    }
    catch (error: any) {
      log.error('POST /api/preferences:', error);
      res.status(500).json({ success: false, error: error.message ?? error } );
      return;
    }
    log.info(`User '${jwtUser.username}' has updated the global preferences`);
    res.status(201).json({ success: true });
  }
);





/// FIXED COLLECTIONS ///

app.get('/api/collection/fixed/:id',
  logConnection,
  jwtAuth,
  (req, res) => {
    // Returns a fixed collection, either complete, or in the process of building
    const jwtUser = req.user as JwtUser;
    const collectionId = req.params.id;
    let collection;
    try {
      collection = afbConfig.getCollection(collectionId);
    }
    catch {
      return res.status(400).json({ success: false, error: `collection ${collectionId} not found`});
    }
    if (collection && ['initial', 'building', 'error'].includes(collection.state)) {
      // collection is either new or is building
      log.info(`User '${jwtUser.username}' has requested incomplete fixed collection ${collection.name}`);
      fixedHandler.onHttpConnection(req, res);
    }
    else if (collection) { // we should even use this if state is 'error'
      // this is a complete fixed collection
      log.info(`User '${jwtUser.username}' has requested complete fixed collection ${collection.name}`);
      try {
        res.json([
          { wholeCollection: collection },
          { close: true }
        ]);
      }
      catch (error: any) {
        log.error('ERROR GET /api/collection/fixed/:id', error);
        res.status(500).json({ success: false, error: error.message ?? error });
      }
    }
    else {
      // couldn't find the collection
      log.info(`User '${jwtUser.username}' has requested a non-existant fixed collection with id '${collectionId}'`);
      res.status(500).json({ success: false, error: 'collection does not exist' });
    }
  }
);



/// ROLLING / MONITORING COLLECTIONS ///

app.get(
  '/api/collection/rolling/:collectionId',
  jwtAuth,
  (req, res) => {
    rollingHandler.onHttpConnection(req, res);
  }
);



app.get(
  '/api/collection/monitoring/pause/:id',
  jwtAuth,
  (req, res) => {
    rollingHandler.pauseMonitoringCollectionHttp(req, res);
  }
);



app.get(
  '/api/collection/monitoring/unpause/:id',
  jwtAuth,
  (req, res) => {
    rollingHandler.unpauseMonitoringCollectionHttp(req, res);
  }
);



/// UTILITY FUNCTIONS ///

function redactApiServerPasswords(apiservers: Record<string, NwServer | SaServer>) {
  // delete passwords - they don't need to be transferred back to the client
  const servers = utils.deepCopy(apiservers);
  Object.values(servers)
    .forEach( (server) => (server.password as any) = undefined);
  return servers;
}



function extractJwtFromCookie(req: Request) {
  // Extract JWT from cookie 'access_token' and return to JwtStrategyf
  return req && req.cookies
    ? req.cookies.access_token
    : null;
}



async function extraJwtTokenValidation(jwt_payload: any, done: VerifiedCallback) {
  // After automatically verifying that JWT was signed by us, perform extra validation with this function
  if (tokenMgr.isTokenBlacklisted(jwt_payload.jti)) {
    // check blacklist
    log.info(`User ${jwt_payload.username} has already logged out!`);
    return done(null, false);
  }

  try {
    // check whether user is enabled
    const user = await UserModel.findOne({id: jwt_payload.sub});
    if (user && user.enabled) {
      return done(null, user);
    }
    if (user && !user.enabled) {
      log.info('Login denied for user', user.username);
      log.info('Attempt to authenticate by disabled user', user.username);
      return done(null, false);
    }
    else {
      return done(null, false);
      // or you could create a new account
    }
  }
  catch (error: any) {
    return done(error, false);
  }
}



async function onMongooseConnected() {
  log.debug('onMongooseConnected()');
  // Create the default user account, if we think the app was just installed and if the count of users is 0
  const count = await UserModel.count( {} );
  if (count === 0) {
    // we only create the default user on first run because we 
    log.info('Adding default user \'admin\'');
    try {
      await createDefaultUser();
    }
    catch (error: any) {
      log.error('Error creating default user:', error);
      process.exit(1);
    }
    afbConfig.justInstalled = false;
  }
}



async function mongooseInit() {
  // Initialise Mongoose.  This gets called from within connectToDB(), after mongoClient has connected to Mongo
  log.debug('Initializing mongoose');

  // Mongoose config
  const mongoConfig = afbConfig.getMongoConfig();
  let mongooseUrl = `mongodb://${mongoConfig.host}:${mongoConfig.port}/afb`
  const mongooseOptions = {};
  if (mongoConfig.authentication.enabled) {
    mongooseUrl = `mongodb://${mongoConfig.authentication.user}:${mongoConfig.authentication.password}@${mongoConfig.host}:${mongoConfig.port}/afb?authSource=admin`;
  }

  // This creates local authentication passport strategy
  // This authenticates a user against the account stored in MongoDB
  // This is only used by /api/login
  const mongooseStrategy = new LocalStrategy( UserModel.authenticate() );
  passport.use(mongooseStrategy);
  passport.serializeUser( UserModel.serializeUser() as any );
  passport.deserializeUser( UserModel.deserializeUser() );

  // This creates the JWT authentication passport strategy
  // This is used to authenticate all API calls except login and ping
  const jwtOpts = {
    jwtFromRequest: ExtractJwt.fromExtractors([extractJwtFromCookie]),
    secretOrKey: afbConfig.getJwtPublicKey(),
    algorithms: ['RS256']
  };
  const jwtStrategy = new JwtStrategy(jwtOpts, (jwt_payload, done) => extraJwtTokenValidation(jwt_payload, done) );
  passport.use(jwtStrategy);

  try {
    await mongoose.connect(mongooseUrl, mongooseOptions);
    await onMongooseConnected();
  }
  catch (error: any) {
    log.error('Mongoose error whilst connecting to mongo.  Exiting with code 1.');
    log.error(error);
    process.exit(1);
  }
}



async function cleanCollectionDirs() {
  try {
    log.info('Cleaning up collection directories');
    await Promise.all(
      Object.entries(afbConfig.getCollections())
        .map(
          async ([collectionId, collection]) => {
            log.debug(`Cleaning collection '${collection.name}' with id ${collectionId}`);
          
            if ( collection.type === 'rolling' || ( collection.type === 'fixed' && collection.state !== 'complete' ) ) {
              await rmfr( `${afbConfig.collectionsDir}/${collectionId}`); // delete output directory
            }
            else if (collection.type === 'monitoring') {
              const filenames = await fs.readdir(afbConfig.collectionsDir);
              await Promise.all(
                filenames.map(
                  async (filename) => {
                    const stat = await fs.stat(`${afbConfig.collectionsDir}/${filename}`);
                    const isDir = stat.isDirectory();
                    if (isDir && filename.startsWith(collectionId)) {
                      await rmfr( `${afbConfig.collectionsDir}/${collectionId}` ); // delete output directory
                    }
                  }
                )
              )
            }
          }
        )
    );
  }
  catch (error: any) {
    log.error(`ERROR deleting cleaning collection dirs:`, error);
  }
}



async function createDefaultUser() {
  log.debug('createDefaultUser()');
  log.info('Creating default user');
  await UserModel.register(
    new UserModel({
      _id: uuidV4(),
      username: 'admin',
      fullname: 'System Administrator',
      email: 'noreply@knowledgekta.com',
      enabled: true
    }),
    'kentech0'
  );
}



const netChunkHandler = (buffer: string, chunk: Buffer, callback: (messages: string[]) => void ) => {
  // Handles socket data received from the feeder process
  buffer += chunk.toString('utf8');

  const splt = buffer
    .split('\n')
    .filter( (el) => el.length !== 0);

  if ( splt.length === 1 && buffer.indexOf('\n') === -1 ) {
    // This case means the split resulted in only one element and that doesn't contain the newline delimiter, which means we haven't received an entire update yet...
    // we'll continue and wait for the next update which will hopefully contain the delimeter
    return buffer;
  }
  const messages: string[] = []; // 'd' is an array of complete JSON messages.  each one should later be parsed with JSON.parse()
  if ( splt.length === 1 && buffer.endsWith('\n') ) {
    // this case means the split resulted in only one element and that it does contain the newline delimiter.  This means we received a single complete update.
    messages.push(splt.shift() as string);
    buffer = '';
  }
  else if ( splt.length > 1 ) {
    // This case means the split resulted in multiple elements and that it does contain a newline delimiter...
    // This means we have at least one complete update, and possibly more.
    if (buffer.endsWith('\n')) {  //the last element is a full update as data ends with a newline
      while (splt.length > 0) {
        messages.push(splt.shift() as string);
      }
      buffer = '';
    }
    else { // the last element is only a partial update, meaning that more data must be coming
      while (splt.length > 1) {
        messages.push(splt.shift() as string);
      }
      buffer = splt.shift() as string;  // this should be the last partial update, which should be appended to in the next update
    }
  }
  callback(messages);
  return buffer;
}



const transformUser = function(doc: UserDoc, ret: Record<string, unknown>): Record<string, unknown> {
  delete ret._id;
  delete ret.id;
  delete ret.email;
  return ret;
};



function writeToNetSocket(socket: NetSocket, data: unknown) {
  socket.write(`${data}\n`);
}



const feederDataHandler = (data: string[]) => {
  // Handles data sent by feeder_srv
  while (data.length > 0) {
    const line = data.shift() as string;
    const message = JSON.parse(line);
    if (!feederInitialized && 'initialized' in message && message.initialized && 'feederSocket' in message) {
      log.info('feederDataHandler(): Feeder is initialized');
      feederInitialized = true;
      feederSocketFilename = message.feederSocket;
      if (rollingHandler) {
        rollingHandler.updateFeederSocketFile(feederSocketFilename);
      }
      if (fixedHandler) {
        fixedHandler.updateFeederSocketFile(feederSocketFilename);
      }
      log.debug(`feederDataHandler(): Feeder socket file is ${feederSocketFilename}`);
      if (!apiInitialized) {
        finishStartup(); // start the API listener
      }
    }
  }
}



function onConnectionFromFeederSrv(socket: NetSocket, tempName: string) {
  feederNetSocket = socket; // assign our socket globally so we can write to it later

  ////////////////////////
  //DEAL WITH THE SOCKET//
  ////////////////////////

  // Buffer for worker data
  let buffer = '';
  
  // Set socket options
  feederNetSocket.setEncoding('utf8');

  // Handle data from the socket
  feederNetSocket.on('data', (chunk) => buffer = netChunkHandler(buffer, chunk, feederDataHandler) );
  
  feederNetSocket.on('end', async () => {
    log.debug('Feeder has disconnected');
    // delete temporary socket
    await fs.unlink(tempName);
    feederInitialized = false;
  });
                          
  // Send configuration to feeder_srv.  After this, we should receive an okay response containing a path to a socket for workers
  writeToNetSocket(feederNetSocket, JSON.stringify( { config: { feedsDir: afbConfig.feedsDir }, feeds: afbConfig.getFeeds() } ));
}




const onFeederExit = (code: number) => {
  feederSrvProcess = undefined;
  if (!code) {
    log.debug('Feeder process exited abnormally without an exit code');
  }
  else if (code !== 0) {
    log.debug('Feeder process exited abnormally with exit code', code);
  }
  else {
    log.debug('Feeder process exited normally with exit code', code);
    return;
  }
  log.debug('Relaunching feeder_srv');
  startFeeder();
}



function startFeeder() {
  log.debug('startFeeder(): starting feeder_srv');

  // get a temporary file to use as our domain socket
  const tempName = temp.path({suffix: '.socket'});
  
  // open UNIX domain socket to talk to server script, and set the socket handler to onConnectionFromFeederSrv
  const socketServer = net.createServer( (socket) => onConnectionFromFeederSrv(socket, tempName) );

  // start the feeder_srv
  socketServer.listen(tempName, () => {
    
    log.debug('Waiting for Feeder connection');
    log.debug(`Launching feeder_srv with socket file ${tempName}`);

    // spawn the feeder process
    feederSrvProcess = spawn(
      './feeder/feeder_stub.py',
      [tempName],
      {
        shell: false,
        stdio: 'inherit'
      }
    );
    
    // wait for the feeder to exit (ideally it shouldn't until we shutdown)
    feederSrvProcess.on('exit', onFeederExit );
  });
}



function schedulerUpdatedCallback(id: string) {
  // log.debug('schedulerUpdatedCallback(): id:', id);
  writeToNetSocket(
    feederNetSocket,
    JSON.stringify({
      updateFile: true,
      id
    })
  ); // let feeder server know of our update
}



/// SOCKET.IO ///

const onSocketIoConnect = (socket: Socket) => {
  // allows for upgrade of auth after connect, for the always connected model - totally incomplete
  log.debug('A socket client connected');
  socket.on('disconnect', (reason) => onSocketIoDisconnect(socket, reason) );

  // immediately send configuration to client
  socket.emit('serverVersion', version);
}



const onClientReady = (socket: Socket) => {
  log.debug('A socket client has authenticated and is ready for data - sendiHTMLElementng data to client');
  socket.emit('preferences', afbConfig.getClientPreferences());
  socket.emit('collections', afbConfig.getCollections());
  socket.emit('publicKey', afbConfig.getInternalPublicKey());
  if (afbConfig.nwEnabled) socket.emit('nwservers', redactApiServerPasswords(afbConfig.getNwServers()));
  if (afbConfig.saEnabled) socket.emit('saservers', redactApiServerPasswords(afbConfig.getSaServers()));
  socket.emit('feeds', afbConfig.getFeeds());
  socket.emit('feedStatus', scheduler.getStatus() );
  emitUsers(socket);
  socket.emit('useCases', afbConfig.getUseCases());
  socket.emit('initialised'); // let the client know we're done
}



const onSocketIoDisconnect = (socket: Socket, reason: string) => {
  if (socket.conn.jwtuser) {
    log.info(`User ${socket.conn.jwtuser.username} has disconnected from an associated socket`);
  }
  else {
    log.debug('An unauthenticated socket client disconnected');
  }
  tokenMgr.removeSocketToken(socket, reason);
}

/// END SOCKET.IO ///



/// CLEANUP ///

const onCleanup = (exitCode: number | null, signal: string | null) => {
  log.debug('onCleanup(): exitCode:', exitCode);
  log.debug('onCleanup(): signal:', signal);
  
  setTimeout( () => {
    // terminate workers
    if (rollingHandler) {
      log.debug('Terminating rolling collection workers');
      rollingHandler.killAll();
    }
    
    if (fixedHandler) {
      log.debug('Terminating fixed collection workers');
      fixedHandler.killAll();
    }
    
    // terminate feeder_srv
    if (feederSrvProcess) {
      log.debug('Stopping feeder_srv')
      feederSrvProcess.removeAllListeners();
      feederSrvProcess.kill('SIGINT');
    }
    
    // save collection state
    
    
    // end program
    if (signal) {
      process.kill(process.pid, signal);
    }
    else {
      process.exit(exitCode === null ? undefined : exitCode);
    }
    
  }, 0);
  
  nodeCleanup.uninstall();
  return false;
}

/// END CLEANUP ///



/// LISTEN ///

const finishStartup = async () => {
  // Start listening for client traffic and away we go
  server.listen(listenPort);
  io.on('connection', (socket) => onSocketIoConnect(socket) );
  
  rollingHandler = new RollingCollectionHandler( afbConfig, feederSocketFilename, collectionsChannel, purgeTest, purgeTestMinutes);
  afbConfig.setRollingHandler(rollingHandler);

  fixedHandler = new FixedCollectionHandler( afbConfig, feederSocketFilename, collectionsChannel);

  log.debug('Installing cleanup handler');
  nodeCleanup( (exitCode, signal) => onCleanup(exitCode, signal) );
  
  // Install SIGINT and SIGTERM handlers if we're running inside a container.  We need this to allow the process to exit normally when running in Docker
  if ( isDocker() ) {
    process.on('SIGINT', () => onCleanup(0, null) );
    process.on('SIGTERM', () => onCleanup(0, null) );
  }

  apiInitialized = true;
  log.info('Serving on port', listenPort);
}
