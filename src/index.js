'use strict';
// Load dependencies
require('source-map-support').install();

global.falseRequire = function(lib) {
  try {
    let func = require(lib);
    return func; 
  }
  catch(err) {
    return null;
  }
}

global.deepCopy = function(o) {
  // taken from https://jsperf.com/deep-copy-vs-json-stringify-json-parse/5
  let newO, i;

  if (typeof o !== 'object') {
    return o;
  }
  if (!o) {
    return o;
  }

  if ('[object Array]' === Object.prototype.toString.apply(o)) {
    newO = [];
    for (i = 0; i < o.length; i += 1) {
      newO[i] = deepCopy(o[i]);
    }
    return newO;
  }

  newO = {};
  for (i in o) {
    if (o.hasOwnProperty(i)) {
      newO[i] = deepCopy(o[i]);
    }
  }
  return newO;
}

// command line arguments
const args = require('yargs').argv;
// console.log(args);

// passport and JWT
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const mongoose = require('mongoose');
mongoose.Promise = Promise;
const User = falseRequire('./user') || MongooseModel;
// passport auth gets set up in mongooseInit(), after we've successfully connected to mongo

// express
const app = require('express')();
const server = require('http').createServer(app);
const cookieParser = require('cookie-parser');
const multer  = require('multer');
const bodyParser = require('body-parser');
const listenPort = 3002;
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());

// misc
global.uuidV4 = require('uuid/v4');
global.fs = require('fs');
global.net = require('net'); //for unix sockets
global.rmfr = require('rmfr');
global.spawn = require('child_process').spawn;
const exec = require('child_process').exec;
global.temp = require('temp');
global.moment = require('moment');
const util = require('util');
global.winston = falseRequire('./logging') || Winston;
const restClient = require('node-rest-client').Client;
global.request = require('request');
const path = require('path');
const nodeCleanup = require('node-cleanup');
const isDocker = require('is-docker');
global.schedule = require('node-schedule');

// socket.io
var socketIoOptions = {
  pingTimeout: 25000,
  perMessageDeflate: false,
  httpCompression: false
};
global.io = require('socket.io')(server, socketIoOptions);
const collectionsChannel = io.of('/collections'); // create /collections namespace


// versioning
const buildProperties = falseRequire('./build-properties') || BuildProperties;
const version = `${buildProperties.major}.${buildProperties.minor}.${buildProperties.patch}.${buildProperties.build}-${buildProperties.level}`;


// project file imports.  Handles native and minified cases
const feedScheduler = falseRequire('./feed-scheduler') || FeedScheduler;
const rollingCollectionHandler = falseRequire('./rolling-collections') || RollingCollectionHandler;
const fixedCollectionHandler = falseRequire('./fixed-collections') || FixedCollectionHandler;

// dev mode?
global.development = process.env.NODE_ENV !== 'production';


// export NODE_ENV='production'
// export NODE_ENV='development'
var debug = 'AFBDEBUG' in process.env && process.env['AFBDEBUG'] > 0;
global.purgeHack = false; // causes sessions older than 5 minutes to be purged, if set to true.  Useful for testing purging without having to wait an hour
global.purgeHackMinutes = 5;

global.tokenSigningHack = false;
global.tokenSigningHackSeconds = 60;

if (development) {
  winston.level = 'debug';
  winston.debug('Atomic Fishbowl Server is running in development mode');
}
else {
  winston.level = 'info';
}

if (debug) {
  winston.debug('Atomic Fishbowl Server debug logging is enabled');
  winston.level = 'debug';
}

winston.info('Starting Atomic Fishbowl server version', version);






//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////CONFIGURATION//////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const testLicensing = false; // will cause the license to expire in testLicensingMins minutes
const testLicensingMins = null; // null will disable override of minutes
global.license = {
  valid: false,
  expiryTime: 0
};

var feederSocket = null;
var feederSocketFile = null;
var feederInitialized = false;
var apiInitialized = false;

var licenseExpiryJob = null; // placeholder for cron-like job to expire the license

// Load config
const ConfigManager = (function() {return falseRequire('./configuration-manager') || ConfigurationManager})();
const afbconfig = new ConfigManager(args, io);
const tokenMgr = afbconfig.tokenMgr;

// Multipart upload config
const upload = multer({ dest: afbconfig.tempDir });



// Set up feed scheduler
const scheduler = new feedScheduler(afbconfig, io, (id) => schedulerUpdatedCallback(id));





// Create LibreOffice profiles dir
if ( !fs.existsSync(afbconfig.dataDir) ) {
  winston.info(`Creating data directory at ${afbconfig.dataDir}`);
  fs.mkdirSync(afbconfig.dataDir);
}
if ( !fs.existsSync(afbconfig.sofficeProfilesDir) ) {
  winston.info(`Creating soffice profiles directory at ${afbconfig.sofficeProfilesDir}`);
  fs.mkdirSync(afbconfig.sofficeProfilesDir);
}
if ( !fs.existsSync(afbconfig.feedsDir) ) {
  winston.info(`Creating feeds directory at ${afbconfig.feedsDir}`);
  fs.mkdirSync(afbconfig.feedsDir);
}
if ( !fs.existsSync(afbconfig.tempDir) ) {
  winston.info(`Creating temp directory at ${afbconfig.tempDir}`);
  fs.mkdirSync(afbconfig.tempDir);
}




///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////STARTUP///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

(async function() {
  await afbconfig.connectToDB(); // this must come before mongoose user connection so that we know whether to create the default admin account
  await mongooseInit();
  // validate the license
  checkLicense();
  tokenMgr.cleanBlackList();
  setInterval( () => tokenMgr.cleanBlackList(), 1000 * 60); // run every minute
  await cleanCollectionDirs();
  scheduler.updateSchedule(afbconfig.feeds);
  try {
    startFeeder();
  }
  catch(err) {
    winston.error("Caught error whilst starting feed server:", err);
    winston.error(err);
    process.exit(1);
  }
})()





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////API CALLS/////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////LOGIN & LOGOUT//////////////////////

app.post('/api/login', passport.authenticate('local'), (req,res) => {
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  User.findOne({username: req.body.username, enabled: true}, (err, user) => {
    if (err) {
      winston.info("Error looking up user " + req.body.username + ': ' + err);
    }
    if (!user) { // we likely will never enter this block as the validation is really already done by passport
      winston.info('Login failed for user ' + req.body.username + '.  User either not found or not enabled');
      res.json({ success: false, message: 'Authentication failed' });
    }
    else {
      winston.info(`User ${req.body.username} has logged in`);
      winston.debug("Found user " + req.body.username + ".  Signing token");
      let tokenEpirySeconds = tokenSigningHack ? tokenSigningHackSeconds : afbconfig.tokenExpirationSeconds;
      winston.debug("tokenExpirationSeconds:", tokenEpirySeconds);
      let token = jwt.sign(user.toObject({versionKey: false, transform: transformUser}), afbconfig.jwtPrivateKey, { subject: user.id, algorithm: 'RS256', expiresIn: tokenEpirySeconds, jwtid: uuidV4() }); // expires in 24 hours

      if ('query' in req && 'socketId' in req.query) {
        // socketId is the socket.io socketID
        let socketId = req.query.socketId;
        
        let decoded = jwt.decode(token);
      
        if (socketId in io.sockets.sockets) {
          let socket = io.sockets.sockets[socketId];
          socket.conn['jwtuser'] = decoded; // write our token info to the socket so it can be accessed later
          tokenMgr.addSocketToken(socket); // decoded.jti, decoded.exp
          socket.once('clientReady', () => onClientReady(socket) );
          socket.emit('socketUpgrade');
        }
        else {
          winston.error(`User ${req.user.username} logged in with an invalid socket id: ${socketId}`);
        }
      }

      res.cookie('access_token', token, { httpOnly: true, secure: true });
      res.json({
        success: true,
        user: user.toObject(),
        sessionId: uuidV4()
      });
    }
  });
});



app.get('/api/logout', passport.authenticate('jwt', { session: false } ), async (req,res) => {
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  winston.info(`User '${req.user.username}' has logged out`);
  let decoded = jwt.decode(req.cookies.access_token); //we can use jwt.decode here without signature verification as it's already been verified during authentication
  // winston.debug("decoded:", decoded);
  let tokenId = decoded.jti; //store this
  // winston.debug("decoded tokenId:", tokenId);

  tokenMgr.removeSocketTokensByJwt(tokenId); // downgrade sockets of token
  await tokenMgr.blacklistToken(tokenId); // blacklist the token

  res.clearCookie('access_token');
  res.status(200).send(JSON.stringify( { success: true } ));
});



app.get('/api/isloggedin', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  winston.info(`User '${req.user.username}' has logged in`);
  
  if ('query' in req && 'socketId' in req.query) {
    // socketId is the socket.io socketID
    let socketId = req.query.socketId;
    
    let decoded = jwt.decode(req.cookies.access_token); //we can use jwt.decode here without signature verification as it's already been verified during authentication
  
    if (socketId in io.sockets.sockets) {
      let socket = io.sockets.sockets[socketId];  
      socket.conn['jwtuser'] = decoded; // write our token info to the socket so it can be accessed later
      tokenMgr.addSocketToken(socket); // decoded.jti, decoded.exp
      socket.once('clientReady', () => onClientReady(socket) );
      socket.emit('socketUpgrade');
    }
    else {
      winston.error(`User ${req.user.username} logged in with an invalid socket id: ${socketId}`);
    }
  }

  res.json( { user: req.user.toObject(), sessionId: uuidV4() }); // { versionKey: false, transform: transformUserIsLoggedIn }
});








//////////////////////USERS//////////////////////

function emitUsers(sock) {
  try {
    User.find( (err, users) => {
      if (err) {
        winston.error("obtaining users:", err);
      }
      else {
        sock.emit('users', users);
      }
    
    } );
  }
  catch(e) {
    winston.error('ERROR GET /api/user:',e);
  }
}



app.get('/api/user/:uname', passport.authenticate('jwt', { session: false } ), (req,res) => {
  // get details of user uname
  let uname = req.params.uname;
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  winston.info(`User '${req.user.username}' has requested info for user ${uname}`);
  try {
    User.findOne( {'username' : uname },(err, user) => {
      if (err) {
        winston.error('ERROR finding user ' + uname + ':', err);
        res.status(500).send( JSON.stringify( { success: false, error: err } ) );
      }
      else {
        res.json(user.toObject());
      }
    
    } );
  }
  catch(e) {
    winston.error('ERROR GET /api/user/' + uname + ':', e);
  }
});  



app.post('/api/user', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // add a new user
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  
  let u = req.body;
  let uPassword = afbconfig.decryptor.decrypt(u.password, 'utf8');
  u.password = uPassword;
  User.register(new User({ id: uuidV4(), username : u.username, fullname: u.fullname, email: u.email, enabled: u.enabled }), u.password, (err, user) => {
    if (err) {
      winston.error("Error adding user " + u.username  + " by user " + req.body.username + ' : ' + err);
      res.status(500).send( JSON.stringify( { success: false, error: err } ) );
    }
    else {
      winston.info(`User '${req.user.username}' has added a new user '${u.username}'`);
      emitUsers(io);
      res.status(201).send( JSON.stringify( { success: true } ) );
    }
  });
});


function updateUser(req, res, passChange = false) {
  let u = req.body;
  User.findOneAndUpdate( { id: u.id }, u, (err, doc) => {
    // winston.info("Updating user object with id", u.id);
    //now update user object
    if (err) {
      winston.error("ERROR modifying user with id" + u.id + ':', err);
      res.status(500).send( JSON.stringify( { success: false, error: err } ) );
    }
    else {
      if (!passChange) {
        winston.info(`User '${req.user.username}' has edited user ${doc._doc.username}`);
      }
      else {
        winston.info(`User '${req.user.username}' has changed the password for user ${doc._doc.username}`);
      }
      emitUsers(io);
      res.status(201).send( JSON.stringify( { success: true } ) );
    }
  });

}



app.post('/api/user/edit', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // edit an existing user
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);

  let u = req.body;
  //winston.debug('user:', u);
  
  if (!('password' in req.body)) {
    updateUser(req, res);
  }
  else {
    winston.debug("Updating password for user with id", u.id);

    let uPassword = afbconfig.decryptor.decrypt(u.password, 'utf8');
    u.password = uPassword;

    //change password
    try {
      let username = '';
      User.findOne( { 'id': u.id }, (err, doc) => {
        if (err) throw(err);
        username = doc.username;
      })
      .then ( () => {
        User.findByUsername(username, (err, user) => {
          if (err) throw(err);
          user.setPassword(u.password, (err) => {
            if (err) throw(err);
            user.save( (error) => { 
              if (err) throw(err);
              delete u.password; //we don't want this getting set when we update the user object
              updateUser(req, res, true);
            });
          });
        });
      });
    }
    catch(e) {
      winston.error("ERROR changing changing password:", e);
      res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
      return;
    }
  }
});



app.delete('/api/user/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let id = req.params.id;
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  try {
    User.findOne( {id: id}, (err, doc) => {
      if (err) {
        throw err;
      }
      
      User.find( {id: id} ).remove( (err) => {
        if (err) {
          throw err;
        }
        else {
          winston.info(`User '${req.user.username}' has deleted user ${doc._doc.username}`);
          emitUsers(io);
          res.status(204).send( JSON.stringify( { success: true } ) );
        }
      } );
    } );
  }
  catch(e) {
    winston.error("ERROR removing user:", e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
    return;
  }
});





//////////////////////COLLECTIONS//////////////////////
  

app.get('/api/collection', passport.authenticate('jwt', { session: false } ), (req,res) => {
  // Gets the configuration of all collections
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  winston.info(`User '${req.user.username}' has requested the collections list`);
  try {
    res.json(afbconfig.collections);
  }
  catch(error) {
    winston.error('ERROR GET /api/collection:', error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
  }
});



function getCollectionPosition(id) {
  for(var i=0; i < afbconfig.collections.length; i++) {
    let col = afbconfig.collections[i];
    if (col.id === id) {
      return i;
    }
  }
}



app.delete('/api/collection/:id', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // Deletes a collection
  let id = req.params.id;
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);

  if (!(id in afbconfig.collections)) {
    winston.info(`WARN DELETE /api/collection/${id} : Collection not found` );
    // res.body = "Collection not found";
    res.status(400).send( JSON.stringify( { success: false, error: 'collection ' + id + ' not found'} ) );
    return;
  }

  let collection = afbconfig.collections[id];
  try {

    if (collection.type === 'rolling' || collection.type === 'monitoring') {
      rollingHandler.collectionDeleted(id, req.user.username);
    }
    else if (collection.type === 'fixed' && collection.state !== 'complete') { // fixed
      fixedHandler.collectionDeleted(id, req.user.username);
    }

    await afbconfig.deleteCollection(id);
    tokenMgr.authSocketsEmit('collectionDeleted', { user: req.user.username, id: id } ); // let socket clients know this has been deleted
  }
  catch(error) {
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    winston.error(`Error deleting ${collection.type} collection with id ${id}`);
    winston.err(error);
    process.exit(1);
  }

  res.status(200).send( JSON.stringify( { success: true } ) );
  winston.info(`User '${req.user.username}' has deleted collection '${collection.name}'`);   
});



app.get('/api/collection/data/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // Gets the collection data for a collection (content, sessions, and search)
  let id = req.params.id;
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  try {
    if (!(id in afbconfig.collectionsData)) {
      throw('collection was not found');
    }
    res.json(afbconfig.collectionsData[id]);
    winston.info(`User '${req.user.username}' has requested the defintion of collection '${afbconfig.collections[id].name}'`);
  }
  catch (error) {
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    return;
  }
});



app.post('/api/collection', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // Adds a new collection
  // 'state' should always be at initial

  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  // winston.debug(req);
  try {
    let timestamp = new Date().getTime();
    //winston.debug(req.body);
    let collection = req.body;
    if (!('type' in collection)) {
      throw("'type' is not defined");
    }
    if (!('id' in collection)) {
      throw("'id' is not defined");
    }
    if (!('name' in collection)) {
      throw("'name' is not defined");
    }
    if (!('nwserver' in collection) && !('saserver' in collection) ) {
      throw("Either 'nwserver' or 'saserver' is not defined");
    }
    if (!('nwserverName' in collection) && !('saserverName' in collection)) {
      throw("Either 'nwserverName' or 'saserverName' is not defined");
    }
    if (!('bound' in collection)) {
      throw("'bound' is not defined");
    }
    if (!('usecase' in collection)) {
      throw("'usecase' is not defined");
    }
    if (collection.bound && collection.usecase == 'custom') {
      throw('A bound collection must be associated with a non-custom use case')
    }
    else if (collection.bound && collection.usecase !== 'custom' && !(collection.usecase in afbconfig.useCases.useCasesObj) ) {
      throw(`Collection use case ${collection.usecase} is not a valid use case!`);
    }
    
    if (!collection.bound) {
      if (!('query' in collection)) {
        throw("'query' is not defined");
      }
      if (!('contentTypes' in collection)) {
        throw("'contentTypes' is not defined");
      }
    }
    
    if (collection.type == 'rolling' || collection.type == 'monitoring') {
      collection['state'] = 'stopped';
    }
    else {
      // fixed
      collection['state'] = 'initial';
    }

    let creator = {
      username: req.user.username,
      id: req.user.id,
      fullname: req.user.fullname,
      timestamp: timestamp
    };
    collection['creator'] = creator;

    await afbconfig.addCollection(collection);
    winston.info(`User '${req.user.username}' has added a new collection '${collection.name}'`);
    res.status(201).send( JSON.stringify( { success: true } ) );   
  }
  catch(error) {
    winston.error("POST /api/collection:", error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
  }
});



app.post('/api/collection/edit', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // Edits an existing collection
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  try {
    let timestamp = new Date().getTime();
    let collection = req.body;
    winston.debug('collection:', collection);
    let id = collection.id;
    let oldCollection = deepCopy(afbconfig.collections[id]);
    if (collection.type == 'rolling' || collection.type == 'monitoring') {
      collection['state'] = 'stopped';
    }
    else {
      collection['state'] = 'initial';
    }
    if (!(id) in afbconfig.collections) {
      throw([oldCollection, `Cannot update collection ${collection.name}.  Collection ${id} does not exist`]);
    }

    // do something here to stop / reload an existing rolling collection

    let modifier = {
      username: req.user.username,
      id: req.user.id,
      fullname: req.user.fullname,
      timestamp: timestamp
    };
    collection['modifier'] = modifier;

    // console.log('got to 1');
    rollingHandler.collectionEdited(id, collection);
    // console.log('got to 2');

    try {
      await afbconfig.editCollection(collection);
      // console.log('got to 3');
    }
    catch (error) {
      throw( [ oldCollection, error ] );
    }
    winston.info(`User '${req.user.username}' has edited collection '${oldCollection.name}'`);
    res.status(205).send( JSON.stringify( { success: true } ) );
  }
  catch(vars) {
    let collection = vars[0];
    let error = vars[1];
    winston.debug("ERROR: POST /api/collection/edit". error);
    winston.error(`A fatal exception was raised whilst User '${req.user.username}' was editing collection ${collection.name}:\n`, error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    process.exit(1);
  }
});






//////////////////////FEEDS//////////////////////

app.post('/api/feed/manual', passport.authenticate('jwt', { session: false } ), upload.single('file'), async (req, res) => {
  // Add a manual feed
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  // winston.debug('req:', req);
  let timestamp = new Date().getTime();
  try {
    // winston.debug(req.body);
    let feed = JSON.parse(req.body.model);
    // winston.debug('req.file:', req.file);
    // winston.debug('feed:', feed);
    if (!('id' in feed)) {
      throw("'id' is not defined");
    }
    let id = feed.id;

    if (id in afbconfig.feeds) {
      throw('Feed id ' + id + ' already exists!')
    }

    if (!('name' in feed)) {
      throw("'name' is not defined");
    }

    if (!('type' in feed)) {
      throw("'type' is not defined");
    }

    if (!('delimiter' in feed)) {
      throw("'delimiter' is not defined");
    }

    if (!('headerRow' in feed)) {
      throw("'headerRow' is not defined");
    }

    if (!('valueColumn' in feed)) {
      throw("'valueColumn' is not defined");
    }

    if (!('typeColumn' in feed)) {
      throw("'typeColumn' is not defined");
    }

    if (!('friendlyNameColumn' in feed)) {
      throw("'friendlyNameColumn' is not defined");
    }

    if (!('filename' in req.file)) {
      throw("'filename' not found in file definition");
    }

    if (!('path' in req.file)) {
      throw("'path' not found in file definition");
    }

    feed['version'] = 1;

    let creator = {
      username: req.user.username,
      id: req.user.id,
      fullname: req.user.fullname,
      timestamp: timestamp
    };
    feed['creator'] = creator;

    try {
      await fs.promises.rename(req.file.path, afbconfig.feedsDir + '/' + id + '.feed');
    }
    catch (error) {
      winston.error('Error moving file to feedsDir:', error);
      await fs.promises.unlink(req.file.path);
      throw(error);
    }

    await afbconfig.addFeed(feed);
    winston.info(`User '${req.user.username}' has added a new manual feed '${feed.name}'`);
    writeToSocket( feederSocket, JSON.stringify( { new: true, feed: feed } ) );
    res.status(201).send( JSON.stringify( { success: true } ) );
  }
  catch (error) {
    winston.error("POST /api/feed/manual: " + error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    return;
  }
});



app.post('/api/feed/scheduled', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // Add a scheduled feed
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  // winston.debug('req:', req);
  let timestamp = new Date().getTime();
  try {
    let feed = req.body;
    // winston.debug('feed:', feed);

    if (!('id' in feed)) {
      throw("'id' is not defined");
    }
    let id = feed.id;

    if (id in afbconfig.feeds) {
      throw('Feed id ' + id + ' already exists!')
    }

    if (!('name' in feed)) {
      throw("'name' property not found in feed definition");
    }

    if (!('type' in feed)) {
      throw("'type' property not found in feed definition");
    }

    if (!('delimiter' in feed)) {
      throw("'delimiter' property not found in feed definition");
    }

    if (!('headerRow' in feed)) {
      throw("'headerRow' property not found in feed definition");
    }

    if (!('valueColumn' in feed)) {
      throw("'valueColumn' property not found in feed definition");
    }

    if (!('typeColumn' in feed)) {
      throw("'typeColumn' property not found in feed definition");
    }

    if (!('friendlyNameColumn' in feed)) {
      throw("'friendlyNameColumn' property not found in feed definition");
    }

    if (!('schedule' in feed)) {
      throw("'schedule' property not found in feed definition");
    }

    if (!('url' in feed)) {
      throw("'url' property not found in feed definition");
    }

    if (!('authentication' in feed)) {
      throw("'authentication' property not found in feed definition");
    }

    if (feed.authentication && !('username' in feed && 'password' in feed)) {
      throw("Credentials not found in feed definition");
    }

    feed['version'] = 1;

    let creator = {
      username: req.user.username,
      id: req.user.id,
      fullname: req.user.fullname,
      timestamp: timestamp
    };
    feed['creator'] = creator;

    // now we need to fetch the file and write it to disk
    let options = { url: feed.url, method: 'GET', gzip: true };
    if (feed.authentication) {
      options['auth'] = { user: feed.username, pass: afbconfig.decryptor.decrypt(feed.password, 'utf8'), sendImmediately: true };
    }
    
    // let tempName = path.basename(temp.path({suffix: '.scheduled'}));

    request(options, async (error, result, body) => { // get the feed
      // callback
      winston.debug('/api/feed/scheduled: myRequest callback()');

      try {
        await afbconfig.addFeed(feed);
      }
      catch (error) {
        winston.error('/api/feed/scheduled: insertOne(): error adding feed to db:', error);
        throw(error);
      }
      winston.debug('/api/feed/scheduled: insertOne(): feed added to db');
      winston.info(`User '${req.user.username}' has added a new scheduled feed '${feed.name}'`);
      scheduler.addFeed(feed);
      writeToSocket( feederSocket, JSON.stringify( { new: true, feed: feed } ) ); // let feeder server know of our update
      res.status(201).send( JSON.stringify( { success: true } ) );
    })
    .on('end', () => {
      winston.debug('/api/feed/scheduled: myRequest end()');
    })
    .on('error', (err) => {
      winston.debug('/api/feed/scheduled: myRequest error()');
      res.status(500).send( JSON.stringify( { success: false, error: err } ) );
    })
    .pipe(fs.createWriteStream(afbconfig.feedsDir + '/' + id + '.feed'));
  }
  catch(error) {
    winston.error("POST /api/feed/scheduled: " + error );
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
  }
});



app.post('/api/feed/edit/withfile', passport.authenticate('jwt', { session: false } ), upload.single('file'), async (req, res) => {
  // this is for editing of manual feeds which contain a new file
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  // winston.debug('req:', req);
  
  try {
    let timestamp = new Date().getTime();
    let feed = JSON.parse(req.body.model);
    
    if (!('id' in feed)) {
      throw("'id' parameter not found in feed");
    }

    let id = feed.id;
    if (!(id in afbconfig.feeds)) {
      throw('Feed not found');
    }

    // get creator from old feed
    let oldFeed = afbconfig.feeds[id];
    let creator = oldFeed.creator
    let oldFeedName = oldFeed.name;
    feed['creator'] = creator;
    feed['version'] = oldFeed.version + 1;

    let modifier = {
      username: req.user.username,
      id: req.user.id,
      fullname: req.user.fullname,
      timestamp: timestamp
    };
    feed['modifier'] = modifier;

    try {
      await fs.promises.rename(req.file.path, afbconfig.feedsDir + '/' + id + '.feed');
    }
    catch (error) {
      winston.error('Error moving file to feedsDir:', error);
      await fs.promises.unlink(req.file.path);
      throw(error);
    }
    await afbconfig.editFeed(feed);
    winston.info(`User '${req.user.username}' has edited feed '${oldFeedName}' and updated its CSV file`);
    writeToSocket( feederSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
    res.status(201).send( JSON.stringify( { success: true } ) );
  }
  catch(error) {
    winston.error("POST /api/feed/edit/withfile: " + error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
  }
});




app.post('/api/feed/edit/withoutfile', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // this is for editing of any feed which does not include a new file, both manual or scheduled
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  // winston.debug('req:', req);
  
  try {
    let timestamp = new Date().getTime();
    let feed = req.body;
    
    if (!('id' in feed)) {
      throw("'id' parameter not found in feed");
    }

    let id = feed.id;
    if (!(id in afbconfig.feeds)) {
      throw('Feed not found');
    }

    // get creator from old feed
    let oldFeed = afbconfig.feeds[id];
    let creator = oldFeed.creator
    let oldFeedName = oldFeed.name;
    feed['creator'] = creator;
    feed['version'] = oldFeed.version + 1;

    let modifier = {
      username: req.user.username,
      id: req.user.id,
      fullname: req.user.fullname,
      timestamp: timestamp
    };
    feed['modifier'] = modifier;

    if (feed.type == 'manual' ) {
      await afbconfig.editFeed(feed);
      winston.info(`User '${req.user.username}' has edited manual feed '${oldFeedName}' without updating its CSV file`);
      writeToSocket( feederSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
      res.status(201).send( JSON.stringify( { success: true } ) );
      if (oldFeed.type == 'scheduled') {
        // tell scheduler to remove old feed
        scheduler.delFeed(feed.id);
      }
    }
    else {
      // scheduled feed
      // always pull feed anew.  this will save on funky logic
      let options = { url: feed.url, method: 'GET', gzip: true };
      if (feed.authentication) {
        if (!feed.authChanged) {
          feed['username'] = oldFeed.username;
          feed['password'] = oldFeed.password; // if credentials haven't changed, then set the password to the old password
        }
        options['auth'] = { user: feed.username, pass: afbconfig.decryptor.decrypt(feed.password, 'utf8'), sendImmediately: true };
      }

      request(options, async (error, result, body) => { // get the feed
        // callback
        winston.debug('/api/feed/edit/withoutfile: myRequest callback()');

        try {
          await afbconfig.editFeed(feed);
        }
        catch(error) {
          winston.error('/api/feed/edit/withoutfile updateOne(): error updating feed in db:', err);
          throw(err);
        }
        winston.debug('/api/feed/edit/withoutfile: updateOne(): feed modified in db');
        winston.info(`User '${req.user.username}' has edited scheduled feed '${oldFeedName}' without updating its CSV file`);
        // calculate file hash for feed file
        scheduler.updateFeed(feed);
        writeToSocket( feederSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
        res.status(201).send( JSON.stringify( { success: true } ) );
      })
      .on('end', () => {
        winston.debug('/api/feed/edit/withoutfile: myRequest end()');
      })
      .on('error', (err) => {
        winston.debug('/api/feed/edit/withoutfile: myRequest error()');
        res.status(500).send( JSON.stringify( { success: false, error: err } ) )
      })
      .pipe(fs.createWriteStream(afbconfig.feedsDir + '/' + id + '.feed'));

    }

  }
  catch(e) {
    winston.error("POST /api/feed/edit/withoutfile: " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});




app.post('/api/feed/testurl', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);

  let url = '';
  let options = { method: 'GET', gzip: true };

  try {
    let host = req.body;
    winston.debug('host:', host);
    
    if (!('url' in host)) {
      throw("'url' property not found in host definition");
    }

    if (!('authentication' in host)) {
      throw("'authentication' property not found in host definition");
    }

    if ('useCollectionCredentials' in host) {
      let id = host.useCollectionCredentials;
      options['auth'] = { user: afbconfig.feeds[id].username, pass: afbconfig.decryptor.decrypt(afbconfig.feeds[id].password, 'utf8'), sendImmediately: true };
    }
    else if (host.authentication && !('username' in host && 'password' in host)) {
      throw("Credentials not found in host definition");
    }
    else if (host.authentication) {
      options['auth'] = { user: host.username, pass: afbconfig.decryptor.decrypt(host.password, 'utf8'), sendImmediately: true };
    }
    url = host.url;
    options['url'] = url

  }
  catch(e) {
    winston.error("POST /api/feed/testurl " + e);
    // res.status(500).send(JSON.stringify(e.message || e) );
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
    return;
  }

  let buffer = '';
  let rawCSV = '';
  let myRes = null;

  let myrequest = request(options, (error, result, body) => {
    winston.debug('/api/feed/testurl: request callback()');
    
    myRes = result;

    if (error) {
      // winston.debug('/api/feed/testurl: caught error:', error);
      winston.debug(`User '${req.user.username}' caught an error whilst testing feed URL '${url}':`, error);
      let body = { success: false, error: error };
      if (result.statusCode) {
        body['statusCode'] = result.statusCode;
      }
      res.status(200).send( JSON.stringify( body ) );
      return;
    }

    winston.info(`User '${req.user.username}' has tested feed URL '${url}'.  Status Code: ${result.statusCode}`);
    
    if (result.statusCode != 200) {
      res.status(200).send( JSON.stringify( { success: false, error: 'Bad HTTP status code', statusCode: result.statusCode } ) );
    }
    else if (rawCSV) {
      // winston.debug('/api/feed/testurl: onEnd(): rawCSV:\n' + rawCSV);
      res.status(200).send( JSON.stringify( { success: true, rawCSV: rawCSV } ) )
    }
    else if (buffer.length > 0) {
      winston.debug('/api/feed/testurl: fewer than 6 lines were found in the CSV');
      // let lines = buffer.split('\n');
      res.status(200).send( JSON.stringify( { success: true, rawCSV: buffer } ) )
    }
    else {
      winston.debug('/api/feed/testurl: empty response');
      res.status(200).send( JSON.stringify( { success: false, error: 'Empty response' } ) );
    }

  });

  myrequest.on('data', (data) => {
    //called when a chunk of data is received
    let dataStr = data.toString('utf8');
    winston.debug('/api/feed/testurl: onData()');
    // winston.debug('/api/feed/testurl: onData(): data:', data);
    // winston.debug('/api/feed/testurl: onData(): dataStr:\n' + dataStr);
    buffer += dataStr;
    
    let count = -1; // the number of newline chars we've found this time
    for (let index = -2; index !== -1; count++, index = buffer.indexOf('\n', index + 1) ) {} // count newlines

    if (count >= 6) {
      let lines = buffer.split('\n');
      // console.debug(lines);
      while (lines.length > 6) {
        lines.pop();
      }
      rawCSV = lines.join('\n');
      // winston.debug('/api/feed/testurl: onData(): rawCSV:\n' + rawCSV);
      myrequest.destroy();
      // myrequest.shouldKeepAlive = false;
    }

  });
});



app.get('/api/feed/filehead/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  try {
    let id = req.params.id;
    winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
    
    if ( !(id in afbconfig.feeds) ) {
      throw('Feed not found');
    }
    
    let feed = afbconfig.feeds[id];
    winston.info(`User '${req.user.username}' has requested CSV file content for feed ${feed.name}`);
    let chunkSize = 1024;
    let maxBufSize = 262144;
    let buffer = new Buffer(maxBufSize);
    let bytesRead = 0;
    let fileSize = fs.statSync(afbconfig.feedsDir + '/' + id + '.feed').size;
    if (chunkSize > fileSize) {
      chunkSize = fileSize;
    }

    fs.open(afbconfig.feedsDir + '/' + id + '.feed', 'r', (err, fd) => {
      
      if (err) {
        throw(err);
      }

      let rawCSV = '';

      let fsCallback = (err, read, buf) => {
        bytesRead += read;
        let data = buffer.toString();
        let count = -1; // the number of newline chars we've found this time
        for (let index = -2; index !== -1; count++, index = data.indexOf('\n', index + 1) ) {} // count newlines
        if (count >= 6) {
          let lines = data.split('\n');
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
          fs.read(fd, buffer, bytesRead, chunkSize, null, fsCallback);
          return;
        }
        // we've read everything
        finishCallback();
      };

      let finishCallback = () => {
        // reading finished
        // winston.debug('!!!FINISHED');
        if (rawCSV) {
          // winston.debug('/api/feed/filehead/:id: onEnd(): rawCSV:\n' + rawCSV);
          res.status(200).send( JSON.stringify( { success: true, rawCSV: rawCSV } ) )
        }
        else if (buffer.length > 0) {
          winston.debug('/api/feed/filehead/:id : fewer than 6 lines were found in the CSV');
          // let lines = buffer.split('\n');
          res.status(200).send( JSON.stringify( { success: true, rawCSV: buffer.toString() } ) )
        }
        else {
          winston.debug('/api/feed/filehead/:id : empty file');
          res.status(200).send( JSON.stringify( { success: false, error: 'Empty response' } ) );
        }
      }

      fs.read(fd, buffer, bytesRead, chunkSize, null, fsCallback);

    });

  }
  catch(e) {
    winston.error("GET /api/feed/filehead/:id : " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
    return;
  }
});



app.delete('/api/feed/:id', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // delete a feed
  let id = req.params.id;
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  try {
    if (id in afbconfig.feeds) {
      let oldFeedName = afbconfig.feeds[id].name;
      await fs.promises.unlink(afbconfig.feedsDir + '/' + id + '.feed');
      await afbconfig.deleteFeed(id); 
      winston.info(`User '${req.user.username}' has deleted feed ${oldFeedName}`);
      writeToSocket( feederSocket, JSON.stringify( { delete: true, id: id } ) ); // let feeder server know of our update
      scheduler.delFeed(id);
      res.status(200).send( JSON.stringify( { success: true } ) );
    }
    else {
      res.status(400).send( JSON.stringify( { success: false, error: 'Feed not found' } ) );
    }
  }
  catch(error) {
    winston.error(`ERROR DELETE /api/feed/${id} :`, error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
  }
});







//////////////////////NWSERVERS//////////////////////

app.delete('/api/nwserver/:id', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // for deleting a netwitness server
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  let oldNwserver, id;
  try {
    if (!('id' in req.params)) {
      throw ('Could not find \'id\' in request parameters' );
    }
    id = req.params.id;
    oldNwserver = afbconfig.nwservers[id];
    await afbconfig.deleteNwServer(id);
  }
  catch (error) {
    winston.error(`ERROR DELETE /api/nwserver/${id} :`, error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    return;
  }
  winston.info(`User '${req.user.username}' has deleted NetWitness server '${oldNwserver.user}@${oldNwserver.host}:${oldNwserver.port}'`);
  tokenMgr.authSocketsEmit('nwservers', redactApiServerPasswords(afbconfig.nwservers));
  res.status(200).send( JSON.stringify( { success: true } ) );
});



app.post('/api/nwserver', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // for adding a netwitness server
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  let nwserver;
  try {
    nwserver = req.body;
    //winston.debug(nwserver);
    if (!('id' in nwserver)) {
      throw("'id' is not defined in nwserver");
    }
    if (!('friendlyName' in nwserver)) {
      throw("'friendlyName' is not defined in nwserver");
    }
    if (!('host' in nwserver)) {
      throw("'host' is not defined in nwserver");
    }
    if (!('port' in nwserver)) {
      throw("'port' is not defined in nwserver");
    }
    if (!('user' in nwserver)) {
      throw("'user' is not defined in nwserver");
    }
    if (!('password' in nwserver)) {
      throw("'password' is not defined in nwserver"); // we don't decrypt here.  We only decrypt when we build a worker config
    }
    if (!('ssl' in nwserver)) {
      throw("'ssl' is not defined in nwserver");
    }
    await afbconfig.addNwServer(nwserver);
  }
  catch(error) {
    winston.error("POST /api/nwserver: " + error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    return;
  }
 
  winston.info(`User '${req.user.username}' has added NetWitness server '${nwserver.user}@${nwserver.host}:${nwserver.port}'`);
  tokenMgr.authSocketsEmit('nwservers', redactApiServerPasswords(afbconfig.nwservers));
  res.status(201).send( JSON.stringify( { success: true } ) );
    
});



app.post('/api/nwserver/edit', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // for editing a netwitness server
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  let oldNwserver;
  try {
    let nwserver = req.body;
    //winston.debug(nwserver);
    if (!('id' in nwserver)) {
      throw("'id' is not defined");
    }
    let id = nwserver.id;
    if (!('friendlyName' in nwserver)) {
      throw("'friendlyName' is not defined in nwserver");
    }
    if (!('host' in nwserver)) {
      throw("'host' is not defined in nwserver");
    }
    if (!('port' in nwserver)) {
      throw("'port' is not defined in nwserver");
    }
    if (!('user' in nwserver)) {
      throw("'user' is not defined in nwserver");
    }
    if (!('password' in nwserver)) {
      // use existing password
      nwserver['password'] = afbconfig.nwservers[id].password;
    }
    oldNwserver = deepCopy(afbconfig.nwservers[id]);
    if (!('ssl' in nwserver)) {
      throw("'ssl' is not defined  in nwserver");
    }
    await afbconfig.editNwServer(nwserver);
  }
  catch(error) {
    winston.error("POST /api/nwserver/edit: " + error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    return;
  }
  winston.info(`User '${req.user.username}' has edited NetWitness server '${oldNwserver.user}@${oldNwserver.host}:${oldNwserver.port}'`);
  tokenMgr.authSocketsEmit('nwservers', redactApiServerPasswords(afbconfig.nwservers));
  res.status(200).send( JSON.stringify( { success: true } ) );
});



app.post('/api/nwserver/test', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // for testing a netwitness serveer
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  let nwserver;
  try {
    nwserver = req.body;
    var uPassword = '';
    // console.log(nwserver);
    if (nwserver.hasOwnProperty('id') && !(nwserver.hasOwnProperty('password'))) {
      let id = nwserver.id;
      uPassword = afbconfig.decryptor.decrypt(afbconfig.nwservers[id].password, 'utf8');
    }
    else if (nwserver.hasOwnProperty('id') && nwserver.hasOwnProperty('password')) {
      let id = nwserver.id;
      uPassword = afbconfig.decryptor.decrypt(nwserver.password, 'utf8');
    }
    else {
      uPassword = afbconfig.decryptor.decrypt(nwserver.password, 'utf8');
    }
    // console.log(nwserver);
    var host = nwserver.host;
    var ssl = nwserver.ssl;
    var port = nwserver.port;
    var user = nwserver.user;
    
    //var uPassword = afbconfig.decryptor.decrypt(nwservers[id].password, 'utf8');
    
    var proto = 'http://'
    if (ssl) {
      proto = 'https://';
    }
    var url = `${proto}${host}:${port}`;

  }
  catch(e) {
    winston.error("POST /api/nwserver/test: " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }

  // Now perform test
  let options = { user: user, password: uPassword, connection: { rejectUnauthorized: false }}; // {requestConfig: {timeout: 5000}, responseConfig: {timeout: 5000}},
  let client = new restClient(options);

  let request = client.get(url, (data, response) => {
    // console.log(response);
    if (response.statusCode == 200) {
      // winston.debug(`REST connection test to url ${url} was successful`);
      winston.info(`User '${req.user.username}' tested NetWitness server '${nwserver.user}@${nwserver.host}:${nwserver.port}' with result success`);
    }
    else {
      // winston.debug(`REST connection test to url ${url} failed.`);
      winston.info(`User '${req.user.username}' tested NetWitness server '${nwserver.user}@${nwserver.host}:${nwserver.port}' with result failure.  STATUS CODE: ${response.statusCode}`);
    }
    res.status(response.statusCode).send( JSON.stringify( { error: response.statusMessage } ) );
  }).on('error', err => {
    // winston.debug(`REST connection test to url ${url} failed with error: ${err.message}`);
    winston.info(`User '${req.user.username}' tested NetWitness server '${nwserver.user}@${nwserver.host}:${nwserver.port}' with result failure.  ${err}`);
    res.status(403).send( JSON.stringify({ error: err.message }) );
  });

});









//////////////////////SASERVERS//////////////////////

app.delete('/api/saserver/:id', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // for deleting an sa server
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  let oldSaserver;
  try {
    if (!('id' in req.params)) {
      throw ('Could not find \'id\' in request parameters' );
    }
    let id = req.params.id;
    oldSaserver = afbconfig.saservers[id];
    await afbconfig.deleteSaServer(id);
  }
  catch(error) {
    winston.error(`ERROR DELETE /api/saserver/${id} :`, error);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
    return;
  }
  winston.info(`User '${req.user.username}' has deleted SA server '${oldSaserver.user}@${oldSaserver.host}:${oldSaserver.port}'`);
  tokenMgr.authSocketsEmit('saservers', redactApiServerPasswords(afbconfig.saservers));
  res.status(200).send( JSON.stringify( { success: true } ) );
});



app.post('/api/saserver', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // for adding an sa server
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  let saserver;
  try {
    //winston.debug(req.body);
    saserver = req.body;
    if (!('id' in saserver)) {
      throw("'id' is not defined");
    }
    if (!('friendlyName' in saserver)) {
      throw("'friendlyName' is not defined in saserver");
    }
    if (!('host' in saserver)) {
      throw("'host' is not defined in saserver");
    }
    if (!('port' in saserver)) {
      throw("'port' is not defined in saserver");
    }
    if (!('user' in saserver)) {
      throw("'user' is not defined in saserver");
    }
    if (!('password' in saserver)) {
      throw("'password' is not defined in saserver"); // we don't decrypt here.  We only decrypt when we build a worker config
    }
    if (!('ssl' in saserver)) {
      throw("'ssl' is not defined in saserver");
    }
    await afbconfig.addSaServer(saserver);
  }
  catch(error) {
    winston.error("POST /api/saserver: " + error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    return;
  }
  winston.info(`User '${req.user.username}' has added SA server '${saserver.user}@${saserver.host}:${saserver.port}'`);
  tokenMgr.authSocketsEmit('saservers', redactApiServerPasswords(afbconfig.saservers));
  res.status(201).send( JSON.stringify( { success: true } ) );
});



app.post('/api/saserver/edit', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  let oldSaserver;
  try {
    //winston.debug(req.body);
    saserver = req.body;
    if (!('id' in saserver)) {
      throw("'id' is not defined in saserver");
    }
    let id = saserver.id;
    oldSaserver = deepCopy(afbconfig.saservers[id]);
    if (!('friendlyName' in saserver)) {
      throw("'friendlyName' is not defined in saserver");
    }
    if (!('host' in saserver)) {
      throw("'host' is not defined in saserver");
    }
    if (!('port' in saserver)) {
      throw("'port' is not defined in saserver");
    }
    if (!('user' in saserver)) {
      throw("'user' is not defined in saserver");
    }
    if (!('password' in saserver)) {
      // use existing password
      saserver['password'] = afbconfig.saservers[id].password;
    }
    if (typeof saserver.ssl === 'undefined') {
      throw("'ssl' is not defined in saserver");
    }
    await afbconfig.editSaServer(saserver);
  }
  catch(error) {
    winston.error("POST /api/saserver/edit: " + error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    return;
  }
  winston.info(`User '${req.user.username}' has edited SA server '${oldSaserver.user}@${oldSaserver.host}:${oldSaserver.port}'`);
  tokenMgr.authSocketsEmit('saservers', redactApiServerPasswords(afbconfig.saservers));
  res.status(200).send( JSON.stringify( { success: true } ) );
});



app.post('/api/saserver/test', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  let saserver;
  try {
    saserver = req.body;
    var uPassword = '';
    // console.log(saserver);
    if (saserver.hasOwnProperty('id') && !(saserver.hasOwnProperty('password'))) {
      let id = saserver.id;
      uPassword = afbconfig.decryptor.decrypt(afbconfig.saservers[id].password, 'utf8');
    }
    else if (saserver.hasOwnProperty('id') && saserver.hasOwnProperty('password')) {
      let id = saserver.id;
      uPassword = afbconfig.decryptor.decrypt(saserver.password, 'utf8');
    }
    else {
      uPassword = afbconfig.decryptor.decrypt(saserver.password, 'utf8');
    }
    // console.log(saserver);
    var host = saserver.host;
    var ssl = saserver.ssl;
    var port = saserver.port;
    var user = saserver.user;
    
    var proto = 'http://'
    if (ssl) {
      proto = 'https://';
    }
    var url = `${proto}${host}:${port}/api/v6/users/account_info`;

  }
  catch(e) {
    winston.error("POST /api/saserver/test: " + e);
    // res.status(500).send(JSON.stringify({error: e.message}) );
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }

  // Now perform test
  let options = { user: user, password: uPassword, connection: { rejectUnauthorized: false }}; // {requestConfig: {timeout: 5000}, responseConfig: {timeout: 5000}},
  let args = { headers: { 'Content-Type': 'application/x-www-form-urlencoded'},
               data: { '_method': 'GET' },
               requestConfig: { timeout: 1000 },
               responseConfig: { timeout: 1000 }
              } //request timeout in milliseconds
  let client = new restClient(options);

    let request = client.post(url, args, (data, response) => {
      // console.log(response);
      if (response.statusCode == 200) {
        // winston.debug(`REST connection test to url ${url} was successful`);
        if (!('resultCode' in data) || data.resultCode != 'API_SUCCESS_CODE') {
          // winston.debug(`REST connection test to url ${url} failed with error:`, data);
          winston.info(`User '${req.user.username}' tested SA server '${saserver.user}@${saserver.host}:${saserver.port}' with result failure.  resultCode: ${data.resultCode || null}`);
          res.status(403).send( JSON.stringify( { success: false, error: data.resultCode } ) );
          return;
        }
        winston.info(`User '${req.user.username}' tested SA server '${saserver.user}@${saserver.host}:${saserver.port}' with result success`);
        res.status(200).send( JSON.stringify( { success: true } ) );
        return;
      }
      else {
        winston.debug(`REST connection test to url ${url} failed.`);
        winston.info(`User '${req.user.username}' tested SA server '${saserver.user}@${saserver.host}:${saserver.port}' with result failure.  STATUS CODE: ${response.statusCode}`);
        // throw(response.statusCode);
        res.status(403).send( JSON.stringify( { success: false, error: data.resultCode } ) );
        return;
        // winston.debug('res:', res);
        // winston.debug('body:', res.body);
      }
    })
    .on('error', err => {
      winston.info(`User '${req.user.username}' tested SA server '${saserver.user}@${saserver.host}:${saserver.port}' with result failure.  ${err}`);
      res.status(403).send( JSON.stringify({ error: err.message }) );
      // throw(err);
    });

});










//////////////////////PING//////////////////////

app.get('/api/ping', (req, res) => {
  // winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  res.status(200).send( JSON.stringify( { success: true } ) );
});






//////////////////////PREFERENCES//////////////////////

app.post('/api/preferences', passport.authenticate('jwt', { session: false } ), async (req, res) => {
  // Set global preferences
  winston.debug(`${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  try {
    let prefs = req.body;
    // winston.debug(prefs);
    await afbconfig.updatePreferences(prefs);
  }
  catch(error) {
    winston.error("POST /api/preferences:", error);
    res.status(500).send( JSON.stringify( { success: false, error: error.message || error } ) );
    return;
  }
  winston.info(`User '${req.user.username}' has updated the global preferences`);
  res.status(201).send( JSON.stringify( { success: true } ) );
});













///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////FIXED COLLECTIONS//////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////




app.get('/api/collection/fixed/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // Returns a fixed collection, either complete, or in the process of building
  let collectionId = req.params.id;
  winston.debug(`GET /api/collection/fixed/${collectionId} from ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`);
  if (collectionId in afbconfig.collections && afbconfig.collections[collectionId].state == 'initial' || afbconfig.collections[collectionId].state == 'building' || collections[collectionId].state == 'error') {
    // collection is either new or is building
    winston.info(`User '${req.user.username}' has requested incomplete fixed collection ${afbconfig.collections[collectionId.name]}`);
    fixedHandler.onHttpConnection(req, res);
  }
  else if (collectionId in afbconfig.collections) { // && this.collections[collectionId]['state'] == 'complete' // we should even use this if state is 'error'
    // this is a complete fixed collection
    winston.info(`User '${req.user.username}' has requested complete fixed collection ${afbconfig.collections[collectionId.name]}`);
    try {
      res.json( [ { wholeCollection: afbconfig.collectionsData[collectionId] }, { close: true } ] );
    }
    catch(e) {
      winston.error('ERROR GET /api/collection/fixed/:id', e);
      res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
    }
  }
  else {
    // couldn't find the collection
    winston.info(`User '${req.user.username}' has requested a non-existant fixed collection with id '${collectionId}'`);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }

});



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////ROLLING / MONITORING COLLECTIONS/////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



app.get('/api/collection/rolling/:collectionId', passport.authenticate('jwt', { session: false } ), (req, res) => {
  rollingHandler.onHttpConnection(req, res);
});



app.get('/api/collection/monitoring/pause/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  rollingHandler.pauseMonitoringCollectionHttp(req, res);
});



app.get('/api/collection/monitoring/unpause/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  rollingHandler.unpauseMonitoringCollectionHttp(req, res);
});
























///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////UTILITY FUNCTIONS/////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


function redactApiServerPasswords(apiservers) {
  let servers = deepCopy(apiservers);
  for (let server in servers) {
    // delete passwords - they don't need to be transferred back to the client
    if (servers.hasOwnProperty(server)) {
      servers[server].password = undefined;
    }
  }
  return servers;
}



function extractJwtFromCookie(req) {
  // Extract JWT from cookie 'access_token' and return to JwtStrategyf
  // winston.debug("extractJwtFromCookie()", req.cookies);
  let token = null;
  if (req && req.cookies)
  {
    token = req.cookies['access_token'];
  }
  return token;
};





function extraJwtTokenValidation(jwt_payload, done) {
  // After automatically verifying that JWT was signed by us, perform extra validation with this function
  // winston.debug("jwt validator jwt_payload:", jwt_payload);
  // winston.debug("verifying token id:", jwt_payload.jti);
  
  // check blacklist
  if (jwt_payload.jti in tokenMgr.tokenBlacklist) {
    winston.info("User " + jwt_payload.username + " has already logged out!");
    return done(null, false);
  }

  // check whether user is enabled
  User.findOne({id: jwt_payload.sub}, function(err, user) {
    if (err) {
      return done(err, false);
    }
    if (user && user.enabled) {
      return done(null, user);
    }
    if (user && !user.enabled) {
      winston.info('Login denied for user', user.username);
      winston.info('Attempt to authenticate by disabled user', user.username);
      return done(null, false);
    }
    else {
      return done(null, false);
      // or you could create a new account
    }
  });
}



async function onMongooseConnected() {
  // Create the default user account, if we think the app was just installed and if the count of users is 0
  let count;
  try {
    count = await User.count( {} );
  }
  catch (error) {
    winston.error("Error getting user count:", error);
  }
  if (afbconfig.justInstalled && ( count == 0 || !count ) ) {
      // we only create the default user on first run because we 
      winston.info("Adding default user 'admin'");
      try {
        await createDefaultUser();
      }
      catch (error) {
        winston.error("Error creating default user:", error);
        process.exit(1);
      }
      afbconfig.justInstalled = false;
  }
}





async function mongooseInit() {
  // Initialise Mongoose.  This gets called from within connectToDB(), after mongoClient has connected to Mongo
  winston.debug('Initializing mongoose');

  // Mongoose config
  // let mongooseUrl = `mongodb://${config['dbConfig']['host']}:${config['dbConfig']['port']}/afb_users`
  let mongooseUrl = `mongodb://${afbconfig.dbconfig.host}:${afbconfig.dbconfig.port}/afb_users`
  let mongooseOptions = { useMongoClient: true, promiseLibrary: global.Promise };
  if (afbconfig.dbconfig.authentication.enabled) {
    mongooseUrl = `mongodb://${afbconfig.dbconfig.authentication.user}:${afbconfig.dbconfig.authentication.password}@${afbconfig.dbconfig.host}:${afbconfig.dbconfig.port}/afb_users?authSource=admin`;
  }


  // This creates local authentication passport strategy
  // This authenticates a user against the account stored in MongoDB
  // This is only used by /api/login
  let mongooseStrategy = new LocalStrategy( User.authenticate() );
  passport.use(mongooseStrategy);
  passport.serializeUser( User.serializeUser() );
  passport.deserializeUser( User.deserializeUser() );


  // This creates the JWT authentication passport strategy
  // This is used to authenticate all API calls except login and ping
  let jwtOpts = {
    jwtFromRequest: ExtractJwt.fromExtractors([extractJwtFromCookie]),
    secretOrKey: afbconfig.jwtPublicKey,
    algorithms: ['RS256']
  };
  let jwtStrategy = new JwtStrategy(jwtOpts, (jwt_payload, done) => extraJwtTokenValidation(jwt_payload, done) );
  passport.use(jwtStrategy);

  try {
    await mongoose.connect(mongooseUrl, mongooseOptions);
    await onMongooseConnected();
  }
  catch(err) {
    winston.error('Mongoose error whilst connecting to mongo.  Exiting with code 1.');
    winston.error(err);
    process.exit(1);
  }

}



function checkLicense() {
  winston.info('Checking license validity');
  // check license validity
  if (!development || testLicensing) {
    let firstRun = afbconfig.preferences.firstRun;
    winston.debug('firstRun:', firstRun);
    let currentTime = Math.floor(Date.now() / 1000);
    winston.debug('currentTime', currentTime);
    let expiryTime = firstRun + 3600 * 24 * 60; // expire in 60 days from firstRun
    if (testLicensing && testLicensingMins) {
      winston.debug(`'testLicensing' is set to true.  License will expire ${testLicensingMins} minutes from now`);
      expiryTime = currentTime + testLicensingMins * 60;
    }
    winston.debug('expiryTime', expiryTime);
    let expiryDate = new Date(expiryTime * 1000);
    license.expiryTime = expiryTime;
    license.valid = currentTime < expiryTime;

    if (license.valid) {
      // run a cron-like job to expire the license at the specified time (60 days from firstRun)
      winston.debug('License is valid.  Starting scheduler')
      licenseExpiryJob = schedule.scheduleJob(expiryDate, onLicenseExpired);
    }
  }
  else {
    // don't expire if in development mode
    license.valid = true;
    license.expiryTime = 0;
  }
  winston.debug('license:', license);
  if (license.valid) {
    winston.info('License is valid and will expire on ' + new Date(license.expiryTime * 1000).toUTCString());
  }
  else {
    winston.info('License has expired.  Only existing fixed collections will be viewable');
  }
}



function onLicenseExpired() {
  winston.info('License has expired.  Rolling and monitoring collections will not function, and fixed collections will not build. ');
  license.valid = false;

  // kill all rolling collections (we'll let any building fixed collections finish building)
  rollingHandler.killall();
  
  // tell all clients that the license is invalid
  tokenMgr.authSocketsEmit('license', license);
}



async function cleanCollectionDirs() {
  try {
    winston.info("Cleaning up collection directories");

    for (let collectionId in afbconfig.collections) {

      if (!afbconfig.collections.hasOwnProperty(collectionId)) {
        continue;
      }

      winston.debug("Cleaning collection '" + afbconfig.collections[collectionId].name + "' with id " + collectionId);
      
      if ( afbconfig.collections[collectionId].type === 'rolling' || ( afbconfig.collections[collectionId].type === 'fixed' && afbconfig.collections[collectionId].state !== 'complete' ) ) {
        
        //winston.debug('Deleting dir', afbconfig.collectionsDir + '/' + collections[collection].id);
        await rmfr( afbconfig.collectionsDir + '/' + collectionId); // delete output directory

      }

      else if (afbconfig.collections[collectionId].type === 'monitoring') {
        let files = await fs.promises.readdir(afbconfig.collectionsDir);
        for (let i = 0; i < files.length; i++) {
          let filename = files[i];
          // winston.debug('filename:', filename);
          let stat = await fs.promises.stat(afbconfig.collectionsDir + '/' + filename);
          let isDir = stat.isDirectory();
          // winston.debug('isDir:', isDir);
          if (isDir && filename.startsWith(collectionId)) {
            await rmfr( afbconfig.collectionsDir + '/' + collectionId ); // delete output directory
          }
        }
      }

    }
  }
  catch(exception) {
    winston.error('ERROR deleting output directory collectionsDir + '/' + id', exception);
  }
}



async function createDefaultUser() {
  // winston.debug('createDefaultUser(): creating default user');
  await User.register(new User({ id: uuidV4(), username : 'admin', fullname: 'System Administrator', email: 'noreply@knowledgekta.com', enabled: true }), 'kentech0', () => {});
  // winston.debug('createDefaultUser(): finished creating default user');
}



function sortNumber(a, b) {
  return b - a;
}



var newChunkHandler = (data, chunk, callback) => {
  // Handles socket data received from the feeder process

  // winston.debug('Processing update');
  data += chunk

  var splt = data.split("\n").filter( (el) => { return el.length != 0});

  if ( splt.length == 1 && data.indexOf("\n") === -1 ) {
    // This case means the split resulted in only one element and that doesn't contain the newline delimiter, which means we haven't received an entire update yet...
    // we'll continue and wait for the next update which will hopefully contain the delimeter
    return data;
  }
  var d = [] // 'd' is an array of complete JSON messages.  each one should later be parsed with JSON.parse()
  if ( splt.length == 1 && data.endsWith("\n") ) {
    // this case means the split resulted in only one element and that it does contain the newline delimiter.  This means we received a single complete update.
    d.push(splt.shift() );
    data='';
  }
  else if ( splt.length > 1 ) {
    // This case means the split resulted in multiple elements and that it does contain a newline delimiter...
    // This means we have at least one complete update, and possibly more.
    if (data.endsWith("\n")) {  //the last element is a full update as data ends with a newline
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

  callback(d);

  return data;

}



var transformUser = function(doc, ret, options) {
  delete ret._id;
  delete ret.id;
  delete ret.email;
  return ret;
};



function writeToSocket(socket, data) {
  socket.write(data + '\n');
  // socket.flush();
}



var feederDataHandler = (data) => {
  // Handles data sent by feeder_srv
  while (data.length > 0) {
    let line = data.shift();
    let message = JSON.parse(line);
    // winston.debug('feederDataHandler(): message:', message);

    if (!feederInitialized && 'initialized' in message && message.initialized && 'feederSocket' in message) {
      winston.info('feederDataHandler(): Feeder is initialized');
      feederInitialized = true;
      feederSocketFile = message.feederSocket;
      if (rollingHandler) {
        rollingHandler.updateFeederSocketFile(feederSocketFile);
      }
      if (fixedHandler) {
        fixedHandler.updateFeederSocketFile(feederSocketFile);
      }
      winston.debug('feederDataHandler(): Feeder socket file is ' + feederSocketFile);
      if (!apiInitialized) {
        finishStartup(); // start the API listener
      }
    }
  }
}



function onConnectionFromFeederSrv(socket, tempName) {

  feederSocket = socket; // assign our socket globally so we can write to it later

  ////////////////////////
  //DEAL WITH THE SOCKET//
  ////////////////////////

  // Buffer for worker data
  var data = '';
  
  // Set socket options
  feederSocket.setEncoding('utf8');

  //Handle data from the socket
  feederSocket.on('data', chunk => data = newChunkHandler(data, chunk, feederDataHandler) );
  
  feederSocket.on('end', () => {
    winston.debug('Feeder has disconnected');
    //delete temporary socket
    fs.unlink(tempName, () => {});
    feederInitialized = false;
  });
                          
  // Send configuration to feeder_srv.  After this, we should receive an okay response containing a path to a socket for workers
  writeToSocket(feederSocket, JSON.stringify( { config: { feedsDir: afbconfig.feedsDir }, feeds: afbconfig.feeds } ));
}




var onFeederExit = (code, signal) => {
  feederSrvProcess = null;

  if (!code) {
    winston.debug('Feeder process exited abnormally without an exit code');
  }
  else if (code !== 0) {
    winston.debug('Feeder process exited abnormally with exit code', code);
  }
  else {
    winston.debug('Feeder process exited normally with exit code', code);
    return;
  }
  winston.log('Relaunching feeder_srv');
  startFeeder();

}



var feederSrvProcess = null;



function startFeeder() {
  winston.debug('startFeeder(): starting feeder_srv');

  // get a temporary file to use as our domain socket
  let tempName = temp.path({suffix: '.socket'});
  
  // open UNIX domain socket to talk to server script, and set the socket handler to onConnectionFromFeederSrv
  let socketServer = net.createServer( (socket) => onConnectionFromFeederSrv(socket, tempName) );

  // start the feeder_srv
  socketServer.listen(tempName, () => {
    
    winston.debug('Waiting for Feeder connection');
    winston.debug("Launching feeder_srv with socket file " + tempName);

    // spawn the feeder process
    feederSrvProcess = spawn('./feeder/feeder_stub.py', [tempName], { shell: false, stdio: 'inherit' });
    
    // wait for the feeder to exit (ideally it shouldn't until we shutdown)
    feederSrvProcess.on('exit', onFeederExit );
  });
}



function schedulerUpdatedCallback(id) {
  // winston.debug('schedulerUpdatedCallback(): id:', id);
  writeToSocket( feederSocket, JSON.stringify( { updateFile: true, id: id } ) ); // let feeder server know of our update
}


var rollingHandler = null;
var fixedHandler = null;












//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////SOCKET.IO/////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


function onSocketIoConnect(socket) {
  // allows for upgrade of auth after connect, for the always connected model - totally incomplete
  winston.debug('A socket client connected');
  socket.on('disconnect', (reason) => onSocketIoDisconnect(socket, reason) );

  // immediately send configuration to client
  socket.emit('serverVersion', version);
}



function onClientReady(socket) {
  winston.debug('A socket client has authenticated and is ready for data - sending data to client');
  socket.emit('preferences', afbconfig.preferences);
  socket.emit('collections', afbconfig.collections);
  socket.emit('publicKey', afbconfig.internalPublicKey);
  if (afbconfig.serviceTypes.nw) socket.emit('nwservers', redactApiServerPasswords(afbconfig.nwservers));
  if (afbconfig.serviceTypes.sa) socket.emit('saservers', redactApiServerPasswords(afbconfig.saservers));
  socket.emit('feeds', afbconfig.feeds);
  socket.emit('feedStatus', scheduler.status() );
  emitUsers(socket);
  socket.emit('useCases', afbconfig.useCases);
  socket.emit('license', license);
}



function onSocketIoDisconnect(socket, reason) {
  if ('jwtuser' in socket.conn) {
    winston.info(`User ${socket.conn.jwtuser.username} has disconnected from an associated socket`);
  }
  else {
      winston.debug('An unauthenticated socket client disconnected');
  }
  tokenMgr.removeSocketToken(socket, reason);
}
















////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////CLEANUP/////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function onCleanup(exitCode, signal) {
  
  winston.debug('onCleanup(): exitCode:', exitCode);
  winston.debug('onCleanup(): signal:', signal);
  
  
  setTimeout( () => {
    
    // terminate workers
    if (rollingHandler) {
      winston.debug('Terminating rolling collection workers');
      rollingHandler.killall();
    }
    
    if (fixedHandler) {
      winston.debug('Terminating fixed collection workers');
      fixedHandler.killall();
    }
    
    // terminate feeder_srv
    if (feederSrvProcess) {
      winston.debug('Stopping feeder_srv')
      // feederSrvProcess.off('exit', onFeederExit);
      feederSrvProcess.removeAllListeners();
      feederSrvProcess.kill('SIGINT');
    }
    
    // save collection state
    
    
    // end program
    if (signal) {
      process.kill(process.pid, signal);
    }
    else {
      process.exit(exitCode);
    }
    
  }, 0 );
  
  nodeCleanup.uninstall();
  return false;

}







///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////LISTEN/////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function finishStartup() {
  // Start listening for client traffic and away we go
  
  server.listen(listenPort);
  
  io.on('connection', (socket) => onSocketIoConnect(socket) );
  
  rollingHandler = new rollingCollectionHandler( afbconfig, feederSocketFile, collectionsChannel);
  afbconfig.rollingHandler = rollingHandler;

  fixedHandler = new fixedCollectionHandler( afbconfig, feederSocketFile, collectionsChannel);

  winston.debug('Installing cleanup handler');
  nodeCleanup( (exitCode, signal) => onCleanup(exitCode, signal) );
  
  // Install SIGINT and SIGTERM handlers if we're running inside a container.  We need this to allow the process to exit normally when running in Docker
  if ( isDocker() ) {
    process.on('SIGINT', () => onCleanup(0, null) );
    process.on('SIGTERM', () => onCleanup(0, null) );
  }


  apiInitialized = true;
  winston.info('Serving on port', listenPort);
}
