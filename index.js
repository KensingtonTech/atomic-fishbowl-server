'use strict';

const version = '2017.08.20';

// Load dependencies
const Observable = require('rxjs/Observable').Observable;
const Subject = require('rxjs/Subject').Subject;
const express = require('express');
const app = express();
const session = require('express-session');
const bodyParser = require('body-parser');
const listenPort = 3002;
const uuidV4 = require('uuid/v4');
const fs = require('fs');
const net = require('net'); //for unix sockets
const rimraf = require('rimraf');
const spawn = require('child_process').spawn;
const temp = require('temp');
const moment = require('moment');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
const util = require('util');
const sprintf = require('sprintf-js').sprintf;
const winston = require('winston');
const mongoose = require('mongoose');
mongoose.Promise = Promise; //global.Promise;
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
var mongo = require('mongodb').MongoClient;
var purgeHack = false; // causes sessions older than 5 minutes to be purged, if set to true.  Useful for testing purging without having to wait an hour






///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////EXPRESS////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*app.set('trust proxy', 1);
app.use(session( {
  name: 'twosession',
  secret: 'abc',
  cookie: { secure: false, httpOnly: false },
  //proxy: true,
  resave: false,
  saveUninitialized: false
}));*/
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());








///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////LOGGING////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

winston.remove(winston.transports.Console);
winston.add(winston.transports.Console, {'timestamp': () => {
                                                              return moment().format('YYYY-MM-DD HH:mm:ss,SSS')
                                                            },
                                          'formatter': (options) => {
                                                                return options.timestamp() + ' 221b_server     ' + sprintf('%-10s', options.level.toUpperCase()) + ' ' + (options.message ? options.message : '') +
          (options.meta && Object.keys(options.meta).length ? '\n\t'+ JSON.stringify(options.meta) : '' );;
                                                              }
                                         });
winston.level = 'debug';


winston.info('Starting 221B server version', version);





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////CONFIGURATION//////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var justInstalled = true;
var preferences = {};
var nwservers = {};
var collections = {};
var collectionsData = {};

const cfgDir = '/etc/kentech/221b';
const certDir = cfgDir + '/certificates';
const jwtPrivateKeyFile = certDir + '/221b.key';
const jwtPublicKeyFile = certDir + '/221b.pem';
const collectionsUrl = '/collections'
var collectionsDir = '/var/kentech/221b/collections';










///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////USER PREFERENCES///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Set default preferences
var defaultPreferences = {
  nwInvestigateUrl: '',
  gsPath: '/usr/bin/gs',
  pdftotextPath: '/usr/bin/pdftotext',
  unrarPath: '/usr/bin/unrar',
  defaultNwQuery: "filetype = 'jpg','gif','png','pdf','zip','rar','windows executable','apple executable (pef)','apple executable (mach-o)'",
  defaultQuerySelection : "All Supported File Types",
  defaultImageLimit: 1000,
  defaultRollingHours: 1,
  minX: 255,
  minY: 255,
  displayedKeys : [ 
    "size", 
    "service", 
    "ip.src", 
    "ip.dst", 
    "alias.host", 
    "city.dst", 
    "country.dst", 
    "action", 
    "content", 
    "ad.username.src", 
    "ad.computer.src", 
    "filename", 
    "client"
  ],
  masonryKeys : [ 
    {
      key : "alias.host",
      friendly : "Hostname"
    }, 
    {
      key : "ad.username.src",
      friendly : "AD User"
    }, 
    {
      key : "ad.computer.src",
      friendly : "AD Computer"
    }, 
    {
      key : "ad.domain.src",
      friendly : "AD Domain"
    }
  ],
  masonryColumnSize : 350,
};



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////PASSPORT AND MONGOOSE//////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var cookieExtractor = function(req) {
  //Extract JWT from cookie 'access_token' and return to JwtStrategy
  //winston.debug("cookieExtractor()", req.cookies);
  var token = null;
  if (req && req.cookies)
  {
      token = req.cookies['access_token'];
  }
  return token;
};

try {
  var jwtPrivateKey = fs.readFileSync(jwtPrivateKeyFile, 'utf8');
}
catch(e) {
  winston.error("Cannot read private key file", jwtPrivateKeyFile);
  process.exit(1);
}

try {
  var jwtPublicKey = fs.readFileSync(jwtPublicKeyFile, 'utf8');
}
catch(e) {
  winston.error("Cannot read public key file", jwtPublicKeyFile);
  process.exit(1);
}

var jwtOpts = {
  jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]),
  secretOrKey: jwtPublicKey,
  algorithms: ['RS256']
};


//We use mongoose for auth, and MongoClient for everything else.  This is because Passport-Local Mongoose required it, and it is ill-suited to the free-formish objects which we want to use.

var mongoUrl = "mongodb://localhost:27017/221b";
connectToDB(); //this must come before mongoose user connection so that we know whether to create the default admin account

var User = require('./models/user');
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Connect to Mongoose
mongoose.connect("mongodb://localhost:27017/221b_users", { useMongoClient: true, promiseLibrary: global.Promise });
var db = mongoose.connection;
//db.on('error', (err) => {winston.error("Error connecting to 221b_users DB:"), err} );
//db.once('open', () => {winston.info("Connected to 221b_users DB")} );

/*
conn.221b_.listCollections({name: 'users'})
        .next(function(err, collinfo) {
                if (collinfo) {
                  winston.info("Collection 'users' exists");
                }
            });
*/
//mongoose.connect("mongodb://localhost:27017/221b_users", { useMongoClient: true });
var tokenBlacklist = {};


// Create the default user account, if we think the app was just installed and if the count of users is 0
User.count({}, (err, count) => {
  if (err) {
    winston.error("Error getting user count:", err);
  }
  else if (justInstalled == true && count == 0) {
      winston.info("Adding default user 'admin'");
      createDefaultUser();
      justInstalled = false;
  }
});


passport.use(new JwtStrategy(jwtOpts, (jwt_payload, done) => {
  //After automatically verifying that JWT was signed by us, perform extra validation with this function
  //winston.debug("jwt validator jwt_payload:", jwt_payload);
  //winston.debug("verifying token id:", jwt_payload.jti);
  if (jwt_payload.jti in tokenBlacklist) { //check blacklist
    winston.info("User " + jwt_payload.username + " has already logged out!");
    return done(null, false);
  }

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
}));







///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////API CALLS/////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


app.post('/api/login', passport.authenticate('local'), (req,res) => {
  winston.info('POST /api/login');
  User.findOne({username: req.body.username, enabled: true}, (err, user) => {
    if (err) {
      winston.info("Error looking up user " + req.body.username + ': ' + err);
    }
    if (!user) { //we likely will never enter this block as  the validation is really already done by passport
      winston.info('Login failed for user ' + req.body.username + '.  User either not found or not enabled');
      res.json({ success: false, message: 'Authentication failed' });
    }
    else {
      winston.info("Login successful for user", req.body.username);
      winston.debug("Found user " + req.body.username + ".  Signing token");
      let token = jwt.sign(user.toObject({versionKey: false, transform: transformUser}), jwtPrivateKey, { subject: user.id, algorithm: 'RS256', expiresIn: 60*60*24, jwtid: uuidV4() }); // expires in 24 hours
      res.cookie('access_token', token, { httpOnly: true, secure: true });
      // res.cookie( req.session );
      res.json({
        success: true,
        user: user.toObject(),
        sessionId: uuidV4()
      });
    }
  });
});

app.get('/api/logout', passport.authenticate('jwt', { session: false } ), (req,res) => {
  winston.info('GET /api/logout');
  let decoded = jwt.decode(req.cookies.access_token); //we can use jwt.decode here without signature verification as it's already been verified during authentication
  // winston.debug("decoded:", decoded);
  let tokenId = decoded.jti; //store this
  // winston.debug("decoded tokenId:", tokenId);
  tokenBlacklist[tokenId] = tokenId;
  res.clearCookie('access_token');
  res.sendStatus(200);
});

/*var transformUserIsLoggedIn = function(doc, ret, options) {
  delete ret._id;
  return ret;
};
*/

app.get('/api/isloggedin', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  winston.debug("GET /api/isloggedin");
  // winston.debug('sessionID:', req.session.id);
  // winston.debug('Session object:', req.session);
  // res.cookie('access_token', token, { httpOnly: true, secure: true })
  // res.cookie( req.session.cookie );
  // req.session.save();

  res.json( { user: req.user.toObject(), sessionId: uuidV4() }); // { versionKey: false, transform: transformUserIsLoggedIn }
});

app.get('/api/users', passport.authenticate('jwt', { session: false } ), (req,res)=>{
  winston.info('GET /api/users');
  try {
    User.find( (err, users) => {
      if (err) {
        winston.error("ERROR obtaining users:", err);
        res.sendStatus(500);
      }
      else {
        res.json(users);
      }
    
    } );
  }
  catch(e) {
    winston.error('ERROR GET /api/users:',e);
  }
});

app.get('/api/user/:uname', passport.authenticate('jwt', { session: false } ), (req,res)=>{
  let uname = req.params.uname;
  winston.info('GET /api/user/' + uname);
  try {
    User.findOne( {'username' : uname },(err, user) => {
      if (err) {
        winston.error('ERROR finding user ' + uname + ':', err);
        res.sendStatus(500);
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

app.post('/api/adduser', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("POST /api/adduser");
  User.register(new User({ id: uuidV4(), username : req.body.username, fullname: req.body.fullname, email: req.body.email, enabled: req.body.enabled }), req.body.password, (err, user) => {
    if (err) {
      winston.error("ERROR adding user " + req.body.username + ':', err);
      res.sendStatus(500);
    }
    else {
      winston.info("User added:", req.body.username);
      res.sendStatus(201);
    }
  });
});

function updateUser(req, res) {
  //User.register(new User({ id: uuidV4(), username : req.body.username, fullname: req.body.fullname, email: req.body.email, enabled: req.body.enabled }), req.body.password, (err, user) => {
  User.findOneAndUpdate( { 'id': req.body.id }, req.body, (err, doc) => {
    winston.info("Updating user object with id", req.body.id);
    //now update user object
    if (err) {
      winston.error("ERROR modifying user with id" + req.body.id + ':', err);
      res.sendStatus(500);
    }
    else {
      winston.info("Updated user with id:", req.body.id);
      res.sendStatus(201);
    }
  });
}

app.post('/api/updateuser', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("POST /api/updateuser");
  
  if ('password' in req.body) {
    winston.info("Updating password for user with id", req.body.id);
    //change password
    try {
      var u;
      User.findOne( { 'id': req.body.id }, (err, doc) => {
        if (err) throw(err);
        u = doc.username;
      })
      .then ( () => {
        User.findByUsername(u, (err, user) => {
          if (err) throw(err);
          user.setPassword(req.body.password, (err) => {
            if (err) throw(err);
            user.save( (error) => { 
              if (err) throw(err);
              delete req.body.password; //we don't want this getting set when we update the user object
              updateUser(req, res);
            });
          });
        });
      });
    }
    catch(e) {
      winston.error("ERROR changing password:", e);
      res.sendStatus(500);
      return;
    }
  }
  else {
    updateUser(req, res)
  }
});

app.delete('/api/user/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  let id = req.params.id;
  winston.info('DELETE /api/user/:id', id);
  try {
    User.find( {id: id} ).remove( (err) => {
      if (err) {
        throw err;
      }
      else {
        res.sendStatus(204);
      }
    } );
  }
  catch(exception) {
    winston.error("ERROR removing user:", exception);
    res.sendStatus(500);
  }
});

//login and return JWT

app.get('/api/version', passport.authenticate('jwt', { session: false } ), (req,res)=>{
  winston.info('GET /api/version');
  try {
    res.json({version: version});
  }
  catch(e) {
    winston.error('ERROR GET /api/version:', e);
    res.sendStatus(500);
  }
});
  

app.get('/api/collections', passport.authenticate('jwt', { session: false } ), (req,res)=>{
  winston.info('GET /api/collections');
  try {
    res.json(collections);
  }
  catch(e) {
    winston.error('ERROR GET /api/collections:', e);
    res.sendStatus(500);
  }
});

function getCollectionPosition(id) {
  for(var i=0; i < collections.length; i++) {
    let col = collections[i];
    if (col.id === id) {
      return i;
    }
  }
}

app.delete('/api/collection/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  let id = req.params.id;
  winston.info("DELETE /api/collection/:id", id);
  try {
    if (collectionsData[id]) {
      delete collectionsData[id];
      delete collections[id];
      res.sendStatus(204);
    }
    else {
      res.body="Collection not found";
      res.sendStatus(400);
    }
  }
  catch(e) {
    res.sendStatus(500);
    winston.error('ERROR DELETE /api/collection/:id:', e);
  }
  db.collection('collections').remove( { 'id': id }, (err, res) => {
    if (err) throw err;
  });
  db.collection('collectionsData').remove( { 'id': id }, (err, res) => {
    if (err) throw err;
  });
  
  try { 
    rimraf( collectionsDir + '/' + id, () => {} );
  } 
  catch(e) {
    winston.error('ERROR removing directory' + collectionsDir + '/' + id + ':', e);
  }

});

app.get('/api/collectiondata/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  let id = req.params.id;
  winston.info('GET /api/collectiondata/:id', id);
  try {
    res.json(collectionsData[id]);
  }
  catch(e) {
    winston.error('ERROR GET /api/collectiondata/:id:', e);
    res.sendStatus(500);
  }
});

app.get('/api/nwservers', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  winston.info('GET /api/nwservers');
  try {
    res.json(nwservers);
  }
  catch(e) {
    winston.error('ERROR GET /api/nwservers', e);
    res.sendStatus(500);
  }
});

app.delete('/api/nwserver/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  let servId = req.params.id;
  winston.info('DELETE /api/nwserver/:id', servId);
  try {
    delete nwservers[servId];
    res.sendStatus(204);
    db.collection('nwservers').remove( { 'id': servId }, (err, res) => {
      if (err) throw err;
    });
  }
  catch(exception) {
    winston.error('ERROR DELETE /api/nwserver/:id:',exception);
    res.sendStatus(500);
  }
});

app.post('/api/addnwserver', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  winston.info("POST /api/addnwserver");
  try {
    //winston.debug(req.body);
    let nwserver = req.body;
    winston.debug(nwserver);
    let id = uuidV4();
    nwserver['id'] = id;
    if (!nwserver.friendlyName) {
      throw("'friendlyName' is not defined");
    }
    if (!nwserver.host) {
      throw("'host' is not defined");
    }
    if (!nwserver.port) {
      throw("'port' is not defined");
    }
    if (!nwserver.user) {
      throw("'user' is not defined");
    }
    if (!nwserver.password) {
      throw("'password' is not defined");
    }
    if (typeof nwserver.ssl === 'undefined') {
      throw("'ssl' is not defined");
    }
    nwservers[id] = nwserver;
    db.collection('nwservers').insertOne( nwserver, (err, res) => {
      if (err) throw err;
    });
    
    res.sendStatus(201);
  }
  catch(e) {
    winston.error("ERROR POST /api/addnwserver: " + e);
    res.sendStatus(500);
  }
});

app.get('/api/ping', (req, res)=>{
  //winston.debug("GET /api/ping");
  res.sendStatus(200);
});

app.get('/api/preferences', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  winston.info("GET /api/preferences");
  try {
    res.json(preferences);
  }
  catch(e) {
    winston.error('ERROR GET /api/preferences:', e);
    res.sendStatus(500);
  }
});

app.post('/api/setpreferences', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  winston.info("POST /api/setpreferences");
  try {
    let prefs = req.body;
    winston.debug(prefs);
    preferences = prefs;
    res.sendStatus(201);
    writePreferences();
  }
  catch(e) {
    winston.error("ERROR POST /api/setpreferences:", e);
    res.sendStatus(500);
  }
});



app.post('/api/addcollection', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  winston.info("POST /api/addcollection");
  try {
    //winston.debug(req.body);
    let collection = req.body;
    if (!collection.type) {
      throw("'type' is not defined");
    }
    if (!collection.id) {
      throw("'id' is not defined");
    }
    if (!collection.name) {
      throw("'name' is not defined");
    }
    if (!collection.query) {
      throw("'query' is not defined");
    }
    if (!collection.nwserver) {
      throw("'nwserver' is not defined");
    }
    if (!collection.nwserverName) {
      throw("'nwserverName' is not defined");
    }
    collection['state'] = 'initial';
    collections[collection.id] = collection;
    let cDef = {
      images: [],
      sessions: {},
      id: collection.id
    };
    collectionsData[collection.id] = cDef;
    res.sendStatus(201);
   
    db.collection('collections').insertOne( collection, (err, res) => {
      if (err) throw err;
    });
    
    db.collection('collectionsData').insertOne( {'id': collection.id, 'data': JSON.stringify(cDef)}, (err, res) => {
      if (err) throw err;
    });
    
  }
  catch(e) {
    winston.error("ERROR POST /api/addcollection:", e);
    res.sendStatus(500);
  }
});

















///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////FIXED COLLECTIONS//////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// Returns a streaming fixed collection which is in the process of building
app.get('/api/getbuildingfixedcollection/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{ 
  var id = req.params.id;
  winston.info('GET /api/getbuildingfixedcollection/:id', id);
  //winston.debug('buildingFixedCollections',buildingFixedCollections);
  try {
    if (buildingFixedCollections[id]) {
      //winston.debug('playing back collection which is in the process of building');
      res.writeHead(200, {'Content-Type': 'application/json','Content-Disposition': 'inline' });
      res.write('['); // Open the array so that oboe can see it
      res.flush();
      var subject = buildingFixedCollections[id].observable; //get our observable

      //play back the data already in buildingFixedCollections. we must play back sessions and images separately as there are generally more images than sessions
      for (var i=0; i < buildingFixedCollections[id].sessions.length; i++) {
        let resp = {
          collectionUpdate: {
            session: buildingFixedCollections[id].sessions[i]
          }
        };
        res.write(JSON.stringify(resp) + ',');
        res.flush();
      }
      
      //now play back images
      for (var i=0; i < buildingFixedCollections[id].images.length; i++) {
        let resp = {
          collectionUpdate: {
            images: [ buildingFixedCollections[id].images[i] ]
          }
        };
        res.write(JSON.stringify(resp) + ',');
        res.flush();
      }
      
      //now play back search text
      winston.debug("Playing back search");
      if (buildingFixedCollections[id].search) {
        for (var i=0; i < buildingFixedCollections[id].search.length; i++) {
          let resp = {
            collectionUpdate: {
              search: buildingFixedCollections[id].search[i]
            }
          };
          res.write(JSON.stringify(resp) + ',');
          res.flush();
        }
      }
    
      subject.subscribe( (output) => { 
        // data from observable
        res.write(JSON.stringify(output) + ',');
        res.flush();
      }
      ,(e) => { throw(e); } // errors from observable
      ,( ) => { 
        winston.debug('ending observable'); // end of observable
        res.write('{"close":true}]'); // Close the array so that oboe knows we're done
        res.flush();
        res.end();
      });
    }


    else if (collections[id].state === 'complete') { //if collection is already complete, play it back (probably won't happen in real life, but we will accommodate it anyway, just in case)
      winston.info('playing back collection', id);
      res.set('Content-Type', 'application/json');
      res.set('Content-Disposition', 'inline');
      res.set(200);
      for (var i=0; i < collectionsData[id].images.length; i++) { //play back the image and session data already in buildingFixedCollections
        var sessionId = collectionsData[id].images[i].session;
        let resp = {
          collectionUpdate: {
            images: [ collectionsData[id].images[i] ],
            session: collectionsData[id].sessions[sessionId],
          }
        };
        res.write(JSON.stringify(resp) + ',');
        res.flush();
      }

      if (buildingFixedCollections[id].search) {
        for (var i=0; i < collectionsData[id].search.length; i++) { //now play back the search info
          let resp = {
            collectionUpdate: {
              search: [ collectionsData[id].search[i] ],
            }
          };
          res.write(JSON.stringify(resp) + ',');
          res.flush();
        }
      }

      res.write('{"close":true}]'); // Close the array so that oboe knows we're done
      res.flush();
      res.end();
    }
    else {
      throw('Collection ' + id + ' not found');
    }
  }
  catch(exception) {
    winston.error('ERROR GET /api/getbuildingfixedcollection/:id', exception);
    res.sendStatus(500);
  }
});

var buildingFixedCollections = {}; // We shall house fixed collections which are under construction here

function fixedSocketConnectionHandler(id, socket, tempName, subject) {
  // For building fixed collections

  winston.info("fixedSocketConnectionHandler(): Connection received from worker to build collection", id);
  
  //////////////////////////////////
  //Build the worker configuration//
  //////////////////////////////////

  let cfg = { 
    id: id,
    query: collections[id].query,
    timeBegin: collections[id].timeBegin,
    timeEnd: collections[id].timeEnd,
    imageLimit: collections[id].imageLimit,
    minX: collections[id].minX,
    minY: collections[id].minY,
    gsPath: preferences.gsPath,
    pdftotextPath: preferences.pdftotextPath,
    unrarPath: preferences.unrarPath,
    distillationEnabled: collections[id].distillationEnabled,
    regexDistillationEnabled: collections[id].regexDistillationEnabled,
    md5Enabled: collections[id].md5Enabled,
    sha1Enabled: collections[id].sha1Enabled,
    sha256Enabled: collections[id].sha256Enabled,
    collectionsDir: collectionsDir
  };
  
  if ('distillationTerms' in collections[id]) {
    cfg['distillationTerms'] = collections[id].distillationTerms;
  }
  if ('regexDistillationTerms' in collections[id]) {
    cfg['regexDistillationTerms'] = collections[id].regexDistillationTerms;
  }
  if ('md5Hashes' in collections[id]) {
    cfg['md5Hashes'] = collections[id].md5Hashes;
  }
  if ('sha1Hashes' in collections[id]) {
    cfg['sha1Hashes'] = collections[id].sha1Hashes;
  }
  if ('sha256Hashes' in collections[id]) {
    cfg['sha256Hashes'] = collections[id].sha256Hashes;
  }

  let nwserver = nwservers[collections[id].nwserver];
  for (var k in nwserver) {
    if (k != 'id') {
      cfg[k] = nwserver[k];  // assign an nwserver to the collection cfg
    }
  }
  let outerCfg = { workerConfig: cfg };

  

  ////////////////////////
  //DEAL WITH THE SOCKET//
  ////////////////////////

  // Tell our subscribers that we're building, so they can start their spinny icon
  subject.next({collection: { id: id, state: 'building'}});

  // Buffer for worker data
  var data = '';
  
  // Set socket options
  socket.setEncoding('utf8');

  //Handle data from the socket (this really builds the collection)
  socket.on('data', chunk => data = chunkHandler(buildingFixedCollections, id, subject, data, chunk) );
  
  //Now that we've finished building the new collection, emit a finished signal, and merge the new collection into the collectionsData object, and delete the object from buildingFixedCollections
  socket.on('end', () => {
    winston.debug('Worker disconnected.  Merging temporary collection into permanent collection');
    collectionsData[id].images = buildingFixedCollections[id].images;
    collectionsData[id].search = buildingFixedCollections[id].search;
    for (var e in buildingFixedCollections[id].sessions) {
      let s = buildingFixedCollections[id].sessions[e];
      let sid = s.id;
      collectionsData[id].sessions[sid] = s;
    }
    //moved into process exit
    winston.debug('Temporary collection merged into main branch.  Deleting temporary collection.');
    delete buildingFixedCollections[id];
    fs.unlink(tempName, () => {});
  });
                          
  // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
  socket.write(JSON.stringify(outerCfg) + '\n'); 
  
}


function buildFixedCollection(id) {
  // Builds fixed collections

  winston.debug('buildFixedCollection(): Building collection', id);
  
  try {
    collections[id]['state'] = 'building';
    //Build observable which we can use to notify others of new additions to the collection
    var subject = new Subject();
    buildingFixedCollections[id] = {
      observable: subject, //we add the observable subject object to the object so we can get it later
      images: [],
      sessions: []
    };
    var tempName = temp.path({suffix: '.socket'});
    //open UNIX domain socket to talk to worker script
    var socketServer = net.createServer( (socket) => { fixedSocketConnectionHandler(id, socket, tempName, subject); });
    socketServer.listen(tempName, () => {
      winston.debug('Listening for worker communication');
      winston.debug("Spawning worker with socket file " + tempName);
      var worker = spawn('./221b_worker.py ',[tempName], {shell:true, stdio: 'inherit'});
      worker.on('exit', (code) => {
        if (typeof code === 'undefined') {
          winston.debug('Worker process exited abnormally without an exit code');
          collections[id]['state'] = 'error';
          subject.next({collection: { id: id, state: 'error'}});
        }
        else if (code != 0) {
          winston.debug('Worker process exited abnormally with exit code',code.toString());
          collections[id]['state'] = 'error';
          subject.next({collection: { id: id, state: 'error'}});
        }
        else {
          winston.debug('Worker process exited normally with exit code', code.toString());
          collections[id]['state'] = 'complete';
          subject.next({collection: { id: id, state: 'complete'}});
          db.collection('collections').update( {'id': id }, collections[id], (err, res) => {
            if (err) throw err;
          });
          db.collection('collectionsData').update( {'id': id }, {'id': id, 'data': JSON.stringify(collectionsData[id])}, (err, res) => {
            if (err) throw err;
          });
        }
        subject.complete();
        
      });
    });
  }
  catch(e) {
    winston.error("buildFixedCollection(): Caught error:",e);
  }

}

app.get('/api/buildfixedcollection/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  let id = req.params.id;
  winston.info('GET /api/buildfixedcollection/:id', id);
  try {
    if (collections[id].state === 'initial') {
      res.sendStatus(202);
    }
    else {
      throw("Collection " + id + " is not in its initial state");
    }
  }
  catch (exception) {
    winston.error('ERROR GET /api/buildfixedcollection/:id:',exception);
    res.sendStatus(500);
    return;
  }
  buildFixedCollection(id);
});




















///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////ROLLING COLLECTIONS////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



function rollingSubjectWatcher(req, res, output) {
  //The only job of this function is to take the output of our collection observable, and write it to the HTTP response stream so our client can see it
  
  //winston.debug("rollingSubjectWatcher()", output);
  //res.write(JSON.stringify(output));
  res.write(JSON.stringify(output) + ',');
  res.flush();
}

var rollingCollectionSubjects = {};
// This contains observables for rolling collections, which can be subscribed to by new connections into a rolling collection
// One observable per-collection
/*
rollingCollectionSubjects = { 
  'collectionId' : { 
    worker: 'spawned worker object',
    interval: 'intervalObject for 60 second loop of worker',
    observers: 'the number of clients watching this rolling collection',
    subject: 'rxjs observable for the collection which can be used to pipe output back to the client',
    lastRun: 'the time it was last run',
    paused: boolean (paused state of a monitoring collection)
  },
  'collectionId2': ...
}
*/


var rollingCollections = {}; // This houses collection data for rolling and monitoring collections.  It is never committed to the DB as these collections are intended to be temporary only


function rollingCollectionSocketConnectionHandler(id, socket, tempName, subject, firstRun, sessionId) {
  // For rolling and monitoring collections
  // Handles all dealings with the worker process after it has been spawned, including sending it its configuration, and sending data received from it to the chunkHandler() function
  // It also purges old data from the collection as defined by the type of collection and number of hours back to retain

  let rollingId = id;
  if (sessionId != '') {
    rollingId = sessionId;
  }

  let thisRollingCollection =  rollingCollections[rollingId];
  let thisRollingCollectionSubject = rollingCollectionSubjects[rollingId];
  let thisCollection = collections[id];
  
  winston.debug("rollingCollectionSocketConnectionHandler(): Connection received from worker to build rolling or monitoring collection", rollingId);
  
    
  // Tell our subscribed clients that we're rolling, so they can start their spinny icon and whatnot
  if (thisCollection.type === 'monitoring') {
    subject.next({collection: { id: id, state: 'refreshing'}});
  }
  else if (thisCollection.type === 'rolling') {
    subject.next({collection: { id: id, state: 'rolling'}});
  }


  ///////////////////////////
  //PURGE AGED-OUT SESSIONS//
  ///////////////////////////

  if (thisCollection.type === 'monitoring') {
    thisRollingCollection.sessions = [];
    thisRollingCollection.images = [];
    thisRollingCollection.search = [];
  }
  else if (!firstRun && thisCollection.type === 'rolling') {
    // Purge events older than thisCollection.lastHours

    winston.debug('Running purge routine');
    let sessionsToPurge = [];
    let purgedSessionPositions = [];

    // Calculate the maximum age a given session is allowed to be
    // let maxTime = thisCollection.lastRun - thisCollection.lastHours * 60 * 60;
    // if (purgeHack) { maxTime = thisCollection.lastRun - 60 * 5; } // 5 minute setting used for testing
    let maxTime = thisRollingCollectionSubject.lastRun - thisCollection.lastHours * 60 * 60;
    if (purgeHack) { maxTime = thisRollingCollectionSubject.lastRun - 60 * 5; } // 5 minute setting used for testing


    for (let i=0; i < thisRollingCollection.sessions.length; i++) {
      // Look at each session and determine whether it is older than maxtime
      // If so, add it to purgedSessionPositions and sessionsToPurge
      let session = thisRollingCollection.sessions[i];
      let sid = session.id;
      if ( session.meta.time < maxTime ) {
        purgedSessionPositions.push(i);
        sessionsToPurge.push(sid);
        //thisRollingCollection.sessions.splice(i, 1);
      }
    }

    // Sort sessionsToPurge
    purgedSessionPositions.sort(sortNumber);
    
    //Now remove purged sessions from thisRollingCollection
    for (let i = 0; i < purgedSessionPositions.length; i++) {
      thisRollingCollection.sessions.splice(purgedSessionPositions[i], 1);
    }

    
    //We now have sessionsToPurge.  let's purge them

    //Purge images
    for (let v = 0; v < sessionsToPurge.length; v++) {
      for (let i = 0; i < thisRollingCollection.images.length; i++) {
        if ( thisRollingCollection.images[i].session === sessionsToPurge[v]) {
          //delete files
          //winston.debug("deleting files for session", sessionsToPurge[v]);
          if ('contentFile' in thisRollingCollection.images[i]) {
            fs.unlink(thisRollingCollection.images[i].contentFile, () => {});
          }
          if ('thumbnail' in thisRollingCollection.images[i]) {
            fs.unlink(thisRollingCollection.images[i].thumbnail, () => {});
          }
          if ('pdfImage' in thisRollingCollection.images[i]) {
            fs.unlink(thisRollingCollection.images[i].pdfImage, () => {});
          }
          thisRollingCollection.images.splice(i, 1);
        }
      }
    }

    // Purge search data
    let purgedSearchPositions = [];
    for (let v = 0; v < sessionsToPurge.length; v++) {
      for (let i = 0; i < thisRollingCollection.search.length; i++) {
        if ( thisRollingCollection.search[i].session === sessionsToPurge[v]) {
          //thisRollingCollection.search.splice(i, 1);
          purgedSearchPositions.push(i);
        }
      }
    }
    purgedSearchPositions.sort(sortNumber);
    for (let i = 0; i < purgedSearchPositions.length; i++) {
      thisRollingCollection.search.splice(purgedSessionPositions[i], 1);
    }
    
    // Notify the client of our purged sessions
    if (sessionsToPurge.length > 0) {
      let update = { collectionPurge: sessionsToPurge };
      subject.next(update);
    }
    
  }

  //////////////////////////////////
  //Build the worker configuration//
  //////////////////////////////////

  let cfg = {
    // id: id,
    id: rollingId,
    query: thisCollection.query,
    imageLimit: thisCollection.imageLimit,
    minX: thisCollection.minX,
    minY: thisCollection.minY,
    gsPath: preferences.gsPath,
    pdftotextPath: preferences.pdftotextPath,
    unrarPath: preferences.unrarPath,
    distillationEnabled: thisCollection.distillationEnabled,
    regexDistillationEnabled: thisCollection.regexDistillationEnabled,
    md5Enabled: thisCollection.md5Enabled,
    sha1Enabled: thisCollection.sha1Enabled,
    sha256Enabled: thisCollection.sha256Enabled,
    collectionsDir: collectionsDir
  };

  if (thisCollection.type === 'monitoring') {
    // If this is a monitoring collection, then set timeEnd and timeBegin to be a one minute window
    cfg['timeEnd'] = moment().startOf('minute').unix() - 61;
    cfg['timeBegin'] = ( cfg['timeEnd'] - 60) + 1;
  }
  
  else if (firstRun) {
    // This is a first run of a rolling collection
    // Set timeEnd as beginning of the minute before last minus one second, to give time for sessions to leave the assembler
    cfg['timeEnd'] = moment().startOf('minute').unix() - 61;
    cfg['timeBegin'] = ( cfg['timeEnd'] - (thisCollection.lastHours * 60 * 60) ) + 1;
  }  

  else {
    // This is a non-first run of a rolling collection
    // cfg['timeBegin'] = thisCollection['lastRun'] + 1;
    cfg['timeBegin'] = thisRollingCollectionSubject['lastRun'] + 1;
    cfg['timeEnd'] = cfg['timeBegin'] + 60; //add one minute to cfg[timeBegin]
  }

  // thisCollection['lastRun'] = cfg['timeEnd']; //store the time of last run so that we can reference it the next time we loop
  thisRollingCollectionSubject['lastRun'] = cfg['timeEnd']; //store the time of last run so that we can reference it the next time we loop

  if ('distillationTerms' in thisCollection) {
    cfg['distillationTerms'] = thisCollection.distillationTerms;
  }
  if ('regexDistillationTerms' in thisCollection) {
    cfg['regexDistillationTerms'] = thisCollection.regexDistillationTerms;
  }
  if ('md5Hashes' in thisCollection) {
    cfg['md5Hashes'] = thisCollection.md5Hashes;
  }
  if ('sha1Hashes' in thisCollection) {
   cfg['sha1Hashes'] = thisCollection.sha1Hashes;
  }
  if ('sha256Hashes' in thisCollection) {
   cfg['sha256Hashes'] = thisCollection.sha256Hashes;
  }

  let nwserver = nwservers[thisCollection.nwserver];
  for (var k in nwserver) {
    if (k != 'id') {
      cfg[k] = nwserver[k]; // assign an nwserver to the collection cfg
    }
  }
  let outerCfg = { workerConfig: cfg };



  ////////////////////////
  //DEAL WITH THE SOCKET//
  ////////////////////////

  // Buffer for worker data
  var data = '';

  //Set socket options
  socket.setEncoding('utf8');
  
  // Handle data received from the worker over the socket (this really builds the collection)
  socket.on('data', chunk => data = chunkHandler(rollingCollections, id, subject, data, chunk, sessionId) );
                              
                              
  // Once the worker has exited, delete the socket temporary file
  socket.on('end', () => {
    winston.debug('Worker disconnected.  Rolling collection update cycle complete.');
    fs.unlink(tempName, () => {}); // Delete the temporary UNIX socket file
  });

  // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
  socket.write(JSON.stringify(outerCfg) + '\n'); 
  
}





function runRollingCollection(id, firstRun, res, sessionId='') {
  // Executes the building of a rolling or monitoring collection

  winston.debug("runRollingCollection(id)");

  let rollingId = id;
  if (collections[id].type === 'monitoring') {
    rollingId = sessionId;
  }

  var subject = rollingCollectionSubjects[rollingId].subject;
  rollingCollections[rollingId] = {
    images: [],
    sessions: [],
    search: []
  };

  let thisRollingCollection =  rollingCollections[rollingId];
  let thisRollingCollectionSubject = rollingCollectionSubjects[rollingId];
  let thisCollection = collections[id];

  var work = ( () => {
    // Main body of worker execution
    // This is wrapped in an arrow function so that it will retain the local scope of 'id' and 'firstRun'
    // We also want to be able to call this body from a timer, so that's another reason we wrap it

    try {

      winston.debug("runRollingCollection(): work(): Starting run for rollingId", rollingId);

      if ( rollingId in rollingCollectionSubjects && 'worker' in thisRollingCollectionSubject ) {
        // Check if there's already a worker process already running which has overrun the 60 second mark, and if so, kill it
        winston.info('runRollingCollection(): work(): Timer expired for running worker.  Terminating worker');
        let oldWorker = thisRollingCollectionSubject['worker'];
        oldWorker.kill('SIGINT');
        // delete thisRollingCollectionSubject['worker']; // we don't want to do this here as it will be handled when the worker exits
      }

      if (thisCollection.type === 'monitoring' && thisRollingCollectionSubject.paused === true) {
        // Monitoring collection is paused
        // Now we end and delete this monitoring collection, except for its files (which still may be in use on the client)
        winston.debug('runRollingCollection(): work(): Ending work for paused monitoring collection', rollingId);
        clearInterval(thisRollingCollectionSubject.interval); // stop work() from being called again
        thisRollingCollectionSubject.subject.complete(); // end observable
        res.write('{"close":true}]'); // Close the array so that oboe knows we're done
        res.flush();
        res.end();
        delete rollingCollectionSubjects[rollingId];
        delete rollingCollections[rollingId];
        return;
      }

      // Create temp file to be used as our UNIX domain socket
      let tempName = temp.path({suffix: '.socket'});

      // Now open the UNIX domain socket that will talk to worker script by creating a handler (or server) to handle communications
      let socketServer = net.createServer( (socket) => { rollingCollectionSocketConnectionHandler(id, socket, tempName, subject, firstRun, sessionId); });

      
      socketServer.listen(tempName, () => {
        // Tell the server to listen for communication from the not-yet-started worker

        winston.debug('runRollingCollection(): work(): listen(): Rolling Collection: Listening for worker communication');
        winston.debug("runRollingCollection(): work(): listen(): Rolling Collection: Spawning worker with socket file " + tempName);
        
        // Start the worker process and assign a reference to it to 'worker'
        let worker = spawn('./221b_worker.py ',[tempName], {shell:true, stdio: 'inherit'});
        // Notice that we don't pass any configuration to the worker on the command line.  It's all done through the UNIX socket for security.
        
        // Add the worker reference to rollingCollectionSubjects so we can work with it later
        thisRollingCollectionSubject['worker'] = worker;

        
        worker.on('exit', (code) => {
          // This is where we handle the exiting of the worker process

          if (typeof code === 'undefined') {
            // Handle really bad worker exit with no error code - maybe because we couldn't spawn it at all?
            winston.debug('runRollingCollection(): work(): listen(): onExit(): Worker process exited abnormally without an exit code');
            thisCollection['state'] = 'error';
            subject.next({collection: { id: id, state: 'error'}});
            if (rollingId in rollingCollectionSubjects && 'worker' in thisRollingCollectionSubject) {
              delete thisRollingCollectionSubject.worker;
            }
          }

          else if (code != 0) {
            // Handle worker exit with error code
            winston.debug('runRollingCollection(): work(): listen(): onExit(): Worker process exited in bad state with non-zero exit code',code.toString());
            thisCollection['state'] = 'error';
            subject.next({collection: { id: id, state: 'error'}});
            if (rollingId in rollingCollectionSubjects && 'worker' in thisRollingCollectionSubject) {
              delete thisRollingCollectionSubject.worker;
            }
          }

          else {
            // Handle normal worker exit
            winston.debug('runRollingCollection(): work(): listen(): onExit(): Worker process exited normally with exit code', code.toString());

            // Tell client that we're resting
            subject.next({collection: { id: id, state: 'resting'}});

            // Save the collection to the DB
            db.collection('collections').update( {'id': id }, thisCollection, (err, res) => {
              if (err) throw err;
            });
            
            /*// Save the collection data to the DB -- WE SHOULDN'T HAVE TO DO THIS AS THESE DON'T PERSIST!!!!!!!
            db.collection('collectionsData').update( {'id': id }, {'id': id, 'data': JSON.stringify(collectionsData[id])}, (err, res) => {
              if (err) throw err;
            });*/
            
            firstRun = false;
            
            if (rollingId in rollingCollectionSubjects && 'worker' in thisRollingCollectionSubject) {
              delete thisRollingCollectionSubject.worker;
            }
          }
        });
      });
    }

    catch(e) {
      winston.error("runRollingCollection(): work(): Caught unhandled error:", e);
    }
    
  });

  // Start the work() function (the main body of worker execution)
  work();

  // Now schedule work() to run every 60 seconds and store a reference to it in thisRollingCollectionSubject['interval'],
  // which we can later use to terminate the timer and prevent future execution.
  // This will not initially execute work() until the first 60 seconds have elapsed, which is why we run work() once before this
  thisRollingCollectionSubject['interval'] = setInterval( () => work(), 60000);
}




app.get('/api/pausemonitoringcollection/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let id = req.headers['twosessionid'];
  winston.info(`GET /api/pausemonitoringcollection/:id: Pausing monitoring collection ${id}`);
  rollingCollectionSubjects[id]['paused'] = true;
  res.sendStatus(202);
});

app.get('/api/unpausemonitoringcollection/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // This only gets used by the client if a monitoring collection is paused and then resumed within the minute the run is permitted to continue executing
  // Otherwise, the client will simply call /api/getrollingcollection/:id again
  let id = req.headers['twosessionid'];
  winston.info(`GET /api/unpausemonitoringcollection/:id: Resuming monitoring collection ${id}`);
  rollingCollectionSubjects[id]['paused'] = false;
  res.sendStatus(202);
});


app.get('/api/getrollingcollection/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // Builds and streams a rolling or monitoring collection back to the client.  Handles the client connection and kicks off the process

  let id = req.params.id;
  let sessionId = req.headers['twosessionid'];
  winston.info('GET /api/getrollingcollection/:id', id);
  // winston.debug('GET /api/getrollingcollection/:id sessionId:', sessionId);

  let rollingId = id;
  if ( collections[id].type === 'monitoring' ) {
    rollingId = sessionId;
  }
  let thisCollection = collections[id];
  
  
  ////////////////////////////////////////////////////
  //////////////////RESPONSE HEADERS//////////////////
  ////////////////////////////////////////////////////

  try {
    // Write the response headers
    if (thisCollection.type === 'rolling' || thisCollection.type === 'monitoring') {
      res.writeHead(200, {'Content-Type': 'application/json','Content-Disposition': 'inline' });
      res.write('['); // Open the array so that oboe can see it
      res.flush();

    }
    else {
      throw("Collection " + id + " is not of type 'rolling' or 'monitoring'");
    }
  }
  catch (exception) {
    winston.error('ERROR GET /api/getrollingcollection/:id', exception);
    res.sendStatus(500);
    return;
  }




  ///////////////////////////////////////////////////////////////////////
  ///////////////////////CLIENT DISCONNECT HANDLER///////////////////////
  ///////////////////////////////////////////////////////////////////////

  req.on('close', () => {
    // Run this block when the client disconnects from the session

    if ( rollingId in rollingCollectionSubjects) {
      winston.debug("Client disconnected from rolling collection with rollingId", rollingId);
      rollingCollectionSubjects[rollingId].observers -= 1;

      if (rollingCollectionSubjects[rollingId].observers === 0) {
        winston.debug("Last client disconnected from rolling collection with rollingId " + rollingId + '.  Destroying observable');
        
        // end execution of work() for this collection
        clearInterval(rollingCollectionSubjects[rollingId].interval);

        // destroy subject
        rollingCollectionSubjects[rollingId].subject.complete();

        try {
          winston.debug("Deleting output directory for collection", rollingId);
          rimraf( collectionsDir + '/' + rollingId, () => {} ); // Delete output directory
        }
        catch(exception) {
          winston.error('ERROR deleting output directory collectionsDir + '/' + rollingId', exception);
        }
        
        if ('worker' in rollingCollectionSubjects[rollingId]) {
          winston.debug("Killing worker for collection", rollingId);
          rollingCollectionSubjects[rollingId].worker.kill('SIGINT');
        }
        delete rollingCollectionSubjects[rollingId];
        res.end();
        return;
      }
    }
  });


  /////////////////////////////////////////
  /////////////NEW ROLLING RUN/////////////
  /////////////////////////////////////////

  if ( thisCollection.type === 'rolling' && !(id in rollingCollectionSubjects) ) {
    // This is a new rolling collection as there are no existing subscribers to it
    // Let's start building it
    let subject = new Subject(); // Create a new observable which will be used to pipe communication between the worker and the client
    
    let firstRun = true;
     
    // Populate rollingCollectionSubjects[id] with some initial values
    rollingCollectionSubjects[id] = {
      subject: subject,
      observers: 1
    }

    // We now subscribe to the existing observable for the collection and pipe its output to rollingSubjectWatcher so it can be output to the http response stream
    rollingCollectionSubjects[id].subject.subscribe( (output) => rollingSubjectWatcher(req, res, output) );
    
    
    // We don't run a while loop here because runRollingCollection will loop on its own
    // Execute our collection building here
    runRollingCollection(id, firstRun, res);
  }



  ////////////////////////////////////////////
  /////////////NEW MONITORING RUN/////////////
  ////////////////////////////////////////////
  

  else if ( thisCollection.type === 'monitoring' ) {
    // This is a new rolling collection as there are no existing subscribers to it
    // Let's start building it
    let subject = new Subject(); // Create a new observable which will be used to pipe communication between the worker and the client

    let firstRun = false;
    
    // Populate rollingCollectionSubjects[rollingId] with some initial values
    rollingCollectionSubjects[rollingId] = {
      subject: subject,
      observers: 1,
      paused: false
    }

    // We now subscribe to the existing observable for the collection and pipe its output to rollingSubjectWatcher so it can be output to the http response stream
    rollingCollectionSubjects[rollingId].subject.subscribe( (output) => rollingSubjectWatcher(req, res, output) );
    
    
    // We don't run a while loop here because runRollingCollection will loop on its own
    // Execute our collection building here
    runRollingCollection(id, firstRun, res, rollingId);
  }





  //////////////////////////////////////////////////////////
  ////////////ALREADY RUNNING ROLLING COLLECTION////////////
  //////////////////////////////////////////////////////////
  
  else {
    // We're not the first client connected to this collection, as the rolling collection is already running
    // Let's play back its contents and subscribe to its observable

    winston.info(`This is not the first client connected to rolling collection ${id}.  Playing back existing collection`);

    rollingCollectionSubjects[id]['observers'] += 1;
    // Increase the observers count so we know how many people are viewing the collection
    
    rollingCollectionSubjects[id].subject.subscribe( (output) => rollingSubjectWatcher(req, res, output) );
    // We now subscribe to the existing observable for the collection and pipe its output to rollingSubjectWatcher so it can be output to the http response stream
      
    // Play back the data already in rollingCollections[id]

    for (var i=0; i < rollingCollections[id].sessions.length; i++) {
      // Play back sessions
      let resp = {
        collectionUpdate: {
          session: rollingCollections[id].sessions[i]
        }
      };
      res.write(JSON.stringify(resp) + ',');
      res.flush();
    }
    
    for (var i=0; i < rollingCollections[id].images.length; i++) {
      // Play back images
      let resp = {
        collectionUpdate: {
          images: [ rollingCollections[id].images[i] ]
        }
      };
      res.write(JSON.stringify(resp) + ',');
      res.flush();
    }
    
    if (rollingCollections[id].search) {
      // Play back search text
      for (var i=0; i < rollingCollections[id].search.length; i++) {
        let resp = {
          collectionUpdate: {
            search: [ rollingCollections[id].search[i] ] 
            // We enclose this in an array to be consistent with the worker, which also does this when it sends search terms, in case there are more than one search term per update.
           // The client should only have to deal with one format
          }
        };
        res.write(JSON.stringify(resp) + ',');
        res.flush();
      }
    }

    // We don't need to wait as the connection will hold open until we call res.end()
  }

});

























///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////UTILITY FUNCTIONS/////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


function connectToDB() {
  mongo.connect(mongoUrl, (err, database) => {
    if (err) throw err;
    db = database;
  
    db.listCollections().toArray( (err, cols) => {
      if (err) throw err;

      let foundPrefs = false;
      for (let i=0; i < cols.length; i++) {
        if (cols[i].name == "preferences") {
           //read prefs
           foundPrefs = true;
           justInstalled = false;
           winston.debug("Reading preferences");
           db.collection('preferences').findOne( (err, res) => {
             preferences = res.preferences;
           });
        }
      
        if (cols[i].name == "nwservers") {
          winston.debug("Reading nwservers");
          db.collection('nwservers').find({}).toArray( (err, res) => {
             for (let x=0; x < res.length; x++) {
                let id = res[x].id;
                nwservers[id] = res[x];
             }
           });
        }
      
        if (cols[i].name == "collections") {
          winston.debug("Reading collections");
          db.collection('collections').find({}).toArray( (err, res) => {
             for (let x=0; x < res.length; x++) {
                let id = res[x].id;
                collections[id] = res[x];
             }
             cleanRollingDirs();
           });
        }
      
        if (cols[i].name == "collectionsData") {
          winston.debug("Reading collectionsData");
          db.collection('collectionsData').find({}).toArray( (err, res) => {
             for (let x=0; x < res.length; x++) {
                //winston.debug("res[x]:", res[x]);
                let id = res[x].id;
                collectionsData[id] = JSON.parse(res[x].data);
             }
           });
        }    
      }
    
      if (!foundPrefs) {
        winston.info("Creating default preferences");
        preferences = defaultPreferences;
        db.collection('preferences').insertOne( {'preferences': preferences}, (err, res) => {
          if (err) throw err;
        });
      }
    });
  
  
  
  });
}

function writePreferences() {
  db.collection('preferences').updateOne({},{'preferences': preferences}, (err, res) => {
    if (err) throw err;
  });
}

function cleanRollingDirs() {
  try {
    winston.info("Cleaning up rolling and monitoring collection directories");
    for (let collection in collections) {
      winston.debug("Cleaning collection '" + collections[collection].name + "' with id " + collection);
      if (collections.hasOwnProperty(collection) && ( collections[collection].type == 'monitoring' || collections[collection].type == 'rolling' ) ) { //hasOwnProperty needed to filter out object prototypes
        //winston.debug('Deleting dir', collectionsDir + '/' + collections[collection].id);
        rimraf( collectionsDir + '/' + collections[collection].id, () => {} ); // delete output directory
      }
    }
  }
  catch(exception) {
    winston.error('ERROR deleting output directory collectionsDir + '/' + id', exception);
  }
}

function createDefaultUser() {
  User.register(new User({ id: uuidV4(), username : 'admin', fullname: 'System Administrator', email: 'noreply@knowledgekta.com', enabled: true }), 'kentech0', (err, user) => {
    if (err) {
      winston.error("ERROR adding default user 'admin':", err);
    }
    else {
      winston.info("Default user 'admin' added");
    }
  });
}

function sortNumber(a, b) {
  return b - a;
}

function chunkHandler(collectionRoot, id, subject, data, chunk, sessionId='') {
  // Handles socket data received from the worker process
  // This actually builds the collection data structures and sends updates to the client

  let rollingId = id;
  if (sessionId != '') {
    rollingId = sessionId;
  }
  let thisCollection = collectionRoot[rollingId];

  winston.debug('Processing update from worker');
  data += chunk

  var splt = data.split("\n").filter( (el) => {return el.length != 0}) ;
  //winston.debug("length of split:", splt.length);

  if ( splt.length == 1 && data.indexOf("\n") === -1 ) {
    //this case means the split resulted in only one element and that doesn't contain the newline delimiter, which means we haven't received an entire update yet...
    //we'll continue and wait for the next update which will hopefully contain the delimeter
    return data;
  }
  var d = []
  if ( splt.length == 1 && data.endsWith("\n") ) {
    //this case means the split resulted in only one element and that it does contain the newline delimiter.  This means we received a single complete update.
    d.push(splt.shift() );
    data='';
  }
  else if ( splt.length > 1 ) {
    //this case means the split resulted in multiple elements and that it does contain a newline delimiter...
    //This means we have at least one complete update, and possibly more.
    if (data.endsWith("\n")) {  //the last element is a full update as data ends with a newline
      while (splt.length > 0) {
        d.push(splt.shift());
      }
      //winston.debug("now the length of split is", splt.length);
      data = '';
    }
    else { //the last element is only a partial update, meaning that more data must be coming
      while (splt.length > 1) {
        d.push(splt.shift());
      }
      data = splt.shift();  //this should be the last partial update, which should be appended to in the next update
    }
  }

  while (d.length > 0) {
    let u = d.shift();
    let update = JSON.parse(u);
    
    thisCollection.sessions.push(update.collectionUpdate.session);
    
    if (update.collectionUpdate.search) {
      if (!thisCollection.search) {
        thisCollection.search = [];
      }
      for (var i = 0; i < update.collectionUpdate.search.length; i++) {
        
        thisCollection.search.push(update.collectionUpdate.search[i]);
      }
    }

    //modify image paths to point to /collections/:collectionId
    for (var i=0; i < update.collectionUpdate.images.length; i++) {
      
      update.collectionUpdate.images[i].contentFile = collectionsUrl + '/' + rollingId + '/' + update.collectionUpdate.images[i].contentFile;

      if ('thumbnail' in update.collectionUpdate.images[i]) {
        update.collectionUpdate.images[i].thumbnail = collectionsUrl + '/' + rollingId + '/' + update.collectionUpdate.images[i].thumbnail;
      }
      if ('pdfImage' in update.collectionUpdate.images[i]) {
        update.collectionUpdate.images[i].pdfImage = collectionsUrl + '/' + rollingId + '/' + update.collectionUpdate.images[i].pdfImage;
      }
      if ('archiveFilename' in update.collectionUpdate.images[i]) {
        update.collectionUpdate.images[i].archiveFilename = collectionsUrl + '/' + rollingId + '/' + update.collectionUpdate.images[i].archiveFilename;
      }
      thisCollection.images.push(update.collectionUpdate.images[i]);
    }
    
    subject.next(update);
  }

  return data;

}

var transformUser = function(doc, ret, options) {
  delete ret._id;
  delete ret.id;
  delete ret.email;
  return ret;
};







///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////LISTEN/////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Start listening for client traffic and away we go
app.listen(listenPort);
winston.info('Serving on localhost:' + listenPort);
