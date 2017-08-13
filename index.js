'use strict';

// Load dependencies
const Observable = require('rxjs/Observable').Observable;
const Subject = require('rxjs/Subject').Subject;
const express = require('express');
const app = express();
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
const version = '2017.08.12';

//Configure logging
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

var justInstalled = true;
var preferences = {};
var nwservers = {};
var collections = {};
var collectionsData = {};

var url = "mongodb://localhost:27017/221b";
var db;
connectToDB(); //this must come before mongoose user connection so that we know whether to create the default admin account

const cfgDir = '/etc/kentech/221b';
const certDir = cfgDir + '/certificates';
const jwtPrivateKeyFile = certDir + '/221b.key';
const jwtPublicKeyFile = certDir + '/221b.pem';
const collectionsUrl = '/collections'
var collectionsDir = '/var/kentech/221b/collections';

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());


// passport config
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

var jwtOpts = {
  jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]),
  secretOrKey: jwtPublicKey,
  algorithms: ['RS256']
};


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


//We use mongoose for auth, and MongoClient for everything else.  This is because Passport-Local Mongoose required it, and it is ill-suited to the free-formish objects which we want to use.
var User = require('./models/user');
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// mongoose
mongoose.connect("mongodb://localhost:27017/221b_users", {useMongoClient: true, promiseLibrary: global.Promise});
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


//Create default user account if we think the app was just installed and if the count of users is 0
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


var transformUser = function(doc, ret, options) {
  delete ret._id;
  delete ret.id;
  delete ret.email;
  return ret;
};

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
      res.cookie('access_token', token, { httpOnly: true, secure: true })
      res.json({
        success: true,
        user: user.toObject()
      });
    }
  });
});

app.get('/api/logout', passport.authenticate('jwt', { session: false } ), (req,res) => {
  winston.info('GET /api/logout');
  let decoded = jwt.decode(req.cookies.access_token); //we can use jwt.decode here without signature verification as it's already been verified during authentication
  //winston.debug("decoded:", decoded);
  let tokenId = decoded.jti; //store this
  //winston.debug("decoded tokenId:", tokenId);
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
  res.json(req.user.toObject()); // { versionKey: false, transform: transformUserIsLoggedIn }
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


//returns a streaming collection which is in the process of building
app.get('/api/getbuildingcollection/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{ 
  var id = req.params.id;
  winston.info('GET /api/getbuildingcollection/:id', id);
  //winston.debug('buildingCollections',buildingCollections);
  try {
    if (buildingCollections[id]) {
      //winston.debug('playing back collection which is in the process of building');
      res.writeHead(200, {'Content-Type': 'application/json','Content-Disposition': 'inline' });
      var subject = buildingCollections[id].observable; //get our observable

      //play back the data already in buildingCollections. we must play back sessions and images separately as there are generally more images than sessions
      for (var i=0; i < buildingCollections[id].sessions.length; i++) {
        let resp = {
          collectionUpdate: {
            session: buildingCollections[id].sessions[i]
          }
        };
        res.write(JSON.stringify(resp));
        res.flush();
      }
      
      //now play back images
      for (var i=0; i < buildingCollections[id].images.length; i++) {
        let resp = {
          collectionUpdate: {
            images: [ buildingCollections[id].images[i] ]
          }
        };
        res.write(JSON.stringify(resp));
        res.flush();
      }
      
      //now play back search text
      winston.debug("Playing back search");
      if (buildingCollections[id].search) {
        for (var i=0; i < buildingCollections[id].search.length; i++) {
          //winston.debug("loop", i);
          let resp = {
            collectionUpdate: {
              search: buildingCollections[id].search[i]
            }
          };
          res.write(JSON.stringify(resp));
          res.flush();
        }
      }
    
      subject.subscribe( (o) => { res.write(JSON.stringify(o)); res.flush(); }, //data from observable
                            (e) => { throw(e); }, //errors from observable
                            ( ) => { winston.debug('ending observable'); //end of observable
                                     res.end(); }
                           );
    }


    else if (collections[id].state === 'complete') { //if collection is already complete, play it back (probably won't happen in real life, but we will accommodate it anyway, just in case)
      winston.info('playing back collection', id);
      res.set('Content-Type', 'application/json');
      res.set('Content-Disposition', 'inline');
      res.set(200);
      for (var i=0; i < collectionsData[id].images.length; i++) { //play back the image and session data already in buildingCollections
        var sessionId = collectionsData[id].images[i].session;
        let resp = {
          collectionUpdate: {
            images: [ collectionsData[id].images[i] ],
            session: collectionsData[id].sessions[sessionId],
          }
        };
        res.write(JSON.stringify(resp));
        res.flush();
      }

      if (buildingCollections[id].search) {
        for (var i=0; i < collectionsData[id].search.length; i++) { //now play back the search info
          let resp = {
            collectionUpdate: {
              search: [ collectionsData[id].search[i] ],
            }
          };
          res.write(JSON.stringify(resp));
          res.flush();
        }
      }
      res.end();
    }
    else {
      throw('Collection ' + id + ' not found');
    }
  }
  catch(exception) {
    winston.error('ERROR GET /api/getbuildingcollection/:id', exception);
    res.sendStatus(500);
  }
});

var buildingCollections = {}; //we shall house collections which are under construction here

function socketConnectionWorker(id, socket, tempName, subject) { // for fixed collections
  winston.info("socketConnectionWorker(): Connection received from worker to build collection",id);
  
  var data = ''; //buffer for worker data

  //Set socket options
  socket.setEncoding('utf8');
  
  //tell our subscribers that we're building, so they can start their spinny icon
  subject.next({collection: { id: id, state: 'building'}});

  //Handle data from the socket (this really builds the collection)
  socket.on('data', chunk => data = chunkHandler(buildingCollections, id, subject, data, chunk) );
  //Now that we've finished building the new collection, emit a finished signal, and merge the new collection into the collectionsData object, and delete the object from buildingCollections
  socket.on('end', () => {
                            winston.debug('Worker disconnected.  Merging temporary collection into permanent collection');
                            collectionsData[id].images = buildingCollections[id].images;
                            collectionsData[id].search = buildingCollections[id].search;
                            for (var e in buildingCollections[id].sessions) {
                              let s = buildingCollections[id].sessions[e];
                              let sid = s.id;
                              collectionsData[id].sessions[sid] = s;
                            }
                            //moved into process exit
                            winston.debug('Temporary collection merged into main branch.  Deleting temporary collection.');
                            delete buildingCollections[id];
                            fs.unlink(tempName, () => {});
                          });

  
  //Build the worker configuration
  let cfg = { id: id,
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
  if (collections[id].distillationTerms) {
    cfg['distillationTerms'] = collections[id].distillationTerms;
  }
  if (collections[id].regexDistillationTerms) {
    cfg['regexDistillationTerms'] = collections[id].regexDistillationTerms;
  }
  if (collections[id].md5Hashes) {
    cfg['md5Hashes'] = collections[id].md5Hashes;
  }
  if (collections[id].sha1Hashes) {
    cfg['sha1Hashes'] = collections[id].sha1Hashes;
  }
  if (collections[id].sha256Hashes) {
    cfg['sha256Hashes'] = collections[id].sha256Hashes;
  }

  let nwserver = nwservers[collections[id].nwserver];
  for (var k in nwserver) {
    if (k != 'id') {
      cfg[k] = nwserver[k];
    }
  }
  let outerCfg = { workerConfig: cfg };
  //winston.debug('cfg:',cfg);
  //Send configuration to worker.  After this, we should start receiving data on the socket
  socket.write(JSON.stringify(outerCfg) + '\n'); 
  
}


function buildCollection(id) { //replacement function
  winston.debug('buildCollection(): Building collection', id);
  
  try {
    collections[id]['state'] = 'building';
    //Build observable which we can use to notify others of new additions to the collection
    var subject = new Subject();
    buildingCollections[id] = {
      observable: subject, //we add the observable subject object to the object so we can get it later
      images: [],
      sessions: []
    };
    var tempName = temp.path({suffix: '.socket'});
    //open UNIX domain socket to talk to worker script
    var socketServer = net.createServer( (socket) => {socketConnectionWorker(id, socket, tempName, subject);} );
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
                                        } );
  }
  catch(e) {
    winston.error("BuildCollection(): Caught error:",e);
  }

}

app.get('/api/buildcollection/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  let id = req.params.id;
  winston.info('GET /api/buildcollection/:id', id);
  try {
    if (collections[id].state === 'initial') {
      res.sendStatus(202);
    }
    else {
      throw("Collection " + id + " is not in its initial state");
    }
  }
  catch (exception) {
    winston.error('ERROR GET /api/buildcollection/:id:',exception);
    res.sendStatus(500);
    return;
  }
  buildCollection(id);
});


function chunkHandler(collectionRoot, id, subject, data, chunk) {
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
    
    collectionRoot[id].sessions.push(update.collectionUpdate.session);
    
    if (update.collectionUpdate.search) {
      if (!collectionRoot[id].search) {
        collectionRoot[id].search = [];
      }
      for (var i = 0; i < update.collectionUpdate.search.length; i++) {
        
        collectionRoot[id].search.push(update.collectionUpdate.search[i]);
      }
    }

    //modify image paths to point to /collections/:collectionId
    for (var i=0; i < update.collectionUpdate.images.length; i++) {
      
      update.collectionUpdate.images[i].contentFile = collectionsUrl + '/' + id + '/' + update.collectionUpdate.images[i].contentFile;

      if ('thumbnail' in update.collectionUpdate.images[i]) {
        update.collectionUpdate.images[i].thumbnail = collectionsUrl + '/' + id + '/' + update.collectionUpdate.images[i].thumbnail;
      }
      if ('pdfImage' in update.collectionUpdate.images[i]) {
        update.collectionUpdate.images[i].pdfImage = collectionsUrl + '/' + id + '/' + update.collectionUpdate.images[i].pdfImage;
      }
      if ('archiveFilename' in update.collectionUpdate.images[i]) {
        update.collectionUpdate.images[i].archiveFilename = collectionsUrl + '/' + id + '/' + update.collectionUpdate.images[i].archiveFilename;
      }
      collectionRoot[id].images.push(update.collectionUpdate.images[i]);
    }
    /*for (var i=0; i < update.collectionUpdate.images.length; i++) {
      update.collectionUpdate.images[i].image = collectionsUrl + '/' + id + '/' + update.collectionUpdate.images[i].image;
      if ('thumbnail' in update.collectionUpdate.images[i]) {
        update.collectionUpdate.images[i].thumbnail = collectionsUrl + '/' + id + '/' + update.collectionUpdate.images[i].thumbnail;
      }
      if (update.collectionUpdate.images[i].contentFile) {
        update.collectionUpdate.images[i].contentFile = collectionsUrl + '/' + id + '/' + update.collectionUpdate.images[i].contentFile;
      }
      collectionRoot[id].images.push(update.collectionUpdate.images[i]);
    }*/
    
    subject.next(update);
  }

  return data;

}


function rollingSubjectWatcher(req, res, output) {
  //winston.debug("rollingSubjectWatcher()", output);
  res.write(JSON.stringify(output));
  res.flush();
}

var rollingCollectionSubjects = {};
var rollingCollections = {};

function rollingCollectionSocketConnectionWorker(id, socket, tempName, subject, firstRun) {

  winston.debug("rollingCollectionSocketConnectionWorker(): Connection received from worker to build rolling or monitoring collection", id);
  var data = ''; //buffer for worker data
  //Set socket options
  socket.setEncoding('utf8');
  
  //tell our subscribers that we're rolling, so they can start their spinny icon
  if (collections[id].type === 'monitoring') {
    subject.next({collection: { id: id, state: 'refreshing'}});
  }
  else if (collections[id].type === 'rolling') {
    subject.next({collection: { id: id, state: 'rolling'}});
  }

  if (collections[id].type === 'monitoring') {
    rollingCollections[id].sessions = [];
    rollingCollections[id].images = [];
    rollingCollections[id].search = [];
  }
  else if (!firstRun && collections[id].type === 'rolling') { //purge events older than collections[id].lastHours
    winston.debug('Running purge routine');
    var sessionsToPurge = [];

    let maxTime = collections[id].lastRun - collections[id].lastHours * 60 * 60;
    //let maxTime = collections[id].lastRun - 60 * 5; //5 minute setting used for testing

    for (let i=0; i < rollingCollections[id].sessions.length; i++) {
      let session = rollingCollections[id].sessions[i];
      winston.debug('session:', session);
      let sessionId = session.id;
      winston.debug('sessionId:', sessionId);
      if ( session.meta.time < maxTime ) {
        sessionsToPurge.push(sessionId);
        rollingCollections[id].sessions.splice(i, 1);
      }
    }

    winston.debug("sessionsToPurge:", sessionsToPurge);
    
    //we now have sessionsToPurge.  let's purge them
    //purge images
    //winston.debug("images:", rollingCollections[id].images);
    for (let v=0; v < sessionsToPurge.length; v++) {
      for (let i=0; i < rollingCollections[id].images.length; i++) {
        if ( rollingCollections[id].images[i].session === sessionsToPurge[v]) {
          //delete files
          //winston.debug("deleting files for session", sessionsToPurge[v]);
          fs.unlink(rollingCollections[id].images[i].image, () => {});
          if ('thumbnail' in rollingCollections[id].images[i]) {
            fs.unlink(rollingCollections[id].images[i].thumbnail, () => {});
          }
          if (rollingCollections[id].images[i].contentFile) {
            fs.unlink(rollingCollections[id].images[i].contentFile, () => {});
          }
          rollingCollections[id].images.splice(i, 1);
        }
      }
    }
    //purge search data
    for (let v=0; v < sessionsToPurge.length; v++) {
      for (let i=0; i < rollingCollections[id].search.length; i++) {
        if ( rollingCollections[id].search[i].session === sessionsToPurge[v]) {
          rollingCollections[id].search.splice(i, 1);
        }
      }
    }
    
    //now send update
    if (sessionsToPurge.length > 0) {
      let update = { collectionPurge: sessionsToPurge };
      subject.next(update);
    }
    
  }
  
  //Handle data from the socket (this really builds the collection)
  socket.on('data', chunk => data = chunkHandler(rollingCollections, id, subject, data, chunk) );
                              
                              
  //Now that we've finished building the new collection, emit a finished signal, and merge the new collection into the collectionsData object, and delete the object from rollingCollections
  socket.on('end', () => {
                            winston.debug('Worker disconnected.  Rolling collection update cycle complete.');
                            fs.unlink(tempName, () => {});
                          });

  
  //Build the rolling collection worker configuration
  let cfg = { id: id,
              query: collections[id].query,
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
              //timeBegin: collections[id].timeBegin,
              //timeEnd: collections[id].timeEnd
  };
  
  if (firstRun) {
  winston.debug("got firstRun");
    //set timeEnd as beginning of the minute before last minus one second, to give time for sessions to leave the assembler
    cfg['timeEnd'] = moment().startOf('minute').unix() - 61;
    cfg['timeBegin'] = ( cfg['timeEnd'] - (collections[id].lastHours * 60 * 60) ) + 1;
  }
  else if (collections[id].type === 'monitoring') {
    cfg['timeEnd'] = moment().startOf('minute').unix() - 61;
    cfg['timeBegin'] = ( cfg['timeEnd'] - 60) + 1;
  }
  else { //this is a non-first run
    cfg['timeBegin'] = collections[id]['lastRun'] + 1;
    cfg['timeEnd'] = cfg['timeBegin'] + 60; //add one minute to cfg[timeBegin]
  }
  collections[id]['lastRun'] = cfg['timeEnd']; //store the time of last run so that we can reference it the next time we loop

  if (collections[id].distillationTerms) {
    cfg['distillationTerms'] = collections[id].distillationTerms;
  }
  if (collections[id].regexDistillationTerms) {
    cfg['regexDistillationTerms'] = collections[id].regexDistillationTerms;
  }
  if (collections[id].md5Hashes) {
    cfg['md5Hashes'] = collections[id].md5Hashes;
  }
  if (collections[id].sha1Hashes) {
    cfg['sha1Hashes'] = collections[id].sha1Hashes;
  }
  if (collections[id].sha256Hashes) {
    cfg['sha256Hashes'] = collections[id].sha256Hashes;
  }

  let nwserver = nwservers[collections[id].nwserver];
  for (var k in nwserver) {
    if (k != 'id') {
      cfg[k] = nwserver[k];
    }
  }
  let outerCfg = { workerConfig: cfg };
  //Send configuration to worker.  After this, we should start receiving data on the socket
  socket.write(JSON.stringify(outerCfg) + '\n'); 
  
}

function runRollingCollection(id, firstRun) {
  winston.debug("runRollingCollection(id)");
  var subject = rollingCollectionSubjects[id].subject;
  rollingCollections[id] = {
    images: [],
    sessions: [],
    search: []
  };

  var work = ( () => {
    //main body of execution
    try {
      winston.debug("Starting run for id", id);
      var tempName = temp.path({suffix: '.socket'});
      //open UNIX domain socket to talk to worker script
      var socketServer = net.createServer( (socket) => {rollingCollectionSocketConnectionWorker(id, socket, tempName, subject, firstRun);} );
      socketServer.listen(tempName, () => {
                      winston.debug('Rolling Collection: Listening for worker communication');
                      winston.debug("Rolling Collection: Spawning worker with socket file " + tempName);
                      var worker = spawn('./221b_worker.py ',[tempName], {shell:true, stdio: 'inherit'});
                      rollingCollectionSubjects[id]['worker'] = worker;
                      worker.on('exit', (code) => {
                                                    //winston.debug('worker.onexit');
                                                    if (typeof code === 'undefined') {
                                                      winston.debug('Worker process exited abnormally without an exit code');
                                                      collections[id]['state'] = 'error';
                                                      subject.next({collection: { id: id, state: 'error'}});
                                                      if (id in rollingCollectionSubjects && 'worker' in rollingCollectionSubjects[id]) delete rollingCollectionSubjects[id].worker;
                                                    }
                                                    else if (code != 0) {
                                                      winston.debug('Worker process exited abnormally with exit code',code.toString());
                                                      collections[id]['state'] = 'error';
                                                      subject.next({collection: { id: id, state: 'error'}});
                                                      if (id in rollingCollectionSubjects && 'worker' in rollingCollectionSubjects[id]) delete rollingCollectionSubjects[id].worker;
                                                    }
                                                    else {
                                                      winston.debug('Worker process exited normally with exit code', code.toString());
                                                      subject.next({collection: { id: id, state: 'resting'}});
                                                      db.collection('collections').update( {'id': id }, collections[id], (err, res) => {
                                                        if (err) throw err;
                                                      });
                                                      db.collection('collectionsData').update( {'id': id }, {'id': id, 'data': JSON.stringify(collectionsData[id])}, (err, res) => {
                                                        if (err) throw err;
                                                      });
                                                      firstRun = false;
                                                      if (id in rollingCollectionSubjects && 'worker' in rollingCollectionSubjects[id]) delete rollingCollectionSubjects[id].worker;
                                                    }
                                                    //subject.complete();
                                                  });
                    });
    }
    catch(e) {
      winston.error("runRollingCollection(): Caught error:",e);
    }
    
  });
  work();
  rollingCollectionSubjects[id]['interval'] = setInterval( () => work(), 60000); //run every minute
}




app.get('/api/getrollingcollection/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  let id = req.params.id;
  winston.info('GET /api/getrollingcollection/:id', id);
  try {
    if (collections[id].type === 'rolling' || collections[id].type === 'monitoring') {
      res.writeHead(200, {'Content-Type': 'application/json','Content-Disposition': 'inline' });
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

  req.on('close', () => {
    if ( id in rollingCollectionSubjects) {
      winston.debug("Client disconnected from rolling collection with id", id);
      rollingCollectionSubjects[id].observers -= 1;
      if (rollingCollectionSubjects[id].observers === 0) {
        //destroy subject
        winston.debug("Last client disconnected from rolling collection with id " + id + '.  Destroying observable');
        clearInterval(rollingCollectionSubjects[id].interval);
        clearInterval(rollingCollectionSubjects[id].keepaliveInterval);
        rollingCollectionSubjects[id].subject.complete();

        try {
          winston.debug("Deleting output directory for collection", id);
          rimraf( collectionsDir + '/' + id, () => {} ); //delete output directory
        }
        catch(exception) {
          winston.error('ERROR deleting output directory collectionsDir + '/' + id', exception);
        }
        
        if ('worker' in rollingCollectionSubjects[id]) {
          winston.debug("Killing worker for collection", id);
          rollingCollectionSubjects[id].worker.kill('SIGINT');
        }
        delete rollingCollectionSubjects[id];
        res.end();
        return;
      }
    }
  });
  
  if ( rollingCollectionSubjects[id] ) { //rolling collection is already running.  let's play back its contents and subscribe to its observable
    rollingCollectionSubjects[id]['observers'] += 1;
    
    //play back the data already in rollingCollections. we must play back sessions and images separately as there are generally more images than sessions
    rollingCollectionSubjects[id].subject.subscribe( (output) => rollingSubjectWatcher(req, res, output) );

    for (var i=0; i < rollingCollections[id].sessions.length; i++) {
      let resp = {
        collectionUpdate: {
          session: rollingCollections[id].sessions[i]
        }
      };
      res.write(JSON.stringify(resp));
      res.flush();
    }
    
    //now play back images
    for (var i=0; i < rollingCollections[id].images.length; i++) {
      let resp = {
        collectionUpdate: {
          images: [ rollingCollections[id].images[i] ]
        }
      };
      res.write(JSON.stringify(resp));
      res.flush();
    }
    
    //now play back search text
    winston.debug("playing back search");
    if (rollingCollections[id].search) {
      for (var i=0; i < rollingCollections[id].search.length; i++) {
        let resp = {
          collectionUpdate: {
            search: [ rollingCollections[id].search[i] ]  //we enclose this in an array to be consistent with the worker, which also does this when it sends search terms, in case there are more than one search term per update.
                                                          //The client should only have to deal with one format
          }
        };
        res.write(JSON.stringify(resp));
        res.flush();
      }
    }
    

    //we don't need to wait as the connection will hold open until we call res.end()
  }
  else {
    var subject = new Subject(); //new rolling collection.  Subscribe to subject and run it.
    var firstRun = true;
    if (collections[id].type === 'monitoring') {
      firstRun = false;
    }
    rollingCollectionSubjects[id] = {};
    rollingCollectionSubjects[id]['subject'] = subject;
    rollingCollectionSubjects[id]['observers'] = 1;
    rollingCollectionSubjects[id].subject.subscribe( (output) => rollingSubjectWatcher(req, res, output) );
    //we don't run while loop here because runRollingCollection will loop on its own
    runRollingCollection(id, firstRun);
  }
});

function connectToDB() {
  mongo.connect(url, (err, database) => {
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
        rimraf( collectionsDir + '/' + collections[collection].id, () => {} ); //delete output directory
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

app.listen(listenPort);
winston.info('Serving on localhost:' + listenPort);
