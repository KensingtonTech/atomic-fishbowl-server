'use strict';

// Load dependencies
require('source-map-support').install();
const Observable = require('rxjs/Observable').Observable;
const Subject = require('rxjs/Subject').Subject;
const express = require('express');
const app = express();
const multer  = require('multer');
const session = require('express-session');
const bodyParser = require('body-parser');
const listenPort = 3002;
const uuidV4 = require('uuid/v4');
const fs = require('fs');
const net = require('net'); //for unix sockets
const rimraf = require('rimraf');
const spawn = require('child_process').spawn;
const exec = require('child_process').exec;
const temp = require('temp');
const moment = require('moment');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
const util = require('util');
const sprintf = require('sprintf-js').sprintf;
const winston = require('winston');
const mongoose = require('mongoose');
mongoose.Promise = Promise;
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
var mongo = require('mongodb').MongoClient;
const NodeRSA = require('node-rsa');
const sleep = require('sleep');
const restClient = require('node-rest-client').Client;
const request = require('request');
const path = require('path');
const buildProperties = require('./build-properties');
const version = `${buildProperties.major}.${buildProperties.minor}.${buildProperties.patch}.${buildProperties.build}-${buildProperties.level}`;
const feedScheduler = require('./feed-scheduler.js');
var development = process.env.NODE_ENV !== 'production';
// export NODE_ENV='production'
// export NODE_ENV='development'
const purgeHack = false; // causes sessions older than 5 minutes to be purged, if set to true.  Useful for testing purging without having to wait an hour
var gsPath = '/usr/bin/gs';
var sofficePath = '/usr/bin/soffice';
var pdftotextPath = '/usr/bin/pdftotext';
var unrarPath = '/usr/bin/unrar';
if (development) {
  sofficePath = '/usr/local/bin/soffice.sh';
  gsPath = '/opt/local/bin/gs';
  pdftotextPath = '/opt/local/bin/pdftotext';
  unrarPath = '/opt/local/bin/unrar';
}
// import { Buffer } from 'buffer';

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////EXPRESS////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*app.set('trust proxy', 1);
app.use(session( {
  name: 'afbsession',
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

let tOptions = {
  'timestamp': () => moment().format('YYYY-MM-DD HH:mm:ss,SSS') + ' ',
  'formatter': (options) => options.timestamp() + 'afb_server    ' + sprintf('%-10s', options.level.toUpperCase()) + ' ' + (options.message ? options.message : '') +
(options.meta && Object.keys(options.meta).length ? '\n\t'+ JSON.stringify(options.meta) : '' )
};
if ('SYSTEMD' in process.env) {
  // systemd journal adds its own timestamp
  tOptions.timestamp = () => '';
}
winston.remove(winston.transports.Console);
winston.add(winston.transports.Console, tOptions);

if (development) {
  winston.level = 'debug';
  winston.debug('Atomic Fishbowl Server is running in development mode');
}
else {
  winston.level = 'info';
}

winston.info('Starting Atomic Fishbowl server version', version);





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////SIGTERM SIGNAL HANDLER////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

process.on('SIGTERM', function() {
  winston.info('Caught SIGTERM.  Exiting gracefully');
  process.exit(0);
});






///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////CONFIGURATION//////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var justInstalled = true;
var preferences = {};
var nwservers = {};
var saservers = {};
var collections = {}; // holds the high-level definition of a collection but not its content data
var collectionsData = {}; // holds content data and session data
var feeds = {}; // holds definitions for hash data CSV's

const cfgDir = '/etc/kentech/afb';
const certDir = cfgDir + '/certificates';
const cfgFile = cfgDir + '/afb-server.conf';
const jwtPrivateKeyFile = certDir + '/ssl.key';
const jwtPublicCertFile = certDir + '/ssl.cer';
const internalPublicKeyFile = certDir + '/internal.pem';
const internalPrivateKeyFile = certDir + '/internal.key';
const collectionsUrl = '/collections';
const dataDir = '/var/kentech/afb';
const collectionsDir = dataDir + '/collections';
const sofficeProfilesDir = dataDir + '/sofficeProfiles';
const feedsDir = dataDir + '/feeds';
const tempDir = dataDir + '/tmp'; // used for temporary holding of uploaded files

var feederSocket = null;
var feederSocketFile = null;
var feederInitialized = false;
var apiInitialized = false;

var tokenExpirationSeconds = 60 * 60 * 24; // 24 hours

// Multipart upload config
const upload = multer({ dest: tempDir });

try {
  // Read in config file
  var config = JSON.parse( fs.readFileSync(cfgFile, 'utf8') );
}
catch(exception) {
  winston.error(`Exception reading config file ${cfgFile}:` + exception);
  process.exit(1);
}

if (! 'dbConfig' in config) {
  winston.error(`'dbConfig' property not defined in ${cfgFile}`);
  sys.exit(1);
}
if (! 'host' in config['dbConfig']) {
  winston.error(`'dbConfig.host' property not defined in ${cfgFile}`);
  sys.exit(1);
}
if (! 'port' in config['dbConfig']) {
  winston.error(`'dbConfig.port' property not defined in ${cfgFile}`);
  sys.exit(1);
}
if (! 'authentication' in config['dbConfig']) {
  winston.error(`'dbConfig.authentication' property not defined in ${cfgFile}`);
  sys.exit(1);
}
if (! 'enabled' in config['dbConfig']['authentication']) {
  winston.error(`'dbConfig.authentication.enabled' property not defined in ${cfgFile}`);
  sys.exit(1);
}
if ( config['dbConfig']['authentication']['enabled']
      && ( ! 'user' in config['dbConfig']['authentication'] || ! 'password' in config['dbConfig']['authentication'])
   ) {
  winston.error(`Either 'dbConfig.authentication.username' or 'dbConfig.authentication.password' property not defined in ${cfgFile}`);
  sys.exit(1);
}
let configCopy = JSON.parse(JSON.stringify(config));
if ('dbConfig' in configCopy && 'authentication' in configCopy['dbConfig'] && 'password' in configCopy['dbConfig']['authentication']) {
  configCopy['dbConfig']['authentication']['password'] = '<redacted>';
}
winston.debug(configCopy);

// Set up encryption
const internalPublicKey = fs.readFileSync(internalPublicKeyFile, 'utf8');
const internalPrivateKey = fs.readFileSync(internalPrivateKeyFile, 'utf8');
const decryptor = new NodeRSA( internalPrivateKey );
decryptor.setOptions({encryptionScheme: 'pkcs1'});

// Set up feed scheduler
// var scheduler = new feedScheduler(feedsDir, winston, decryptor, () => schedulerUpdatedCallback);
var scheduler = new feedScheduler(feedsDir, winston, decryptor, (id) => schedulerUpdatedCallback(id));

// Create LibreOffice profiles dir
if ( !fs.existsSync(dataDir) ) {
  winston.info(`Creating data directory at ${dataDir}`);
  fs.mkdirSync(dataDir);
}
if ( !fs.existsSync(sofficeProfilesDir) ) {
  winston.info(`Creating soffice profiles directory at ${sofficeProfilesDir}`);
  fs.mkdirSync(sofficeProfilesDir);
}
if ( !fs.existsSync(feedsDir) ) {
  winston.info(`Creating feeds directory at ${feedsDir}`);
  fs.mkdirSync(feedsDir);
}
if ( !fs.existsSync(tempDir) ) {
  winston.info(`Creating temp directory at ${tempDir}`);
  fs.mkdirSync(tempDir);
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////GLOBAL PREFERENCES/////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Set default preferences
var defaultPreferences = {
  minX: 255,
  minY: 255,  
  defaultContentLimit: 1000,
  defaultRollingHours: 1,
  masonryColumnSize: 350,
  debugLogging: false,
  serviceTypes: { nw: true, sa: false },

  nw: {
    nwInvestigateUrl: '',
    summaryTimeout: 5,
    queryTimeout: 5,
    contentTimeout: 5,
    queryDelayMinutes: 1,
    maxContentErrors: 10,
    presetQuery: "filetype = 'jpg','gif','png','pdf','zip','rar','windows executable','x86 pe','windows dll','x64pe','apple executable (pef)','apple executable (mach-o)'",
    defaultQuerySelection : "All Supported File Types",
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
    ]
  },

  sa: { // solera
    url: '',
    presetQuery: "filetype = 'jpg','gif','png','pdf','zip','rar','windows executable','x86 pe','windows dll','x64pe','apple executable (pef)','apple executable (mach-o)'",
    defaultQuerySelection : "PDF's", // "All Supported File Types",
    queryTimeout: 5,
    contentTimeout: 5,
    queryDelayMinutes: 1,
    maxContentErrors: 10,
    displayedKeys : [ 
      "total_bytes", 
      "protocol_family", 
      "initiator_ip", 
      "responder_ip", 
      "aggregate_http_server_hooks", 
      "responder_country", 
      "aggregate_http_method_hooks", 
      "aggregate_file_type_hooks", 
      // "filename", 
      "aggregate_user_agent_hooks"
    ],
    masonryKeys : [
      {
        key : "aggregate_http_server_hooks",
        friendly : "Hostname"
      }, 
      {
        key : "responder_country",
        friendly : "Responder Country"
      }, 
      /*{
        key : "aggregate_http_uri_hooks",
        friendly : "URL"
      },*/ 
      {
        key : "protocol_family",
        friendly : "Protocol Family"
      }
    ]
  }
};



// Set use-cases
// A use-case consists of a name (mandatory), a friendly name (mandatory), a query (mandatory), its allowed content types[] (mandatory), distillation terms (optional), regex distillation terms (optional), and a description (mandatory)
// { name: '', friendlyName: '', query: "", contentTypes: [], description: '', distillationTerms: [], regexTerms: [] }
var useCases = [

  {
    name: 'outboundDocuments',
    friendlyName: 'Outbound Documents',
    nwquery: "direction = 'outbound' && filetype = 'pdf','office 2007 document'",
//Need to add outbound and office
    saquery: '["file_type=PDF"]',
    contentTypes: [ 'pdfs', 'officedocs' ],
    description: 'Displays documents which are being transferred outbound'
  },
  
  {
    name: 'ssns',
    friendlyName: 'Social Security Numbers',
    nwquery: "filetype = 'pdf','office 2007 document','zip','rar'",
// !!! need to add Office and confirm RAR
    saquery: "file_type=PDF file_type=ZIP file_type=RAR",
    contentTypes: [ 'pdfs', 'officedocs' ],
    description: 'Displays documents which contain social security numbers.  It will look inside ZIP and RAR archives, as well',
    regexTerms: [ '\\d\\d\\d-\\d\\d-\\d\\d\\d\\d' ]
  },

  {
    name: 'dob',
    friendlyName: 'Date of Birth',
    nwquery: "filetype = 'pdf','office 2007 document','zip','rar'",
// !!! need to add Office and confirm rar
    saquery: "file_type=PDF file_type=ZIP file_type=RAR",
    contentTypes: [ 'pdfs', 'officedocs' ],
    description: 'Displays documents which contain dates of birth', 
    regexTerms: [ 
      '(?i)(dob|date of birth|birth date|birthdate|birthday|birth day).*\\d\\d?[-/]\\d\\d?[-/]\\d{2}(?:\\d{2})?\\W',
      '(?i)(dob|date of birth|birth date|birthdate|birthday|birth day).*\\d\\d? \\w+,? \\d{2}(?:\\d{2})?\\W',
      '(?i)(dob|date of birth|birth date|birthdate|birthday|birth day).*\\w+ \\d\\d?,? \\d{2}(?:\\d{2})?\\W'
    ]
  },

  {
    name: 'contentinarchives',
    friendlyName: 'All Content Contained in Archives',
    nwquery: "filetype = 'zip','rar' && filetype != 'office 2007 document'",
// !!! need to add !Office and confirm RAR
    saquery: "file_type=ZIP file_type=RAR",
    contentTypes: [ 'images', 'pdfs', 'officedocs' ],
    description: 'Displays any content type contained within a ZIP or RAR archive.  It does not display dodgy archives'
  },
  
  {
    name: 'contentinarchivesdodgy',
    friendlyName: 'All Content Contained in Archives (with Dodgy Archives)',
    nwquery: "filetype = 'zip','rar' && filetype != 'office 2007 document'",
// !!! need to add !Office and confirm RAR
    saquery: "file_type=ZIP file_type=RAR",
    contentTypes: [ 'images', 'pdfs', 'officedocs', 'dodgyarchives' ],
    description: 'Displays any content type contained within a ZIP or RAR archive.  It also displays dodgy archives'
  },

  {
    name: 'suspiciousdestcountries',
    friendlyName: 'Documents to Suspicious Destination Countries',
    nwquery: `country.dst = 'russian federation','china','romania','belarus','iran, islamic republic of',"korea, democratic people's republic of",'ukraine','syrian arab republic','yemen' && filetype = 'zip','rar','pdf','office 2007 document'`,
// !!! need to add filetypes
    saquery: `responder_country="russian federation" responder_country="china" responder_country="romania" responder_country="belarus" responder_country="iran, islamic republic of" responder_country="korea, democratic people's republic of" responder_country="ukraine" responder_country="syrian arab republic" responder_country="yemen"`,
    contentTypes: [ 'pdfs', 'officedocs', 'dodgyarchives' ],
    description: 'Displays documents and dodgy archives transferred to suspicious destination countries: Russia, China, Romania, Belarus, Iran, North Korea, Ukraine, Syra, or Yemen'
  },

  {
    name: 'dodgyarchives',
    friendlyName: 'Dodgy Archives',
    nwquery: "filetype = 'zip','rar'",
//!!! Need to confirm RAR
    saquery: "file_type=ZIP file_type=RAR",
    contentTypes: [ 'dodgyarchives' ],
    description: 'Displays ZIP and RAR Archives which are encrypted or which contain some encrypted files'
  },

  {
    name: 'outboundwebmonitoring',
    friendlyName: 'Outbound Web Usage Monitoring',
//!!! Need outbound and combine with web! application_group=Web
    nwquery: "direction = 'outbound' && service = 80 && filetype = 'jpg','gif','png'",
    saquery: "file_type~GIF file_type=PNG file_type=JPEG",
    contentTypes: [ 'images' ],
    description: 'Displays images from outbound web usage.  Recommended for use in a Monitoring Collection'
  }

];
var useCasesObj = {};
// Populate an object with our use cases so we can later reference them by use case name
for (let i = 0; i < useCases.length; i++) {
  let thisUseCase = useCases[i];
  useCasesObj[thisUseCase.name] = thisUseCase;
}
// winston.debug('useCasesObj:', useCasesObj);


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////PASSPORT AND MONGOOSE//////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var cookieExtractor = function(req) {
  // Extract JWT from cookie 'access_token' and return to JwtStrategy
  // winston.debug("cookieExtractor()", req.cookies);
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
  var jwtPublicKey = fs.readFileSync(jwtPublicCertFile, 'utf8');
}
catch(e) {
  winston.error("Cannot read public key file", jwtPublicCertFile);
  process.exit(1);
}

var jwtOpts = {
  jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]),
  secretOrKey: jwtPublicKey,
  algorithms: ['RS256']
};


// We use mongoose for auth, and MongoClient for everything else.  This is because Passport-Local Mongoose required it, and it is ill-suited to the free-formish objects which we want to use.
var tokenBlacklist = {};

var mongoUrl = `mongodb://${config['dbConfig']['host']}:${config['dbConfig']['port']}/afb`;
if (config.dbConfig.authentication.enabled) {
  mongoUrl = `mongodb://${config.dbConfig.authentication.user}:${config.dbConfig.authentication.password}@${config['dbConfig']['host']}:${config['dbConfig']['port']}/afb?authSource=admin`;
}
connectToDB(); // this must come before mongoose user connection so that we know whether to create the default admin account


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////API CALLS/////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////LOGIN & LOGOUT//////////////////////

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
      let token = jwt.sign(user.toObject({versionKey: false, transform: transformUser}), jwtPrivateKey, { subject: user.id, algorithm: 'RS256', expiresIn: tokenExpirationSeconds, jwtid: uuidV4() }); // expires in 24 hours
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
  // tokenBlacklist[tokenId] = tokenId;
  blacklistToken(tokenId);
  res.clearCookie('access_token');
  res.status(200).send(JSON.stringify( { success: true } ));
});

app.get('/api/isloggedin', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.debug("GET /api/isloggedin");
  // winston.debug('sessionID:', req.session.id);
  // winston.debug('Session object:', req.session);
  // res.cookie('access_token', token, { httpOnly: true, secure: true })
  // res.cookie( req.session.cookie );
  // req.session.save();
  res.json( { user: req.user.toObject(), sessionId: uuidV4() }); // { versionKey: false, transform: transformUserIsLoggedIn }
});















//////////////////////SERVER PUBLIC KEY//////////////////////

app.get('/api/publickey', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  winston.debug("GET /api/publickey");
  res.json( { pubKey: internalPublicKey });
});











//////////////////////USE CASES//////////////////////

app.get('/api/usecases', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.debug("GET /api/usecases");
  res.json( { useCases: useCases } );
});








//////////////////////USERS//////////////////////

app.get('/api/user', passport.authenticate('jwt', { session: false } ), (req,res) => {
  winston.info('GET /api/user');
  try {
    User.find( (err, users) => {
      if (err) {
        winston.error("obtaining users:", err);
        res.status(500).send( JSON.stringify( { success: false, error: err } ) );
      }
      else {
        res.json(users);
      }
    
    } );
  }
  catch(e) {
    winston.error('ERROR GET /api/user:',e);
  }
});

app.get('/api/user/:uname', passport.authenticate('jwt', { session: false } ), (req,res) => {
  let uname = req.params.uname;
  winston.info('GET /api/user/' + uname);
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
  winston.info("POST /api/user for user " + req.body.username);
  let u = req.body;
  let uPassword = decryptor.decrypt(u.password, 'utf8');
  u.password = uPassword;
  User.register(new User({ id: uuidV4(), username : u.username, fullname: u.fullname, email: u.email, enabled: u.enabled }), u.password, (err, user) => {
    if (err) {
      winston.error("Error adding user " + u.username  + " by user " + req.body.username + ' : ' + err);
      res.status(500).send( JSON.stringify( { success: false, error: err } ) );
    }
    else {
      winston.info("User " + req.body.username + " added user " + u.username);
      res.status(201).send( JSON.stringify( { success: true } ) );
    }
  });
});


function updateUser(req, res) {
  let u = req.body;
  User.findOneAndUpdate( { id: u.id }, u, (err, doc) => {
    winston.info("Updating user object with id", u.id);
    //now update user object
    if (err) {
      winston.error("modifying user with id" + u.id + ':', err);
      res.status(500).send( JSON.stringify( { success: false, error: err } ) );
    }
    else {
      winston.info("Updated user with id:", u.id);
      res.status(201).send( JSON.stringify( { success: true } ) );
    }
  });

}

app.post('/api/user/edit', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // edit an existing user
  winston.info("POST /api/user/edit");

  let u = req.body;
  //winston.debug('user:', u);
  
  if (!('password' in req.body)) {
    updateUser(req, res);
  }
  else {
    winston.info("Updating password for user with id", u.id);

    let uPassword = decryptor.decrypt(u.password, 'utf8');
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
              updateUser(req, res);
            });
          });
        });
      });
    }
    catch(e) {
      winston.error("Error changing changing password:", e);
      res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
      return;
    }
  }
});

app.delete('/api/user/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let id = req.params.id;
  winston.info(`DELETE /api/user/${id}`);
  try {
    User.find( {id: id} ).remove( (err) => {
      if (err) {
        throw err;
      }
      else {
        res.status(204).send( JSON.stringify( { success: true } ) );
      }
    } );
  }
  catch(e) {
    winston.error("Error removing user:", e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

//login and return JWT







//////////////////////SERVER VERSION//////////////////////

app.get('/api/version', passport.authenticate('jwt', { session: false } ), (req,res) => {
  // Gets the server version
  winston.info('GET /api/version');
  try {
    res.json({version: version});
  }
  catch(e) {
    winston.error('ERROR GET /api/version:', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});






//////////////////////COLLECTIONS//////////////////////
  

app.get('/api/collection', passport.authenticate('jwt', { session: false } ), (req,res) => {
  winston.info('GET /api/collections');
  try {
    res.json(collections);
  }
  catch(e) {
    winston.error('ERROR GET /api/collection:', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
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

app.delete('/api/collection/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let id = req.params.id;
  winston.info(`DELETE /api/collection/${id}`);
  try {
    if (collectionsData[id]) {
      delete collectionsData[id];
      delete collections[id];
      res.status(200).send( JSON.stringify( { success: true } ) );
    }
    else {
      res.body="Collection not found";
      res.status(400).send( JSON.stringify( { success: false, error: 'collection ' + id + ' not found'} ) );
    }
  }
  catch(e) {
    winston.error(`ERROR DELETE /api/collection/${id} :`, e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
  db.collection('collections').remove( { id: id }, (err, res) => {
    if (err) throw err;
  });
  db.collection('collectionsData').remove( { id: id }, (err, res) => {
    if (err) throw err;
  });
  
  try { 
    rimraf( collectionsDir + '/' + id, () => {} );
  } 
  catch(e) {
    winston.error('ERROR removing directory' + collectionsDir + '/' + id + ':', e);
  }
});

app.get('/api/collection/data/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let id = req.params.id;
  winston.info(`GET /api/collection/data/${id}`);
  try {
    res.json(collectionsData[id]);
  }
  catch(e) {
    winston.error('ERROR GET /api/collection/data/:id:', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

app.post('/api/collection', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // add a new collection

  winston.info("POST /api/collection");
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
    else if (collection.bound && collection.usecase != 'custom' && !(collection.usecase in useCasesObj) ) {
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
    
    // collection['state'] = 'initial';

    let creator = {
      username: req.user.username,
      id: req.user.id,
      fullname: req.user.fullname,
      timestamp: timestamp
    };
    collection['creator'] = creator;

    collections[collection.id] = collection;
    let cDef = {
      images: [],
      sessions: {},
      id: collection.id
    };
    collectionsData[collection.id] = cDef;
    
   
    db.collection('collections').insertOne( collection, (err) => {
      if (err) throw err;

      db.collection('collectionsData').insertOne( { id: collection.id, data: JSON.stringify(cDef)}, (err) => {
        if (err) throw err;
        res.status(201).send( JSON.stringify( { success: true } ) );
      });
    });
    
  }
  catch(e) {
    winston.error("POST /api/collection:", e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});


app.post('/api/collection/edit', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("POST /api/collection/edit");
  try {
    let timestamp = new Date().getTime();
    let collection = req.body;
    winston.debug('collection:', collection);
    let id = collection.id;
    collection['state'] = 'initial';
    if (!(id) in collections) {
      throw(`Cannot update collection ${collection.name}.  Collection ${id} does not exist`);
    }

    // do something here to stop / reload an existing rolling collection

    let modifier = {
      username: req.user.username,
      id: req.user.id,
      fullname: req.user.fullname,
      timestamp: timestamp
    };
    collection['modifier'] = modifier;

    collections[id] = collection;
    let cDef = {
      images: [],
      sessions: {},
      id: collection.id
    };
    collectionsData[id] = cDef;
    
    // Update collection in mongo
    db.collection('collections').updateOne( { id: id }, { $set: collection}, (err, result) => {
      if (err) throw err;

      db.collection('collectionsData').updateOne( { id: collection.id }, { $set: { data: JSON.stringify(cDef) } }, (err, result) => {
        // Update collection data in mongo
        if (err) throw err;
        res.status(205).send( JSON.stringify( { success: true } ) );
      });
    });

  }
  catch(e) {
    winston.error("POST /api/collection/edit:", e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});






//////////////////////FEEDS//////////////////////

app.get('/api/feed', passport.authenticate('jwt', { session: false } ), (req,res) => {
  winston.info('GET /api/feeds');
  try {
    res.json(feeds);
  }
  catch(e) {
    winston.error('ERROR GET /api/feeds:', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});



app.post('/api/feed/manual', passport.authenticate('jwt', { session: false } ), upload.single('file'), (req, res) => {
  winston.info("POST /api/feed/manual");
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

    if (id in feeds) {
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

    fs.rename(req.file.path, feedsDir + '/' + id + '.feed', (mverror) => {
      // rename feed callback
      if (mverror) {
        winston.error('error moving file to feedsDir:', err);
        fs.unlinkSync(req.file.path);
        throw(mverror);
      }
      else {
        db.collection('feeds').insertOne( feed, (err, result) => {
          //insert into db callback
          if (err) {
            throw(err);
          }
          else 
          {
            feeds[id] = feed;
            res.status(201).send( JSON.stringify( { success: true } ) );
            // writeToSocket( feederSocket, JSON.stringify( { feeds: feeds } ) );
            writeToSocket( feederSocket, JSON.stringify( { new: true, feed: feed } ) );
          }
        });
      }
    });
  
  }
  catch(e) {
    winston.error("POST /api/feed/manual: " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});


app.post('/api/feed/scheduled', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("POST /api/feed/scheduled");
  // winston.debug('req:', req);
  let timestamp = new Date().getTime();
  try {
    let feed = req.body;
    // winston.debug('feed:', feed);

    if (!('id' in feed)) {
      throw("'id' is not defined");
    }
    let id = feed.id;

    if (id in feeds) {
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
      options['auth'] = { user: feed.username, pass: decryptor.decrypt(feed.password, 'utf8'), sendImmediately: true };
    }
    
    // let tempName = path.basename(temp.path({suffix: '.scheduled'}));

    let myRequest = request(options, (error, result, body) => { // get the feed
      // callback
      winston.debug('/api/feed/scheduled: myRequest callback()');

      db.collection('feeds').insertOne( feed, (err, dbresult) => {
        if (err) {
          winston.error('/api/feed/scheduled: insertOne(): error adding feed to db:', err);
          throw(err);
        }
        else 
        {
          winston.debug('/api/feed/scheduled: insertOne(): feed added to db');
          feeds[id] = feed;
          scheduler.addFeed(feed);
          res.status(201).send( JSON.stringify( { success: true } ) );
          // writeToSocket(feederSocket, JSON.stringify( { feeds: feeds } ) ); // let feeder server know of our update
          writeToSocket( feederSocket, JSON.stringify( { new: true, feed: feed } ) ); // let feeder server know of our update
        }
      });
    })
    .on('end', () => {
      winston.debug('/api/feed/scheduled: myRequest end()');
      // res.status(201).send( JSON.stringify( { success: true } ) )
    })
    .on('error', (err) => {
      winston.debug('/api/feed/scheduled: myRequest error()');
      res.status(500).send( JSON.stringify( { success: false, error: err } ) )
    })
    .pipe(fs.createWriteStream(feedsDir + '/' + id + '.feed'));
  }
  catch(e) {
    winston.error("POST /api/feed/scheduled: " + e );
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});



app.post('/api/feed/edit/withfile', passport.authenticate('jwt', { session: false } ), upload.single('file'), (req, res) => {
  // this is for editing of manual feeds which contain a new file
  winston.info("POST /api/feed/edit/withfile");
  // winston.debug('req:', req);
  
  try {
    let timestamp = new Date().getTime();
    let feed = JSON.parse(req.body.model);
    
    if (!('id' in feed)) {
      throw("'id' parameter not found in feed");
    }

    let id = feed.id;
    if (!(id in feeds)) {
      throw('Feed not found');
    }

    // get creator from old feed
    let oldFeed = feeds[id];
    let creator = oldFeed.creator
    feed['creator'] = creator;
    feed['version'] = oldFeed.version + 1;

    let modifier = {
      username: req.user.username,
      id: req.user.id,
      fullname: req.user.fullname,
      timestamp: timestamp
    };
    feed['modifier'] = modifier;



    fs.rename(req.file.path, feedsDir + '/' + id + '.feed', (mverror) => {
      // rename feed callback
      if (mverror) {
        winston.error('error moving file to feedsDir:', err);
        fs.unlinkSync(req.file.path);
        throw(mverror);
      }
      else {
        db.collection('feeds').updateOne( { id: id }, { $set: feed}, (err, result) => {
          //insert into db callback
          if (err) {
            throw(err);
          }
          else {
            feeds[id] = feed;
            res.status(201).send( JSON.stringify( { success: true } ) );
            // writeToSocket( feederSocket, JSON.stringify( { feeds: feeds } ) );
            writeToSocket( feederSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
          }
        });
      }
    });

  }
  catch(e) {
    winston.error("POST /api/feed/edit/withfile: " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }

});




app.post('/api/feed/edit/withoutfile', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // this is for editing of any feed which does not include a new file, both manual or scheduled
  winston.info("POST /api/feed/edit/withoutfile");
  // winston.debug('req:', req);
  
  try {
    let timestamp = new Date().getTime();
    let feed = req.body;
    
    if (!('id' in feed)) {
      throw("'id' parameter not found in feed");
    }

    let id = feed.id;
    if (!(id in feeds)) {
      throw('Feed not found');
    }

    // get creator from old feed
    let oldFeed = feeds[id];
    let creator = oldFeed.creator
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

      db.collection('feeds').updateOne( { id: id }, { $set: feed}, (err, result) => {
        //insert into db callback
        if (err) {
          throw(err);
        }
        else {
          feeds[id] = feed;
          res.status(201).send( JSON.stringify( { success: true } ) );
          if (oldFeed.type == 'scheduled') {
            // tell scheduler to remove old feed
            scheduler.delFeed(feed.id);
          }
          // writeToSocket( feederSocket, JSON.stringify( { feeds: feeds } ) );
          writeToSocket( feederSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
        }
      });
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
        options['auth'] = { user: feed.username, pass: decryptor.decrypt(feed.password, 'utf8'), sendImmediately: true };
      }

      let myRequest = request(options, (error, result, body) => { // get the feed
        // callback
        winston.debug('/api/feed/edit/withoutfile: myRequest callback()');
  
        // db.collection('feeds').updateOne( feed, (err, dbresult) => {
        db.collection('feeds').updateOne( { id: id }, { $set: feed}, (err, dbresult) => {
          if (err) {
            winston.error('/api/feed/edit/withoutfile updateOne(): error updating feed in db:', err);
            throw(err);
          }
          else 
          {
            winston.debug('/api/feed/edit/withoutfile: updateOne(): feed modified in db');
            // calculate file hash for feed file
            feeds[id] = feed;
            
            scheduler.updateFeed(feed);
            
            res.status(201).send( JSON.stringify( { success: true } ) );
            //notify scheduler of update here
            // writeToSocket(feederSocket, JSON.stringify( { feeds: feeds } ) ); // let feeder server know of our update
            writeToSocket( feederSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
          }
        });
      })
      .on('end', () => {
        winston.debug('/api/feed/edit/withoutfile: myRequest end()');
      })
      .on('error', (err) => {
        winston.debug('/api/feed/edit/withoutfile: myRequest error()');
        res.status(500).send( JSON.stringify( { success: false, error: err } ) )
      })
      .pipe(fs.createWriteStream(feedsDir + '/' + id + '.feed'));

    }

  }
  catch(e) {
    winston.error("POST /api/feed/edit/withoutfile: " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});




app.post('/api/feed/testurl', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.debug('/api/feed/testurl');

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
      options['auth'] = { user: feeds[id].username, pass: decryptor.decrypt(feeds[id].password, 'utf8'), sendImmediately: true };
    }
    else if (host.authentication && !('username' in host && 'password' in host)) {
      throw("Credentials not found in host definition");
    }
    else if (host.authentication) {
      options['auth'] = { user: host.username, pass: decryptor.decrypt(host.password, 'utf8'), sendImmediately: true };
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
      winston.debug('/api/feed/testurl: caught error:', error);
      let body = { success: false, error: error };
      if (result.statusCode) {
        body['statusCode'] = result.statusCode;
      }
      res.status(200).send( JSON.stringify( body ) );
      return;
    }
    
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
    winston.info("GET /api/feed/filehead/" + id);

    if ( !(id in feeds) ) {
      throw('Feed not found');
    }
    
    let feed = feeds[id];
    let chunkSize = 1024;
    let maxBufSize = 262144;
    let buffer = new Buffer(maxBufSize);
    let bytesRead = 0;
    let fileSize = fs.statSync(feedsDir + '/' + id + '.feed').size;
    if (chunkSize > fileSize) {
      chunkSize = fileSize;
    }

    fs.open(feedsDir + '/' + id + '.feed', 'r', (err, fd) => {
      
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




app.delete('/api/feed/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // delete a feed
  let id = req.params.id;
  winston.info(`DELETE /api/feed/${id}`);
  try {
    if (id in feeds) {
      fs.unlink(feedsDir + '/' + id + '.feed', (err) => {

        if (err) throw(err);

        db.collection('feeds').remove( { 'id': id }, (err, result) => {
          
          if (err) throw err;
          
          delete feeds[id];
          res.status(200).send( JSON.stringify( { success: true } ) );
          // console.log(feederSocket);
          // writeToSocket(feederSocket, JSON.stringify( { feeds: feeds } ) ); // let feeder server know of our update
          scheduler.delFeed(id);
          writeToSocket( feederSocket, JSON.stringify( { delete: true, id: id } ) ); // let feeder server know of our update
        });
      });
    }
    else {
      res.status(400).send( JSON.stringify( { success: false, error: 'Feed not found' } ) );
    }
  }
  catch(e) {
    winston.error(`ERROR DELETE /api/feed/${id} :`, e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
  
  /*
  try { 
    rimraf( collectionsDir + '/' + id, () => {} );
  } 
  catch(e) {
    winston.error('ERROR removing directory' + collectionsDir + '/' + id + ':', e);
  }*/
});


app.get('/api/feed/status', passport.authenticate('jwt', { session: false } ), (req, res) => {
  try {
    res.status(200).send( JSON.stringify( scheduler.status() ) );
  }
  catch(e) {
    winston.error(`ERROR GET /api/feed/status :`, e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});








//////////////////////NWSERVERS//////////////////////

app.get('/api/nwserver', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info('GET /api/nwserver');
  try {
    let servers = JSON.parse(JSON.stringify(nwservers));  // make deep copy of nwservers
    for (let server in servers) {
      // delete passwords - they don't need to be transferred back to the client
      if (servers.hasOwnProperty(server)) {
        servers[server].password = undefined;
      }
    }
    res.json(servers);
  }
  catch(e) {
    winston.error('ERROR GET /api/nwserver', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

app.delete('/api/nwserver/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let servId = req.params.id;
  winston.info(`DELETE /api/nwserver/${servId}`);
  try {
    delete nwservers[servId];
    res.status(200).send( JSON.stringify( { success: true } ) );
    db.collection('nwservers').remove( { 'id': servId }, (err, res) => {
      if (err) throw err;
    });
  }
  catch(e) {
    winston.error(`ERROR DELETE /api/nwserver/${servId} :`, e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

app.post('/api/nwserver', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // for adding a netwitness server
  winston.info("POST /api/nwserver");
  try {
    //winston.debug(req.body);
    let nwserver = req.body;
    if (!nwserver.id) {
      throw("'id' is not defined");
    }
    let id = nwserver.id;
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
      throw("'password' is not defined"); // we don't decrypt here.  We only decrypt when we build a worker config
    }
    if (typeof nwserver.ssl === 'undefined') {
      throw("'ssl' is not defined");
    }
    nwservers[id] = nwserver;
    db.collection('nwservers').insertOne( nwserver, (err, res) => {
      if (err) throw err;
    });
    
    res.status(201).send( JSON.stringify( { success: true } ) );
  }
  catch(e) {
    winston.error("POST /api/nwserver: " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});


app.post('/api/nwserver/edit', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("POST /api/nwserver/edit");
  try {
    //winston.debug(req.body);
    let nwserver = req.body;
    if (!nwserver.id) {
      throw("'id' is not defined");
    }
    let id = nwserver.id;
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
      // use existing password
      nwserver['password'] = nwservers[id].password;
    }
    if (typeof nwserver.ssl === 'undefined') {
      throw("'ssl' is not defined");
    }
    nwservers[id] = nwserver;
    db.collection('nwservers').updateOne( { id: id }, { $set: nwserver }, (err, res) => {
      if (err) throw err;
    });
    
    res.status(200).send( JSON.stringify( { success: true } ) );
  }
  catch(e) {
    winston.error("POST /api/nwserver/edit: " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

app.post('/api/nwserver/test', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("POST /api/nwserver/test");
  try {
    let nwserver = req.body;
    var uPassword = '';
    // console.log(nwserver);
    if (nwserver.hasOwnProperty('id') && !(nwserver.hasOwnProperty('password'))) {
      let id = nwserver.id;
      uPassword = decryptor.decrypt(nwservers[id].password, 'utf8');
    }
    else if (nwserver.hasOwnProperty('id') && nwserver.hasOwnProperty('password')) {
      let id = nwserver.id;
      uPassword = decryptor.decrypt(nwserver.password, 'utf8');
    }
    else {
      uPassword = decryptor.decrypt(nwserver.password, 'utf8');
    }
    // console.log(nwserver);
    var host = nwserver.host;
    var ssl = nwserver.ssl;
    var port = nwserver.port;
    var user = nwserver.user;
    
    //var uPassword = decryptor.decrypt(nwservers[id].password, 'utf8');
    
    var proto = 'http://'
    if (ssl) {
      proto = 'https://';
    }
    var url = `${proto}${host}:${port}`;

  }
  catch(e) {
    winston.error("POST /api/nwserver/test: " + e);
    // res.status(500).send(JSON.stringify({error: e.message}) );
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }

  // Now perform test
  let options = { user: user, password: uPassword, connection: { rejectUnauthorized: false }}; // {requestConfig: {timeout: 5000}, responseConfig: {timeout: 5000}},
  let client = new restClient(options);

  let request = client.get(url, (data, response) => {
    // console.log(response);
    if (response.statusCode == 200) {
      winston.debug(`REST connection test to url ${url} was successful`);
    }
    else {
      winston.debug(`REST connection test to url ${url} failed.`);  
    }
    res.status(response.statusCode).send( JSON.stringify( { error: response.statusMessage } ) );
  }).on('error', err => {
    winston.debug(`REST connection test to url ${url} failed with error: ${err.message}`);
    res.status(403).send( JSON.stringify({ error: err.message }) );
  });

});









//////////////////////SASERVERS//////////////////////

app.get('/api/saserver', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info('GET /api/saserver');
  try {
    let servers = JSON.parse(JSON.stringify(saservers));  // make deep copy of saservers
    for (let server in servers) {
      // delete passwords - they don't need to be transferred back to the client
      if (servers.hasOwnProperty(server)) {
        servers[server].password = undefined;
      }
    }
    res.json(servers);
  }
  catch(e) {
    winston.error('ERROR GET /api/saserver', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

app.delete('/api/saserver/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let servId = req.params.id;
  winston.info(`DELETE /api/saserver/${servId}`);
  try {
    delete saservers[servId];
    res.status(200).send( JSON.stringify( { success: true } ) );
    db.collection('saservers').remove( { 'id': servId }, (err, res) => {
      if (err) throw err;
    });
  }
  catch(e) {
    winston.error(`ERROR DELETE /api/saserver/${servId} :`, e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

app.post('/api/saserver', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // for adding a netwitness server
  winston.info("POST /api/saserver");
  try {
    //winston.debug(req.body);
    let saserver = req.body;
    if (!saserver.id) {
      throw("'id' is not defined");
    }
    let id = saserver.id;
    if (!saserver.friendlyName) {
      throw("'friendlyName' is not defined");
    }
    if (!saserver.host) {
      throw("'host' is not defined");
    }
    if (!saserver.port) {
      throw("'port' is not defined");
    }
    if (!saserver.user) {
      throw("'user' is not defined");
    }
    if (!saserver.password) {
      throw("'password' is not defined"); // we don't decrypt here.  We only decrypt when we build a worker config
    }
    if (typeof saserver.ssl === 'undefined') {
      throw("'ssl' is not defined");
    }
    saservers[id] = saserver;
    db.collection('saservers').insertOne( saserver, (err, res) => {
      if (err) throw err;
    });
    
    res.status(201).send( JSON.stringify( { success: true } ) );
  }
  catch(e) {
    winston.error("POST /api/saserver: " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});


app.post('/api/saserver/edit', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("POST /api/saserver/edit");
  try {
    //winston.debug(req.body);
    let saserver = req.body;
    if (!saserver.id) {
      throw("'id' is not defined");
    }
    let id = saserver.id;
    if (!saserver.friendlyName) {
      throw("'friendlyName' is not defined");
    }
    if (!saserver.host) {
      throw("'host' is not defined");
    }
    if (!saserver.port) {
      throw("'port' is not defined");
    }
    if (!saserver.user) {
      throw("'user' is not defined");
    }
    if (!saserver.password) {
      // use existing password
      saserver['password'] = saservers[id].password;
    }
    if (typeof saserver.ssl === 'undefined') {
      throw("'ssl' is not defined");
    }
    saservers[id] = saserver;
    db.collection('saservers').updateOne( { id: id }, { $set: saserver }, (err, res) => {
      if (err) throw err;
    });
    
    res.status(200).send( JSON.stringify( { success: true } ) );
  }
  catch(e) {
    winston.error("POST /api/saserver/edit: " + e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

app.post('/api/saserver/test', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("POST /api/saserver/test");
  try {
    let saserver = req.body;
    var uPassword = '';
    // console.log(saserver);
    if (saserver.hasOwnProperty('id') && !(saserver.hasOwnProperty('password'))) {
      let id = saserver.id;
      uPassword = decryptor.decrypt(saservers[id].password, 'utf8');
    }
    else if (saserver.hasOwnProperty('id') && saserver.hasOwnProperty('password')) {
      let id = saserver.id;
      uPassword = decryptor.decrypt(saserver.password, 'utf8');
    }
    else {
      uPassword = decryptor.decrypt(saserver.password, 'utf8');
    }
    // console.log(saserver);
    var host = saserver.host;
    var ssl = saserver.ssl;
    var port = saserver.port;
    var user = saserver.user;
    
    //var uPassword = decryptor.decrypt(saservers[id].password, 'utf8');
    
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
               data: { '_method': 'GET' } };
  let client = new restClient(options);

    let request = client.post(url, args, (data, response) => {
      // console.log(response);
      if (response.statusCode == 200) {
        // winston.debug(`REST connection test to url ${url} was successful`);
        // winston.debug(data.resultCode);
        if (!('resultCode' in data) || data.resultCode != 'API_SUCCESS_CODE') {
          winston.debug(`REST connection test to url ${url} failed with error:`, data);
          res.status(403).send( JSON.stringify( { success: false, error: data.resultCode } ) );
          return;
        }
        res.status(200).send( JSON.stringify( { success: true } ) );
        return;
      }
      else {
        winston.debug(`REST connection test to url ${url} failed.`);
        // throw(response.statusCode);
        res.status(403).send( JSON.stringify( { success: false, error: data.resultCode } ) );
        return;
        // winston.debug('res:', res);
        // winston.debug('body:', res.body);
      }
    })
    .on('error', err => {
      throw(err);
    });

});










//////////////////////PING//////////////////////

app.get('/api/ping', (req, res)=>{
  //winston.debug("GET /api/ping");
  res.status(200).send( JSON.stringify( { success: true } ) );
});






//////////////////////PREFERENCES//////////////////////

app.get('/api/preferences', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("GET /api/preferences");
  try {
    res.json(preferences);
  }
  catch(e) {
    winston.error('ERROR GET /api/preferences:', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

app.post('/api/preferences', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.info("POST /api/preferences");
  try {
    let prefs = req.body;
    // winston.debug(prefs);
    
    // merge in default preferences which we haven't worked into our the UI preferences yet (like summaryTimeout) do we need this?  I think we do
    for (let pref in defaultPreferences) {
      if (defaultPreferences.hasOwnProperty(pref)) {
        if (!prefs.hasOwnProperty(pref)) {
          prefs[pref] = defaultPreferences[pref];
        }
      }
    }
    for (let pref in defaultPreferences.nw) {
      if (defaultPreferences.nw.hasOwnProperty(pref)) {
        if (!prefs.nw.hasOwnProperty(pref)) {
          prefs.nw[pref] = defaultPreferences.nw[pref];
        }
      }
    }
    for (let pref in defaultPreferences.sa) {
      if (defaultPreferences.sa.hasOwnProperty(pref)) {
        if (!prefs.sa.hasOwnProperty(pref)) {
          prefs.sa[pref] = defaultPreferences.sa[pref];
        }
      }
    }
  

    db.collection('preferences').updateOne( {}, prefs, (err, result) => {
      if (err) throw err;
      preferences = prefs;
      res.status(201).send( JSON.stringify( { success: true } ) );
    });


  }
  catch(e) {
    winston.error("POST /api/preferences:", e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});













///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////FIXED COLLECTIONS//////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// Returns a streaming fixed collection which is in the process of building
app.get('/api/collection/fixed/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{ 
  var id = req.params.id;
  winston.info('GET /api/collection/fixed/:id', id);
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
      for (var i=0; i < collectionsData[id].images.length; i++) { //play back the content and session data already in buildingFixedCollections
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
  catch(e) {
    winston.error('ERROR GET /api/collection/fixed/:id', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});

var buildingFixedCollections = {}; // We shall house fixed collections which are under construction here

function fixedSocketConnectionHandler(id, socket, tempName, subject) {
  // For building fixed collections

  winston.info("fixedSocketConnectionHandler(): Connection received from worker to build collection", id);
  let thisCollection = collections[id];
  
  //////////////////////////////////
  //Build the worker configuration//
  //////////////////////////////////

  let cfg = { 
    id: id,
    collectionId: id, // we include this to disambiguate a difference in monitoring collections between id and collectionId
    state: 'building',
    timeBegin: thisCollection.timeBegin,
    timeEnd: thisCollection.timeEnd,
    contentLimit: thisCollection.contentLimit,
    minX: thisCollection.minX,
    minY: thisCollection.minY,
    gsPath: gsPath,
    pdftotextPath: pdftotextPath,
    sofficePath: sofficePath,
    sofficeProfilesDir: sofficeProfilesDir,
    unrarPath: unrarPath,
    collectionsDir: collectionsDir,
    privateKeyFile: internalPrivateKeyFile,
    useHashFeed: thisCollection.useHashFeed,
    serviceType: thisCollection.serviceType
  };

  if (thisCollection.serviceType == 'nw') {
    cfg['summaryTimeout'] = preferences.nw.summaryTimeout;
    cfg['queryTimeout'] = preferences.nw.queryTimeout;
    cfg['contentTimeout'] = preferences.nw.contentTimeout;
    cfg['maxContentErrors'] = preferences.nw.maxContentErrors;
  }

  if (thisCollection.serviceType == 'sa') {
    cfg['queryTimeout'] = preferences.sa.queryTimeout;
    cfg['contentTimeout'] = preferences.sa.contentTimeout;
    cfg['maxContentErrors'] = preferences.sa.maxContentErrors;
  }

  if (thisCollection.bound) {
    // This is an OOTB use case
    let useCaseName = thisCollection.usecase;
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
    // This is custom use case, not an OOTB use case

    cfg['distillationEnabled'] = thisCollection.distillationEnabled;
    cfg['regexDistillationEnabled'] = thisCollection.regexDistillationEnabled;

    if (!thisCollection.useHashFeed) {
      // we're not using a hash feed
      cfg['md5Enabled'] = thisCollection.md5Enabled;
      cfg['sha1Enabled'] = thisCollection.sha1Enabled;
      cfg['sha256Enabled'] = thisCollection.sha256Enabled;
      if ('md5Hashes' in thisCollection) {
        cfg['md5Hashes'] = thisCollection.md5Hashes;
      }
      if ('sha1Hashes' in thisCollection) {
        cfg['sha1Hashes'] = thisCollection.sha1Hashes;
      }
      if ('sha256Hashes' in thisCollection) {
        cfg['sha256Hashes'] = thisCollection.sha256Hashes;
      }
    }
    else {
      // we're using a hash feed
      cfg['hashFeed'] = feeds[thisCollection.hashFeed] // pass the hash feed definition
      cfg['hashFeederSocket'] = feederSocketFile
    }

    cfg['query'] = thisCollection.query;
    cfg['contentTypes'] = thisCollection.contentTypes;
  
    if ('distillationTerms' in thisCollection) {
      cfg['distillationTerms'] = thisCollection.distillationTerms;
    }
    if ('regexDistillationTerms' in thisCollection) {
      cfg['regexDistillationTerms'] = thisCollection.regexDistillationTerms;
    }
  }

  if (thisCollection.serviceType == 'nw') {
    let nwserver = nwservers[thisCollection.nwserver];
    for (var k in nwserver) {

      if (nwserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
        cfg[k] = nwserver[k];  // assign properties of nwserver to the collection cfg
      }
    }
  }
  if (thisCollection.serviceType == 'sa') {
    let saserver = saservers[thisCollection.saserver];
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
    if (id in collectionsData) { // needed in case the collection has been deleted whilst still building
      collectionsData[id].images = buildingFixedCollections[id].images;
      collectionsData[id].search = buildingFixedCollections[id].search;
      for (var e in buildingFixedCollections[id].sessions) {
        let s = buildingFixedCollections[id].sessions[e];
        let sid = s.id;
        collectionsData[id].sessions[sid] = s;
      }
    }
    //moved into process exit
    winston.debug('Temporary collection merged into main branch.  Deleting temporary collection.');
    delete buildingFixedCollections[id];
    fs.unlink(tempName, () => {});
  });
                          
  // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
  // socket.write(JSON.stringify(outerCfg) + '\n');
  writeToSocket(socket, JSON.stringify(outerCfg));
  
}


function buildFixedCollection(id) {
  // Builds fixed collections

  winston.debug('buildFixedCollection(): Building collection', id);
  
  try {
    let thisCollection = collections[id];
    thisCollection['state'] = 'building';
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
      var worker = spawn('./worker_stub.py ',[tempName], {shell:true, stdio: 'inherit'});
      worker.on('exit', (code) => {
        if (typeof code === 'undefined') {
          winston.debug('Worker process exited abnormally without an exit code');
          thisCollection['state'] = 'error';
          subject.next({collection: { id: id, state: 'error'}});
        }
        else if (code != 0) {
          winston.debug('Worker process exited abnormally with exit code',code.toString());
          thisCollection['state'] = 'error';
          subject.next({collection: { id: id, state: 'error'}});
        }
        else {
          winston.debug('Worker process exited normally with exit code', code.toString());
          thisCollection['state'] = 'complete';
          subject.next({collection: { id: id, state: 'complete'}});
          db.collection('collections').update( {'id': id }, thisCollection, (err, res) => {
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

app.get('/api/collection/fixed/build/:id', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  // builds a fixed collection
  let id = req.params.id;
  winston.info('GET /api/collection/fixed/build/' + id);
  let thisCollection = collections[id];
  try {
    if (thisCollection.bound && !('usecase' in thisCollection )) {
      throw(`Bound collection ${id} does not have a use case defined`);
    }
    if (thisCollection.bound && !(thisCollection.usecase in useCasesObj) ) {
      throw(`Use case ${thisCollection.usecase} in bound collection ${id} is not a valid use case`);
    }
    if (thisCollection.state === 'initial') {
      res.status(202).send( JSON.stringify( { success: true } ) );
    }
    else {
      throw(`Collection ${id} is not in its initial state`);
    }
  }
  catch (e) {
    winston.error(`GET /api/collection/fixed/build/${id}:`, e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
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
    paused: boolean (paused state of a monitoring collection),
    runs: 'number of times rollingCollectionSocketConnectionHandler() has run',
    socket: the unix socket
  },
  'collectionId2': ...
}
*/


var rollingCollections = {}; // This houses collection data for rolling and monitoring collections.  It is never committed to the DB as these collections are intended to be temporary only


function rollingCollectionSocketConnectionHandler(id, socket, tempName, subject, clientSessionId) {
  // For rolling and monitoring collections
  // Handles all dealings with the worker process after it has been spawned, including sending it its configuration, and sending data received from it to the chunkHandler() function
  // It also purges old data from the collection as defined by the type of collection and number of hours back to retain

  let rollingId = id;
  if (clientSessionId != '') {
    rollingId = clientSessionId;
  }

  let thisRollingCollection =  rollingCollections[rollingId];
  let thisRollingCollectionSubject = rollingCollectionSubjects[rollingId];
  let thisCollection = collections[id];

  thisRollingCollectionSubject.runs++;
  
  winston.debug("rollingCollectionSocketConnectionHandler(): Connection received from worker to build rolling or monitoring collection", rollingId);
  
  let ourState = '';
  // Tell our subscribed clients that we're rolling, so they can start their spinny icon and whatnot
  if (thisCollection.type === 'monitoring') {
    ourState = 'monitoring';
  }
  else if (thisCollection.type === 'rolling') {
    ourState = 'rolling';
  }
  subject.next({collection: { id: id, state: ourState}});


  ///////////////////////////
  //PURGE AGED-OUT SESSIONS//
  ///////////////////////////

  if (thisCollection.type === 'monitoring') {
    thisRollingCollection.sessions = [];
    thisRollingCollection.images = [];
    thisRollingCollection.search = [];
  }
  else if (thisRollingCollectionSubject.runs > 1 && thisCollection.type === 'rolling') {
    // Purge events older than thisCollection.lastHours

    winston.debug('Running purge routine');
    let sessionsToPurge = [];

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
        sessionsToPurge.push(sid);
      }
    }

    purgeSessions(thisRollingCollection, sessionsToPurge.slice());
   
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
    collectionId: id, // original collection ID
    state: ourState,
    contentLimit: thisCollection.contentLimit,
    minX: thisCollection.minX,
    minY: thisCollection.minY,
    gsPath: gsPath,
    pdftotextPath: pdftotextPath,
    sofficePath: sofficePath,
    sofficeProfilesDir: sofficeProfilesDir,
    unrarPath: unrarPath,
    collectionsDir: collectionsDir,
    privateKeyFile: internalPrivateKeyFile,
    useHashFeed: thisCollection.useHashFeed,
    serviceType: thisCollection.serviceType

    // query: thisCollection.query,
    // regexDistillationEnabled: thisCollection.regexDistillationEnabled,
    // md5Enabled: thisCollection.md5Enabled,
    // sha1Enabled: thisCollection.sha1Enabled,
    // sha256Enabled: thisCollection.sha256Enabled,
    // contentTypes: collections[id].contentTypes,
    // distillationEnabled: thisCollection.distillationEnabled
  };

  if (thisCollection.serviceType == 'nw') {
    cfg['summaryTimeout'] = preferences.nw.summaryTimeout;
    cfg['queryTimeout'] = preferences.nw.queryTimeout;
    cfg['contentTimeout'] = preferences.nw.contentTimeout;
    cfg['maxContentErrors'] = preferences.nw.maxContentErrors;
  }

  if (thisCollection.serviceType == 'sa') {
    cfg['queryTimeout'] = preferences.sa.queryTimeout;
    cfg['contentTimeout'] = preferences.sa.contentTimeout;
    cfg['maxContentErrors'] = preferences.sa.maxContentErrors;
  }

  if (thisCollection.bound) {
    // This is an OOTB use case
    let useCaseName = thisCollection.usecase;
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
    // This is not an OOTB use case
    cfg['distillationEnabled'] = thisCollection.distillationEnabled;
    cfg['regexDistillationEnabled'] = thisCollection.regexDistillationEnabled;
    
    if (!thisCollection.useHashFeed) {
      // we're not using a hash feed
      cfg['md5Enabled'] = thisCollection.md5Enabled;
      cfg['sha1Enabled'] = thisCollection.sha1Enabled;
      cfg['sha256Enabled'] = thisCollection.sha256Enabled;
      if ('md5Hashes' in thisCollection) {
        cfg['md5Hashes'] = thisCollection.md5Hashes;
      }
      if ('sha1Hashes' in thisCollection) {
        cfg['sha1Hashes'] = thisCollection.sha1Hashes;
      }
      if ('sha256Hashes' in thisCollection) {
        cfg['sha256Hashes'] = thisCollection.sha256Hashes;
      }
    }
    else {
      // we're using a hash feed
      cfg['hashFeed'] = feeds[thisCollection.hashFeed] // pass the hash feed definition
      cfg['hashFeederSocket'] = feederSocketFile
    }

    cfg['query'] = thisCollection.query;
    cfg['contentTypes'] = thisCollection.contentTypes;
  
    if ('distillationTerms' in thisCollection) {
      cfg['distillationTerms'] = thisCollection.distillationTerms;
    }
    if ('regexDistillationTerms' in thisCollection) {
      cfg['regexDistillationTerms'] = thisCollection.regexDistillationTerms;
    } 
  }

  let queryDelaySeconds = preferences.nw.queryDelayMinutes * 60;

  if (thisCollection.type === 'monitoring') {
    // If this is a monitoring collection, then set timeEnd and timeBegin to be a one minute window
    cfg['timeEnd'] = moment().startOf('minute').unix() - 61 - queryDelaySeconds;
    cfg['timeBegin'] = ( cfg['timeEnd'] - 60) + 1;
  }
  
  else if (thisRollingCollectionSubject.runs == 1) {
    // This is the first run of a rolling collection
    winston.debug('rollingCollectionSocketConnectionHandler(): Got first run');
    cfg['timeEnd'] = moment().startOf('minute').unix() - 61 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
    cfg['timeBegin'] = ( cfg['timeEnd'] - (thisCollection.lastHours * 60 * 60) ) + 1;
  }
  
  else if (thisRollingCollectionSubject.runs == 2 && (moment().unix() - thisRollingCollectionSubject['lastRun'] >= 61) ) {
    // This is the second run of a rolling collection - this allows the first run to exceed one minute of execution and will take up whatever excess time has elapsed
    // It will only enter this block if more than 61 seconds have elapsed since the last run
    winston.debug('rollingCollectionSocketConnectionHandler(): Got second run');
    cfg['timeBegin'] = thisRollingCollectionSubject['lastRun'] + 1; // one second after the last run
    cfg['timeEnd'] = moment().startOf('minute').unix() - 61 - queryDelaySeconds; // the beginning of the last minute minus one second, to give time for sessions to leave the assembler
  }  

  else {
    // This is the third or greater run of a rolling collection
    winston.debug('rollingCollectionSocketConnectionHandler(): Got subsequent run');
    cfg['timeBegin'] = thisRollingCollectionSubject['lastRun'] + 1; // one second after the last run
    cfg['timeEnd'] = cfg['timeBegin'] + 60; //add one minute to cfg[timeBegin]
  }

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

  if (thisCollection.serviceType == 'nw') {
    let nwserver = nwservers[thisCollection.nwserver];
    for (var k in nwserver) {

      if (nwserver.hasOwnProperty(k) && k != 'id' && k != '_id') {
        cfg[k] = nwserver[k];  // assign properties of nwserver to the collection cfg
      }
    }
  }
  if (thisCollection.serviceType == 'sa') {
    let saserver = saservers[thisCollection.saserver];
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

  // Buffer for worker data
  var data = '';

  //Set socket options
  socket.setEncoding('utf8');
  
  // Handle data received from the worker over the socket (this really builds the collection)
  socket.on('data', chunk => data = chunkHandler(rollingCollections, id, subject, data, chunk, clientSessionId) );
                              
                              
  // Once the worker has exited, delete the socket temporary file
  socket.on('end', () => {
    winston.debug('Worker disconnected.  Rolling collection update cycle complete.');
    fs.unlink(tempName, () => {}); // Delete the temporary UNIX socket file
  });

  // Send configuration to worker.  This officially kicks off the work.  After this, we should start receiving data on the socket
  // socket.write(JSON.stringify(outerCfg) + '\n'); 
  writeToSocket(socket, JSON.stringify(outerCfg));
  socket.end();
  
}





function runRollingCollection(collectionId, res, clientSessionId='') {
  // Executes the building of a rolling or monitoring collection

  winston.debug("runRollingCollection(collectionId)");

  let rollingId = collectionId;
  if (collections[collectionId].type === 'monitoring') {
    rollingId = clientSessionId;
  }

  var subject = rollingCollectionSubjects[rollingId].subject;
  rollingCollections[rollingId] = {
    images: [],
    sessions: [],
    search: []
  };

  let thisRollingCollection =  rollingCollections[rollingId];
  let thisRollingCollectionSubject = rollingCollectionSubjects[rollingId];
  let thisCollection = collections[collectionId];

  var work = ( () => {
    // Main body of worker execution
    // This is wrapped in an arrow function so that it will retain the local scope of 'collectionId'
    // We also want to be able to call this body from a timer, so that's another reason we wrap it

    try {

      winston.debug("runRollingCollection(): work(): Starting run for rollingId", rollingId);

      if ( collections[collectionId].type === 'rolling' && rollingId in rollingCollectionSubjects && 'worker' in thisRollingCollectionSubject && thisRollingCollectionSubject.runs == 1) {
        // If we're a rolling collection still on our first run, let it continue running until it completes
        winston.info('runRollingCollection(): work(): First run of rolling collection is still running.  Delaying next run 60 seconds');
        return;
      }
      
      if ( rollingId in rollingCollectionSubjects && 'worker' in thisRollingCollectionSubject && thisRollingCollectionSubject.runs > 1) {
        // Check if there's already a python worker process already running which has overrun the 60 second mark, and if so, kill it
        winston.info('runRollingCollection(): work(): Timer expired for running worker.  Terminating worker');
        let oldWorker = thisRollingCollectionSubject['worker'];
        oldWorker.kill('SIGINT');
        // delete thisRollingCollectionSubject['worker']; // we don't want to do this here as it will be handled when the worker exits
      }

      if (thisCollection.type === 'monitoring' && thisRollingCollectionSubject.paused === true) {
        winston.debug(`runRollingCollection(): work(): Collection ${rollingId} is puased.  Returning`);
        return;
      }

      // Create temp file to be used as our UNIX domain socket
      let tempName = temp.path({suffix: '.socket'});

      // Now open the UNIX domain socket that will talk to worker script by creating a handler (or server) to handle communications
      let socketServer = net.createServer( (socket) => { 
        // Add our socket to rollingCollectionSubjects[] so we can handle it later
        thisRollingCollectionSubject['socket'] = socket;
        rollingCollectionSocketConnectionHandler(collectionId, socket, tempName, subject, clientSessionId);
        // We won't write any more data to the socket, so we will call close() on socketServer.  This prevents the server from accepting any new connections
        socketServer.close();
      });

      
      socketServer.listen(tempName, () => {
        // Tell the server to listen for communication from the not-yet-started worker

        winston.debug('runRollingCollection(): work(): listen(): Rolling Collection: Listening for worker communication');
        winston.debug("runRollingCollection(): work(): listen(): Rolling Collection: Spawning worker with socket file " + tempName);
        
        // Start the worker process and assign a reference to it to 'worker'
        let worker = spawn('./worker_stub.py ', [tempName, '2>&1'], { shell:true, stdio: 'inherit'});
        // Notice that we don't pass any configuration to the worker on the command line.  It's all done through the UNIX socket for security.
        
        // Add the worker reference to rollingCollectionSubjects so we can work with it later
        thisRollingCollectionSubject['worker'] = worker;

        
        worker.on('exit', (code, signal) => {
          // This is where we handle the exiting of the worker process

          if (typeof code === 'undefined') {
            // Handle really abnormal worker exit with no error code - maybe because we couldn't spawn it at all?  We likely won't ever enter this block
            winston.debug('runRollingCollection(): work(): listen(): onExit(): Worker process exited abnormally without an exit code');
            thisCollection['state'] = 'error';
            subject.next({collection: { id: collectionId, state: 'error'}});
            if (rollingId in rollingCollectionSubjects && 'worker' in thisRollingCollectionSubject) {
              delete thisRollingCollectionSubject.worker;
            }
          }




          else if (code !== null || signal !== null) {
            // Handle normal worker exit code 0
            if (code !== null && code === 0) {
              winston.debug('runRollingCollection(): work(): listen(): onExit(): Worker process exited normally with exit code 0');
              // Tell client that we're resting
              subject.next({collection: { id: collectionId, state: 'resting'}});
            
            }
            else if (code !== null && code !== 0) {
              // Handle worker exit with non-zero (error) exit code
              winston.debug('runRollingCollection(): work(): listen(): onExit(): Worker process exited in bad state with non-zero exit code', code.toString() );
              thisCollection['state'] = 'error';
              subject.next({collection: { id: collectionId, state: 'error'}});
              if (rollingId in rollingCollectionSubjects && 'worker' in thisRollingCollectionSubject) {
                delete thisRollingCollectionSubject.worker;
              }
            }
            else {
              winston.debug('runRollingCollection(): work(): listen(): onExit(): Worker process was terminated by signal', signal);
              // Tell client that we're resting
              subject.next({collection: { id: collectionId, state: 'resting'}});
            }

            // Save the collection to the DB
            db.collection('collections').update( {'id': collectionId }, thisCollection, (err, res) => {
              if (err) throw err;
            });
            
            if (thisCollection.type === 'monitoring' && thisRollingCollectionSubject.paused === true) {
              // Monitoring collection is paused
              // Now we end and delete this monitoring collection, except for its files (which still may be in use on the client)
              winston.debug('runRollingCollection(): work(): listen(): onExit(): Completing work for paused monitoring collection', rollingId);
              clearInterval(thisRollingCollectionSubject.interval); // stop work() from being called again
              thisRollingCollectionSubject.subject.complete(); // end observable
              res.write('{"close":true}]'); // Close the array so that oboe knows we're done
              res.flush();
              res.end();
              delete rollingCollectionSubjects[rollingId];
              delete rollingCollections[rollingId];
              return;
            }
            
            /*// Save the collection data to the DB -- WE SHOULDN'T HAVE TO DO THIS AS THESE DON'T PERSIST!!!!!!!
            db.collection('collectionsData').update( {'id': collectionId }, {'id': collectionId, 'data': JSON.stringify(collectionsData[collectionId])}, (err, res) => {
              if (err) throw err;
            });*/
            
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




app.get('/api/collection/monitoring/pause/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let clientSessionId = req.headers['afbsessionid'];
  winston.info(`GET /api/collection/monitoring/pause/:id: Pausing monitoring collection ${clientSessionId}`);
  // rollingCollectionSubjects[id]['paused'] = true;
  rollingCollectionSubjects[clientSessionId]['paused'] = true;
  res.status(202).send( JSON.stringify( { success: true } ) );
});

app.get('/api/collection/monitoring/unpause/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // This only gets used by the client if a monitoring collection is paused and then resumed within the minute the run is permitted to continue executing
  // Otherwise, the client will simply call /api/collection/rolling/:id again
  let clientSessionId = req.headers['afbsessionid'];
  winston.info(`GET /api/collection/monitoring/unpause/:id: Resuming monitoring collection ${clientSessionId}`);
  // rollingCollectionSubjects[id]['paused'] = false;
  rollingCollectionSubjects[clientSessionId]['paused'] = false;
  res.status(202).send( JSON.stringify( { success: true } ) );
});


app.get('/api/collection/rolling/:collectionId', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // Builds and streams a rolling or monitoring collection back to the client.  Handles the client connection and kicks off the process

  let collectionId = req.params.collectionId;
  let clientSessionId = req.headers['afbsessionid'];


/*
//DEBUG  
  if (! 'clientSessionId' in req.headers ) {
    winston.error('clientSessionId missing from HTTP header!!!');
    process.exit(1);
  }
  winston.debug(`clientSessionID: ${clientSessionId}`);
//////
*/

  winston.info('GET /api/collection/rolling/:id', collectionId);
  // winston.debug('GET /api/collection/rolling/:id clientSessionId:', clientSessionId);

  let rollingId = collectionId;
  if ( collections[collectionId].type === 'monitoring' ) {
    rollingId = clientSessionId;
  }
  let thisCollection = collections[collectionId];
  
  
  ////////////////////////////////////////////////////
  //////////////////RESPONSE HEADERS//////////////////
  ////////////////////////////////////////////////////

  try {
    // Write the response headers
    if (thisCollection.bound && !('usecase' in thisCollection )) {
      throw(`Bound collection ${collectionId} does not have a use case defined`);
    }
    if (thisCollection.bound && !(thisCollection.usecase in useCasesObj) ) {
      throw(`Use case ${thisCollection.usecase} in bound collection ${collectionId} is not a valid use case`);
    }
    if (thisCollection.type === 'rolling' || thisCollection.type === 'monitoring') {
      res.writeHead(200, {'Content-Type': 'application/json','Content-Disposition': 'inline' });
      res.write('['); // Open the array so that oboe can see it
      res.flush();
    }
    else {
      throw("Collection " + collectionId + " is not of type 'rolling' or 'monitoring'");
    }
  }
  catch (e) {
    winston.error('GET /api/collection/rolling/:id', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
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

  if ( thisCollection.type === 'rolling' && !(collectionId in rollingCollectionSubjects) ) {
    // This is a new rolling collection as there are no existing subscribers to it
    // Let's start building it
    let subject = new Subject(); // Create a new observable which will be used to pipe communication between the worker and the client
    

    // Populate rollingCollectionSubjects[collectionId] with some initial values
    rollingCollectionSubjects[collectionId] = {
      subject: subject,
      observers: 1,
      runs: 0
    }

    // We now subscribe to the existing observable for the collection and pipe its output to rollingSubjectWatcher so it can be output to the http response stream
    rollingCollectionSubjects[collectionId].subject.subscribe( (output) => rollingSubjectWatcher(req, res, output) );
    
    
    // We don't run a while loop here because runRollingCollection will loop on its own
    // Execute our collection building here
    runRollingCollection(collectionId, res);
  }



  ////////////////////////////////////////////
  /////////////NEW MONITORING RUN/////////////
  ////////////////////////////////////////////
  

  else if ( thisCollection.type === 'monitoring' ) {
    // This is a new monitoring collection as there are no existing subscribers to it
    // Let's start building it
    let subject = new Subject(); // Create a new observable which will be used to pipe communication between the worker and the client

    
    // Populate rollingCollectionSubjects[rollingId] with some initial values
    rollingCollectionSubjects[rollingId] = {
      subject: subject,
      observers: 1,
      paused: false,
      runs: 0
    }

    // We now subscribe to our new observable for the collection and pipe its output to rollingSubjectWatcher so it can be output to the http response stream
    rollingCollectionSubjects[rollingId].subject.subscribe( (output) => rollingSubjectWatcher(req, res, output) );
    
    
    // We don't run a while loop here because runRollingCollection will loop on its own
    // Execute our collection building here
    runRollingCollection(collectionId, res, rollingId);
  }





  //////////////////////////////////////////////////////////
  ////////////ALREADY RUNNING ROLLING COLLECTION////////////
  //////////////////////////////////////////////////////////
  
  else {
    // We're not the first client connected to this collection, as the rolling collection is already running
    // Let's play back its contents and subscribe to its observable

    winston.info(`This is not the first client connected to rolling collection ${collectionId}.  Playing back existing collection`);

    rollingCollectionSubjects[collectionId]['observers'] += 1;
    // Increase the observers count so we know how many people are viewing the collection
    
    rollingCollectionSubjects[collectionId].subject.subscribe( (output) => rollingSubjectWatcher(req, res, output) );
    // We now subscribe to the existing observable for the collection and pipe its output to rollingSubjectWatcher so it can be output to the http response stream
      
    // Play back the data already in rollingCollections[collectionId]

    for (var i=0; i < rollingCollections[collectionId].sessions.length; i++) {
      // Play back sessions
      let resp = {
        collectionUpdate: {
          session: rollingCollections[collectionId].sessions[i]
        }
      };
      res.write(JSON.stringify(resp) + ',');
      res.flush();
    }
    
    for (var i=0; i < rollingCollections[collectionId].images.length; i++) {
      // Play back images
      let resp = {
        collectionUpdate: {
          images: [ rollingCollections[collectionId].images[i] ]
        }
      };
      res.write(JSON.stringify(resp) + ',');
      res.flush();
    }
    
    if (rollingCollections[collectionId].search) {
      // Play back search text
      for (var i=0; i < rollingCollections[collectionId].search.length; i++) {
        let resp = {
          collectionUpdate: {
            search: [ rollingCollections[collectionId].search[i] ] 
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

function writePreferences() {
  db.collection('preferences').updateOne( {}, preferences, (err, res) => {
    if (err) throw err;
  });
}

var User = null;
function mongooseInitFunc() {
  winston.debug('Initializing mongoose');
  // Initialise Mongoose.  This gets called from within connectToDB()
  
  User = require('./models/user');
  passport.use(new LocalStrategy(User.authenticate()));
  passport.serializeUser(User.serializeUser());
  passport.deserializeUser(User.deserializeUser());

  // Connect to Mongoose
  var mongooseUrl = `mongodb://${config['dbConfig']['host']}:${config['dbConfig']['port']}/afb_users`
  var mongooseOptions = { useMongoClient: true, promiseLibrary: global.Promise };
  if (config.dbConfig.authentication.enabled) {
    mongooseUrl = `mongodb://${config.dbConfig.authentication.user}:${config.dbConfig.authentication.password}@${config['dbConfig']['host']}:${config['dbConfig']['port']}/afb_users?authSource=admin`;
  }
  
  let mongooseOnConnectFunc = () => {
    var db = mongoose.connection;
  
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
  };

  let mongooseConnectFunc = () => {
    mongoose.connect(mongooseUrl, mongooseOptions )
            .then( () => mongooseOnConnectFunc() )
            .then( () => startFeeder() )
            // .then( () => listener() ) // now starting after feeder is running
            .catch( (err) => {
              winston.error('Mongoose error whilst connecting to mongo.  Exiting with code 1.');
              winston.error(err);
              process.exit(1);
            } );
  };

  mongooseConnectFunc();
}


var db = null;

function connectToDB() {
  // mongo.connect(mongoUrl, (err, database) => {

  let connectFunc = (database) => {
    // winston.debug('connectFunc()');
    // console.log('db:', db);
    // if (err) throw err;
    db = database;
  
    db.listCollections().toArray( (err, cols) => {
      if (err) throw err;

      let foundPrefs = false;
      
      for (let i=0; i < cols.length; i++) {
        let collectionName = cols[i].name;
        
        if (collectionName == "preferences") {
           // read prefs
           foundPrefs = true;
           justInstalled = false;
           winston.debug("Reading preferences");
           db.collection('preferences').findOne( (err, res) => {
            let rewritePrefs = false; 
            // preferences = res.preferences;
            preferences = res;
            // merge in default preferences which aren't in our loaded preferences (like for upgrades)
            for (let pref in defaultPreferences) {
              if (defaultPreferences.hasOwnProperty(pref)) {
                if (!preferences.hasOwnProperty(pref)) {
                  winston.info(`Adding new default preference for ${pref}`);
                  preferences[pref] = defaultPreferences[pref];
                  rewritePrefs = true;
                }
              }
            }
            for (let pref in defaultPreferences.nw) {
              if (defaultPreferences.nw.hasOwnProperty(pref)) {
                if (!preferences.nw.hasOwnProperty(pref)) {
                  winston.info(`Adding new default NetWitness preference for ${pref}`);
                  preferences.nw[pref] = defaultPreferences.nw[pref];
                  rewritePrefs = true;
                }
              }
            }
            for (let pref in defaultPreferences.sa) {
              if (defaultPreferences.sa.hasOwnProperty(pref)) {
                if (!preferences.sa.hasOwnProperty(pref)) {
                  winston.info(`Adding new default Security Analytics preference for ${pref}`);
                  preferences.sa[pref] = defaultPreferences.sa[pref];
                  rewritePrefs = true;
                }
              }
            }
            if (rewritePrefs) {
              writePreferences();
            }
           });
        }
      
        if (collectionName == "nwservers") {
          winston.debug("Reading nwservers");
          db.collection('nwservers').find({}).toArray( (err, res) => {
             for (let x=0; x < res.length; x++) {
                let id = res[x].id;
                nwservers[id] = res[x];
             }
           });
        }

        if (collectionName == "saservers") {
          winston.debug("Reading saservers");
          db.collection('saservers').find({}).toArray( (err, res) => {
             for (let x=0; x < res.length; x++) {
                let id = res[x].id;
                saservers[id] = res[x];
             }
           });
        }

        if (collectionName == "feeds") {
          winston.debug("Reading feeds");
          db.collection('feeds').find({}).toArray( (err, res) => {
             for (let x = 0; x < res.length; x++) {
                let id = res[x].id;
                feeds[id] = res[x];
             }
             scheduler.updateSchedule(feeds);
           });
        }

        if (collectionName == "blacklist") {
          winston.debug("Reading blacklist");
          db.collection('blacklist').find({}).toArray( (err, res) => {
            // winston.debug('blacklist:', res); 
            for (let x = 0; x < res.length; x++) {
                let id = res[x].id;
                let timestamp = res[x].timestamp;
                tokenBlacklist[id] = timestamp;
             }
             winston.debug('tokenBlacklist:', tokenBlacklist);
             setInterval( () => cleanBlackList(), 1000 * 60); // run every minute
             cleanBlackList();
           });
        }
      
        if (collectionName == "collections") {
          winston.debug("Reading collections");
          db.collection('collections').find({}).toArray( (err, res) => {
             for (let x=0; x < res.length; x++) {
                let id = res[x].id;
                collections[id] = res[x];
             }
             cleanRollingDirs();
           });
        }
      
        if (collectionName == "collectionsData") {
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
        db.collection('preferences').insertOne( preferences, (err, res) => {
          if (err) throw err;
        });
      }
    });
  };

  winston.debug('Initializing mongo db');
  let connectionAttempts = 1;
  // winston.debug('mongoUrl:', mongoUrl);
  let connectorFunc = () => {
        mongo.connect(mongoUrl)
        .then( (database) => connectFunc(database) )
        .then( () => mongooseInitFunc() )
        .catch( (err) => {
          // winston.error(err);
          if (connectionAttempts == 3) {
            winston.error('Maximum retries reached whilst connecting to mongo.  Exiting with code 1.');
            winston.error(err.message);
            process.exit(1);
          }
          winston.warn('Could not connect to Mongo DB');
          connectionAttempts++;
          if (connectionAttempts <= 3) {
            winston.warn('Retrying mongo connection in 3 seconds');
          }
          sleep.sleep(3);
         connectorFunc();
        });
      };
  connectorFunc();
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
      winston.error("adding default user 'admin':", err);
    }
    else {
      winston.info("Default user 'admin' added");
    }
  });
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

function chunkHandler(collectionRoot, id, subject, data, chunk, clientSessionId='') {
  // Handles socket data received from the worker process
  // This actually builds the collection data structures and sends updates to the client

  let rollingId = id;
  if (clientSessionId != '') {
    rollingId = clientSessionId;
  }
  let thisCollection = collectionRoot[rollingId];

  /*
////DEBUG CODE//
  if (thisCollection == undefined) {
    console.error('ERROR: thisCollection is undefined');
    console.error('id:', id);
    console.error('clientSessionId:', clientSessionId);
    console.error('collectionRoot:');
    for (let i in collectionRoot) {
      console.error(i);
    }
    data += chunk
    console.error('data:', data);
    process.exit(1);
  }
////
*/

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
    
    if ('heartbeat' in update) {
      return data;
    }

    if ('collectionUpdate' in update) {

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
        
        if ('proxyContentFile' in update.collectionUpdate.images[i]) {
          update.collectionUpdate.images[i].proxyContentFile = collectionsUrl + '/' + rollingId + '/' + update.collectionUpdate.images[i].proxyContentFile;
        }

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

function purgeSessions(thisRollingCollection, sessionsToPurge) {
  // winston.debug('purgeSessions(): sessionsToPurge.length: ', sessionsToPurge.length)
  while (sessionsToPurge.length > 0) {
    let sessionToPurge = sessionsToPurge.shift();
    // winston.debug('purgeSessions(): Trying to purge session', sessionToPurge);

    for (let i = 0; i < thisRollingCollection.sessions.length; i++) {
      // Purge session
      let session = thisRollingCollection.sessions[i];
      if (session.id == sessionToPurge) {
        // winston.debug('purgeSessions(): purging session', session.id);
        thisRollingCollection.sessions.splice(i, 1);
        break;
      }
    }

    let searchesToPurge = [];
    for (let i = 0; i < thisRollingCollection.search.length; i++) {
      let search = thisRollingCollection.search[i];
      if (search.session == sessionToPurge) {
        searchesToPurge.push(search);
      }
    }
    while (searchesToPurge.length != 0) {
      let searchToPurge = searchesToPurge.shift();
      for (let i = 0; i < thisRollingCollection.search.length; i++) {
        let search = thisRollingCollection.search[i];
        if (searchToPurge.session == search.session && searchToPurge.contentFile == search.contentFile) {
          // Purge search
          winston.debug('purgeSessions(): purging search', search.session);
          thisRollingCollection.search.splice(i, 1);
          break;
        }
      }
    }


    let contentsToPurge = [];
    for (let i = 0; i < thisRollingCollection.images.length; i++) {
      // Purge content
      let content = thisRollingCollection.images[i];
      if (content.session == sessionToPurge) {
        contentsToPurge.push(content);
      }
    }
    while (contentsToPurge.length != 0) {
      let contentToPurge = contentsToPurge.shift();
      for (let i = 0; i < thisRollingCollection.images.length; i++) {
        let content = thisRollingCollection.images[i];
        if (contentToPurge.session == content.session && contentToPurge.contentFile == content.contentFile && contentToPurge.contentType == content.contentType) {
          // Purge content
          winston.debug('purgeSessions(): purging content', content.session);
          thisRollingCollection.images.splice(i, 1);
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

function writeToSocket(socket, data) {
  socket.write(data + '\n');
}

function feederSocketCommunicationHandler(socket, tempName) {

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
  writeToSocket(feederSocket, JSON.stringify( { config: { feedsDir: feedsDir }, feeds: feeds } ));
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
      winston.debug('feederDataHandler(): Feeder socket file is ' + feederSocketFile);
      if (!apiInitialized) {
        listener(); // start the API listener
      }
    }
  }
};

function startFeeder() {
  winston.debug('startFeeder(): starting feeder_srv');

  try {
    // get a temporary file to use as our domain socket
    var tempName = temp.path({suffix: '.socket'});
    
    // open UNIX domain socket to talk to server script, and set the socket handler to feederSocketCommunicationHandler
    var socketServer = net.createServer( (socket) => feederSocketCommunicationHandler(socket, tempName) );

    // start the feeder_srv
    socketServer.listen(tempName, () => {
      
      winston.debug('Waiting for Feeder connection');
      winston.debug("Spawning feeder_srv with socket file " + tempName);

      // spawn the feeder process
      var feederSrv = spawn('./feeder_stub.py ', [tempName], { shell: true, stdio: 'inherit' });

      // wait for the feeder to exit (ideally it shouldn't until we shutdown)
      feederSrv.on('exit', (code) => {
        if (typeof code === 'undefined') {
          winston.debug('Feeder process exited abnormally without an exit code');
        }
        else if (code != 0) {
          winston.debug('Feeder process exited abnormally with exit code',code.toString());
        }
        else {
          winston.debug('Feeder process exited normally with exit code', code.toString());
        }
        
      });
    });
  }
  catch(e) {
    winston.error("startFeeder(): Caught error:", e);
  }
}

function schedulerUpdatedCallback(id) {
  // winston.debug('schedulerUpdatedCallback(): id:', id);
  writeToSocket( feederSocket, JSON.stringify( { updateFile: true, id: id } ) ); // let feeder server know of our update
}

function blacklistToken(id) {
  let timestamp = new Date().getTime();
  try {
    db.collection('blacklist').insertOne( { id: id, timestamp: timestamp }, (err) => {
      if (err) throw err;
      tokenBlacklist[id] = timestamp;
    });
  }
  catch(e) {
    winston.error('Error updating token blacklist:', e);
  }
}

function cleanBlackList() {
  // winston.debug('cleanBlackList()');
  let currentTime = new Date().getTime();
  for (let id in tokenBlacklist) {
    if (tokenBlacklist.hasOwnProperty(id)) {
      let timestamp = tokenBlacklist[id];
      if ( currentTime >= timestamp + tokenExpirationSeconds * 1000) {
        winston.debug('cleanBlackList(): cleaning token with id', id);
        try {
          db.collection('blacklist').remove( { id: id}, (err, res) => {
            if (err) throw err;
            delete tokenBlacklist[id];
          });
        }
        catch(e) {
          winston.error('Error purging token from blacklist');
        }
      }
    }
  }
}






///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////LISTEN/////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function listener() {
  // Start listening for client traffic and away we go
  // app.listen(listenPort, '127.0.0.1');
  app.listen(listenPort);
  apiInitialized = true;
  winston.info('Serving on localhost:' + listenPort);
}
