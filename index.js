'use strict';

// Load dependencies
require('source-map-support').install();
const Observable = require('rxjs/Observable').Observable;
const Subject = require('rxjs/Subject').Subject;
const app = require('express')();
const server = require('http').createServer(app);  
const io = require('socket.io')(server);
const ioCookieParser = require('socket.io-cookie');
const multer  = require('multer');
const session = require('express-session');
const bodyParser = require('body-parser');
const listenPort = 3002;
global.uuidV4 = require('uuid/v4');
global.fs = require('fs');
global.net = require('net'); //for unix sockets
global.rimraf = require('rimraf');
global.spawn = require('child_process').spawn;
const exec = require('child_process').exec;
global.temp = require('temp');
global.moment = require('moment');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
const util = require('util');
const sprintf = require('sprintf-js').sprintf;
global.winston = require('winston');
const mongoose = require('mongoose');
mongoose.Promise = Promise;
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const mongo = require('mongodb').MongoClient;
const NodeRSA = require('node-rsa');
const sleep = require('sleep');
const restClient = require('node-rest-client').Client;
global.request = require('request');
const path = require('path');
const nodeCleanup = require('node-cleanup');
const isDocker = require('is-docker');

const buildProperties = require('./build-properties');
const version = `${buildProperties.major}.${buildProperties.minor}.${buildProperties.patch}.${buildProperties.build}-${buildProperties.level}`;

var feedScheduler;
try {
  feedScheduler = FeedScheduler;
}
catch (e) {
  feedScheduler = require('./feed-scheduler.js');
}

var rollingCollectionHandler;
try {
  rollingCollectionHandler = RollingCollectionHandler;
}
catch (e) {
  rollingCollectionHandler = require('./rolling-collections');
}

var fixedCollectionHandler;
try {
  fixedCollectionHandler = FixedCollectionHandler;
}
catch(e) {
  fixedCollectionHandler = require('./fixed-collections');
}

// export NODE_ENV='production'
// export NODE_ENV='development'
var development = process.env.NODE_ENV !== 'production';
var debug = 'AFBDEBUG' in process.env;
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////EXPRESS////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

if (debug) {
  winston.debug('Atomic Fishbowl Server debug logging is enabled');
  winston.level = 'debug';
}

winston.info('Starting Atomic Fishbowl server version', version);





//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////CONFIGURATION//////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var justInstalled = true;
var preferences = {};
var nwservers = {};
var saservers = {};
var collections = {}; // holds the high-level definition of a collection but not its content data
var collectionsData = {}; // holds content data and session data
var feeds = {}; // holds definitions for hash data CSV's
var exiting = false;

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

// var tokenExpirationSeconds = 60 * 60 * 24; // 24 hours
// var tokenExpirationSeconds = 60 * 60 * preferences.tokenExpirationHours; // 24 hours is default
var tokenExpirationSeconds = 0;

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
var scheduler = new feedScheduler(feedsDir, decryptor, (id) => schedulerUpdatedCallback(id), io);


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
  debugLogging: false,
  serviceTypes: { nw: false, sa: false },
  tokenExpirationHours: 24,

  nw: {
    url: '',
    summaryTimeout: 5,
    sessionLimit: 2000,
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
    presetQuery: '[ { "any" : [ "file_type=PDF", "file_extension=\"pdf\"", "mime_type=\"application/pdf\"", "file_type=ZIP", "file_extension=\"docx\"", "mime_type=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\"", "file_extension=\"xlsx\"", "mime_type=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\"", "file_extension=\"pptx\"",  "mime_type=\"application/vnd.openxmlformats-officedocument.presentationml.presentation\"" ] } ]',
    defaultQuerySelection : "All Supported File Types",
    sessionLimit: 2000,
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
    saquery: '[ { "any" : [ "ipv4_initiator=172.16.0.0/12", "ipv4_initiator=192.168.0.0/16", "ipv4_initiator=192.168.0.0/16" ] }, { "all" : [ "ipv4_responder!=172.16.0.0/12", "ipv4_responder!=192.168.0.0/16", "ipv4_responder!=192.168.0.0/16" ] }, { "any" : [ "file_type=PDF", "file_extension=\\"pdf\\"", "mime_type=\\"application/pdf\\"", "file_type=ZIP", "file_extension=\\"docx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\\"", "file_extension=\\"xlsx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\\"", "file_extension=\\"pptx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.presentationml.presentation\\"" ] } ]',
    contentTypes: [ 'pdfs', 'officedocs' ],
    description: 'Displays documents which are being transferred outbound',
    onlyContentFromArchives: false
  },
  
  {
    name: 'ssns',
    friendlyName: 'Social Security Numbers',
    nwquery: "filetype = 'pdf','office 2007 document','zip','rar'",
    saquery: '[ { "any" : [ "file_type=PDF", "file_extension=\\"pdf\\"", "mime_type=\\"application/pdf\\"", "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"", "file_extension=\\"docx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\\"", "file_extension=\\"xlsx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\\"", "file_extension=\\"pptx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.presentationml.presentation\\"" ] } ]',
    contentTypes: [ 'pdfs', 'officedocs' ],
    description: 'Displays documents which contain social security numbers.  It will look inside ZIP and RAR archives, as well',
    regexTerms: [ '\\d\\d\\d-\\d\\d-\\d\\d\\d\\d' ],
    onlyContentFromArchives: false
  },

  {
    name: 'dob',
    friendlyName: 'Date of Birth',
    nwquery: "filetype = 'pdf','office 2007 document','zip','rar'",
    saquery: '[ { "any" : [ "file_type=PDF", "file_extension=\\"pdf\\"", "mime_type=\\"application/pdf\\"", "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"", "file_extension=\\"docx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\\"", "file_extension=\\"xlsx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\\"", "file_extension=\\"pptx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.presentationml.presentation\\"" ] } ]',
    contentTypes: [ 'pdfs', 'officedocs' ],
    description: 'Displays documents which contain dates of birth', 
    regexTerms: [ 
      '(?i)(dob|date of birth|birth date|birthdate|birthday|birth day).*\\d\\d?[-/]\\d\\d?[-/]\\d{2}(?:\\d{2})?\\W',
      '(?i)(dob|date of birth|birth date|birthdate|birthday|birth day).*\\d\\d? \\w+,? \\d{2}(?:\\d{2})?\\W',
      '(?i)(dob|date of birth|birth date|birthdate|birthday|birth day).*\\w+ \\d\\d?,? \\d{2}(?:\\d{2})?\\W'
    ],
    onlyContentFromArchives: false
  },

  {
    name: 'contentinarchives',
    friendlyName: 'All Content Contained in Archives',
    nwquery: "filetype = 'zip','rar'",
    saquery: '[ { "any" : [ "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"" ] } ]',
    contentTypes: [ 'images', 'pdfs', 'officedocs' ],
    description: 'Displays any content type contained within a ZIP or RAR archive.  It does not display dodgy archives',
    onlyContentFromArchives: true
  },
  
  {
    name: 'contentinarchivesdodgy',
    friendlyName: 'All Content Contained in Archives (with Dodgy Archives)',
    nwquery: "filetype = 'zip','rar'",
    saquery: '[ { "any" : [ "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"" ] } ]',
    contentTypes: [ 'images', 'pdfs', 'officedocs', 'dodgyarchives' ],
    description: 'Displays any content type contained within a ZIP or RAR archive.  It also displays dodgy archives',
    onlyContentFromArchives: true
  },

  {
    name: 'suspiciousdestcountries',
    friendlyName: 'Documents to Suspicious Destination Countries',
    nwquery: `country.dst = 'russian federation','china','romania','belarus','iran, islamic republic of',"korea, democratic people's republic of",'ukraine','syrian arab republic','yemen' && filetype = 'zip','rar','pdf','office 2007 document'`,
    saquery: '[ { "any" : [ "responder_country=\\"russian federation\\"", "responder_country=\\"china\\"", "responder_country=\\"romania\\"", "responder_country=\\"belarus\\"", "responder_country=\\"iran, islamic republic of\\"", "responder_country=\\"korea, democratic people\'s republic of\\"", "responder_country=\\"ukraine\\"", "responder_country=\\"syrian arab republic\\"", "responder_country=\\"yemen\\"" ] }, { "any" : [ "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"", "file_extension=\\"docx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\\"", "file_extension=\\"xlsx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\\"", "file_extension=\\"pptx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.presentationml.presentation\\"" ] } ]',
    contentTypes: [ 'pdfs', 'officedocs', 'dodgyarchives' ],
    description: 'Displays documents and dodgy archives transferred to suspicious destination countries: Russia, China, Romania, Belarus, Iran, North Korea, Ukraine, Syra, or Yemen',
    onlyContentFromArchives: false
  },

  {
    name: 'dodgyarchives',
    friendlyName: 'Dodgy Archives',
    nwquery: "filetype = 'zip','rar'",
    saquery: '[ { "any" : [ "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"" ] } ]',
    contentTypes: [ 'dodgyarchives' ],
    description: 'Displays ZIP and RAR Archives which are encrypted or which contain some encrypted files',
    onlyContentFromArchives: false
  },

  {
    name: 'outboundwebmonitoring',
    friendlyName: 'Outbound Web Usage Monitoring',
    nwquery: "direction = 'outbound' && service = 80 && filetype = 'jpg','gif','png'",
    saquery: '[ { "any" : [ "ipv4_initiator=172.16.0.0/12", "ipv4_initiator=192.168.0.0/16", "ipv4_initiator=192.168.0.0/16" ] }, { "all" : [ "ipv4_responder!=172.16.0.0/12", "ipv4_responder!=192.168.0.0/16", "ipv4_responder!=192.168.0.0/16" ] }, { "any" : [ "file_type~GIF", "file_extension=\\"gif\\"", "mime_type=\\"image/gif\\"", "file_type=PNG", "file_extension=\\"png\\"", "mime_type=\\"image/png\\"", "file_type=JPEG", "file_extension=\\"jpg\\"", "file_extension=\\"jpeg\\"", "mime_type=\\"image/jpeg\\"", "mime_type=\\"image/jpg\\"", "mime_type=\\"image/pjpeg\\"", "mime_type=\\"image/jp2\\"" ] } ]',
    contentTypes: [ 'images' ],
    description: 'Displays images from outbound web usage.  Recommended for use in a Monitoring Collection',
    onlyContentFromArchives: false
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
////////////////////////////////////////////////////////////////KEYS///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
      winston.debug("tokenExpirationSeconds:", tokenExpirationSeconds);
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

/*app.get('/api/publickey', passport.authenticate('jwt', { session: false } ), (req, res)=>{
  winston.debug("GET /api/publickey");
  res.json( { pubKey: internalPublicKey });
});
*/











//////////////////////USE CASES//////////////////////

/*app.get('/api/usecases', passport.authenticate('jwt', { session: false } ), (req, res) => {
  winston.debug("GET /api/usecases");
  res.json( { useCases: useCases } );
});*/








//////////////////////USERS//////////////////////

/*app.get('/api/user', passport.authenticate('jwt', { session: false } ), (req,res) => {
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
});*/



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
      emitUsers(io);
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
      emitUsers(io);
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
        emitUsers(io);
        res.status(204).send( JSON.stringify( { success: true } ) );
      }
    } );
  }
  catch(e) {
    winston.error("Error removing user:", e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});







//////////////////////SERVER VERSION//////////////////////

/*app.get('/api/version', passport.authenticate('jwt', { session: false } ), (req,res) => {
  // Gets the server version
  winston.info('GET /api/version');
  try {
    res.json({version: version});
  }
  catch(e) {
    winston.error('ERROR GET /api/version:', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});*/






//////////////////////COLLECTIONS//////////////////////
  

app.get('/api/collection', passport.authenticate('jwt', { session: false } ), (req,res) => {
  // Gets the configuration of all collections
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
  // Deletes a collection
  let id = req.params.id;
  winston.info(`DELETE /api/collection/${id}`);
  let collection = null;
  try {
    collection = collections[id];

    if (collection.type == 'rolling' || collection.type == 'monitoring') {
      setTimeout( () => rollingHandler.collectionDeleted(id, req.user.username) );
    }
    else {
      setTimeout( () => fixedHandler.collectionDeleted(id, req.user.username) );
    }

    if (id in collectionsData) {
      db.collection('collections').remove( { id: id }, (err, result) => {
        if (err) throw err;
        db.collection('collectionsData').remove( { id: id }, (err, result) => {
          if (err) throw err;
          delete collections[id];
          delete collectionsData[id];
          io.emit('collections', collections);
          res.status(200).send( JSON.stringify( { success: true } ) );
        });
      });
      
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
  
  if (collection.type != 'monitoring') {
    try { 
      rimraf( collectionsDir + '/' + id, () => {} );
    } 
    catch(e) {
      winston.error('ERROR removing directory' + collectionsDir + '/' + id + ':', e);
    }
  }
});



app.get('/api/collection/data/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // Gets the collection data for a collection (content, sessions, and search)
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
  // Adds a new collection
  // 'state' should always be at initial

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
    
    if (collection.type == 'rolling' || collection.type == 'monitoring') {
      collection['state'] = 'disconnected';
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
        io.emit('collections', collections);
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
  // Edits an existing collection
  winston.info("POST /api/collection/edit");
  try {
    let timestamp = new Date().getTime();
    let collection = req.body;
    winston.debug('collection:', collection);
    let id = collection.id;
    if (collection.type == 'rolling' || collection.type == 'monitoring') {
      collection['state'] = 'disconnected';
    }
    else {
      collection['state'] = 'initial';
    }
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

    setTimeout( () => rollingHandler.collectionEdited(id, collection), 0); // run asynchronously
    
    // Update collection in mongo
    db.collection('collections').updateOne( { id: id }, { $set: collection}, (err, result) => {
      if (err) throw err;

      db.collection('collectionsData').updateOne( { id: collection.id }, { $set: { data: JSON.stringify(cDef) } }, (err, result) => {
        // Update collection data in mongo
        if (err) throw err;
        io.emit('collections', collections);
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

/*app.get('/api/feed', passport.authenticate('jwt', { session: false } ), (req,res) => {
  winston.info('GET /api/feeds');
  try {
    res.json(feeds);
  }
  catch(e) {
    winston.error('ERROR GET /api/feeds:', e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});*/



app.post('/api/feed/manual', passport.authenticate('jwt', { session: false } ), upload.single('file'), (req, res) => {
  // Add a manual feed
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
            io.emit('feeds', feeds);
            res.status(201).send( JSON.stringify( { success: true } ) );
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
  // Add a scheduled feed
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
          io.emit('feeds', feeds);
          writeToSocket( feederSocket, JSON.stringify( { new: true, feed: feed } ) ); // let feeder server know of our update
          res.status(201).send( JSON.stringify( { success: true } ) );
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
            io.emit('feeds', feeds);
            writeToSocket( feederSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
            res.status(201).send( JSON.stringify( { success: true } ) );
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
          io.emit('feeds', feeds);
          writeToSocket( feederSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
          res.status(201).send( JSON.stringify( { success: true } ) );
          if (oldFeed.type == 'scheduled') {
            // tell scheduler to remove old feed
            scheduler.delFeed(feed.id);
          }
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
            io.emit('feeds', feeds);
            scheduler.updateFeed(feed);
            writeToSocket( feederSocket, JSON.stringify( { update: true, feed: feed } ) ); // let feeder server know of our update
            res.status(201).send( JSON.stringify( { success: true } ) );
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
          io.emit('feeds', feeds);
          writeToSocket( feederSocket, JSON.stringify( { delete: true, id: id } ) ); // let feeder server know of our update
          res.status(200).send( JSON.stringify( { success: true } ) );
          scheduler.delFeed(id);
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


/*app.get('/api/feed/status', passport.authenticate('jwt', { session: false } ), (req, res) => {
  try {
    res.status(200).send( JSON.stringify( scheduler.status() ) );
  }
  catch(e) {
    winston.error(`ERROR GET /api/feed/status :`, e);
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }
});*/








//////////////////////NWSERVERS//////////////////////

/*app.get('/api/nwserver', passport.authenticate('jwt', { session: false } ), (req, res) => {
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
*/



app.delete('/api/nwserver/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let servId = req.params.id;
  winston.info(`DELETE /api/nwserver/${servId}`);
  try {
    delete nwservers[servId];
    db.collection('nwservers').remove( { 'id': servId }, (err, result) => {
      if (err) throw err;
      io.emit('nwservers', redactApiServerPasswords(nwservers));
      res.status(200).send( JSON.stringify( { success: true } ) );
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
    db.collection('nwservers').insertOne( nwserver, (err, result) => {
      if (err) throw err;
      io.emit('nwservers', redactApiServerPasswords(nwservers));
      res.status(201).send( JSON.stringify( { success: true } ) );
    });
    
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
    db.collection('nwservers').updateOne( { id: id }, { $set: nwserver }, (err, result) => {
      if (err) throw err;
      io.emit('nwservers', redactApiServerPasswords(nwservers));
      res.status(200).send( JSON.stringify( { success: true } ) );
    });
    
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

/*app.get('/api/saserver', passport.authenticate('jwt', { session: false } ), (req, res) => {
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
*/



app.delete('/api/saserver/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  let servId = req.params.id;
  winston.info(`DELETE /api/saserver/${servId}`);
  try {
    delete saservers[servId];
    db.collection('saservers').remove( { 'id': servId }, (err, result) => {
      if (err) throw err;
      io.emit('saservers', redactApiServerPasswords(saservers));
      res.status(200).send( JSON.stringify( { success: true } ) );
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
    db.collection('saservers').insertOne( saserver, (err, result) => {
      if (err) throw err;
      io.emit('saservers', redactApiServerPasswords(saservers));
      res.status(201).send( JSON.stringify( { success: true } ) );
    });
    
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
    db.collection('saservers').updateOne( { id: id }, { $set: saserver }, (err, result) => {
      if (err) throw err;
      io.emit('saservers', redactApiServerPasswords(saservers));
      res.status(200).send( JSON.stringify( { success: true } ) );
    });
    
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

app.get('/api/ping', (req, res) => {
  //winston.debug("GET /api/ping");
  res.status(200).send( JSON.stringify( { success: true } ) );
});






//////////////////////PREFERENCES//////////////////////

/*
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
*/



app.post('/api/preferences', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // Set global preferences
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
      tokenExpirationSeconds = 60 * 60 * preferences.tokenExpirationHours
      io.emit('preferences', preferences);
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




function updateFixedCollectionsDbCallback(collectionId, collection) {
  winston.debug('updateFixedCollectionsDbCallback()');
  try {
    db.collection('collections').update( {id: collectionId }, collection, (err, res) => {
      if (err) throw err;
    });
    db.collection('collectionsData').update( {id: collectionId }, { id: collectionId, 'data': JSON.stringify(collectionsData[collectionId]) }, (err, res) => {
      if (err) throw err;
    });
  }
  catch(e) {
    log.error('updateFixedCollectionsDbCallback(): caught exception when updating database:', e);
  }
}



app.get('/api/collection/fixed/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  // Returns a fixed collection, either complete, or in the process of building
  let collectionId = req.params.id;
  winston.info('GET /api/collection/fixed/:id', collectionId);
  if (collectionId in collections && collections[collectionId]['state'] == 'initial' || collections[collectionId]['state'] == 'building' || collections[collectionId]['state'] == 'error') {
    // collection is either new or is building
    fixedHandler.onHttpConnection(req, res);
  }
  else if (collectionId in collections) { // && this.collections[collectionId]['state'] == 'complete' // we should even use this if state is 'error'
    // this is a complete fixed collection
    try {
      res.json( [ { wholeCollection: collectionsData[collectionId] }, { close: true } ] );
    }
    catch(e) {
      winston.error('ERROR GET /api/collection/fixed/:id', e);
      res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
    }
  }
  else {
    // couldn't find the collection
    res.status(500).send( JSON.stringify( { success: false, error: e.message || e } ) );
  }

});



app.get('/api/collection/monitoring/pause/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  rollingHandler.pauseMonitoringCollection(req, res);
});



app.get('/api/collection/monitoring/unpause/:id', passport.authenticate('jwt', { session: false } ), (req, res) => {
  rollingHandler.unpauseMonitoringCollection(req, res);
});



app.get('/api/collection/rolling/:collectionId', passport.authenticate('jwt', { session: false } ), (req, res) => {
  rollingHandler.onHttpConnection(req, res);
});



function updateCollectionsDbCallback(collectionId) {
  winston.debug('updateCollectionsDbCallback()');
  let collection = collections[collectionId];
  // winston.debug('updateCollectionsDbCallback(): collection:', collection);
  try {
    db.collection('collections').update( { id: collectionId }, collection, (err, res) => {
      if (err) throw err;
    });
  }
  catch(e) {
    log.error('updateCollectionsDbCallback(): caught exception when updating database:', e);
  }
}
























///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////UTILITY FUNCTIONS/////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


function redactApiServerPasswords(apiservers) {
  let servers = JSON.parse(JSON.stringify(apiservers));  // make deep copy of servers
  for (let server in servers) {
    // delete passwords - they don't need to be transferred back to the client
    if (servers.hasOwnProperty(server)) {
      servers[server].password = undefined;
    }
  }
  return servers;
}



function writePreferences() {
  db.collection('preferences').updateOne( {}, preferences, (err, res) => {
    if (err) throw err;
  });
}



function extractJwtFromCookie(req) {
  // Extract JWT from cookie 'access_token' and return to JwtStrategy
  // winston.debug("extractJwtFromCookie()", req.cookies);
  let token = null;
  if (req && req.cookies)
  {
    token = req.cookies['access_token'];
  }
  return token;
};



var tokenBlacklist = {};



function extraJwtTokenValidation(jwt_payload, done) {
  // After automatically verifying that JWT was signed by us, perform extra validation with this function
  // winston.debug("jwt validator jwt_payload:", jwt_payload);
  // winston.debug("verifying token id:", jwt_payload.jti);
  
  // check blacklist
  if (jwt_payload.jti in tokenBlacklist) {
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



function onMongooseConnected() {
  // Create the default user account, if we think the app was just installed and if the count of users is 0
  User.count( {}, (err, count) => {
    if (err) {
      winston.error("Error getting user count:", err);
    }
    else if (justInstalled && ( count == 0 || !count ) ) {
        // we only create the default user on first run because we 
        winston.info("Adding default user 'admin'");
        createDefaultUser();
        justInstalled = false;
    }
  });
}



var User = null;

function mongooseInit() {
  // Initialise Mongoose.  This gets called from within connectToDB(), after mongoClient has connected to Mongo
  winston.debug('Initializing mongoose');

  // Mongoose config
  let mongooseUrl = `mongodb://${config['dbConfig']['host']}:${config['dbConfig']['port']}/afb_users`
  let mongooseOptions = { useMongoClient: true, promiseLibrary: global.Promise };
  if (config.dbConfig.authentication.enabled) {
    mongooseUrl = `mongodb://${config.dbConfig.authentication.user}:${config.dbConfig.authentication.password}@${config['dbConfig']['host']}:${config['dbConfig']['port']}/afb_users?authSource=admin`;
  }


  // This creates local authentication passport strategy
  // This authenticates a user against the account stored in MongoDB
  // This is only used by /api/login
  try {
    User = model;
  }
  catch(e) {
    User = require('./models/user');
  }
  let mongooseStrategy = new LocalStrategy( User.authenticate() );
  passport.use(mongooseStrategy);
  passport.serializeUser( User.serializeUser() );
  passport.deserializeUser( User.deserializeUser() );


  // This creates the JWT authentication passport strategy
  // This is used to authenticate all API calls except login and ping
  let jwtOpts = {
    jwtFromRequest: ExtractJwt.fromExtractors([extractJwtFromCookie]),
    secretOrKey: jwtPublicKey,
    algorithms: ['RS256']
  };
  let jwtStrategy = new JwtStrategy(jwtOpts, (jwt_payload, done) => extraJwtTokenValidation(jwt_payload, done) );
  passport.use(jwtStrategy);
  

  

  // Connect to Mongoose
  mongoose.connect(mongooseUrl, mongooseOptions )
          .then( () => onMongooseConnected() )
          .then( () => startFeeder() )
          .catch( (err) => {
            winston.error('Mongoose error whilst connecting to mongo.  Exiting with code 1.');
            winston.error(err);
            process.exit(1);
          } );

}



function processMongoCollections() {
  winston.debug('processMongoCollections()');
  
  return db.collection('preferences').findOne().then( (res) => {
    winston.debug("Reading preferences");

    let rewritePrefs = false; 
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
    tokenExpirationSeconds = 60 * 60 * preferences.tokenExpirationHours; // 24 hours is default
    justInstalled = false;
    if (rewritePrefs) {
      writePreferences();
    }
    // winston.debug('preferences:', preferences);
  })
  .catch( () => {
    winston.info("Creating default preferences");
    preferences = defaultPreferences;
    db.collection('preferences').insertOne( preferences, (err, res) => {
      if (err) throw err;
    });
  } )
  
  
  .then( () => {
    return db.collection('nwservers').find({}).toArray().then( (res) => {
      if (Object.keys(res).length === 0) {
        return Promise.reject();
      }
      winston.debug("Reading nwservers");
      for (let x=0; x < res.length; x++) {
        let id = res[x].id;
        nwservers[id] = res[x];
      }
      // winston.debug('nwservers:', nwservers);
    } );
  } )
  .catch( () => { winston.info('Collection nwservers was not previously defined')} )

  .then( () => {
    return db.collection('saservers').find({}).toArray().then( (res) => {
      if (Object.keys(res).length === 0) {
        return Promise.reject();
      }
      winston.debug("Reading saservers");
      for (let x = 0; x < res.length; x++) {
        let id = res[x].id;
        saservers[id] = res[x];
      }
      // winston.debug('saservers:', saservers);
    } );
  } )
  .catch( () => { winston.info('Collection saservers was not previously defined')} )

  .then( () => {
    return db.collection('feeds').find({}).toArray().then( (res) => {
      if (Object.keys(res).length === 0) {
        return Promise.reject();
      }
      winston.debug("Reading feeds");
      for (let x = 0; x < res.length; x++) {
        let id = res[x].id;
        feeds[id] = res[x];
      }
      scheduler.updateSchedule(feeds);
      // winston.debug('feeds:', feeds);

    } );
  } )
  .catch( () => { winston.info('Collection feeds was not previously defined')} )


  .then( () => {
    return db.collection('blacklist').find({}).toArray().then( (res) => {
      winston.debug("Reading blacklist");
      for (let x = 0; x < res.length; x++) {
        let id = res[x].id;
        let timestamp = res[x].timestamp;
        tokenBlacklist[id] = timestamp;
      }
      // winston.debug('tokenBlacklist:', tokenBlacklist);
      setInterval( () => cleanBlackList(), 1000 * 60); // run every minute
      cleanBlackList();
    } );
  } )


  .then( () => {
    return db.collection('collections').find({}).toArray().then( (res) => {
      if (Object.keys(res).length === 0) {
        return Promise.reject();
      }
      winston.debug("Reading collections");
      for (let x = 0; x < res.length; x++) {
        let collection = res[x];
        if (collection.type == 'monitoring' || collection.type == 'rolling') {
          collection.state = 'disconnected';
        }
        collections[collection.id] = collection;
       }
       cleanCollectionDirs();
       // winston.debug('collections:', collections);
    } );
  } )
  .catch( () => {
    winston.info('Collection \'collections\' was not previously defined')
  } )

  .then( () => {
    return db.collection('collectionsData').find({}).toArray().then( (res) => {
      if (Object.keys(res).length === 0) {
        return Promise.reject();
      }
      winston.debug("Reading collectionsData");
      for (let x = 0; x < res.length; x++) {
        let id = res[x].id;
        collectionsData[id] = JSON.parse(res[x].data);
      }
    } );
  } )
  .catch( () => {
    winston.info('Collection \'collectionsData\' was not previously defined')
  } )



}



var db = null;



function onMongoConnected(database) {
  winston.debug('onMongoConnected()');
  db = database;
  return Promise.resolve();
}



function connectToDB() {
  winston.debug('Initializing mongo db and reading settings');

  
  // We use mongoose for auth, and MongoClient for everything else.  This is because Passport-Local Mongoose required it, and it is ill-suited to the free-formish objects which we want to use.
  let mongoUrl = `mongodb://${config['dbConfig']['host']}:${config['dbConfig']['port']}/afb`;
  if (config.dbConfig.authentication.enabled) {
    mongoUrl = `mongodb://${config.dbConfig.authentication.user}:${config.dbConfig.authentication.password}@${config['dbConfig']['host']}:${config['dbConfig']['port']}/afb?authSource=admin`;
  }
  
  let connectionAttempts = 1;
  let connectorFunc = () => {
    mongo.connect(mongoUrl)
    .then( (database) => onMongoConnected(database) )
    .then( () => processMongoCollections() )
    .then( () => mongooseInit() )
    .catch( (err) => {
      // winston.error(err);
      if (connectionAttempts == 3) {
        winston.error('Maximum retries reached whilst connecting to mongo.  Exiting with code 1');
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



function cleanCollectionDirs() {
  try {
    winston.info("Cleaning up collection directories");

    for (let collectionId in collections) {

      winston.debug("Cleaning collection '" + collections[collectionId].name + "' with id " + collectionId);
      
      if (collections.hasOwnProperty(collectionId) && ( collections[collectionId].type == 'rolling' || ( collections[collectionId].type == 'fixed' && collections[collectionId].state != 'complete' ) ) ) {
        
        //winston.debug('Deleting dir', collectionsDir + '/' + collections[collection].id);
        rimraf( collectionsDir + '/' + collectionId, () => {} ); // delete output directory

      }

      else if (collections.hasOwnProperty(collectionId) && collections[collectionId].type == 'monitoring') {
  
        fs.readdirSync(collectionsDir).forEach( filename => {
          // winston.debug('filename:', filename);
          let isDir = fs.statSync(collectionsDir + '/' + filename).isDirectory();
          // winston.debug('isDir:', isDir);
          
          if (isDir && filename.startsWith(collectionId)) {
            rimraf( collectionsDir + '/' + collectionId, () => {} ); // delete output directory
          }

        })

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
  writeToSocket(feederSocket, JSON.stringify( { config: { feedsDir: feedsDir }, feeds: feeds } ));
}




var onFeederExit = (code, signal) => {
  /*if (exiting) {
    return;
  }*/

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

  try {
    // get a temporary file to use as our domain socket
    let tempName = temp.path({suffix: '.socket'});
    
    // open UNIX domain socket to talk to server script, and set the socket handler to onConnectionFromFeederSrv
    let socketServer = net.createServer( (socket) => onConnectionFromFeederSrv(socket, tempName) );

    // start the feeder_srv
    socketServer.listen(tempName, () => {
      
      winston.debug('Waiting for Feeder connection');
      winston.debug("Launching feeder_srv with socket file " + tempName);

      // spawn the feeder process
      feederSrvProcess = spawn('./feeder_stub.py', [tempName], { shell: false, stdio: 'inherit' });
      
      // wait for the feeder to exit (ideally it shouldn't until we shutdown)
      feederSrvProcess.on('exit', onFeederExit );
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
      if (id in tokensToIoSockets) {
        // disconnect socket.io for token
        winston.debug('Forcibly logging out socket')
        let socket = tokensToIoSockets[id];
        if (socket) {
          socket.emit('logout');
          socket.disconnect(true);
        }
      }
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



var rollingHandler = null;
var fixedHandler = null;












//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////SOCKET.IO/////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


var ioSocket = null;

function extraIoJwtTokenValidation(jwt_payload, done) {
  // After automatically verifying that JWT was signed by us, perform extra validation with this function
  // winston.debug("jwt validator jwt_payload:", jwt_payload);
  // winston.debug("verifying token id:", jwt_payload.jti);
  
  // check blacklist
  if (jwt_payload.jti in tokenBlacklist) {
    winston.info("User " + jwt_payload.username + " has already logged out!");
    return done(new Error());
  }

  // check whether user is enabled
  User.findOne({id: jwt_payload.sub}, function(err, user) {
    if (err) {
      socket.disconnect(true);
      return done(new Error());
    }
    if (user && user.enabled) {
      // winston.debug('Accepting socket.io connection');
      return done();
    }
    if (user && !user.enabled) {
      // user is disabled
      winston.info('Socket login denied for user', user.username);
      winston.info('Attempt to authenticate by disabled user', user.username);
      return done(new Error());
    }
    else {
      socket.disconnect(true);
      return done(new Errror());
      // or you could create a new account
    }
  });
}


var tokensToIoSockets = {};



function ioAuthenticator(socket, done) {
  let req = socket.request;
  // winston.debug('cookie:', req.headers.cookie);
  let cookies = req.headers.cookie;
  if (!cookies) {
    socket.error('Failed to authenticate socket.io connection: no cookies in header');
    socket.disconnect(true);
    return done(new Error());
  }
  if ( !('access_token' in cookies) ) {
    // winston.debug('Failed to authenticate socket.io connection: no access token');
    socket.error('Failed to authenticate socket.io connection: no access token');
    socket.disconnect(true);
    return done(new Error());
  }
  if ('access_token' in cookies) {
    let token = cookies['access_token'];
    // winston.debug('token:', token);
    jwt.verify(token, jwtPublicKey, { algorithms: ['RS256'] }, (err, decoded) => {

      // winston.debug('auth error:', err);

      // winston.debug('jwt:', decoded);
      socket['user'] = decoded; // write our token info to the socket so it can be accessed later
      
      if (err) {
        // authentication failed
        socket.error('Failed to authenticate socket.io connection: token authentication failed');
        socket.disconnect(true);
        return done(new Error());
      }

      tokensToIoSockets[decoded.jti] = socket;
      extraIoJwtTokenValidation(decoded, done);
      
    } );
  }
  
}

io.use(ioCookieParser);
io.use(ioAuthenticator);

var collectionsChannel = null;
collectionsChannel = io.of('/collections');

function onSocketIoConnect(socket) {
  ioSocket = socket;
  winston.debug('A socket client connected');
  socket.on('disconnect', () => onSocketIoDisconnect() );

  // immediately send configuration to client
  socket.emit('preferences', preferences);
  socket.emit('collections', collections);
  socket.emit('serverVersion', version);
  socket.emit('publicKey', internalPublicKey);
  socket.emit('nwservers', redactApiServerPasswords(nwservers));
  socket.emit('saservers', redactApiServerPasswords(saservers));
  socket.emit('feeds', feeds);
  socket.emit('feedStatus', scheduler.status() );
  emitUsers(socket);
  socket.emit('useCases', useCases);
}



function onSocketIoDisconnect(socket) {
  // winston.debug('A socket client disconnected');
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
  
  
  rollingHandler = new rollingCollectionHandler( updateCollectionsDbCallback, collections, collectionsDir, feeds, feederSocketFile, gsPath, pdftotextPath, sofficePath, sofficeProfilesDir, unrarPath, internalPrivateKeyFile, useCasesObj, preferences, nwservers, saservers, collectionsUrl, collectionsChannel);

  fixedHandler = new fixedCollectionHandler( updateFixedCollectionsDbCallback, collections, collectionsData, collectionsDir, feeds, feederSocketFile, gsPath, pdftotextPath, sofficePath, sofficeProfilesDir, unrarPath, internalPrivateKeyFile, useCasesObj, preferences, nwservers, saservers, collectionsUrl, collectionsChannel);

  winston.debug('Installing cleanup handler');
  nodeCleanup( (exitCode, signal) => onCleanup(exitCode, signal) );
  
  // Install SIGINT and SIGTERM handlers if we're running inside a container.  We need this to allow the process to exit normally when running in Docker
  if ( isDocker() ) {
    process.on('SIGINT', () => onCleanup(0, null) );
    process.on('SIGTERM', () => onCleanup(0, null) );
  }


  apiInitialized = true;
  winston.info('Serving on localhost:' + listenPort);
}
