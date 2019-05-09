class ConfigurationManager {

  constructor(args, socketIo) {

    this.io = socketIo;
    const NodeRSA = require('node-rsa');

    // file paths -- these will be accessed directly
    this.cfgDir = '/etc/kentech/afb';
    this.certDir = this.cfgDir + '/certificates';
    this.cfgFile = this.cfgDir + '/afb-server.conf';
    this._jwtPrivateKeyFile = this.certDir + '/ssl.key';
    this._jwtPublicCertFile = this.certDir + '/ssl.cer';
    this._internalPublicKeyFile = this.certDir + '/internal.pem';
    this._internalPrivateKeyFile = this.certDir + '/internal.key';
    this.collectionsUrl = '/collections';
    this.dataDir = '/var/kentech/afb';
    this.collectionsDir = this.dataDir + '/collections';
    this.sofficeProfilesDir = this.dataDir + '/sofficeProfiles';
    this.feedsDir = this.dataDir + '/feeds';
    this.tempDir = this.dataDir + '/tmp'; // used for temporary holding of uploaded files

    this.gsPath = '/usr/bin/gs';
    this.sofficePath = '/usr/bin/soffice';
    this.pdftotextPath = '/usr/bin/pdftotext';
    this.unrarPath = '/usr/bin/unrar';
    if (development) {
      this.sofficePath = '/usr/local/bin/soffice.sh';
      this.gsPath = '/opt/local/bin/gs';
      this.pdftotextPath = '/opt/local/bin/pdftotext';
      this.unrarPath = '/opt/local/bin/unrar';
    }
    
    this._dbconfig;
    this.loadConfigFile(this.cfgFile);

    this._justInstalled = true;
    this._preferences = {};
    this._nwservers = {};
    this._saservers = {};
    this._collections = {}; // holds the high-level definition of a collection but not its content data
    this._collectionsData = {}; // holds content data and session data
    this._feeds = {}; // holds definitions for hash data CSV's

    this._rollingHandler = null;
    

    // this._tokenExpirationSeconds = 60 * 60 * 24; // 24 hours
    // this._tokenExpirationSeconds = 60 * 60 * preferences.tokenExpirationHours; // 24 hours is default
    this._tokenExpirationSeconds = 0;

    // Set up encryption
    try {
      this._internalPublicKey = fs.readFileSync(this._internalPublicKeyFile, 'utf8');
    }
    catch (error) {
      winston.error("Cannot read internal key file", this._internalPublicKeyFile);
      process.exit(1);
    }
    try {
      this._internalPrivateKey = fs.readFileSync(this._internalPrivateKeyFile, 'utf8');
    }
    catch (error) {
      winston.error("Cannot read internal private key file", this._internalPrivateKeyFile);
    }
    // this.kentechCert = falseRequire('./kentech-public-key') || KentechCert;
    
    // read keys
    try {
      this._jwtPrivateKey = fs.readFileSync(this._jwtPrivateKeyFile, 'utf8');
    }
    catch(error) {
      winston.error("Cannot read private key file", this._jwtPrivateKeyFile);
      process.exit(1);
    }
    try {
      this._jwtPublicKey = fs.readFileSync(this._jwtPublicCertFile, 'utf8');
    }
    catch(error) {
      winston.error("Cannot read public key file", this._jwtPublicCertFile);
      process.exit(1);
    }


    // get type of service
    if ('service' in args && development) {
      this._serviceTypes = args.service === 'sa' ? { nw: false, sa: true } : { nw: true, sa: false };
    }
    else {
      this._serviceTypes = falseRequire('./servicetype') || ServiceTypes;
    }


    // Set default preferences
    this._defaultPreferences = falseRequire('./default-afb-preferences') || DefaultAfbPreferences;
    if (this.serviceTypes.nw) {
      this._defaultPreferences['nw'] = falseRequire('./default-nw-preferences') || DefaultNwPreferences;
    }
    else {
      this._defaultPreferences['sa'] = falseRequire('./default-sa-preferences') || DefaultSaPreferences;
    }

    // set up SSL decryptor
    this._decryptor = new NodeRSA( this._internalPrivateKey );
    this._decryptor.setOptions({encryptionScheme: 'pkcs1'});

    // Set use-cases
    // A use-case consists of a name (mandatory), a friendly name (mandatory), a query (mandatory), its allowed content types[] (mandatory), distillation terms (optional), regex distillation terms (optional), and a description (mandatory)
    // { name: '', friendlyName: '', query: "", contentTypes: [], description: '', distillationTerms: [], regexTerms: [] }
    this._useCases = falseRequire('./usecases') || UseCases;
    // console.log('_useCases:', _useCases);
    this._useCasesObj = {};
    this._useCases.forEach( thisUseCase => {
      this._useCasesObj[thisUseCase.name] = thisUseCase;
    });
    // console.log('useCasesObj:', this._useCasesObj);

    const DbMgrClass = falseRequire('./database') || DatabaseManager;
    this.dbMgr = new DbMgrClass(this);

    const TokenMgrClass = falseRequire('./token-manager') || TokenManager;
    this._tokenMgr = new TokenMgrClass(this, this.dbMgr);

  }



  async connectToDB() {
    await this.dbMgr.connectToDB(); // this will exit on its own if there's an error, so no need to try/catch
    await this.loadMongoCollections();
  }



  async loadMongoCollections() {
    winston.debug('ConfigurationManager: loadMongoCollections()');
    
    // load preferences
    let prefs;
    try {
      prefs = await this.dbMgr.getOnlyRecord('preferences');
      // winston.debug('loaded preferences:', prefs);
    }
    catch (err) {
      // this just means there were no preferences, so create the default preferences
    }
  
    if (prefs) {
      try {
        this._preferences = await this.processPreferences(prefs);
      }
      catch (error) {
        winston.error('caught error when processing loaded preferences:', error);
      }
    }
    else {
      try {
        winston.info("Creating default preferences");
        this._preferences = this._defaultPreferences;
        // insert first run timestamp into preference
        // preferences['firstRun'] = Math.floor(Date.now() / 1000);
        this.setPreference('firstRun', Math.floor(Date.now() / 1000));
        await this.dbMgr.insertRecord('preferences', this._preferences);
        // merge in serviceTypes afterwards so it doesn't get saved
        // this.setPreference('serviceTypes', serviceTypes);
      }
      catch(err) {
        winston.error('Caught error writing default preferences to DB.  Exiting with code 1');
        winston.error(err);
        process.exit(1);
      }
    }
   
  
    // load nw servers
    if (this.serviceTypes.nw) {
      try {
        let res = await this.dbMgr.getAllRecords('nwservers');
        if (Object.keys(res).length === 0) {
          throw "No NW servers were defined";
        }
        winston.debug("Reading nwservers");
        for (let x = 0; x < res.length; x++) {
          let id = res[x].id;
          this._nwservers[id] = res[x];
        }
        // winston.debug('nwservers:', nwservers);
      }
      catch (err) {
        winston.info('Collection nwservers was not previously defined');
      }
    }
    
    // load sa servers
    if (this.serviceTypes.sa) {
      try {
        let res = await this.dbMgr.getAllRecords('saservers');
        if (Object.keys(res).length === 0) {
          throw "No SA servers were defined";
        }
        winston.debug("Reading saservers");
        for (let x = 0; x < res.length; x++) {
          let id = res[x].id;
          this._saservers[id] = res[x];
        }
        // winston.debug('saservers:', saservers);
      }
      catch (err) {
        winston.info('Collection saservers was not previously defined');
      }
    }
  
    // load feeds
    try {
      let res = await this.dbMgr.getAllRecords('feeds');
      if (Object.keys(res).length === 0) {
        throw "No feeds were found";
      }
      winston.debug("Reading feeds");
      for (let x = 0; x < res.length; x++) {
        let id = res[x].id;
        this._feeds[id] = res[x];
      }
      // this.scheduler.updateSchedule(feeds);
      // winston.debug('feeds:', feeds);
    }
    catch (err) {
      winston.info('Collection feeds was not previously defined');
    }
  
  
    // blacklist
    try {
      let res = await this.dbMgr.getAllRecords('feeds');
      winston.debug("Reading blacklist");
        for (let x = 0; x < res.length; x++) {
          let id = res[x].id;
          let timestamp = res[x].timestamp;
          this._tokenMgr.addTokenToBlacklist(id, timestamp);
        }
        winston.debug('tokenBlacklist:', this._tokenMgr.tokenBlacklist);
    }
    catch (err) {}
  
    // collections
    try {
      let res = await this.dbMgr.getAllRecords('collections');
      if (Object.keys(res).length === 0) {
        throw "No feeds were found";
      }
      winston.debug("Reading collections");
      for (let x = 0; x < res.length; x++) {
        let collection = res[x];
        if (collection.type == 'monitoring' || collection.type == 'rolling') {
          collection.state = 'stopped';
        }
        this._collections[collection.id] = collection;
       }
       // winston.debug('collections:', collections);
    }
    catch (err) {
      winston.info('Collection \'collections\' was not previously defined');
    }
  
    // collectionsData
    try {
      let res = await this.dbMgr.getAllRecords('collectionsData');
      if (Object.keys(res).length === 0) {
        throw "No feeds were found";
      }
      winston.debug("Reading collectionsData");
      for (let x = 0; x < res.length; x++) {
        let id = res[x].id;
        this._collectionsData[id] = JSON.parse(res[x].data);
      }
    }
    catch (err) {
      winston.info('Collection \'collectionsData\' was not previously defined');
    }
    
  }



  async processPreferences(prefs) {
    winston.debug("Reading preferences");
  
    let rewritePrefs = false; 
  
    // merge in default preferences which aren't in our loaded preferences (like for upgrades)
    // this block isn't used in the justInstalled case
    for (let pref in this._defaultPreferences) {
      if (this._defaultPreferences.hasOwnProperty(pref)) {
        if (!prefs.hasOwnProperty(pref)) {
          winston.info(`Adding new default preference for ${pref}`);
          prefs[pref] = this._defaultPreferences[pref];
          rewritePrefs = true;
        }
      }
    }
    if (!('firstRun' in prefs)) {
      prefs['firstRun'] = Math.floor(Date.now() / 1000);
      rewritePrefs = true;
    }
    if (this.serviceTypes.nw) {
      for (let pref in this._defaultPreferences.nw) {
        if (this._defaultPreferences.nw.hasOwnProperty(pref)) {
          if (!prefs.nw.hasOwnProperty(pref)) {
            winston.info(`Adding new default NetWitness preference for ${pref}`);
            prefs.nw[pref] = this._defaultPreferences.nw[pref];
            rewritePrefs = true;
          }
        }
      }
    }
    if (this.serviceTypes.sa) {
      for (let pref in this._defaultPreferences.sa) {
        if (this._defaultPreferences.sa.hasOwnProperty(pref)) {
          if (!prefs.sa.hasOwnProperty(pref)) {
            winston.info(`Adding new default Security Analytics preference for ${pref}`);
            prefs.sa[pref] = this._defaultPreferences.sa[pref];
            rewritePrefs = true;
          }
        }
      }
    }
    this._tokenExpirationSeconds = 60 * 60 * prefs.tokenExpirationHours; // 24 hours is default
    this._justInstalled = false;
    try {
      if (rewritePrefs) {
        // writePreferences(prefs);
        await this.dbMgr.updateOnlyRecord('preferences', prefs);
      }
    }
    catch (error) {
      winston.error('Something went seriously wrong when writing the preferences.  Exiting with code 1');
      winston.error(error);
      process.exit(1);
    }
    
    prefs['serviceTypes'] = this.serviceTypes;
    // winston.debug('preferences:', prefs);
    return prefs;
  }



  loadConfigFile(cfgFile) {
    let config;
    try {
      // Read in config file
      config = JSON.parse( fs.readFileSync(cfgFile, 'utf8') );
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
    let configCopy = deepCopy(config);
    if ('dbConfig' in configCopy && 'authentication' in configCopy['dbConfig'] && 'password' in configCopy['dbConfig']['authentication']) {
      configCopy['dbConfig']['authentication']['password'] = '<redacted>';
    }
    winston.debug(configCopy);
    this._dbconfig = config['dbConfig'];
  }



  get preferences() {
    let prefs = deepCopy(this._preferences);
    prefs['serviceTypes'] = this.serviceTypes;
    return prefs;
  }



  async updatePreferences(prefs) {
    let oldPreferences = deepCopy(this._preferences);
    let serviceTypes;
    // merge in default preferences which we haven't worked into our the UI preferences yet (like summaryTimeout) do we need this?  I think we do
    for (let pref in this._defaultPreferences) {
      if (this._defaultPreferences.hasOwnProperty(pref) && !(['nw','sa'].includes(pref) ) ) {
        if (!prefs.hasOwnProperty(pref)) {
          prefs[pref] = this._defaultPreferences[pref];
        }
      }
    }
    if (this.serviceTypes.nw) {
      // merge nw preferences
      for (let pref in this._defaultPreferences.nw) {
        if (this._defaultPreferences.nw.hasOwnProperty(pref)) {
          if (!prefs.nw.hasOwnProperty(pref)) {
            prefs.nw[pref] = this._defaultPreferences.nw[pref];
          }
        }
      }
    }
    else {
      // merge sa preferences
      for (let pref in this._defaultPreferences.sa) {
        if (this._defaultPreferences.sa.hasOwnProperty(pref)) {
          if (!prefs.sa.hasOwnProperty(pref)) {
            prefs.sa[pref] = this._defaultPreferences.sa[pref];
          }
        }
      }
    }

    if ('serviceTypes' in prefs) {
      // we don't want to save the serviceType to the DB
      serviceTypes = prefs.serviceTypes;
      delete prefs.serviceTypes;
    }
    await this.dbMgr.updateOnlyRecord('preferences', prefs);
    if (serviceTypes) {
      prefs['serviceTypes'] = serviceTypes; // re-add the service types
    }
    this._tokenExpirationSeconds = 60 * 60 * prefs.tokenExpirationHours;
    this._preferences = prefs;
    this.io.emit('preferences', this._preferences);
    if ( (this.serviceTypes.nw && prefs.nw.queryDelayMinutes !== oldPreferences.nw.queryDelayMinutes) || (this.serviceTypes.sa && prefs.sa.queryDelayMinutes !== oldPreferences.sa.queryDelayMinutes) )  {
      // we need to bounce any running rolling collections to use the new query delay setting
      this._rollingHandler.restartRunningCollections();

    }

  }



  setPreference(key, value) {
    Object.defineProperty(this._preferences, key, value);
  }



  get nwservers() {
    return this._nwservers;
  }



  set nwservers(nwservers) {
    this._nwservers = nwservers;
  }



  async addNwServer(nwserver) {
    let id = nwserver.id;
    await this.dbMgr.insertRecord( 'nwservers', nwserver );
    this._nwservers[id] = nwserver;
  }



  async editNwServer(nwserver) {
    let id = nwserver.id;
    await this.dbMgr.replaceRecord('nwservers', id, nwserver);
    this._nwservers[id] = nwserver;
  }



  async deleteNwServer(id) {
    await this.dbMgr.deleteRecord('nwservers', id);
    delete this._nwservers[id];
  }



  get saservers() {
    return this._saservers;
  }



  set saservers(saservers) {
    this._saservers = saservers;
  }



  async addSaServer(saserver) {
    let id = saserver.id;
    await this.dbMgr.insertRecord('saservers', saserver);
    this._saservers[id] = saserver;
  }



  async editSaServer(saserver) {
    let id = saserver.id;
    await this.dbMgr.replaceRecord('saservers', id, saserver);
    this._saservers[id] = saserver;
  }



  async deleteSaServer(id) {
    await this.dbMgr.deleteRecord('saservers', id);
    delete this._saservers[id];
  }



  get collections() {
    return this._collections;
  }



  set collections(collections) {
    this._collections = collections;
  }



  async addCollection(collection) {
    let id = collection.id
    this._collections[id] = collection;
    let cDef = {
      images: [],
      sessions: {},
      id: id
    };
    this.io.emit('collections', this._collections);
    await this.dbMgr.insertRecord('collections', collection);
    await this.addCollectionsData(cDef);
  }



  async editCollection(collection) {
    // only rolling collections can be edited
    let id = collection.id;
    this._collections[id] = collection;
    let cDef = {
      images: [],
      sessions: {},
      id: id
    };
    this.io.emit('collections', this._collections);
    console.log('editCollection: got to 1');
    await this.dbMgr.replaceRecord('collections', id, collection);
    console.log('editCollection: got to 2');
    await this.editCollectionsData( { id: id, data: JSON.stringify(cDef) } );
    console.log('editCollection: got to 3');
  }



  async saveFixedCollection(id, collection) {
    // only saves collection, not collectionsData
    try {
      await this.dbMgr.replaceRecord('collections', id, collection);
    }
    catch (error) {
      log.error(`caught exception when updating collection ${id} in database:`, error);
      process.exit(1);
    }
  }



  async updateRollingCollection(id) {
    // we're just writing our current collection state
    winston.debug('updateRollingCollection()');
    let collection = this._collections[id];
    this.io.emit('collections', this._collections);
    try {
      await this.dbMgr.replaceRecord('collections', id, collection);
    }
    catch (error) {
      log.error(`caught exception when updating collection ${id} in database:`, error);
      process.exit(1);
    }
  }



  async deleteCollection(id) {
    delete this._collections[id];
    this.io.emit('collections', this._collections);
    await this.dbMgr.deleteRecord('collections', id);
    if (id in this._collectionsData) {
      await this.deleteCollectionsData(id);
    }
  }



  async deleteCollectionsData(id) {
    delete this._collectionsData[id];
    await this.dbMgr.deleteRecord('collectionsData', id);
  }



  async addCollectionsData(collectionData) {
    // receives a full collectionsData object, saves it here, and upserts it in the database
    let id = collectionData.id;
    this._collectionsData[id] = collectionData;
    await this.dbMgr.insertOrUpdateRecord('collectionsData', id, { id: id, data: JSON.stringify(collectionData) });
  }



  overwriteCollectionsDataForRolling(id, collectionData) {
    // overwrites collectionsData object but doesn't save
    if ('images' in collectionData) {
      this._collectionsData[id]['data']['images'] = collectionData.images;
    }
    if ('search' in collectionData) {
      this._collectionsData[id]['data']['search'] = collectionData.search;
    }
    if ('sessions' in collectionData) {
      this._collectionsData[id]['data']['sessions'] = collectionData.sessions;
    }
  }



  async editCollectionsData(collectionData) {
    let id = collectionData.id;
    this._collectionsData[id] = collectionData;
    await this.dbMgr.replaceRecord('collectionsData', id, collectionData);
  }



  get collectionsData() {
    return this._collectionsData;
  }



  get feeds() {
    return this._feeds;
  }



  set feeds(feeds) {
    this._feeds = feeds;
  }



  async addFeed(feed) {
    let id = feed.id;
    this._feeds[id] = feed;
    this.io.emit('feeds', this._feeds);
    await this.dbMgr.insertRecord('feeds', feed);
  }



  async editFeed(feed) {
    let id = feed.id;
    this._feeds[id] = feed;
    this.io.emit('feeds', this._feeds);
    await this.dbMgr.replaceRecord('feeds', id, feed);
  }



  async deleteFeed(id) {
    delete this._feeds[id];
    io.emit('feeds', this._feeds);
    await this.dbMgr.deleteRecord('feeds',id);
  }



  get dbconfig() {
    return this._dbconfig;
  }



  get tokenMgr() {
    return this._tokenMgr;
  }



  get decryptor() {
    return this._decryptor;
  }



  get justInstalled() {
    return this._justInstalled;
  }



  set justInstalled(justInstalled) {
    this._justInstalled = justInstalled;
  }



  get jwtPrivateKey() {
    return this._jwtPrivateKey;
  }



  get jwtPublicKey() {
    return this._jwtPublicKey;
  }



  get internalPublicKey() {
    return this._internalPublicKey;
  }



  get useCases() {
    return {
      useCases: this._useCases,
      useCasesObj: this._useCasesObj
    };
  }



  get serviceTypes() {
    return this._serviceTypes;
  }



  get tokenExpirationSeconds() {
    return this._tokenExpirationSeconds;
  }



  get internalPrivateKeyFile() {
    return this._internalPrivateKeyFile;
  }



  set rollingHandler(handler) {
    this._rollingHandler = handler;
  }



  


}

module.exports = ConfigurationManager;