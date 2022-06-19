import fs from 'fs';
import log from './logging.js';
import * as utils from './utils.js';
import selfsigned from 'selfsigned';
import os from 'os';
import NodeRSA from 'node-rsa';
import { DatabaseManager } from './database.js';
import { UseCases } from './usecases.js';
import { TokenManager } from './token-manager.js'
import { ServiceTypes } from './servicetype.js';
import { DefaultAfbPreferences } from './default-afb-preferences.js';
import { DefaultNwPreferences } from './default-nw-preferences.js';
import { DefaultSaPreferences } from './default-sa-preferences.js';
import { Server as SocketServer } from 'socket.io';
import { UseCase, ClientUseCases } from './types/use-case';
import { Preferences } from './types/preferences';
import { NwServer, NwServers } from './types/nw-server';
import { SaServer, SaServers } from './types/sa-server';
import { Feed, ScheduledFeed } from './types/feed';
import {
  Collection,
  CollectionData,
  CollectionDataEntry,
  Collections
} from './types/collection';
import { TokenBlacklist } from './types/token-blacklist';
import { RollingCollectionHandler } from 'rolling-collections.js';

export interface MongoDBConfig {
  host: string;
  port: number;
  authentication: {
    enabled: boolean;
    user?: string;
    password?: string;
  }
}

export class ConfigurationManager {
  
  io: SocketServer;
  private cfgDir = '/etc/kentech/afb';
  private certDir = `${this.cfgDir}/certificates`;
  private readonly jwtPrivateKeyFile = `${this.certDir}/jwt.key`;
  private readonly jwtPublicCertFile = `${this.certDir}/jwt.cer`;
  private readonly jwtPublicKeyFile = `${this.certDir}/jwt.pem`;
  private readonly internalPublicKeyFile = `${this.certDir}/internal.pem`;
  readonly internalPrivateKeyFile = `${this.certDir}/internal.key`;
  private readonly sslPublicKeyFile = `${this.certDir}/ssl.cer`;
  private readonly sslPrivateKeyFile = `${this.certDir}/ssl.key`;
  readonly collectionsDir = `/var/kentech/afb/collections`;
  readonly dataDir = '/var/kentech/afb/server';
  readonly sofficeProfilesDir = `${this.dataDir}/sofficeProfiles`;
  readonly feedsDir = `${this.dataDir}/feeds`;
  readonly tempDir = `${this.dataDir}/tmp`; // used for temporary holding of uploaded files

  readonly gsPath = '/usr/bin/gs';
  readonly sofficePath = '/usr/bin/soffice';
  readonly pdftotextPath = '/usr/bin/pdftotext';
  readonly unrarPath = '/usr/bin/unrar';

  justInstalled = true;
  private preferences!: Preferences;
  private nwservers: NwServers = {};
  private saservers: SaServers = {};
  private collections: Record<string, Collection> = {}; // holds the high-level definition of a collection but not its content data
  private collectionsData: Record<string, CollectionData> = {}; // holds content data and session data
  private feeds: Record<string, Feed> = {}; // holds definitions for hash data CSV's
  tokenExpirationSeconds = 0;
  
  private internalPublicKey: string;
  private internalPrivateKey: string;
  
  private jwtPublicKey: string;
  private jwtPrivateKey: string;

  private decryptor: NodeRSA;
  
  // Set use-cases
  // A use-case consists of a name (mandatory), a friendly name (mandatory), a query (mandatory), its allowed content types[] (mandatory), distillation terms (optional), regex distillation terms (optional), and a description (mandatory)
  // { name: '', friendlyName: '', query: '', contentTypes: [], description: '', distillationTerms: [], regexTerms: [] }
  private _useCases = UseCases;
  private _useCasesObj: Record<string, UseCase> = {};

  private rollingHandler!: RollingCollectionHandler;
  private tokenMgr: TokenManager;
  private mongoConfig: MongoDBConfig;
  private defaultPreferences: Preferences;
  private serviceTypes: typeof ServiceTypes;
  private dbMgr: DatabaseManager;



  constructor(socketIo: SocketServer) {
    this.io = socketIo;
    this.mongoConfig = this.loadMongoConfig();

    
    // Set up encryption
    try {
      // Load internal public key
      this.internalPublicKey = fs.readFileSync(this.internalPublicKeyFile, 'utf8');
    }
    catch (error: any) {
      this.createInternalCerts();
      this.internalPublicKey = fs.readFileSync(this.internalPublicKeyFile, 'utf8');
    }
    this.internalPrivateKey = fs.readFileSync(this.internalPrivateKeyFile, 'utf8');
    
    // read keys
    try {
      // Load JWT public key
      this.jwtPublicKey = fs.readFileSync(this.jwtPublicCertFile, 'utf8');
    }
    catch (error: any) {
      this.createJWTCerts();
      this.jwtPublicKey = fs.readFileSync(this.jwtPublicCertFile, 'utf8');
    }
    this.jwtPrivateKey = fs.readFileSync(this.jwtPrivateKeyFile, 'utf8');

    if (!fs.existsSync(this.sslPublicKeyFile) || !fs.existsSync(this.sslPrivateKeyFile) ) {
      this.createSSLCerts();
    }

    this.serviceTypes = ServiceTypes;

    // Set default preferences
    this.defaultPreferences = {
      ...DefaultAfbPreferences,
      serviceTypes: this.serviceTypes,
      nw: DefaultNwPreferences,
      sa: DefaultSaPreferences
    };
    
    // set up SSL decryptor
    this.decryptor = new NodeRSA( this.internalPrivateKey );
    this.decryptor.setOptions({encryptionScheme: 'pkcs1'});

    this._useCases.forEach( useCase => {
      this._useCasesObj[useCase.name] = useCase;
    });

    this.dbMgr = new DatabaseManager();
    this.tokenMgr = new TokenManager(this, this.dbMgr);
  }



  createInternalCerts() {
    log.debug('createInternalCerts()');
    log.info('Creating internal certificate keypair');
    const attrs = [
      {
        name: 'commonName',
        value: 'afb-server-internal'
      },
      {
        name: 'countryName',
        value: 'US'
      },
      {
        name: 'organizationName',
        value: 'Kensington Technology Associates, Limited'
      },
      {
        shortName: 'OU',
        value: 'Kensington Technology Associates, Limited'
      }
    ];
    const extensions = [
      {
        name: 'basicConstraints',
        cA: true
      },
      {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true
      },
      {
        name: 'extKeyUsage',
        serverAuth: true
      }
    ];
    const options: selfsigned.Options = {
      keySize: 2048,
      days: 2653,
      algorithm: 'sha256',
      extensions
    };
    const pems = selfsigned.generate(attrs, options);
    fs.writeFileSync(this.internalPublicKeyFile, utils.dos2unix(pems.public), { encoding: 'utf8', mode: 0o660 });
    fs.writeFileSync(this.internalPrivateKeyFile, utils.dos2unix(pems.private), { encoding: 'utf8', mode: 0o660 });
  }



  createJWTCerts() {
    log.debug('createJWTCerts()');
    log.info('Creating JWT certificate keypair');
    const attrs = [
      {
        name: 'commonName',
        value: 'afb-server-jwt'
      },
      {
        name: 'countryName',
        value: 'US'
      },
      {
        name: 'organizationName',
        value: 'Kensington Technology Associates, Limited'
      },
      {
        shortName: 'OU',
        value: 'Kensington Technology Associates, Limited'
      }
    ];
    const extensions = [
      {
        name: 'basicConstraints',
        cA: true,
        critical: true
      },
      {
        name: 'keyUsage',
        critical: true,
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: false,
        keyEncipherment: false,
        dataEncipherment: false
      },
      {
        name: 'extKeyUsage',
        serverAuth: true
      },
      {
        name: 'subjectAltName',
        altNames: [
          {
            type: 2, // DNS
            value: os.hostname()
          },
          {
            type: 2,
            value: 'localhost'
          }
        ]
      },
      {
        name: 'subjectKeyIdentifier'
      }
    ];
    const options: selfsigned.Options = {
      keySize: 2048,
      days: 825,
      algorithm: 'sha256',
      extensions
    };
    const pems = selfsigned.generate(attrs, options);
    fs.writeFileSync(this.jwtPublicCertFile, utils.dos2unix(pems.cert), { encoding: 'utf8', mode: 0o660 });
    fs.writeFileSync(this.jwtPublicKeyFile, utils.dos2unix(pems.public), { encoding: 'utf8', mode: 0o660 });
    fs.writeFileSync(this.jwtPrivateKeyFile, utils.dos2unix(pems.private), { encoding: 'utf8', mode: 0o660 });
  }
  
  
  
  createSSLCerts() {
    log.debug('createSSLCerts()');
    log.info('Creating SSL certificate keypair');
    const attrs = [
      {
        name: 'commonName',
        value: utils.getStringEnvVar('SSL_CERT_HOSTNAME', os.hostname())
      },
      {
        name: 'countryName',
        value: 'US'
      },
      {
        name: 'organizationName',
        value: 'Kensington Technology Associates, Limited'
      },
      {
        shortName: 'OU',
        value: 'Kensington Technology Associates, Limited'
      }
    ];
    const extensions = [
      {
        name: 'basicConstraints',
        cA: true,
        critical: true
      },
      {
        name: 'keyUsage',
        critical: true,
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: false,
        keyEncipherment: false,
        dataEncipherment: false
      },
      {
        name: 'extKeyUsage',
        serverAuth: true
      },
      {
        name: 'subjectAltName',
        altNames: [
          {
            type: 2,
            value: 'localhost'
          },
          {
            type: 2,
            value: utils.getStringEnvVar('SSL_CERT_HOSTNAME', os.hostname())
          }
        ]
      },
      {
        name: 'subjectKeyIdentifier'
      }
    ];
    if (utils.getStringEnvVar('SSL_CERT_ALT_HOSTNAME')) {
      extensions[3].altNames?.push({
        type: 2,
        value: utils.getStringEnvVar('SSL_CERT_ALT_HOSTNAME') as string
      });
    }
    const options: selfsigned.Options = {
      keySize: 2048,
      days: 825,
      algorithm: 'sha256',
      extensions
    };
    const pems = selfsigned.generate(attrs, options);
    fs.writeFileSync(this.sslPublicKeyFile, utils.dos2unix(pems.cert), { encoding: 'utf8', mode: 0o660 });
    fs.writeFileSync(this.sslPrivateKeyFile, utils.dos2unix(pems.private), { encoding: 'utf8', mode: 0o660 });
  }



  async connectToDB() {
    await this.dbMgr.connectToDB(this.mongoConfig); // this will exit on its own if there's an error, so no need to try/catch
    await this.loadMongoCollections();
  }



  async loadMongoCollections() {
    log.debug('ConfigurationManager: loadMongoCollections()');
    
    let prefs: Preferences | undefined;
    try {
      // load preferences
      prefs = await this.dbMgr.getOnlyRecord('preferences') as unknown as Preferences;
      delete (prefs as any)._id;
    }
    catch {
      // this just means there were no preferences, so create the default preferences
    }
  
    if (prefs) {
      try {
        // non-first run
        this.preferences = await this.processPreferences(prefs);
      }
      catch (error: any) {
        log.error('caught error when processing loaded preferences:', error);
      }
    }
    else {
      // first run
      try {
        log.info('Creating default preferences');
        this.preferences = this.defaultPreferences;
        this.tokenExpirationSeconds = 60 * 60 * this.preferences.tokenExpirationHours;
        await this.dbMgr.insertRecord('preferences', this.preferences);
      }
      catch (error: any) {
        log.error(error);
        log.error('Caught error writing default preferences to DB.  Exiting with code 1');
        process.exit(1);
      }
    }
     
    if (this.serviceTypes.nw) {
      // load nw servers
      try {
        const nwservers = await this.dbMgr.getAllRecords('nwservers') as unknown as NwServer[];
        if (Object.keys(nwservers).length === 0) {
          throw new Error('No NW servers were defined');
        }
        log.debug('Reading nwservers');
        nwservers.forEach( (nwserver) => this.nwservers[nwserver.id] = nwserver );
      }
      catch {
        log.info('Collection nwservers was not previously defined');
      }
    }
    
    if (this.serviceTypes.sa) {
      // load sa servers
      try {
        const saservers = await this.dbMgr.getAllRecords('saservers') as unknown as SaServer[];
        if (Object.keys(saservers).length === 0) {
          throw new Error('No SA servers were defined');
        }
        log.debug('Reading saservers');
        saservers.forEach( (saserver) => this.saservers[saserver.id] = saserver)
      }
      catch {
        log.info('Collection saservers was not previously defined');
      }
    }
  
    try {
      // load feeds
      const feeds = await this.dbMgr.getAllRecords('feeds') as unknown as Feed[];
      if (Object.keys(feeds).length === 0) {
        throw new Error('No feeds were found');
      }
      log.debug('Reading feeds');
      feeds.forEach( (feed) => this.feeds[feed.id] = feed );
    }
    catch {
      log.info('Collection feeds was not previously defined');
    }
  
    try {
      // blacklist
      const tokens = await this.dbMgr.getAllRecords('blacklist') as unknown as TokenBlacklist[];
      log.debug('Reading blacklist');
      tokens.forEach( (token) => this.tokenMgr.addTokenToBlacklist(token.id, token.timestamp) );
    }
    catch {}
  
    try {
      // collections
      const collections = await this.dbMgr.getAllRecords('collections') as unknown as Collection[];
      if (collections.length === 0) {
        throw new Error('No feeds were found');
      }
      log.debug('Reading collections');
      collections.forEach( collection => {
        if (collection.type === 'monitoring' || collection.type === 'rolling') {
          collection.state = 'stopped';
        }
        this.collections[collection.id] = collection;
      });
    }
    catch (error: any) {
      log.info('Collection \'collections\' was not previously defined');
    }
  
    try {
      // collectionsData
      const collectionDataEntries = await this.dbMgr.getAllRecords('collectionsData') as unknown as CollectionDataEntry[];
      if (collectionDataEntries.length === 0) {
        throw new Error('No feeds were found');
      }
      log.debug('Reading collectionsData');
      collectionDataEntries.forEach(
        (entry) => this.collectionsData[entry.id] = JSON.parse(entry.data)
      );
    }
    catch {
      log.info('Collection \'collectionsData\' was not previously defined');
    }
  }



  async processPreferences(loadedPrefs: Preferences) {
    log.debug('Reading preferences');
    let rewritePrefs = false;
  
    // merge in default preferences which aren't in our loaded preferences (like for upgrades)
    // this block isn't used in the justInstalled case
    Object.entries(this.defaultPreferences)
      .filter( ([key]) => !(key in loadedPrefs))
      .forEach( ([key, value]) => {
        log.info(`Adding new default preference for ${key}`);
        (loadedPrefs as Record<string, any>)[key] = value;
        rewritePrefs = true;
      });
    Object.entries(this.defaultPreferences.nw)
      .filter( ([key]) => !(key in loadedPrefs.nw) )
      .forEach( ([key, value]) => {
        log.info(`Adding new default NetWitness preference for ${key}`);
        (loadedPrefs.nw as Record<string, any>)[key] = value;
        rewritePrefs = true;
      });
    Object.entries(this.defaultPreferences.sa)
      .filter( ([key]) => !(key in loadedPrefs.sa) )
      .forEach( ([key, value]) => {
        log.info(`Adding new default Security Analytics preference for ${value}`);
        (loadedPrefs.sa as Record<string, any>)[key] = value;
        rewritePrefs = true;
      });
    
    this.tokenExpirationSeconds = 60 * 60 * loadedPrefs.tokenExpirationHours; // 24 hours is default
    this.justInstalled = false;
    try {
      if (rewritePrefs) {
        console.dir(loadedPrefs);
        await this.dbMgr.updateOnlyRecord('preferences', loadedPrefs);
      }
    }
    catch (error: any) {
      log.error('Something went seriously wrong when writing the preferences.  Exiting with code 1');
      log.error(error);
      process.exit(1);
    }
    
    loadedPrefs.serviceTypes = this.serviceTypes;
    return loadedPrefs;
  }



  loadMongoConfig(): MongoDBConfig {
    const config = {
      host: utils.getStringEnvVar('MONGO_HOST', 'db'),
      port: utils.getNumberEnvVar('MONGO_PORT', 27017),
      authentication: {
        enabled: utils.getBooleanEnvVar('MONGO_AUTH', false),
        user: utils.getStringEnvVar('MONGO_USER'),
        password: utils.getStringEnvVar('MONGO_PASSWORD')
      }
    };
    if (config.authentication.enabled && (!config.authentication.user || !config.authentication.password)) {
      log.error('Mongo authentication is enabled but missing user or password');
      process.exit(1);
    }
    return config;
  }



  getPreferences(): Preferences {
    return this.preferences;
  }



  getClientPreferences() {
    return {
      ...utils.deepCopy(this.preferences),
      serviceTypes: this.serviceTypes
    };
  }



  async updatePreferences(prefs: Preferences) {
    const oldPreferences = utils.deepCopy(this.preferences);
    // merge in default preferences which we haven't worked into our the UI preferences yet.  ???Do we need this???  I think we do
    Object.entries(this.defaultPreferences)
      .filter( ([key]) => !['nw','sa'].includes(key) && !(key in prefs))
      .forEach( ([key, value]) => (prefs as Record<string, any>)[key] = value );

    if (this.serviceTypes.nw) {
      // merge nw preferences
      Object.entries(this.defaultPreferences.nw)
        .filter( ([key]) => !(key in prefs.nw) )
        .forEach( ([key, value]) => (prefs.nw as Record<string, any>)[key] = value );
    }
    if (this.serviceTypes.sa) {
      // merge sa preferences
      Object.entries(this.defaultPreferences.sa)
        .filter( ([key]) => !(key in prefs.sa) )
        .forEach( ([key, value]) => (prefs.sa as Record<string, any>)[key] = value );
    }
    await this.dbMgr.updateOnlyRecord('preferences', prefs);

    this.tokenExpirationSeconds = 60 * 60 * prefs.tokenExpirationHours;
    this.preferences = prefs;
    this.tokenMgr.authSocketsEmit('preferences', this.preferences);

    const restartNwCollection = this.serviceTypes.nw && prefs.nw.queryDelayMinutes !== oldPreferences.nw.queryDelayMinutes;
    const restartSaCollection = this.serviceTypes.sa && prefs.sa.queryDelayMinutes !== oldPreferences.sa.queryDelayMinutes;
    if ( restartNwCollection || restartSaCollection )  {
      // we need to bounce any running rolling collections to use the new query delay setting
      this.rollingHandler.restartRunningCollections();
    }
  }



  setPreference(key: string, value: unknown) {
    Object.defineProperty(this.preferences, key, { value: value, writable: true, configurable: true, enumerable: true });
  }



  getNwServers(): NwServers {
    return this.nwservers;
  }



  getNwServer(id: string): NwServer {
    const nwserver = this.nwservers[id];
    if (!nwserver) {
      throw new Error(`NW Server ${id} not found`);
    }
    return nwserver;
  }



  getSaServers(): SaServers {
    return this.saservers;
  }
  
  
  
  getSaServer(id: string): SaServer {
    const saserver = this.saservers[id];
    if (!saserver) {
      throw new Error(`SA Server ${id} not found`);
    }
    return saserver;
  }


  async addNwServer(nwserver: NwServer) {
    const id = nwserver.id;
    await this.dbMgr.insertRecord( 'nwservers', nwserver );
    this.nwservers[id] = nwserver;
  }



  async editNwServer(nwserver: NwServer) {
    const id = nwserver.id;
    await this.dbMgr.replaceRecord('nwservers', id, nwserver);
    this.nwservers[id] = nwserver;
  }



  async deleteNwServer(id: string) {
    await this.dbMgr.deleteRecord('nwservers', id);
    delete this.nwservers[id];
  }



  async addSaServer(saserver: SaServer): Promise<void> {
    const id = saserver.id;
    await this.dbMgr.insertRecord('saservers', saserver);
    this.saservers[id] = saserver;
  }



  async editSaServer(saserver: SaServer): Promise<void> {
    const id = saserver.id;
    await this.dbMgr.replaceRecord('saservers', id, saserver);
    this.saservers[id] = saserver;
  }



  async deleteSaServer(id: string): Promise<void> {
    await this.dbMgr.deleteRecord('saservers', id);
    delete this.saservers[id];
  }


  
  getCollection(id: string): Collection {
    const collection = this.collections[id];
    if (!collection) {
      throw new Error(`Collection ${id} not found`);
    }
    return collection;
  }



  getCollections(): Collections {
    return this.collections;
  }



  hasCollection(id: string): boolean {
    return this.collections[id] !== undefined;
  }



  getCollectionData(id: string): CollectionData {
    const collectionData = this.collectionsData[id];
    if (!collectionData) {
      throw new Error(`Collection data ${id} not found`);
    }
    return collectionData;
  }



  hasCollectionData(id: string): boolean {
    return this.collectionsData[id] !== undefined;
  }
  
  
  
  /*getCollectionsData(): Record<string, CollectionData> {
    const collectionData = this.collectionsData[id];
    if (!collectionData) {
      throw new Error(`Collection data ${id} not found`);
    }
    return collectionData;
  }*/



  async addCollection(collection: Collection) {
    const id = collection.id
    this.collections[id] = collection;
    const cDef: CollectionData = {
      images: [],
      sessions: {},
      id
    };
    this.tokenMgr.authSocketsEmit('collections', this.collections);
    await this.dbMgr.insertRecord('collections', collection);
    await this.addCollectionsData(cDef);
  }



  async editCollection(collection: Collection) {
    // only rolling collections can be edited
    const id = collection.id;
    this.collections[id] = collection;
    const cDef: CollectionData = {
      id,
      images: [],
      sessions: {}
    };
    this.tokenMgr.authSocketsEmit('collections', this.collections);
    await this.dbMgr.replaceRecord('collections', id, collection);
    await this.editCollectionsData(id, cDef);
  }



  async saveFixedCollection(id: string, collection: Collection) {
    // only saves collection, not collectionsData
    try {
      await this.dbMgr.replaceRecord('collections', id, collection);
    }
    catch (error: any) {
      log.error(`caught exception when updating collection ${id} in database:`, error);
      process.exit(1);
    }
  }



  async updateRollingCollection(id: string) {
    // we're just writing our current collection state
    log.debug('updateRollingCollection()');
    const collection = this.collections[id];
    this.tokenMgr.authSocketsEmit('collections', this.collections);
    try {
      await this.dbMgr.replaceRecord('collections', id, collection);
    }
    catch (error: any) {
      log.error(`caught exception when updating collection ${id} in database:`, error);
      process.exit(1);
    }
  }



  async deleteCollection(id: string) {
    delete this.collections[id];
    this.tokenMgr.authSocketsEmit('collections', this.collections);
    await this.dbMgr.deleteRecord('collections', id);
    if (id in this.collectionsData) {
      await this.deleteCollectionsData(id);
    }
  }



  async deleteCollectionsData(id: string) {
    delete this.collectionsData[id];
    await this.dbMgr.deleteRecord('collectionsData', id);
  }



  async addCollectionsData(collectionData: CollectionData) {
    // receives a full collectionsData object, saves it here, and upserts it in the database
    const id = collectionData.id;
    this.collectionsData[id] = collectionData;
    await this.dbMgr.insertOrUpdateRecord(
      'collectionsData',
      id,
      {
        id,
        data: JSON.stringify(collectionData)
      });
  }



  async editCollectionsData(id: string, collectionData: CollectionData) {
    this.collectionsData[id] = collectionData;
    await this.dbMgr.replaceRecord(
      'collectionsData',
      id,
      {
        id,
        data: JSON.stringify(collectionData)
      }
    );
  }



  async addFeed(feed: Feed) {
    const id = feed.id;
    this.feeds[id] = feed;
    this.tokenMgr.authSocketsEmit('feeds', this.feeds);
    await this.dbMgr.insertRecord('feeds', feed);
  }



  async editFeed(feed: Feed) {
    const id = feed.id;
    this.feeds[id] = feed;
    this.tokenMgr.authSocketsEmit('feeds', this.feeds);
    await this.dbMgr.replaceRecord('feeds', id, feed);
  }



  async deleteFeed(id: string) {
    delete this.feeds[id];
    this.tokenMgr.authSocketsEmit('feeds', this.feeds);
    await this.dbMgr.deleteRecord('feeds',id);
  }



  get nwEnabled(): boolean {
    return this.serviceTypes.nw;
  }
  
  
  
  get saEnabled(): boolean {
    return this.serviceTypes.sa;
  }



  getTokenManager(): TokenManager {
    return this.tokenMgr;
  }



  getJwtPrivateKey(): string {
    return this.jwtPrivateKey;
  }



  getJwtPublicKey(): string {
    return this.jwtPublicKey;
  }



  getInternalPublicKey(): string {
    return this.internalPublicKey;
  }



  getUseCases(): ClientUseCases {
    return {
      useCases: this._useCases,
      useCasesObj: this._useCasesObj
    };
  }



  getMongoConfig() {
    return this.mongoConfig;
  }



  getServiceTypes(): typeof ServiceTypes {
    return this.serviceTypes;
  }



  setRollingHandler(handler: RollingCollectionHandler) {
    this.rollingHandler = handler;
  }



  getFeed(id: string): Feed {
    const feed = this.feeds[id];
    if (!feed) {
      throw new Error(`Feed ${id} not found`);
    }
    return feed;
  }



  getFeeds(): Record<string, Feed> {
    return this.feeds;
  }
  
  
  
  getScheduledFeeds(): Record<string, ScheduledFeed> {
    const temp: Record<string, ScheduledFeed> = {};
    Object.entries(this.feeds)
      .filter( ([,feed]) => feed.type === 'scheduled')
      .forEach( ([id, feed]) => temp[id] = feed as ScheduledFeed);
    return temp;
  }



  decrypt(value: string): string {
    return this.decryptor.decrypt(value, 'utf8');
  }



  hasUseCase(name: string): boolean {
    return name in this._useCasesObj;
  }



  getUseCase(name: string): UseCase {
    if (!this.hasUseCase(name)) {
      throw new Error('Use Case not defined');
    }
    return this._useCasesObj[name];
  }
}
