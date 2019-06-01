class DatabaseManager {

  constructor(afbconfig) {
    this.mongo = require('mongodb').MongoClient;
    this.afbconfig = afbconfig;
    this._db;
  }


  async connectToDB() {
    winston.debug('Initializing mongo db and reading settings');

    const sleep = require('./sleep');
    
    // We use mongoose for auth, and MongoClient for everything else.  This is because Passport-Local Mongoose required it, and it is ill-suited to the free-formish objects which we want to use.
    let mongoUrl = `mongodb://${this.afbconfig.dbconfig.host}:${this.afbconfig.dbconfig.port}/afb`;
    if (this.afbconfig.dbconfig.authentication.enabled) {
      mongoUrl = `mongodb://${this.afbconfig.dbconfig.authentication.user}:${this.afbconfig.dbconfig.authentication.password}@${this.afbconfig.dbconfig.host}:${this.afbconfig.dbconfig.port}/afb?authSource=admin`;
    }
 
    for (let connectionAttempts = 0; connectionAttempts <= 3; connectionAttempts++ ) {
      try {
        this._db = await this.mongo.connect(mongoUrl);
        winston.debug('MongoManager: connectToDB(): Connected successfully to MongoDB');
        // await processMongoCollections();
        // await mongooseInit();
        break;
      }
      catch (err) {
        // winston.error(err);
        if (connectionAttempts == 3) {
          winston.error('Maximum retries reached whilst connecting to MongoDB.  Exiting with code 1');
          winston.error(err.message);
          process.exit(1);
        }
        winston.info('Could not connect to MongoDB.  Retrying in 3 seconds');
        sleep(3);
      }
    }
  }



  get db() {
    return this._db;
  }



  updateOnlyRecord(collection, document) {
    return this._db.collection(collection).updateOne( {}, document);
  }



  updateRecord(collection, id, document) {
    return this._db.collection(collection).updateOne( { id: id }, { $set: document });
  }



  replaceRecord(collection, id, document) {
    return this._db.collection(collection).replaceOne( { id: id }, document );
  }



  deleteRecord(collection, id) {
    return this._db.collection(collection).remove( { id: id } );
  }



  insertRecord(collection, document) {
    return this._db.collection(collection).insertOne(document);
  }



  insertOrUpdateRecord(collection, id, document) {
    return this._db.collection(collection).updateOne( { id: id }, document, { upsert: true } );
  }



  getOnlyRecord(collection) {
    return this._db.collection(collection).findOne();
  }



  getAllRecords(collection) {
    // returns an array of all records in a collection
    return this._db.collection(collection).find( {} ).toArray();
  }

}

module.exports = DatabaseManager;