import log from './logging.js';
import { sleep } from './utils.js';
import mongo from 'mongodb';
import process from 'process';
import { MongoDBConfig } from './configuration-manager.js';
const { MongoClient } = mongo;


export class DatabaseManager {

  private client!: mongo.MongoClient;
  private db!: mongo.Db;

  async connectToDB(mongoConfig: MongoDBConfig) {
    log.debug('Initializing mongo db and reading settings');
    
    // We use mongoose for auth, and MongoClient for everything else.  This is because Passport-Local Mongoose required it, and it is ill-suited to the free-formish objects which we want to use.
    const mongoUrl = mongoConfig.authentication.enabled
      ? `mongodb://${mongoConfig.authentication.user}:${mongoConfig.authentication.password}@${mongoConfig.host}:${mongoConfig.port}/afb?authSource=admin`
      : `mongodb://${mongoConfig.host}:${mongoConfig.port}/afb`;
 
    for (let connectionAttempts = 0; connectionAttempts <= 3; connectionAttempts++ ) {
      try {
        this.client = await MongoClient.connect(mongoUrl);
        this.db = this.client.db('afb');
        log.debug('MongoManager: connectToDB(): Connected successfully to MongoDB');
        break;
      }
      catch (error: any) {
        if (connectionAttempts === 3) {
          log.error('Maximum retries reached whilst connecting to MongoDB.  Exiting with code 1');
          log.error(error.message ?? error);
          process.exit(1);
        }
        log.info('Could not connect to MongoDB.  Retrying in 3 seconds');
        await sleep(3000);
      }
    }
  }



  updateOnlyRecord(collection: string, document: unknown) {
    return this.db.collection(collection).updateOne( {}, { $set: document } );
  }



  updateRecord(collection: string, id: string, document: unknown) {
    return this.db.collection(collection).updateOne( { id }, { $set: document });
  }



  replaceRecord(collection: string, id: string, document: any) {
    return this.db.collection(collection).replaceOne( { id }, document );
  }



  deleteRecord(collection: string, id: string) {
    return this.db.collection(collection).deleteOne( { id } );
  }



  insertRecord(collection: string, document: any) {
    return this.db.collection(collection).insertOne(document);
  }



  insertOrUpdateRecord(collection: string, id: string, document: unknown) {
    return this.db.collection(collection).updateOne( { id }, { $set: document }, { upsert: true } );
  }



  getOnlyRecord(collection: string) {
    return this.db.collection(collection).findOne();
  }



  getAllRecords(collection: string) {
    // returns an array of all records in a collection
    return this.db.collection(collection).find( {} ).toArray();
  }

}
