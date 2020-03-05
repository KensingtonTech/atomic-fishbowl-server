#!/usr/bin/env python3
import json
import sys
import os
from pprint import pprint
from collections import OrderedDict
from pymongo import MongoClient

host = 'localhost'
host = 'afb-mongo'
port = '27017'
user = 'admin'
password = 'kentech0'
# mongo = MongoClient('mongodb://{}:{}'.format(host, port))
mongo = MongoClient('mongodb://{}:{}@{}:{}'.format(user, password, host, port))
db = mongo['afb']

preferences = db.preferences.find_one({})

#pprint(preferences)

preferences['firstRun'] = 1583340251

prefs_id = preferences['_id']

#pprint(preferences)

db.preferences.update_one({'_id': prefs_id}, {"$set": preferences}, upsert=False)



#for doc in col:
#  # pprint(doc)
#  collectionDefs.append(doc)

#pprint(collectionDefs)

"""
for d in collectionDefs:
  #pprint(d)
  #d[u'serviceType'] = u'nw'
  id = d['id']
  data = json.loads(d['data'])
  data[u'serviceType'] = u'nw'
  d['data'] = json.dumps(data)
  db.get_collection('collectionsData').update_one({'id': id}, { '$set': d } )
"""


#pprint(collectionDefs[15])




#collectionsFilename = './etc/collections.cfg'
#collectionDefsFilename = './etc/collectiondefs.cfg'

#collectionsFile = open(collectionsFilename, 'rb')
#collectionDefsFile = open(collectionDefsFilename, 'rb')

#collections = json.loads(collectionsFile.read(), object_pairs_hook=OrderedDict)
#collectionDefs = json.loads(collectionDefsFile.read(), object_pairs_hook=OrderedDict)

"""print "Converting collections..."
for c in collections:
  #pprint(collections[c])
  print "Inserting collection with id",c
  db.collections.insert_one(collections[c])
"""

"""
print "Converting collectionDefs..."  
for id in collectionDefs:
  #pprint(collectionDefs[c])
  #print id
  #collectionDefs[id]['id'] = id
  #print collectionDefs[id]['id']
  data = json.dumps(collectionDefs[id])
  #print data
  colDef = { 'id': id, 'data': data}
  #pprint(colDef)
  db.collectionDefs.insert_one(colDef)
"""