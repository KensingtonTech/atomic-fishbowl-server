#!/usr/bin/env python

import json
import sys
import os
from pprint import pprint
from collections import OrderedDict

collectionsFilename = './etc/collections.cfg'
collectionDefsFilename = './etc/collectiondefs.cfg'
errorMsg = "Argument must be a valid collection ID"

def main(id):
  collectionsFile = open(collectionsFilename, 'rb')
  collectionDefsFile = open(collectionDefsFilename, 'rb')
  collections = json.loads(collectionsFile.read(), object_pairs_hook=OrderedDict)
  collectionDefs = json.loads(collectionDefsFile.read(), object_pairs_hook=OrderedDict)
  collectionsFile.close()
  collectionDefsFile.close()
  #pprint(collections)
  #pprint(collectionDefs)
  #print type(collections)
  #print type(id)
  if id in collections or id in collectionDefs: #we must make allowances for a condition where a collection exists in only one or the other
    collections.pop(id, None)
    collectionDefs.pop(id, None)
    with open(collectionsFilename, 'w') as f:
      f.write(json.dumps(collections))
    with open(collectionDefsFilename, 'w') as f:
      f.write(json.dumps(collectionDefs))
    print "Deleted", id
  else:
    print errorMsg
    sys.exit(1)
  

if __name__ == "__main__":
  if len(sys.argv) == 1:
    print errorMsg
    sys.exit(1)
  else:
    main(sys.argv[1])