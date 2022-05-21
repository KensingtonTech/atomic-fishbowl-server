#!/usr/bin/env python

import json
import sys
import os
from pprint import pprint
from collections import OrderedDict

collectionsFilename = './etc/collections.cfg'
collectionDefsFilename = './etc/collectiondefs.cfg'

collectionsFile = open(collectionsFilename, 'rb')
collectionDefsFile = open(collectionDefsFilename, 'rb')

collections = json.loads(collectionsFile.read(), object_pairs_hook=OrderedDict)
collectionDefs = json.loads(collectionDefsFile.read(), object_pairs_hook=OrderedDict)

for c in collections:
  print collections[c]['name']
  print "\tName:",collections[c]['name']
  print "\tID:",collections[c]['id']
  print "\tState:",collections[c]['state']
  print "\tServer:",collections[c]['nwserverName']
  print "\tServerID:",collections[c]['nwserver']
  print "\tQuery:",collections[c]['query']
  print "\tSession Limit:",collections[c]['sessionLimit']

  print "\tStats:"
  
  i = 0
  for img in collectionDefs[collections[c]['id']]['images']:
    if img['contentType'] == 'image':
      i += 1

  p = 0
  for img in collectionDefs[collections[c]['id']]['images']:
    if img['contentType'] == 'pdf':
      p += 1

  print "\t\tImages: " + str(i)
  print "\t\tPDF's: " + str(p)
  print "\n"