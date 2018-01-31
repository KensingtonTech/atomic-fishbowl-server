import os
import sys
import json
import logging
from pprint import pprint, pformat
from zlib import adler32

log = logging.getLogger(__name__)

class Hasher():

  def __init__(self):
    self.feedConfig = {} # the feed definitions
    self.feedData = {} # the feeds themselves
    self.feedCRCs = {}

  def setFeedsDir(self, feedsDir):
    self.feedsDir = feedsDir



  def updateFeedFile(self, id):
    log.debug('updateFeedFile(): id: ' + id)
    feed = self.feedConfig[id]
    with open(self.feedsDir + '/' + id + '.feed', 'r', -1 ) as feedFile:
      crc = adler32( feedFile.read() ) #calculate CRC file (faster than hashing, in theory, and is good enough for us)
      if id in self.feedCRCs and self.feedCRCs[id] != crc:
        # this feed content has been updated
        self.feedCRCs[id] = crc
        feedData = { 'md5': {}, 'sha1': {}, 'sha256': {} }
        delimiter = feed['delimiter']
        headerRow = feed['headerRow']
        valueColumn = feed['valueColumn']
        typeColumn = feed['typeColumn']
        friendlyNameColumn = None
        if 'friendlyNameColumn' in feed:
          friendlyNameColumn = feed['friendlyNameColumn']
        
        num = 0
        feedFile.seek(0)
        for line in feedFile.readlines():
          if num == 0 and headerRow == True:
            num += 1
            continue
          splitLine = line.rstrip().split(delimiter)
          hashValue = splitLine[valueColumn].lower()
          hashType = splitLine[typeColumn].lower()
          if friendlyNameColumn and len(splitLine) >= friendlyNameColumn:
            friendlyName = splitLine[friendlyNameColumn]
          else:
            friendlyName = None
          if hashType in ['md5', 'sha1', 'sha256']:
            #self.feedData[id][hashType][hashValue] = friendlyName
            feedData[hashType][hashValue] = friendlyName
          num += 1
        self.feedData[id] = feedData

        # pre-calculate what hash types are specified in feeds
        feedTypes = { 'md5': False, 'sha1': False, 'sha256': False }
        feedData = self.feedData[id]
        if len(feedData['md5']) > 0:
          feedTypes['md5'] = True
        if len(feedData['sha1']) > 0:
          feedTypes['sha1'] = True
        if len(feedData['sha256']) > 0:
          feedTypes['sha256'] = True
        self.feedConfig[id]['feedTypes'] = feedTypes
        




  def updateFeed(self, feed):
    id = feed['id']
    self.feedConfig[id] = feed
    with open(self.feedsDir + '/' + id + '.feed', 'r', -1 ) as feedFile:
      crc = adler32( feedFile.read() ) #calculate CRC file (faster than hashing, in theory, and is good enough for us)
      self.feedCRCs[id] = crc
      feedData = { 'md5': {}, 'sha1': {}, 'sha256': {} }
      delimiter = feed['delimiter']
      headerRow = feed['headerRow']
      valueColumn = feed['valueColumn']
      typeColumn = feed['typeColumn']
      friendlyNameColumn = None
      if 'friendlyNameColumn' in feed:
        friendlyNameColumn = feed['friendlyNameColumn']
      
      num = 0
      feedFile.seek(0)
      for line in feedFile.readlines():
        if num == 0 and headerRow == True:
          num += 1
          continue
        splitLine = line.rstrip().split(delimiter)
        hashValue = splitLine[valueColumn].lower()
        hashType = splitLine[typeColumn].lower()
        if friendlyNameColumn and len(splitLine) >= friendlyNameColumn:
          friendlyName = splitLine[friendlyNameColumn]
        else:
          friendlyName = None
        if hashType in ['md5', 'sha1', 'sha256']:
          #self.feedData[id][hashType][hashValue] = friendlyName
          feedData[hashType][hashValue] = friendlyName
        num += 1
      self.feedData[id] = feedData

      # pre-calculate what hash types are specified in feeds
      feedTypes = { 'md5': False, 'sha1': False, 'sha256': False }
      feedData = self.feedData[id]
      if len(feedData['md5']) > 0:
        feedTypes['md5'] = True
      if len(feedData['sha1']) > 0:
        feedTypes['sha1'] = True
      if len(feedData['sha256']) > 0:
        feedTypes['sha256'] = True
      self.feedConfig[id]['feedTypes'] = feedTypes




  def delFeed(self, id):
    self.feedConfig.pop(id)
    self.feedData.pop(id)
    self.feedCRCs.pop(id)

  
  
  def updateFeeds(self, feeds):
    # this should only run on startup now
    self.feedConfig = feeds

    for id in feeds:
      feed = feeds[id]
      #log.debug('\n' + pformat(feed) )
      filename = self.feedsDir + '/' + id + '.feed' 
      with open(filename, 'r', -1 ) as feedFile:
        feedFile.seek(0)
        #pprint(feedFile.readlines())
        self.feedData[id] = { 'md5': {}, 'sha1': {}, 'sha256': {} }
        
        crc = adler32( feedFile.read() ) #calculate CRC file (faster than hashing, in theory, and is good enough for us)
        self.feedCRCs[id] = crc
        
        #pprint(self.feedData)
        delimiter = feed['delimiter']
        headerRow = feed['headerRow']
        valueColumn = feed['valueColumn']
        typeColumn = feed['typeColumn']
        friendlyNameColumn = None
        if 'friendlyNameColumn' in feed:
          friendlyNameColumn = feed['friendlyNameColumn']

        num = 0

        feedFile.seek(0)
        for line in feedFile.readlines():
          if num == 0 and headerRow == True:
            num += 1
            continue
          splitLine = line.rstrip().split(delimiter)
          hashValue = splitLine[valueColumn].lower()
          hashType = splitLine[typeColumn].lower()
          #print "hashValue: " + hashValue
          #print "hashType: " + hashType
          if friendlyNameColumn and len(splitLine) >= friendlyNameColumn:
            friendlyName = splitLine[friendlyNameColumn]
          else:
            friendlyName = None
          if hashType in ['md5', 'sha1', 'sha256']:
            self.feedData[id][hashType][hashValue] = friendlyName
          num += 1

        feedTypes = { 'md5': False, 'sha1': False, 'sha256': False }
        feedData = self.feedData[id]
        if len(feedData['md5']) > 0:
          feedTypes['md5'] = True
        if len(feedData['sha1']) > 0:
          feedTypes['sha1'] = True
        if len(feedData['sha256']) > 0:
          feedTypes['sha256'] = True
        self.feedConfig[id]['feedTypes'] = feedTypes
    
    #pprint(self.feedConfig)
    #pprint(self.feedData)
    #pprint (self.feedCRCs)
   




  def updateFeedsOld(self, feeds):
    # this should only run on startup now
    #self.feedConfig = feeds

    for id in feeds:
      feed = feeds[id]
      #log.debug('\n' + pformat(feed) )
      with open(self.feedsDir + '/' + id + '.feed', 'r', -1 ) as feedFile:
        self.feedData[id] = { 'md5': {}, 'sha1': {}, 'sha256': {} }
        
        crc = adler32( feedFile.read() ) #calculate CRC file (faster than hashing, in theory, and is good enough for us)
        if id in self.feedCRCs and self.feedCRCs[id] == crc:
          # this feed content hasn't been updated, but check to see if the definition has
          oldFeed = { 'delimiter': self.feedConfig[id]['delimiter'], 'headerRow': self.feedConfig[id]['headerRow'], 'valueColumn': self.feedConfig[id]['valueColumn'], 'typeColumn': self.feedConfig[id]['typeColumn'], 'friendlyNameColumn': self.feedConfig[id]['friendlyNameColumn'] }
          newFeed = { 'delimiter': feeds[id]['delimiter'], 'headerRow': feeds[id]['headerRow'], 'valueColumn': feeds[id]['valueColumn'], 'typeColumn': feeds[id]['typeColumn'], 'friendlyNameColumn': feeds[id]['friendlyNameColumn'] }
          if cmp(oldFeed, newFeed) == 0:
            # the feed definition hasn't changed, so move on to the next feed
            next
          else:
            # the feed definition has changed, so proceed with processing it
            self.feedConfig[id] = feed

        elif id in self.feedCRCs and self.feedCRCs[id] != crc:
          # this feed content has been updated
          self.feedConfig[id] = feed
          self.feedCRCs[id] = crc

        else:
          #this is a new feed
          self.feedConfig[id] = feed
          self.feedCRCs[id] = crc

        #self.feedConfig = feeds
        
        #pprint(self.feedData)
        delimiter = feed['delimiter']
        headerRow = feed['headerRow']
        valueColumn = feed['valueColumn']
        typeColumn = feed['typeColumn']
        friendlyNameColumn = None
        if 'friendlyNameColumn' in feed:
          friendlyNameColumn = feed['friendlyNameColumn']

        num = 0

        feedFile.seek(0)
        for line in feedFile.readlines():
          if num == 0 and headerRow == True:
            num += 1
            continue
          splitLine = line.rstrip().split(delimiter)
          hashValue = splitLine[valueColumn - 1].lower()
          hashType = splitLine[typeColumn - 1].lower()
          if friendlyNameColumn and len(splitLine) >= friendlyNameColumn:
            friendlyName = splitLine[friendlyNameColumn - 1]
          else:
            friendlyName = None
          if hashType in ['md5', 'sha1', 'sha256']:
            self.feedData[id][hashType][hashValue] = friendlyName

          num += 1
    
    #pprint(self.feedConfig)
    #pprint(self.feedData)
    #pprint (self.feedCRCs)

    # clean out feedData to remove any deleted feeds
    feedsIdsToPop = []
    for feedId in self.feedData:
      if feedId not in self.feedConfig: # this means our feed has been deleted
        feedsIdsToPop.append(feedId)
    for feedId in feedsIdsToPop:
      self.feedData.pop(feedId)
      self.feedCRCs.pop(feedId)
    
    # pre-calculate what hash types are specified in feeds
    for feedId in self.feedData:
      feedTypes = { 'md5': False, 'sha1': False, 'sha256': False }
      feed = self.feedData[feedId]
      if len(feed['md5']) > 0:
        feedTypes['md5'] = True
      if len(feed['sha1']) > 0:
        feedTypes['sha1'] = True
      if len(feed['sha256']) > 0:
        feedTypes['sha256'] = True
      self.feedConfig[feedId]['feedTypes'] = feedTypes

    #print('feedConfig:\n' + pformat(self.feedConfig))

  def getTypes(self, feedId):
    #log.debug('Hasher: getTypes(): feedId: ' + feedId)
    return { 'types' : self.feedConfig[feedId]['feedTypes'] }

  def submit(self, req):
    #log.debug('Hasher: submit(): req:\n' + pformat(req))

    id = req['id']
    hash = req['hash']
    hashType = req['type']
    feedId = req['feedId']

    res = { 'id': id, 'hash': hash, 'type': hashType }
    if feedId in self.feedData and hash in self.feedData[feedId][hashType]:
      res['found'] = True
      friendly = self.feedData[feedId][hashType][hash]
      if friendly != None:
        res['friendlyName'] = friendly
    else:
      res['found'] = False
    return res

  def isInitialized(self):
    if hasattr(self, 'feedsDir') and hasattr(self, 'feedData') and hasattr(self, 'feedConfig'):
      return True
    return False