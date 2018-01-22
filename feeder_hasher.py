import os
import sys
import json
import logging
from pprint import pprint, pformat

log = logging.getLogger(__name__)

class Hasher():

  def __init__(self):
    self.feedConfig = {}
    self.feedData = {}

  def setFeedsDir(self, feedsDir):
    self.feedsDir = feedsDir

  def updateFeeds(self, feeds):
    self.feedConfig = feeds

    for id in self.feedConfig:
      feed = self.feedConfig[id]
      #log.debug('\n' + pformat(feed) )
      with open(self.feedsDir + '/' + feed['internalFilename'], 'r', -1 ) as feedFile:
        self.feedData[id] = { 'md5': {}, 'sha1': {}, 'sha256': {} }
        #pprint(self.feedData)
        delimiter = feed['delimiter']
        headerRow = feed['headerRow']
        valueColumn = feed['valueColumn']
        typeColumn = feed['typeColumn']
        friendlyNameColumn = None
        if 'friendlyNameColumn' in feed:
          friendlyNameColumn = feed['friendlyNameColumn']

        num = 0

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
    
    # pprint(self.feedData)
    
    # calculate what hash types are specified in feeds
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

