import logging
import json
from worker_communicator import FeederCommunicator
from worker_contentobj import ContentObj
from pprint import pprint, pformat

log = logging.getLogger(__name__)

class FeedManager():
 
  def __init__(self, socketFile, callback, endCallback, feedId):
    self.communicator = FeederCommunicator(socketFile, self.onResponse)
    self.socketFile = socketFile
    self.feedId = feedId
    self.counter = 0
    self.requests = {}
    self.callback = callback
    self.endCallback = endCallback
    self.hashTypes = {}
    # preemptively get hash types
    self.communicator.write_data( json.dumps( { 'getTypes' : True, 'feedId': self.feedId } ) + '\n' )



  def getTypes(self):
    return self.hashTypes



  def submit(self, hashValue, hashType, contentObj):
    #log.debug('FeedManager: submit()' )
    self.counter += 1
    req = { 'id': self.counter, 'hash': hashValue, 'type': hashType, 'feedId': self.feedId }
    self.requests[self.counter] = contentObj
    self.communicator.write_data( json.dumps(req) + '\n')



  def onResponse(self, res):
    log.debug('FeedManager: onResponse(): ' + pformat(res) )

    if 'types' in res:
      log.debug('FeedManager: onResponse(): types were found in res.  Setting hashTypes and returning')
      self.hashTypes = res['types']
      return
    
    if 'found' in res and res['found']:
      log.debug('FeedManager: onResponse(): found was found in res and found was true')
      id = res['id']
      contentObj = self.requests[id]
      #del self.requests[id]
      self.requests.pop(id, None)
      self.callback(res, contentObj)

    if 'found' in res and not res['found']:
      log.debug('FeedManager: onResponse(): found was found in res and found was false')
      id = res['id']
      #contentObj = self.requests[id]
      #self.callback(res, contentObj)
      self.requests.pop(id, None)

    log.debug('FeedManager: onResponse(): got to end: self.requests: ' + pformat(self.requests) )



  def end(self):
    log.debug('FeedManager: end(): waiting for all Feeder responses')
    while len(self.requests) != 0:
      #wait for requests to complete
      #log.debug(pformat(self.requests))
      pass
    log.debug('FeedManager: end(): closing communicator')
    #self.communicator.close()
    #self.communicator.handle_close()
    self.endCallback()
