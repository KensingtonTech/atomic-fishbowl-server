import logging
import json
from worker_communicator import FeederCommunicator
from worker_contentobj import ContentObj
from pprint import pprint, pformat

log = logging.getLogger(__name__)

class FeedManager():
 
  def __init__(self, socketFile, callback, feedId):
    self.communicator = FeederCommunicator(socketFile, self.onResponse)
    self.socketFile = socketFile
    self.feedId = feedId
    self.counter = 0
    self.requests = {}
    self.callback = callback
    self.hashTypes = {}
    # preemptively get hash types
    self.communicator.send( json.dumps( { 'getTypes' : True, 'feedId': self.feedId } ) + '\n' )



  def getTypes(self):
    return self.hashTypes



  def submit(self, hashValue, hashType, contentObj):
    #log.debug('FeedManager: submit()' )
    self.counter += 1
    req = { 'id': self.counter, 'hash': hashValue, 'type': hashType, 'feedId': self.feedId }
    self.requests[self.counter] = contentObj
    self.communicator.send( json.dumps(req) + '\n')



  def onResponse(self, res):
    #log.debug('FeedManager: onResponse(): ' + pformat(res) )

    if 'types' in res:
      self.hashTypes = res['types']
      return
    
    if 'found' in res:
      id = res['id']
      contentObj = self.requests[id]
      self.callback(res, contentObj)
      del self.requests[id]



  def end(self):
    log.debug('FeedManager: end(): waiting for all Feeder responses')
    while len(self.requests) != 0:
      #wait for requests to complete
      pass
    self.communicator.close()  