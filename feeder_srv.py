#!/usr/bin/env python

import os
import sys
import socket
import json
import asyncore
from feeder_communicator import Communicator, HashServer
from feeder_hasher import Hasher
from pprint import pprint, pformat
import logging
import signal
import tempfile

config = {}
feeds = {}
hasher = Hasher()
listenerSocketFile = None
hashCommunicator = None
configCommunicator = None
feedsDir = None
initialized = False

def sigIntHandler(signal, frame):
  log.info("Feeder terminated cleanly by interrupt")
  log.info("Exiting with code 0")
  configCommunicator.handle_close()
  hashCommunicator.handle_close()
  sys.exit(0)

def exitWithError(message):
  log.error(message)
  configCommunicator.write_data(json.dumps( { 'error': message} ) + '\n')
  configCommunicator.handle_close()
  hashCommunicator.handle_close()
  sys.exit(1)

def exitWithException(message):
  log.exception(message)
  configCommunicator.write_data(json.dumps( { 'error': message} ) + '\n')
  configCommunicator.handle_close()
  hashCommunicator.handle_close()
  sys.exit(1)

def configReceived(cfg):
  log.debug("configReceived(): Data received on configuration socket")
  try:
    log.debug('configReceived():\n' + pformat(cfg))
    global hasher
    
    if 'config' in cfg:
      global config
      config = cfg['config']
      if 'feedsDir' in config:
        global feedsDir
        feedsDir = config['feedsDir']
        hasher.setFeedsDir(feedsDir)
    
    if 'feeds' in cfg:
      global feeds
      feeds = cfg['feeds']    
      hasher.updateFeeds(feeds)

    if 'new' in cfg:
      feed = cfg['feed']
      hasher.updateFeed(feed) # update and add are exactly the same

    if 'update' in cfg:
      feed = cfg['feed']
      hasher.updateFeed(feed)

    if 'updateFile' in cfg:
      id = cfg['id']
      hasher.updateFeedFile(id)

    if 'delete' in cfg:
      id = cfg['id']
      hasher.delFeed(id)

    # tell node.js that we're ready to roll
    global initialized
    if not initialized and hasher.isInitialized():
      initialized = True
      configCommunicator.send( json.dumps( { 'initialized': True, 'feederSocket': listenerSocketFile } ) + '\n' )
    else:
      configCommunicator.send( json.dumps( { 'initialized': False } ) + '\n' )

  except KeyError as e:
    raise
    error = 'ERROR: Missing critical configuration data: ' + str(e)
    exitWithError(error)


def main():
  if len(sys.argv) == 1:
    print "Argument must be a path to a UNIX socket"
    sys.exit(1)
  try:
    #Set up logging
    global log
    log = logging.getLogger()
    handler = logging.StreamHandler()
    formatStr = '%(asctime)s afb_feeder    %(levelname)-10s %(message)s'
    if 'SYSTEMD' in os.environ:
      formatStr = 'afb_feeder    %(levelname)-10s %(message)s'
    formatter = logging.Formatter(formatStr)
    handler.setFormatter(formatter)

    log.setLevel(logging.DEBUG)
    #log.setLevel(logging.INFO) #for testing

    try:
      NODE_ENV = os.environ['NODE_ENV']
      if NODE_ENV == 'production':
        log.setLevel(logging.INFO)
    except KeyError:
      pass
    
    log.addHandler(handler)

    #Register handler for SIGINT
    signal.signal(signal.SIGINT, sigIntHandler)

    #Handle rest of startup
    log.info("afb_feeder is starting")
    socketFile = sys.argv[1]
    
    global configCommunicator
    configCommunicator = Communicator(socketFile, configReceived)
    
    #create a temp unix socket to listen for worker connections
    tempDir = tempfile._get_default_tempdir() + '/'
    global listenerSocketFile
    listenerSocketFile = tempDir + next(tempfile._get_candidate_names()) + '.socket'
    global hashCommunicator
    if hashCommunicator == None:
      hashCommunicator = HashServer(listenerSocketFile, hasher)

    
    asyncore.loop(use_poll=True)
    os.remove(listenerSocketFile)
    log.info("Exiting afb_feeder with code 0")
    sys.exit(0)
  except Exception as e:
    log.exception("Unhandled general exception: " + str(e) )