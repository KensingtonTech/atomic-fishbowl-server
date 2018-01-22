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

def sigIntHandler(signal, frame):
  log.info("Feeder terminated cleanly by interrupt")
  log.info("Exiting with code 0")
  configSocket.handle_close()
  hashSocket.handle_close()
  sys.exit(0)

def exitWithError(message):
  log.error(message)
  configSocket.write_data(json.dumps( { 'error': message} ) + '\n')
  configSocket.handle_close()
  hashSocket.handle_close()
  sys.exit(1)

def exitWithException(message):
  log.exception(message)
  configSocket.write_data(json.dumps( { 'error': message} ) + '\n')
  configSocket.handle_close()
  hashSocket.handle_close()
  sys.exit(1)

config = {}
feeds = {}
hasher = Hasher()
listenerSocketFile = None
hashSocket = None
feedsDir = None

def configReceived(cfg):
  log.debug("configReceived(): Data received on configuration socket")
  try:
    log.debug('configReceived():\n' + pformat(cfg))
    
    global config
    config = cfg['config']
    
    global feeds
    feeds = cfg['feeds']
    
    global hasher
    global feedsDir
    feedsDir = config['feedsDir']
    hasher.setFeedsDir(feedsDir)
    hasher.updateFeeds(feeds)

    global hashSocket
    hashSocket = HashServer(listenerSocketFile, hasher)

    # tell node.js that we're ready to roll
    configSocket.send( json.dumps( { 'initialized': True, 'feederSocket': listenerSocketFile } ) + '\n' )

  except KeyError as e:
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
    
    global configSocket
    configSocket = Communicator(socketFile, configReceived)
    
    #create a temp unix socket to listen for worker connections
    tempDir = tempfile._get_default_tempdir() + '/'
    global listenerSocketFile
    listenerSocketFile = tempDir + next(tempfile._get_candidate_names()) + '.socket'

    
    asyncore.loop(use_poll=True)
    os.remove(listenerSocketFile)
    log.info("Exiting afb_feeder with code 0")
    sys.exit(0)
  except Exception as e:
    log.exception("Unhandled general exception: " + str(e) )