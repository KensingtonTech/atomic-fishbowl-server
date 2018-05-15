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



def systemdLevelFormatter(level):
  if level == 50: # CRITICAL or FATAL
    return '<2>'
  elif level == 40: # ERROR
    return '<3>'
  elif level == 30: # WARNING or WARN
    return '<4>'
  elif level == 20: # INFO
    return '<6>'
  elif level == 10: # DEBUG
    return '<7>'



class SystemdFormatter(logging.Formatter):

  def __init__(self, fmt=None, datefmt=None):
    logging.Formatter.__init__(self, fmt, datefmt)

  def formatOld(self, record):
    return logging.Formatter.format(self, record)

  def format(self, record):
    record.message = record.getMessage()
    if self.usesTime():
      record.asctime = self.formatTime(record, self.datefmt)
    try:
      #s = self._fmt % record.__dict__
      s = systemdLevelFormatter(record.levelno) + self._fmt % record.__dict__
    except UnicodeDecodeError as e:
      # Issue 25664. The logger name may be Unicode. Try again ...
      try:
        record.name = record.name.decode('utf-8')
        #s = self._fmt % record.__dict__
        s = systemdLevelFormatter(record.levelno) + self._fmt % record.__dict__
      except UnicodeDecodeError:
        raise e

    if record.exc_info:
      # Cache the traceback text to avoid converting it multiple times
      # (it's constant anyway)
      if not record.exc_text:
        record.exc_text = self.formatException(record.exc_info)

    if record.exc_text:
      if s[-1:] != "\n":
        s = s + "\n"
      try:
        s = s + record.exc_text
      except UnicodeError:
        # Sometimes filenames have non-ASCII chars, which can lead
        # to errors when s is Unicode and record.exc_text is str
        # See issue 8924.
        # We also use replace for when there are multiple
        # encodings, e.g. UTF-8 for the filesystem and latin-1
        # for a script. See issue 13232.
        s = s + record.exc_text.decode(sys.getfilesystemencoding(), 'replace')
    return s



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
  # log.debug("configReceived(): Data received on configuration socket")
  try:
    #log.debug('configReceived():\n' + pformat(cfg))
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
    log.setLevel(logging.DEBUG)
    
    handler = logging.StreamHandler()
    formatStr = '%(asctime)s afb_feeder    %(levelname)-10s %(message)s'
    if 'SYSTEMD' in os.environ:
      from systemd.journal import JournalHandler
      handler = JournalHandler()
      formatStr = 'afb_feeder    %(message)s'
      #formatter = SystemdFormatter(formatStr)

    formatter = logging.Formatter(formatStr)
    handler.setFormatter(formatter)
    log.addHandler(handler)

    #log.setLevel(logging.INFO) #for testing

    try:
      NODE_ENV = os.environ['NODE_ENV']
      if NODE_ENV == 'production' and ( ('AFBDEBUG' not in os.environ) or ('AFBDEBUG' in os.environ and os.environ['AFBDEBUG'] == '0') ):
        log.setLevel(logging.INFO)
    except KeyError:
      pass
    

    #Register handler for SIGINT
    signal.signal(signal.SIGINT, sigIntHandler)

    #Handle rest of startup
    log.info("afb_feeder is starting")
    socketFile = sys.argv[1]
    
    global configCommunicator
    #print "socketFile:", socketFile
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