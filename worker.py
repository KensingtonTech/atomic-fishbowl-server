#!/usr/bin/env python

import os
import sys
import socket
import json
import urllib
import time
import calendar
import asyncore
from worker_fetcher import Fetcher
from worker_communicator import communicator
from pprint import pprint, pformat
import logging
import signal
from Crypto.PublicKey import RSA
from base64 import b64decode

def sigIntHandler(signal, frame):
  log.info("Worker terminated cleanly by interrupt")
  log.info("Exiting with code 0")
  sys.exit(0)

def pkcs1_unpad(text):
  if len(text) > 0 and text[0] == '\x02':
    # Find end of padding marked by nul
    pos = text.find('\x00')
    if pos > 0:
      return text[pos+1:]
  return None

def configReceived(cfgObj):
  try:
    '''select * where (time='2017-May-02 14:00:00'-'2017-May-02 14:59:59') && (vis.level exists)'''
    #query = '''select * where (time='%s'-'%s') && (vis.level exists)''' % (oneHourAgoStr, curtimeStr)
    #query = '''select sessionid where (time='%s'-'%s') && (vis.level exists)''' % (oneHourAgoStr, curtimeStr)

    try:
      cfg = cfgObj['workerConfig']
      log.debug('configReceived: cfg:\n' + pformat(cfg))

      #decrypt password
      ePassword = cfg['password']
      privateKeyFile = cfg['privateKeyFile']
      rsaKey = RSA.importKey(open(privateKeyFile, "rb").read())
      rawCipherData = b64decode(ePassword)
      cfg['dpassword'] = pkcs1_unpad(rsaKey.decrypt(rawCipherData)) # write decrypted password back to config

      # Leave these
      collectionId = cfg['collectionId']
      id = cfg['id']
      state = cfg['state']
      collectionsDir = cfg['collectionsDir']
      timeformatter='%Y-%B-%d %H:%M:%S'
      timeBegin = time.gmtime( cfg['timeBegin'] )
      timeBeginStr = time.strftime(timeformatter, timeBegin)
      timeEnd = time.gmtime( cfg['timeEnd'] )
      timeEndStr = time.strftime(timeformatter,timeEnd)
      timeClause = "time='%s'-'%s'" % (timeBeginStr, timeEndStr)
      log.debug("timeClause: " + timeClause)
      outputDir = collectionsDir + '/' + id
      cfg['outputDir'] = outputDir
      
      try:
        os.makedirs(outputDir)
      except Exception as e:
        pass
      
      query = 'select * where (%s) && (%s)' % (timeClause, cfg['query'])
      cfg['queryEnc'] = urllib.quote_plus(query)
      log.info("Query: " + query)
      #log.debug("queryEnc: " + cfg['queryEnc'])


    except KeyError as e:
      error = 'ERROR: Missing critical configuration data: ' + str(e)
      exitWithError(error)
  
    
    fetcher = Fetcher(cfg, client)

    ###QUERY DATA###
    log.info("Executing query")
    client.write_data(json.dumps( { 'collection': { 'id': collectionId, 'state': 'querying' }} ) + '\n') #Tell client that we're querying
    time0 = time.time()
    numResults = fetcher.runQuery()
    log.info(str(numResults) + " sessions returned from query")
    time1 = time.time()
    log.info("Query completed in " + str(time1 - time0) + " seconds")

    ###PULL FILES###
    if (numResults > 0):
      log.info("Extracting files from sessions")
      client.write_data(json.dumps( { 'collection': { 'id': collectionId, 'state': state }} ) + '\n')
      time0 = time.time()
      fetcher.pullFiles()
      time1 = time.time()
      log.info("Pulled files in " + str(time1 - time0) + " seconds")

    client.handle_close()

  except Exception as e:
    #log.exception("Unhandled exception in configReceived() - exiting worker with code 1: " + str(e) )
    #client.handle_close()
    #sys.exit(1)
    error = "configReceived(): Unhandled exception.  Exiting worker with code 1: " + str(e)
    exitWithException(error)


def exitWithError(message):
  log.error(message)
  client.write_data(json.dumps( { 'error': message} ) + '\n')
  client.handle_close()
  sys.exit(1)

def exitWithException(message):
  log.exception(message)
  client.write_data(json.dumps( { 'error': message} ) + '\n')
  client.handle_close()
  sys.exit(1)

  
def main():
  if len(sys.argv) == 1:
    print "Argument must be a path to a UNIX socket"
    sys.exit(1)
  try:
    #Set up logging
    global log
    log = logging.getLogger()
    handler = logging.StreamHandler()
    formatStr = '%(asctime)s afb_worker    %(levelname)-10s %(message)s'
    if 'SYSTEMD' in os.environ:
      formatStr = 'afb_worker    %(levelname)-10s %(message)s'
    formatter = logging.Formatter(formatStr)
    #formatter = logging.Formatter('%(asctime)s afb_worker    %(levelname)-10s %(message)s')
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
    log.info("afb_worker is starting")
    socketFile = sys.argv[1]
    global client
    client = communicator(socketFile, configReceived)
    asyncore.loop(use_poll=True)
    log.info("Exiting afb_worker with code 0")
    sys.exit(0)
  except Exception as e:
    log.exception("Unhandled general exception: " + str(e) )