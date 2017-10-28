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
from Crypto.Hash import SHA
from base64 import b64decode

def sigIntHandler(signal, frame):
  log.info("Worker terminated cleanly by interrupt")
  log.info("Exiting with code 0")
  sys.exit(0)

def configCallback(cfg):
  log.debug("Configuration received")
  #pprint(cfg)
  configReceived(cfg)

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
      log.debug(pformat(cfg))

      #decrypt password
      epassword = cfg['password']
      privateKeyFile = cfg['privateKeyFile']
      rsa_key = RSA.importKey(open(privateKeyFile, "rb").read())
      h = SHA.new()
      raw_cipher_data = b64decode(epassword)
      password = pkcs1_unpad(rsa_key.decrypt(raw_cipher_data))
            

      collectionId = cfg['collectionId']
      id = cfg['id']
      state = cfg['state']

      outputDir = cfg['collectionsDir']

      timeformatter='%Y-%B-%d %H:%M:%S'
      timeBegin = time.gmtime( cfg['timeBegin'] )
      timeBeginStr = time.strftime(timeformatter, timeBegin)
      timeEnd = time.gmtime( cfg['timeEnd'] )
      timeEndStr = time.strftime(timeformatter,timeEnd)
      timeClause = "time='%s'-'%s'" % (timeBeginStr, timeEndStr)
      
      log.debug("timeClause: " + timeClause)

      directory = outputDir + '/' + id
      try:
        os.makedirs(directory)
      except Exception as e:
        pass
      query = 'select * where (%s) && (%s)' % (timeClause, cfg['query'])
      queryEnc = urllib.quote_plus(query)
      log.info("Query: " + query)
      log.debug("queryEnc: " + queryEnc)
      
      proto='http://'
      if 'ssl' in cfg and cfg['ssl'] == True:
        proto='https://'
      host = cfg['host']
      port = str(cfg['port'])
      user = cfg['user']
      minX = cfg['minX']
      minY = cfg['minY']
      gsPath = cfg['gsPath']
      pdftotextPath = cfg['pdftotextPath']
      unrarPath = cfg['unrarPath']
      imageLimit = int(cfg['imageLimit'])
      
      distillationEnabled = cfg['distillationEnabled']
      distillationTerms = []
      if distillationEnabled:
        distillationTerms = cfg['distillationTerms']
      
      regexDistillationEnabled = cfg['regexDistillationEnabled']
      regexDistillationTerms = []
      if regexDistillationEnabled:
        regexDistillationTerms = cfg['regexDistillationTerms']
        
      md5Enabled = cfg['md5Enabled']
      md5Hashes = []
      if md5Enabled:
        md5Hashes = cfg['md5Hashes']
      
      sha1Enabled = cfg['sha1Enabled']
      sha1Hashes = []
      if sha1Enabled:
        sha1Hashes = cfg['sha1Hashes']
        
      sha256Enabled = cfg['sha256Enabled']
      sha256Hashes = []
      if sha256Enabled:
        sha256Hashes = cfg['sha256Hashes']

      summaryTimeout = int(cfg['summaryTimeout'])
      queryTimeout = int(cfg['queryTimeout'])
      contentTimeout = int(cfg['contentTimeout'])

    except KeyError as e:
      error = 'ERROR: Missing critical configuration data: ' + str(e)
      exitWithError(error)
  
    baseUrl = proto + host + ':' + port
    fetcher = Fetcher(client, collectionId, baseUrl, user, password, directory, minX, minY, gsPath, pdftotextPath, unrarPath, imageLimit, summaryTimeout, queryTimeout, contentTimeout)
    
    ###QUERY DATA###
    log.info("Executing query")
    client.write_data(json.dumps( { 'collection': { 'id': collectionId, 'state': 'querying' }} ) + '\n') #Tell client that we're querying
    time0 = time.time()
    numResults = fetcher.runQuery(queryEnc)
    log.info(str(numResults) + " sessions returned from query")
    time1 = time.time()
    log.info("Query completed in " + str(time1 - time0) + " seconds")

    ###PULL FILES###
    if (numResults > 0):
      log.info("Extracting files from sessions")
      client.write_data(json.dumps( { 'collection': { 'id': collectionId, 'state': state }} ) + '\n')
      time0 = time.time()
      fetcher.pullFiles(distillationTerms, regexDistillationTerms, md5Hashes=md5Hashes, sha1Hashes=sha1Hashes, sha256Hashes=sha256Hashes)
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
    formatStr = '%(asctime)s 221b_worker     %(levelname)-10s %(message)s'
    if 'SYSTEMD' in os.environ:
      formatStr = '221b_worker     %(levelname)-10s %(message)s'
    formatter = logging.Formatter(formatStr)
    #formatter = logging.Formatter('%(asctime)s 221b_worker     %(levelname)-10s %(message)s')
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
    log.info("221b_worker is starting")
    socketFile = sys.argv[1]
    global client
    client = communicator(socketFile, configCallback)
    asyncore.loop()
    log.info("Exiting 221b_worker with code 0")
    sys.exit(0)
  except Exception as e:
    log.exception("Unhandled general exception: " + str(e) )