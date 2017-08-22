#!/usr/bin/env python

import os
import sys
import socket
import json
import urllib
import time
import calendar
import asyncore
from fetcher import Fetcher
from communicator import communicator
from pprint import pprint, pformat
import logging
import signal

#sys.exit(1)

def sigIntHandler(signal, frame):
  log.info("Worker terminated cleanly by interrupt")
  log.info("Exiting with code 0")
  sys.exit(0)

def configCallback(cfg):
  log.debug("Configuration received")
  #pprint(cfg)
  configReceived(cfg)

def configReceived(cfgObj):
  try:
    '''select * where (time='2017-May-02 14:00:00'-'2017-May-02 14:59:59') && (vis.level exists)'''
    #query = '''select * where (time='%s'-'%s') && (vis.level exists)''' % (oneHourAgoStr, curtimeStr)
    #query = '''select sessionid where (time='%s'-'%s') && (vis.level exists)''' % (oneHourAgoStr, curtimeStr)

    cfg = cfgObj['workerConfig']
    password = cfg['password']
    cfg.pop('password', None)
    log.debug(pformat(cfg))

    outputDir = cfg['collectionsDir']

    ignoredSessions = [] #used by rolling collections
    #type=cfg['type']
    #if type == 'fixed':
    timeformatter='%Y-%B-%d %H:%M:%S'
    timeBegin = time.gmtime( cfg['timeBegin'] )
    timeBeginStr = time.strftime(timeformatter, timeBegin)
    timeEnd = time.gmtime( cfg['timeEnd'] )
    timeEndStr = time.strftime(timeformatter,timeEnd)
    timeClause = "time='%s'-'%s'" % (timeBeginStr, timeEndStr)
     
    log.debug("timeClause: " + timeClause)

    directory = outputDir + '/' + cfg['id']
    try:
      os.makedirs(directory)
    except Exception as e:
      pass
    query = 'select * where (%s) && (%s)' % (timeClause, cfg['query'])
    queryEnc = urllib.quote_plus(query)
    log.info("Query: " + query)
    log.debug("queryEnc: " + queryEnc)
    
    #sys.exit(1)

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
  
    baseUrl = proto + host + ':' + port

    fetcher = Fetcher(client, baseUrl, user, password, directory, minX, minY, gsPath, pdftotextPath, unrarPath, imageLimit)
    log.info("Executing query")
    time0 = time.time()
    numResults = fetcher.runQuery(queryEnc)
    log.info(str(numResults) + " sessions returned from query")
    time1 = time.time()
    log.debug("Query completed in " + str(time1 - time0) + " seconds")
    #pprint(fetcher.sessions)

    log.info("Pulling files from sessions")
    time0 = time.time()
    fetcher.pullFiles(distillationTerms, regexDistillationTerms, ignoredSessions, md5Hashes=md5Hashes, sha1Hashes=sha1Hashes, sha256Hashes=sha256Hashes)
    time1 = time.time()
    log.debug("Pulled files in " + str(time1 - time0) + " seconds")
    #pprint(fetcher.sessions)
    #client.close()
    #asyncore.close_all()
    #asyncore.close_all()
    log.debug("Handling close")
    client.handle_close()
    #client.close_when_done()

  except Exception as e:
    log.exception("Exception in configReceived() - exiting worker: " + str(e) )
    #raise
    #asyncore.close_all()
    #client.close()
    #asyncore.close_all()
    log.debug("Handling close")
    client.handle_close()
    log.debug("Exiting")
    #client.close_when_done()
    sys.exit(1)

 
if __name__ == "__main__":
  if len(sys.argv) == 1:
    print "Argument must be a path to a UNIX socket"
    sys.exit(1)
  try:
    #Set up logging
    log = logging.getLogger()
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s 221b_worker     %(levelname)-10s %(message)s')
    handler.setFormatter(formatter)
    log.setLevel(logging.DEBUG)
    log.addHandler(handler)

    #Register handler for SIGINT
    signal.signal(signal.SIGINT, sigIntHandler)

    #Handle rest of startup
    log.info("221b_worker is starting")
    socketFile = sys.argv[1]
    client = communicator(socketFile, configCallback)
    asyncore.loop()
    log.info("Exiting 221b_worker with code 0");
    sys.exit(0)
  except Exception as e:
    log.exception("General exception: " + str(e) )
    