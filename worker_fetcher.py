import logging
import os
import sys
import urllib, urllib2, urlparse
import ssl
import base64
import json
from pprint import pprint, pformat
import cStringIO
from worker_communicator import communicator
import time
import zipfile
from multiprocessing import Pool, Manager, Value, current_process, cpu_count
import socket
from httplib import BadStatusLine
from requests_futures.sessions import FuturesSession
import requests
from worker_contentprocessor import ContentProcessor
from threading import Timer, Thread, Event

#logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()

def unwrapExtractFilesFromMultipart(*arg, **kwarg):
  #print "unwrapExtractFilesFromMultipart()"
  return ContentProcessor.extractFilesFromMultipart(*arg, **kwarg)

def unwrapGo(*arg, **kwarg):
  #log.debug("unwrapGo()")
  return ContentProcessor.go(*arg, **kwarg)

def unwrapPullFiles(*arg, **kwarg):
  #print "unwrapExtractFilesFromMultipart()"
  return ContentProcessor.pullFiles(*arg, **kwarg)

class ApiUnsuccessful(Exception):
  pass






class TimerThread(Thread):

  def __init__(self, event, cb):
    Thread.__init__(self)
    self.stopped = event
    self.cb = cb
    self.daemon = True

  def run(self):
    while not self.stopped.wait(5):
      self.cb()




class Fetcher:

  # Base class for product-specific fetcher classes

  def __init__(self, cfg, communicator):
    self.cfg = cfg
    self.communicator = communicator
    self.cfg['devmode'] = True
    self.pool = Pool()
    self.manager = Manager()
    self.cfg['contentCount'] = self.manager.Value('I', 0)
    self.cfg['contentErrors'] = self.manager.Value('I', 0)
    self.summary = {}
    self.sessions = {}

    self.cfg['thumbnailSize'] = 350, 350
    proto='http://'
    if 'ssl' in cfg and cfg['ssl'] == True:
      proto='https://'
    host = cfg['host']
    port = str(cfg['port'])
    baseUrl = proto + host + ':' + port
    self.cfg['url'] = baseUrl
    
    #convert to integers
    if 'minX' in self.cfg and 'minY' in self.cfg:
      self.cfg['minX'] = int(self.cfg['minX'])
      self.cfg['minY'] = int(self.cfg['minY'])
      log.debug("Fetcher: __init__(): Minimum dimensions are: " + str(self.cfg['minX']) + " x " + str(self.cfg['minY']))
    self.cfg['contentLimit'] = int(self.cfg['contentLimit'])
    # self.cfg['summaryTimeout'] = int(self.cfg['summaryTimeout'])
    self.cfg['queryTimeout'] = int(self.cfg['queryTimeout'])
    self.cfg['contentTimeout'] = int(self.cfg['contentTimeout'])
    self.cfg['maxContentErrors'] = int(self.cfg['maxContentErrors'])

  def exitWithError(self, message):
    log.error(message)
    self.communicator.write_data(json.dumps( { 'error': message} ) + '\n')
    self.communicator.handle_close()
    sys.exit(1)

  def exitWithException(self, message):
    log.exception(message)
    self.communicator.write_data(json.dumps( { 'error': message} ) + '\n')
    self.communicator.handle_close()
    sys.exit(1)

  def sendResult(self, res):
    #log.debug('Fetcher: sendResult()')
    #log.debug( 'Fetcher(): sendResult(): ' + str(type(res)) )
    if res and isinstance(res, list):
      #log.error('Fetcher: sendResult(): Caught error in worker:\n' + str(res))
      for l in res:
        print l.rstrip()
    elif res and len(res['images']) != 0:
      #log.debug("Fetcher: sendResult(): Worker sending update")
      self.communicator.write_data(json.dumps( { 'collectionUpdate': res } ) + '\n')
    elif not res:
      log.debug("SaFetcher: sendResult(): no results")

  def heartbeat(self):
    #log.debug( "heartbeat()" )
    self.communicator.write_data( json.dumps( { 'heartbeat': True } ) + '\n' )

  def terminate(self):
    self.pool.terminate()
    self.pool.join()




















class SaFetcher(Fetcher): # For Solera


  def runQuery(self):
    self.queryTime0 = time.time()
    self.sessionIds = []
    self.extractFilesMap = {}
    self.extractResults = {}
    self.extractionComplete = False
    self.extractFutures = []
    stopFlag = Event()
    timerThread = TimerThread(stopFlag, lambda y=self: self.heartbeat())
    timerThread.start()
    
    
    # URL to call
    url = self.cfg['url'] + '/api/v6/deepsee_reports/report'

    # params
    data = {
      'identityPath': {
        'timespan': {
          'start': self.cfg['time1'],
          'end': self.cfg['time2']
        },
        'field': 'flow_id',
        #'query': self.cfg['saQuery']
        'query': json.loads(self.cfg['query'] )
      },
      'metrics' : '"sessions"',
      'direction' : '"asc"',
      'pageSize': 100,
      'page': 0,
      'restart': True
    }
    #pprint(data)
    post = self.convertToPostBody(data, 'GET')
    #pprint(post)
    #session = FuturesSession(max_workers=cpu_count() )
    #cpucount = cpu_count()
    #if cpucount >= 6:
    #  cpucount = cpucount - 2
    #session = FuturesSession(max_workers=cpucount)
    self.session = FuturesSession()
    session = self.session
    try:
      self.queryDef = { 'url': url, 'auth': ( self.cfg['user'], self.cfg['dpassword'] ), 'data': post, 'verify': False, 'stream': False }

      resultCode = None
      state = None

      while state != 'complete':
        response = requests.post( self.queryDef['url'], auth=self.queryDef['auth'], data=self.queryDef['data'], verify=self.queryDef['verify'], stream=self.queryDef['stream'] )
        #print response.text
        if response.status_code >= 400:
          self.exitWithError('Received HTTP error code on query response: ' + str(response.status_code))
        res = response.json()
        #self.pretty_print_POST(response.request)
        #pprint(res)
        resultCode = res['resultCode']
        if resultCode != 'API_SUCCESS_CODE':
          raise ApiUnsuccessful("API call returned " + resultCode)
        state = res['result']['result']['status']['state']
        if state == 'error':
          raise ApiUnsuccessful("API call returned an error")

      count = res['result']['result']['total_count']
      log.debug('SaFetcher: runQuery(): count: ' + str(count))

      for f in res['result']['result']['data']:
        flow = int( f['columns'][0] )
        self.sessionIds.append(flow)

      if count == 0:
        return count
      elif count <= 100:
        # move on to pulling meta
        pass
      else:
        # break up the remaining queries into async tasks, so as to pull them all at the same time
        remainingCount = count - 100
        numTasks, remainder = divmod(remainingCount, 100)
        if remainder > 0:
          numTasks += 1
        log.debug('The remaining number of query pages is ' + str(numTasks))
        futures = []
        for i in xrange(numTasks):
          # Pull remaining report results
          data['page'] += 1
          future = session.post(self.queryDef['url'], auth=self.queryDef['auth'], data=self.convertToPostBody(data, 'GET'), verify=self.queryDef['verify'], stream=self.queryDef['stream'], background_callback=self.checkForQueryResult )
          futures.append(future)

        for future in futures:
          # wait for all results to complete
          future.result()

    except requests.ConnectTimeout as e:
      error = "Query timed out"
      self.exitWithError(error)
    except requests.ConnectionError as e:
      error = "A connection error occurred whilst executing query: " + str(e)
      self.exitWithError(error)
    except requests.HTTPError as e:
      error = "An HTTP error occured whilst executing query: " + str(e)
      self.exitWithError(error)
    except requests.URLRequired as e:
      error = "A valid URL is required to issue a query: " + str(e)
      self.exitWithError(error)
    except requests.TooManyRedirects as e:
      error = "Too many redirects whilst executing query"
      self.exitWithError(error)
    except requests.RequestException as e:
      error = "Ambiguous exception whilst executing query: " + str(e)
      self.exitWithError(error)
    except KeyError as e:
      error = "Could not locate initial query state"
      self.exitWithError(error)
    except ApiUnsuccessful as e:
      self.exitWithError(str(e))
    except Exception as e:
      error = "SaFetcher: runQuery(): Unhandled exception whilst running query.  Exiting with code 1: " + str(e)
      self.exitWithException(error)

    # We now have our initial query results
    time1 = time.time()
    log.info("Query completed in " + str(time1 - self.queryTime0) + " seconds")    
    
    
    # Initiate file extraction immediately after the query, so that it has time to build
    self.extractionTime0 = time.time()
    flowsToPull = str(self.sessionIds[0])
    count = 0
    for f in self.sessionIds:
      if count > 0:
        flowsToPull = flowsToPull + '_or_' + str(f)
      count += 1
    data = {
      'identityPath': '/timespan/' + self.cfg['time1'] + '_' + self.cfg['time2'] + '/flow_id/' + flowsToPull,
      'pageSize': 100,
      'page': 1,
      'mediapanel': None,
      'restart': True
    }
    self.extractPostData = data
    extractFuture = session.post(self.cfg['url'] + '/api/v6/artifacts/artifacts', auth=self.queryDef['auth'], data=self.convertToPostBody(data, 'GET'), verify=False, stream=False, background_callback=self.onFileExtractionResults )
    self.extractFutures.append(extractFuture)

    
    
    # Initiate extraction of metadata
    fetchTime0 = time.time()
    if len(self.sessionIds) > 0:
      self.fetchMeta(self.sessionIds, session)
    # Wait for all meta extraction results to complete
    for future in self.metaExtractionFutures:
      future.result()
    fetchTime1 = time.time()
    log.info("SaFetcher: fetchMeta(): Meta extraction completed in " + str(fetchTime1 - fetchTime0) + " seconds")
    log.debug('SaFetcher: fetchMeta(): Number of flows in meta list: ' + str(len(self.sessions)))

    
    
    # Wait for file extraction to complete
    log.debug('SaFetcher: fetchMeta(): waiting for file extraction to complete')
    while len(self.extractFutures) != 0:
      future = self.extractFutures.pop()
      future.result()
    log.debug('SaFetcher: fetchMeta(): we think the download is complete')

    
    # Our zip download is complete.  Now extract the results and do the rest
    session.close()
    log.debug('SaFetcher: fetchMeta(): starting download of zip file')
    self.extractDownloadedZip(self.zipFileHandle)
    #t.cancel()

    self.pool.terminate()
    self.pool.join()
    return count




  def checkForQueryResult(self, session, result):  #session = requests_futures.sessions.FuturesSession
    log.debug('SaFetcher: checkForQueryResult()')
    request = result.request

    res = result.json()
    resultCode = res['resultCode']
    if resultCode != 'API_SUCCESS_CODE':
      raise ApiUnsuccessful("API call returned " + resultCode)
    state = res['result']['result']['status']['state']
    if state == 'error':
      raise ApiUnsuccessful("API call returned an error")
    if state != 'complete':
      log.debug('SaFetcher: checkForQueryResult(): trying to launch another session')
      parsedBody = urlparse.parse_qs(request.body)
      page = int(parsedBody['page'][0])
      data = self.queryDef['data']
      data['page'] = page
      data['restart'] = False
      session.post(self.queryDef['url'], auth=self.queryDef['auth'], data=self.convertToPostBody(data, 'GET'), verify=self.queryDef['verify'], stream=self.queryDef['stream'], background_callback=self.checkForQueryResult )
      return

    for f in res['result']['result']['data']:
      # add our results to the total query results
      flow = int( f['columns'][0] )
      self.sessionIds.append(flow)




  def fetchMeta(self, sessionIds, futuresSession):

    log.debug('SaFetcher: fetchMeta(): Fetching metadata')
    self.lastFileExtractionStatus = None

    limit = 25 # the current max imposed by Solera

    numTasks, remainder = divmod( len(sessionIds), 25)
    if remainder > 0:
      numTasks += 1

    fieldStr = """aggregate_database_query_hooks
aggregate_dns_query_hooks
aggregate_dns_web_application_info_hooks
aggregate_email_address_hooks
aggregate_email_recipient_hooks
aggregate_email_sender_hooks
aggregate_file_type_hooks
aggregate_filename_hooks
aggregate_http_code_hooks
aggregate_http_content_disposition_hooks
aggregate_http_forward_addr_hooks
aggregate_http_method_hooks
aggregate_http_server_hooks
aggregate_http_uri_hooks
aggregate_machine_id_hooks
aggregate_mime_type_hooks
aggregate_password_hooks
aggregate_referer_hooks
aggregate_social_persona_hooks
aggregate_ssl_cipher_suite_hooks
aggregate_ssl_common_name_hooks
aggregate_ssl_protocol_version_hooks
aggregate_ssl_serial_number_hooks
aggregate_ssl_server_name_hooks
aggregate_ssl_validity_not_after_hooks
aggregate_ssl_validity_not_before_hooks
aggregate_subject_hooks
aggregate_user_agent_hooks
aggregate_voip_id_hooks
aggregate_web_query_hooks
aggregate_web_server_hooks
application_ids
autogenerated_domain
autogenerated_domain_score
connection_flags
dns_ancount
dns_host_ipv4_addr
dns_host_ipv6_addr
dns_name
dns_ttl
domain_user_ids
element_id
file_extension
first_slot_id
flow_duration
flow_flags
flow_id
http_content_len
http_location
import_id
initiator_country
initiator_ip
initiator_mac
initiator_port
interfaceXXX
ip_bad_csums
ip_fragments
layer3_id
layer4_id
mail_uri
packet_count
protocol_family
responder_country
responder_ip
responder_mac
responder_port
slot_id
start_time
stop_time
tls_heartbeat_attack_attempt
tls_heartbeat_mismatch
total_bytes
tunnel_initiator_ip
tunnel_responder_ip
vlan_id"""
    
    fields = fieldStr.split('\n')

    #data = { 
    #  'path': '/timespan/2018-02-01T10:46:00_2018-02-01T11:01:00/flow_id/10065_or_10079',
    #  'fields': fields
    #}
    #res = s.callAPI("GET", "/pcap/download/raw", data, 'tsv.tsv' )

    self.metaExtractionFutures = []

    for i in xrange(numTasks):
      idsToPull = []
      #print "numtasks: " + str(numTasks)
      #print "!!!i: " + str(i)
      for n in xrange(limit):
        #print "!!!n: " + str(n)
        if i == numTasks - 1 and n == remainder: # remainder - 1
          break
        idsToPull.append(sessionIds.pop())

      path = '/timespan/' + self.cfg['time1'] + '_' + self.cfg['time2'] + '/flow_id/'
      count = 0
      
      for f in idsToPull:
        if count == 0:
          path = path + str(f)
        else:
          path = path + '_or_' + str(f)
        count += 1
      
      data = { 
        #'path': '/timespan/2018-02-01T10:46:00_2018-02-01T11:01:00/flow_id/10065_or_10079',
        'path': path,
        'fields': fields
      }

      post = self.convertToPostBody(data, 'GET')
      future = futuresSession.post(self.cfg['url'] + '/api/v6/pcap/download/raw', auth=self.queryDef['auth'], data=self.convertToPostBody(data, 'GET'), verify=False, stream=False, background_callback=self.onMetaReceived )
      self.metaExtractionFutures.append(future)







  def onMetaReceived(self, session, result):
    log.debug('SaFetcher: onMetaReceived()')
    #request = result.request
    if result.status_code >= 400:
      self.exitWithError('Received error on response')

    res = result.text
    #print res
    csvLines = res.split('\n')
    keys = []
    keyPositions = {}
    flowidPos = None
    count = 0
    log.debug('SaFetcher: onMetaReceived(): number of lines received: ' + str(len(csvLines)))

    if len(csvLines) == 1:
      log.warning('SaFetcher: onMetaReceived(): Only a single line received! :\n' + result.text )

    for line in csvLines:
      #print "line: " + line
      if len(line) in [ 0, 1 ] :
        #print "continuing from line: " + line
        continue
      
      if count == 0:
        #header line
        keys = line.split('\t')
        for i in xrange(len(keys)):
          key = keys[i]
          keyPositions[i] = key
          if key == 'flow_id':
            flowidPos = i
      else:
        values = line.split('\t')
        flowid = values[flowidPos]
        thisSession = { 'images': [], 'session': { 'id': flowid, 'meta': {} } }
        for i in xrange(len(values)):
          metaKey = keyPositions[i]
          metaValue = values[i]
          if len(metaValue) > 0:
            decodedValue = urllib2.unquote(metaValue).decode('utf8')
            valueList = decodedValue.split(',')
            #print 'valueList: ' + str(valueList)
            if metaKey == 'aggregate_user_agent_hooks':
              newValueList = []
              for x in xrange(len(valueList)):
                if valueList[x].startswith(' like '):
                  newValue = valueList[x - 1] + valueList[x]
                  newValueList.append(newValue)
              valueList = newValueList
            #pprint(valueList)
            #print 'valueList: ' + str(valueList)
            #if len(valueList) > 1:
            thisSession['session']['meta'][metaKey] = valueList
            #elif len(valueList) == 1:
            #  thisSession['session']['meta'][metaKey] = valueList.pop()
        self.sessions[int(flowid)] = thisSession
      count += 1






  def onFileExtractionResults(self, session, result):
    log.debug('SaFetcher: onFileExtractionResults()')
    
    if result.status_code >= 400:
      self.exitWithError('onFileExtractionResults(): Received HTTP error code on file extraction initiate or update response: ' + str(result.status_code))
    
    res = result.json()
    resultCode = res['resultCode']
    if resultCode != 'API_SUCCESS_CODE':
      raise ApiUnsuccessful("API call returned " + resultCode)
    
    searchId = res['result']['artifact_search_id']
    percent = int(res['result']['percentcomplete'])
    numresults = res['result']['numResults']
    status = res['result']['search_status']  #extractor.status.finished     #extractor.status.initializing

    if percent == 100 and status != 'extractor.status.finished' and status != 'extractor.status.cancel':
      log.debug('onFileExtractionResults(): 100% progress but status not finished.  Status: ' + status)
    
    if status == 'extractor.status.cancel':
      # restart the extraction
      """log.debug('onFileExtractionResults(): Status was extractor.status.cancel.  Restarting extraction')
      extractPostData = self.extractPostData
      extractPostData['restart'] = True
      future = session.post(self.cfg['url'] + '/api/v6/artifacts/artifacts', auth=self.queryDef['auth'], data=self.convertToPostBody(extractPostData, 'GET'), verify=False, stream=False, background_callback=self.onFileExtractionResults )
      self.extractFutures.append(future)
      return"""
      self.exitWithError('onFileExtractionResults(): Extraction was cancelled by Security Analytics.  Exiting with error')

    
    elif percent != 100 or (percent == 100 and status != 'extractor.status.finished'):
      fileExtractionStatus = "percent: " + str(percent) + " status: " + status
      if self.lastFileExtractionStatus != fileExtractionStatus:
        log.debug( fileExtractionStatus )
        self.lastFileExtractionStatus = fileExtractionStatus
      # loop again
      extractPostData = self.extractPostData
      extractPostData['restart'] = False
      future = session.post(self.cfg['url'] + '/api/v6/artifacts/artifacts', auth=self.queryDef['auth'], data=self.convertToPostBody(extractPostData, 'GET'), verify=False, stream=False, background_callback=self.onFileExtractionResults )
      self.extractFutures.append(future)
      return
    
    elif percent == 100 and status == 'extractor.status.finished' and numresults > 0:
      # now get all the results, which we'll need to map our extracted files back to the meta

      print "got to 1"
      
      for a in res['result']['sorted_artifacts']:
        artifact = a['Artifact']
        filename = os.path.basename( artifact['filename'] )
        flow_id = artifact['flow_id']
        self.extractFilesMap[filename] = artifact
        self.extractResults[flow_id] = artifact

      

      if numresults > 100:
        print "got to 2"
        # fire off new API calls to obtain remaining pages
        extractionPageFutures = []
        numresults = numresults - 100
        numTasks, remainder = divmod(numresults, 100)
        if remainder > 0:
          numTasks += 1
        for i in xrange(numTasks):
          self.extractPostData['page'] += 1 #increment the page count by 1
          log.debug( "onFileExtractionResults(): obtaining page " + str(self.extractPostData['page']) + " of file extraction results")
          extractPostData = self.extractPostData
          extractPostData['restart'] = False
          future = session.post(self.cfg['url'] + '/api/v6/artifacts/artifacts', auth=self.queryDef['auth'], data=self.convertToPostBody(extractPostData, 'GET'), verify=False, stream=False, background_callback=self.extractionPageGetter )
          extractionPageFutures.append(future)
        for f in extractionPageFutures:
          #print "got to 4"
          # we have to wait to get all the page results so we know all the appropriate download id's to pass to the download api call
          f.result()
        log.debug("onFileExtractionResults(): we think we've got all pages of file extraction results")
        
      # now download the extracted files

      #pprint(self.extractResults)
      
      log.debug("onFileExtractionResults(): initiating download of extracted artifacts zip")
      idsToDownload = []
      for a in self.extractResults:
        artifact = self.extractResults[a]
        idsToDownload.append(artifact['id'])
      data = {
        'searchId': searchId,
        'type': 'zip',
        'ids': idsToDownload
      }
      future = session.post(self.cfg['url'] + '/api/v6/artifacts/download', auth=self.queryDef['auth'], data=self.convertToPostBody(data, 'GET'), verify=False, stream=True, background_callback=self.onExtractedFileDownload )
      self.extractFutures.append(future)
      




  def extractionPageGetter(self, session, result):
    log.debug('SaFetcher: extractionPageGetter()')

    if result.status_code >= 400:
      self.exitWithError('Received HTTP error code on extraction page response: ' + str(result.status_code))
    
    res = result.json()
    resultCode = res['resultCode']
    if resultCode != 'API_SUCCESS_CODE':
      raise ApiUnsuccessful("API call returned " + resultCode)

    for a in res['result']['sorted_artifacts']:
      artifact = a['Artifact']
      filename = os.path.basename( artifact['filename'] )
      flow_id = artifact['flow_id']
      self.extractFilesMap[filename] = artifact
      self.extractResults[flow_id] = artifact






  def onExtractedFileDownload(self, session, result):
    log.debug('SaFetcher: onExtractedFileDownload()')

    if result.status_code >= 400:
      self.exitWithError('Received HTTP error code on file extraction download response: ' + str(result.status_code))

    if result.headers['content-type'] == 'application/zip':
      zipFile = cStringIO.StringIO()
      zipFile.write(result.content)
      self.zipFileHandle = zipfile.ZipFile(zipFile)
    
    else:
      self.exitWithError('Did not receive zip response.  Formatted response: ' + pformat(result.json()) )






  def extractDownloadedZip(self, zipHandle):
    log.debug('SaFetcher: extractDownloadedZip()')
    for zinfo in zipHandle.infolist():
      archivedFilename = zinfo.filename
      #if archivedFilename.startswith('META-INF/') or archivedFilename.startswith('AssetData/'):
      #  continue
      compressedFileHandle = zipHandle.open(archivedFilename)
      payload = compressedFileHandle.read()
      compressedFileHandle.close()
      flowId = self.extractFilesMap[archivedFilename]['flow_id']
      if flowId:
        if not flowId in self.sessions:
          log.warning('Flow ' + str(flowId) + ' was not found amongst extracted meta.  Skipping processing for this flow.')
          continue
        session = self.sessions[flowId]
        #pprint(session)
        if session:
          # now fire!!!
          #log.debug('SaFetcher: extractDownloadedZip(): Launching extractor from pool')
          processor = ContentProcessor(self.cfg)
          r = self.pool.apply_async( unwrapGo, args=(processor, payload, session, flowId, archivedFilename), callback=self.sendResult )
          #r.get() # useful to see if an error was thrown during apply_sync()
    
    self.pool.close()
    self.pool.join()
    #pprint(self.sessions)



  def convertToPostBody(self, data, method):
    post = {}
    if len(data) != 0:
      for k,v in data.items():
        try:
          isStr = isinstance(v, basestring)
        except NameError as e:
          isStr = isinstance(v, str)
        else:
          post[k] = json.dumps(v)
    post['_method'] = method.upper()
    return post


  def exitWithError(self, message):
    log.error(message)
    self.session.close()
    self.communicator.write_data(json.dumps( { 'error': message} ) + '\n')
    self.communicator.handle_close()
    sys.exit(1)

  def exitWithException(self, message):
    log.exception(message)
    self.session.close()
    self.communicator.write_data(json.dumps( { 'error': message} ) + '\n')
    self.communicator.handle_close()
    sys.exit(1)

  def terminate(self):
    self.pool.terminate()
    self.pool.join()
    self.session.close()

  def pretty_print_POST(self, req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in 
    this function because it is programmed to be pretty 
    printed and may differ from the actual request.
    """
    print('{}\n{}\n{}\n\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))




















class NwFetcher(Fetcher):

  """
  def __init__(self, cfg, communicator):
    self.cfg = cfg
    self.communicator = communicator
    self.cfg['devmode'] = True
    self.pool = Pool()
    self.manager = Manager()
    self.cfg['contentCount'] = self.manager.Value('I', 0)
    self.cfg['contentErrors'] = self.manager.Value('I', 0)
    self.summary = {}
    self.sessions = {}

    self.cfg['thumbnailSize'] = 350, 350
    proto='http://'
    if 'ssl' in cfg and cfg['ssl'] == True:
      proto='https://'
    host = cfg['host']
    port = str(cfg['port'])
    baseUrl = proto + host + ':' + port
    self.cfg['url'] = baseUrl
    
    #convert to integers
    if 'minX' in self.cfg and 'minY' in self.cfg:
      self.cfg['minX'] = int(self.cfg['minX'])
      self.cfg['minY'] = int(self.cfg['minY'])
      log.debug("Fetcher: __init__(): Minimum dimensions are: " + str(self.cfg['minX']) + " x " + str(self.cfg['minY']))
    self.cfg['contentLimit'] = int(self.cfg['contentLimit'])
    self.cfg['summaryTimeout'] = int(self.cfg['summaryTimeout'])
    self.cfg['queryTimeout'] = int(self.cfg['queryTimeout'])
    self.cfg['contentTimeout'] = int(self.cfg['contentTimeout'])
    self.cfg['maxContentErrors'] = int(self.cfg['maxContentErrors'])
    
    #self.contentTypes = contentTypes

  '''curl "http://admin:netwitness@172.16.0.55:50104/sdk?msg=query&query=$query&force-content-type=application/json'''

  def fetchSummary(self):
    request = urllib2.Request(self.cfg['url'] + '/sdk?msg=summary')
    base64string = base64.b64encode('%s:%s' % (self.cfg['user'], self.cfg['dpassword']))
    request.add_header("Authorization", "Basic %s" % base64string)
    request.add_header('Content-type', 'application/json')
    request.add_header('Accept', 'application/json')
    summaryResult = json.load(urllib2.urlopen(request, timeout=self.cfg['summaryTimeout']))
    for e in summaryResult['string'].split():
      (k, v) = e.split('=')
      self.summary[k] = v
  """



  def runQuery(self):
    reqStr = self.cfg['url'] + '/sdk?msg=query&query=' + self.cfg['queryEnc']  #&flags=4096
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib2.Request(reqStr)
    base64string = base64.b64encode('%s:%s' % (self.cfg['user'], self.cfg['dpassword']))
    request.add_header("Authorization", "Basic %s" % base64string)
    request.add_header('Content-type', 'application/json')
    request.add_header('Accept', 'application/json')
    try:
      rawQueryRes = json.load(urllib2.urlopen(request, context=ctx, timeout=self.cfg['queryTimeout']))
      #pprint(rawQueryRes)
      #print "length of rawQueryRes", len(rawQueryRes)
      log.debug('Fetcher: runQuery(): Parsing query results')
      for field in rawQueryRes:
        #print "loop"
        if 'results' in field and isinstance(field, dict):
          if 'fields' in field['results']:
            metaList = field['results']['fields']
            for meta in metaList:
              
              metaKey = meta['type']
              metaValue = meta['value']
              sessionId = meta['group']

              if sessionId in self.sessions:
                thisSession = self.sessions[sessionId]
              else:
                thisSession = { 'images': [], 'session': { 'id': sessionId, 'meta': {} } }

              #if not sessionId in self.sessions:
              #  self.sessions[sessionId] = { 'images': [], 'session': { 'id': sessionId, 'meta': {} } }
              
              #if not key in self.sessions[sessionId]['session']['meta']:
              #  self.sessions[sessionId]['session']['meta'][key] = []
              if not metaKey in thisSession['session']['meta']:
                thisSession['session']['meta'][metaKey] = []
              
              #self.sessions[sessionId]['session']['meta'][key].append(value)
              thisSession['session']['meta'][metaKey].append(metaValue)
              
              #Update dict
              self.sessions[sessionId] = thisSession

    except BadStatusLine as e:
      error = "Bad status raised whilst executing query.  This might be an SSL setting mismatch.  Run a Connection Test against your NetWitness server to check"
      self.exitWithError(error)
    except urllib2.HTTPError as e:
      error = "HTTP Error whilst running query.  Exiting with code 1: " + str(e)
      self.exitWithError(error)
    except socket.timeout as e:
      error = "Query to NetWitness service timed out after " + str(self.cfg['queryTimeout']) + " seconds"
      self.exitWithError(error)
    except urllib2.URLError as e:
      if 'Connection refused' in str(e):
        error = "Connection refused whilst trying to query NetWitness service"
      elif 'timed out' in str(e):
        error = "Query to NetWitness service timed out after " + str(self.cfg['queryTimeout']) + " seconds"
      elif 'No route to host' in str(e):
        error = "No route to host whilst trying to query NetWitness service"
      elif 'Host is down' in str(e):
        error = "Host is down error whilst trying to query NetWitness service"
      else:
        error = "runQuery(): URL Error whilst running query.  Exiting with code 1: "  + str(e)
      self.exitWithError(error)
    except Exception as e:
      error = "Fetcher: runQuery(): Unhandled exception whilst running query.  Exiting with code 1: " + str(e)
      self.exitWithException(error)
    return len(self.sessions)



  def pullFiles(self):

    error = ''

    for sessionId in self.sessions:

      if self.cfg['contentErrors'].value == self.cfg['maxContentErrors']:
        e = "pullFiles(): Maximum retries reached whilst pulling files for session " + str(sessionId) + ".  The last error was " + error + ".  Try either increasing the Query Delay setting or increasing the Max. Content Errors setting.  Exiting with code 1"
        self.exitWithError(e)
      
      if self.cfg['contentCount'].value >= self.cfg['contentLimit']:
        log.info("Fetcher: pullFiles(): Image limit of " + str(self.cfg['contentLimit']) + " has been reached.  Ending collection build.  You may want to narrow your result set with a more specific query")
        return
      
      elif not self.cfg['contentCount'].value >= self.cfg['contentLimit']:
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        uri = '/sdk/content?render=107&session=' + str(sessionId)
        request = urllib2.Request(self.cfg['url'] + uri )
        base64string = base64.b64encode('%s:%s' % (self.cfg['user'], self.cfg['dpassword']))
        request.add_header("Authorization", "Basic %s" % base64string)
        request.add_header('Content-type', 'application/json')
        request.add_header('Accept', 'application/json')
        #while self.cfg['contentErrors'].value < self.cfg['maxContentErrors']:
        try:
          res = urllib2.urlopen(request, context=ctx, timeout=self.cfg['contentTimeout'])
          #break
        except urllib2.HTTPError as e:
          self.cfg['contentErrors'].value += 1
          error = "HTTP exception pulling content for session " + str(sessionId) + ".  URI was '" + uri + "'.  The HTTP status code was " + str(e.code)
          log.warning("Fetcher: pullFiles(): " + error )
          continue
        except urllib2.URLError as e:
          self.cfg['contentErrors'].value += 1
          error = "URL error pulling content for session " + str(sessionId) + ".  The reason was " + e.reason
          log.warning("Fetcher: pullFiles(): " + error)
          continue
        except socket.timeout as e:
          self.cfg['contentErrors'].value += 1
          error = "Content call for session " + str(sessionId) + " timed out after " + str(self.cfg['contentTimeout']) + " seconds"
          log.warning("Fetcher: pullFiles(): " + error)
          continue

        if 'res' in locals() and res.info().getheader('Content-Type').startswith('multipart/mixed'):
          contentType = res.info().getheader('Content-Type')
          mimeVersion = res.info().getheader('Mime-Version')
          payload = 'Content-Type: ' + contentType + '\n' + 'Mime-Version: ' + mimeVersion + '\n' + res.read()
          
          ##############EXTRACT FILES AND DO THE WORK##############
          log.debug('Fetcher: pullFiles(): Launching extractor from pool')
          processor = ContentProcessor(self.cfg)
          self.pool.apply_async(unwrapGo, args=(processor, payload, self.sessions[sessionId], sessionId), callback=self.sendResult )

    self.pool.close()
    self.pool.join()





  def newpullFiles(self):
    #This tries to put every content call in its own process but this is actually slower than handling the content call in a single-threaded manner
    for sessionId in self.sessions:
      if not self.cfg['contentCount'].value >= self.cfg['contentLimit']:

        processor = ContentProcessor(self.cfg)

        ##############PULL FILES AND PROCESS THEM##############
        log.debug('Fetcher: newPullFiles(): Launching extractor from pool')
        res = self.pool.apply_async(unwrapPullFiles, args=(processor, self.sessions[sessionId], sessionId), callback=self.sendResult )
        res.get()

      else:
        log.info("Fetcher: newPullFiles(): Image limit of " + str(self.cfg['contentLimit']) + " has been reached.  Ending collection build.  You may want to narrow your result set with a more specific query")
        return
    
