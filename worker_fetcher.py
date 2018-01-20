import os
import sys
import urllib2
import ssl
import base64
import json
import email
import mimetypes
from pprint import pprint, pformat
import StringIO
from PIL import Image ##install
from worker_communicator import communicator
import time
from subprocess import Popen, PIPE
import zipfile
import shutil
import magic ##install
import hashlib
import rarfile ##install
import re
import logging
from worker_contentobj import ContentObj
from copy import deepcopy, copy
from multiprocessing import Pool, Manager, Value, current_process
import shlex
import socket
from httplib import BadStatusLine

log = logging.getLogger(__name__)

def unwrapExtractFilesFromMultipart(*arg, **kwarg):
  #print "unwrapExtractFilesFromMultipart()"
  return ContentProcessor.extractFilesFromMultipart(*arg, **kwarg)

def unwrapPullFiles(*arg, **kwarg):
  #print "unwrapExtractFilesFromMultipart()"
  return ContentProcessor.pullFiles(*arg, **kwarg)

class Fetcher:

  #def __init__(self, communicator, collectionId, url, user, password, directory, minX, minY, gsPath, pdftotextPath, sofficePath, sofficeProfilesDir, unrarPath, contentLimit, summaryTimeout, queryTimeout, contentTimeout, maxContentErrors, contentTypes):
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
      log.debug("Minimum dimensions are: " + str(self.cfg['minX']) + " x " + str(self.cfg['minY']))
    self.cfg['contentLimit'] = int(self.cfg['contentLimit'])
    self.cfg['summaryTimeout'] = int(self.cfg['summaryTimeout'])
    self.cfg['queryTimeout'] = int(self.cfg['queryTimeout'])
    self.cfg['contentTimeout'] = int(self.cfg['contentTimeout'])
    self.cfg['maxContentErrors'] = int(self.cfg['maxContentErrors'])
    
    #self.contentTypes = contentTypes

  """curl "http://admin:netwitness@172.16.0.55:50104/sdk?msg=query&query=$query&force-content-type=application/json"""

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
      log.debug('runQuery(): Parsing query results')
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
      error = "runQuery(): Unhandled exception whilst running query.  Exiting with code 1: " + str(e)
      #log.exception("runQuery(): Unhandled exception whilst running query.  Exiting with code 1")
      #sys.exit(1)
      self.exitWithException(error)
    return len(self.sessions)



  def sendResult(self, session):
    #log.debug('sendResult()')
    if len(session['images']) != 0:
      log.debug("sendResult(): Worker sending update")
      self.communicator.write_data(json.dumps( { 'collectionUpdate': session } ) + '\n')


  def pullFiles(self):

    error = ''

    for sessionId in self.sessions:

      if self.cfg['contentErrors'].value == self.cfg['maxContentErrors']:
        e = "pullFiles(): Maximum retries reached whilst pulling files for session " + str(sessionId) + ".  The last error was " + error + ".  Try either increasing the Query Delay setting or increasing the Max. Content Errors setting.  Exiting with code 1"
        self.exitWithError(e)
      
      if self.cfg['contentCount'].value >= self.cfg['contentLimit']:
        log.info("Image limit of " + str(self.cfg['contentLimit']) + " has been reached.  Ending collection build.  You may want to narrow your result set with a more specific query")
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
          log.warning("pullFiles(): " + error )
          continue
        except urllib2.URLError as e:
          self.cfg['contentErrors'].value += 1
          error = "URL error pulling content for session " + str(sessionId) + ".  The reason was " + e.reason
          log.warning("pullFiles(): " + error)
          continue
        except socket.timeout as e:
          self.cfg['contentErrors'].value += 1
          error = "Content call for session " + str(sessionId) + " timed out after " + str(self.cfg['contentTimeout']) + " seconds"
          log.warning("pullFiles(): " + error)
          continue

        if 'res' in locals() and res.info().getheader('Content-Type').startswith('multipart/mixed'):
          contentType = res.info().getheader('Content-Type')
          mimeVersion = res.info().getheader('Mime-Version')
          newFileStr = 'Content-Type: ' + contentType + '\n' + 'Mime-Version: ' + mimeVersion + '\n' + res.read()
          
          ##############EXTRACT FILES AND DO THE WORK##############
          log.debug('Launching extractor from pool')
          #processor = ContentProcessor(self.directory, self.minX, self.minY, self.gsPath, self.pdftotextPath, self.contentLimit, self.contentCount)
          #processor = ContentProcessor(self.cfg['url'], self.cfg['user'], self.cfg['dpassword'], self.cfg['directory'], self.cfg['minX'], self.cfg['minY'], self.cfg['gsPath'], self.pdftotextPath, self.cfg['sofficePath'], self.cfg['sofficeProfilesDir'], self.contentLimit, self.contentCount, self.contentErrors, self.maxContentErrors, self.contentTimeout, self.contentTypes)
          processor = ContentProcessor(self.cfg)
          
          #self.pool.apply_async(unwrapExtractFilesFromMultipart, args=(processor, newFileStr, self.sessions[sessionId], sessionId, distillationTerms, regexDistillationTerms, md5Hashes, sha1Hashes, sha256Hashes), callback=self.sendResult )
          self.pool.apply_async(unwrapExtractFilesFromMultipart, args=(processor, newFileStr, self.sessions[sessionId], sessionId), callback=self.sendResult )
      

    self.pool.close()
    self.pool.join()





  def newpullFiles(self):
    #This tries to put every content call in its own process but this is actually slower than handling the content call in a single-threaded manner
    for sessionId in self.sessions:
      if not self.cfg['contentCount'].value >= self.cfg['contentLimit']:
        #processor = ContentProcessor(self.cfg['url'], self.cfg['user'], self.cfg['dpassword'], self.cfg['directory'], self.cfg['minX'], self.cfg['minY'], self.cfg['gsPath'], self.pdftotextPath, self.cfg['sofficePath'], self.contentLimit, self.contentCount, self.contentErrors, self.maxContentErrors, self.contentTimeout)
        processor = ContentProcessor(self.cfg)

        ##############PULL FILES AND PROCESS THEM##############
        log.debug('Launching extractor from pool')
        #res = self.pool.apply_async(unwrapPullFiles, args=(processor, self.sessions[sessionId], sessionId, self.cfg['distillationTerms'], self.cfg['regexDistillationTerms'], md5Hashes, sha1Hashes, sha256Hashes), callback=self.sendResult )
        res = self.pool.apply_async(unwrapPullFiles, args=(processor, self.sessions[sessionId], sessionId), callback=self.sendResult )
        res.get()

      else:
        log.info("Image limit of " + str(self.cfg['contentLimit']) + " has been reached.  Ending collection build.  You may want to narrow your result set with a more specific query")
        return
    
   

























class ContentProcessor:

  #def __init__(self, url, user, password, directory, minX, minY, gsPath, pdftotextPath, sofficePath, sofficeProfilesDir, contentLimit, contentCount, contentErrors, maxContentErrors, timeout, contentTypes):
  def __init__(self, cfg):
    self.cfg = cfg

    #pprint(self.cfg)

    rarfile.UNRAR_TOOL = self.cfg['unrarPath']
    #self.contentCount = contentCount # is a manager proxy
    #self.contentErrors = contentErrors # is a manager proxy

    
    self.imagesAllowed = False
    self.pdfsAllowed = False
    self.dodgyArchivesAllowed = False
    self.hashesAllowed = False
    if 'images' in self.cfg['contentTypes']:
      self.imagesAllowed = True
    if 'pdfs' in self.cfg['contentTypes']:
      self.pdfsAllowed = True
    if 'dodgyarchives' in self.cfg['contentTypes']:
      self.dodgyArchivesAllowed = True
    if 'hashes' in self.cfg['contentTypes']:
      self.hashesAllowed = True
    if 'officedocs' in self.cfg['contentTypes']:
      self.officeAllowed = True
    #log.debug('My Process Identifier: ' + str(self.processId))
    #print current_process()


  def pullFiles(self, session, sessionId):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib2.Request(self.cfg['url'] + '/sdk/content?render=107&session=' + str(sessionId))
    base64string = base64.b64encode('%s:%s' % (self.cfg['user'], self.cfg['dpassword']))
    request.add_header("Authorization", "Basic %s" % base64string)
    request.add_header('Content-type', 'application/json')
    request.add_header('Accept', 'application/json')
    while self.cfg['contentErrors'].value < self.cfg['maxContentErrors']:
      try:
        res = urllib2.urlopen(request, context=ctx, timeout=self.cfg['contentTimeout'])
        break
      except urllib2.HTTPError as e:
        if self.cfg['contentErrors'].value == self.cfg['maxContentErrors']:
          log.warning("pullFiles(): Maximum allowable errors reached whilst pulling content for session " + str(sessionId) + ".  Try either increasing the Query Delay setting or increasing the Max. Content Errors setting.  Exiting with code 1")
          sys.exit(1)
        self.cfg['contentErrors'].value += 1
        log.warning("pullFiles(): HTTP error pulling content for session " + str(sessionId) + ".  Retrying")
        continue
      except urllib2.URLError as e:
        if self.cfg['contentErrors'].value == self.cfg['maxContentErrors']:
          log.warning("pullFiles(): Maximum retries reached whilst pulling content for session " + str(sessionId) + ".  Try either increasing the Query Delay setting or increasing the Max. Content Errors setting.  Exiting with code 1")
          sys.exit(1)
        self.cfg['contentErrors'].value += 1
        log.warning("pullFiles(): ERROR: URL error pulling content for session " + str(sessionId) + ".  Retrying")
        continue

    if res.info().getheader('Content-Type').startswith('multipart/mixed'):
      contentType = res.info().getheader('Content-Type')
      mimeVersion = res.info().getheader('Mime-Version')
      newFileStr = 'Content-Type: ' + contentType + '\n' + 'Mime-Version: ' + mimeVersion + '\n' + res.read()
      
      ##############EXTRACT FILES AND DO THE WORK##############
      #log.debug('Launching extractor from pool')
      #processor = ContentProcessor(self.directory, self.minX, self.minY, self.gsPath, self.pdftotextPath, self.contentLimit, self.contentCount)
      #self.pool.apply_async(unwrapExtractFilesFromMultipart, args=(processor, newFileStr, self.sessions[sessionId], sessionId, distillationTerms, regexDistillationTerms, md5Hashes, sha1Hashes, sha256Hashes), callback=self.sendResult )
      return self.extractFilesFromMultipart(newFileStr, session, sessionId)
        

  
  def processImage(self, contentObj): #must specify either part or stringFile
    log.debug("processImage(): Analyzing image " + contentObj.contentFile)
    contentObj.contentType = 'image'
    output = contentObj.getFileContent()
      
    try:
      im = Image.open(output)
      (x,y) = im.size
    except Exception as e:
      log.warning("Could not identify image file " + contentObj.contentFile + ".  This is likely due to file corruption")
      return False
      
    #check file for dimensions and only write if minimum
    if x >= int(self.cfg['minX']) and y >= int(self.cfg['minY']):
      log.debug("processImage(): Keeping image " + contentObj.contentFile + " of resolution " + str(x) + ' x ' + str(y) )
      fp = open(os.path.join(self.cfg['outputDir'], contentObj.contentFile), 'wb')
      fp.write(output.getvalue())
      fp.close()

      log.debug("processImage(): Generating thumbnail for image " + contentObj.contentFile)
      thumbnailName = 'thumbnail_' + contentObj.contentFile
      
      try:
        im.thumbnail(self.cfg['thumbnailSize'], Image.ANTIALIAS)
      except IOError as e: #we don't want to keep corrupt files.  we know it's corrupt if we can't generate a thumbnail
        log.warning("Image appears to be corrupt: " + contentObj.contentFile)
        return False
      except Exception as e:
        log.exception("Unhandled exception whilst generating thumbnail")
        return False
      
      im.save(os.path.join(self.cfg['outputDir'], thumbnailName), im.format)
      contentObj.thumbnail = thumbnailName
      
      self.cfg['contentCount'].value += 1

      #self.sessions[contentObj.session]['images'].append( contentObj.get() )
      self.thisSession['images'].append( contentObj.get() )
      

    else:
      log.debug("processImage(): Discarding image " + contentObj.contentFile + " due to minimum size requirements")
      return False
    
    return True




  


  def processOfficeDoc(self, contentObj):
    contentObj.contentType = 'office'
    #log.debug('processOfficeDoc(): contentObj:' + pformat(contentObj.get()) )

    baseName = os.path.splitext(contentObj.contentFile)[0]
    pdfOutName = baseName + '.pdf'
    firstPageOutName = baseName + '.jpg'
    
    #write document to disk
    log.debug("processOfficeDoc(): Session " + str(contentObj.session) + ". Writing document to " + os.path.join(self.cfg['outputDir'], contentObj.contentFile) )
    fp = open(os.path.join(self.cfg['outputDir'], contentObj.contentFile), 'wb')
    shutil.copyfileobj(contentObj.getFileContent(), fp)
    fp.close()
    


    #convert document to PDF
    sofficeCmd = self.cfg['sofficePath'] + " --headless --norestore -env:SingleAppInstance='false' -env:UserInstallation=file://" + self.cfg['sofficeProfilesDir'] + "/" + self.poolId + " --convert-to pdf --outdir " + self.cfg['outputDir'] + " '" + os.path.join(self.cfg['outputDir'], contentObj.contentFile) + "'"
    log.debug("processOfficeDoc(): Session " + str(contentObj.session) + ". soffice command line: " + sofficeCmd)
    args = shlex.split(sofficeCmd)
    try:
      process = Popen(args, stdout=PIPE, stderr=PIPE, shell = False)
      (output, err) = process.communicate()
      exit_code = process.wait()
    except OSError as e:
      if ('No such file or directory' in str(e)):
        log.error("Session " + str(contentObj.session) + ". Could not run soffice command as " + self.cfg['sofficePath'] + " was not found")
      else:
        log.exception(str(e))
      return False
    except Exception as e:
      #soffice couldn't even be run
      log.exception("Session " + str(contentObj.session) + ": Could not run soffice command for file " + contentObj.contentFile + " at " + self.cfg['sofficePath'] )
      return False
    if exit_code != 0:
      #soffice exited with a non-zero exit code, and thus was unsuccessful
      log.warning("Session " + str(contentObj.session) + ". soffice exited abnormally for file " + contentObj.contentFile + " with exit code " + str(exit_code) )
      log.warning("Session " + str(contentObj.session) + ". The 'soffice' command output was: " + output)
      return False
    log.debug('returned from soffice')
    contentObj.proxyContentFile = pdfOutName
    log.debug('returned from soffice 2')

    #extract first page of pdf
    #gs -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile="p%o3d.jpg" -dFirstPage=1 -dLastPage=1 -dBATCH "$filename"
    log.debug("processOfficeDoc(): Session " + str(contentObj.session) + ". Extracting first page of pdf " + contentObj.proxyContentFile)
    outputfile = "page1-" + firstPageOutName
    contentObj.pdfImage = outputfile
    log.debug("processOfficeDoc(): Session " + str(contentObj.session) + ". Running gs on file " + contentObj.proxyContentFile)
    
    
    gsCmd = self.cfg['gsPath'] + " -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile='" + os.path.join(self.cfg['outputDir'], outputfile) + "' -dNoVerifyXref -dPDFSTOPONERROR -dFirstPage=1 -dLastPage=1 -dBATCH '" +  os.path.join(self.cfg['outputDir'], contentObj.proxyContentFile) + "'"
    log.debug("processOfficeDoc(): Session " + str(contentObj.session) + ". Ghostscript command line: " + gsCmd)
    args = shlex.split(gsCmd)
    try:
      process = Popen(args, stdout=PIPE, stderr=PIPE, shell = False)
      (output, err) = process.communicate()
      exit_code = process.wait()
    
    except OSError as e:
      if ('No such file or directory' in str(e)):
        log.error("Session " + str(contentObj.session) + ". Could not run ghostscript command as " + self.cfg['gsPath'] + " was not found")
      else:
        log.exception(str(e))
      return False

    except Exception as e:
      #Ghostscript couldn't even be run
      log.exception("Session " + str(contentObj.session) + ": Could not run GhostScript command for file " + contentObj.contentFile + " at " + self.cfg['gsPath'] )
      return False

    if exit_code != 0:
      #Ghostscript exited with a non-zero exit code, and thus was unsuccessful
      log.warning("Session " + str(contentObj.session) + ". GhostScript exited abnormally for file " + contentObj.contentFile + " with exit code " + str(exit_code) )
      #log.warning("The 'gs' command was: " + gsCmd)
      log.warning("Session " + str(contentObj.session) + ". The 'gs' command output was: " + output)
      return False

    if exit_code == 0: #this means we successfully generated an image of the pdf and we want to keep it
      keep = True
      ###keep means we want to keep the file.  We choose to not keep the file (by making keep = False) on these conditions:
      ###1: if an error is generated by gs whilst trying to render an image of the first page
      ###2: if we have distillationTerms and/or regexDistillationTerms and they aren't matched

      returnObj = self.getPdfText(contentObj)
      keep = returnObj['keep']
      contentObj = returnObj['contentObj']

      if keep == False:
        return False #return if we've chosen to not keep the file
      
      try:
        #now let's try generating a thumbnail - if we already have an image, this should succeed.  If not, there's something screwy...
        #but we'll keep it anyway and use the original image as the thumbnail and let the browser deal with any potential corruption
        log.debug("processOfficeDoc(): Session " + str(contentObj.session) + ". Generating thumbnail for pdf " + outputfile)
        thumbnailName = 'thumbnail_' + outputfile
        pdfim = Image.open(os.path.join(self.cfg['outputDir'], outputfile))
        pdfim.thumbnail(self.cfg['thumbnailSize'], Image.ANTIALIAS)
        pdfim.save(os.path.join(self.cfg['outputDir'], thumbnailName), pdfim.format)
        #pdfim.close()

        #set thumbnail to our generated thumbnail
        contentObj.thumbnail = thumbnailName
        self.thisSession['images'].append( contentObj.get() )
        self.cfg['contentCount'].value += 1
        return True
      except Exception as e:
        log.exception("Session " + str(contentObj.session) + ". Error generating thumbnail for pdf " + contentObj.proxyContentFile)
        #thumbnail generation failed, so set thumbnail to be the original image generated by gs
        contentObj.thumbnail = outputfile
        self.thisSession['images'].append( contentObj.get() )
        self.cfg['contentCount'].value += 1
        return True







  def processPdf(self, contentObj):
    contentObj.contentType = 'pdf'
    #log.debug('processPdf(): contentObj:' + pformat(contentObj.get()) )

    #write pdf to disk
    log.debug("processPdf(): Session " + str(contentObj.session) + ". Writing pdf to " + os.path.join(self.cfg['outputDir'], contentObj.contentFile) )
    fp = open(os.path.join(self.cfg['outputDir'], contentObj.contentFile), 'wb')
    shutil.copyfileobj(contentObj.getFileContent(), fp)
    fp.close()
    
    #extract first page of pdf
    #gs -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile="p%o3d.jpg" -dFirstPage=1 -dLastPage=1 -dBATCH "$filename"
    log.debug("processPdf(): Session " + str(contentObj.session) + ". Extracting first page of pdf " + contentObj.contentFile)
    outputfile = "page1-" + contentObj.contentFile + ".jpg"
    contentObj.pdfImage = outputfile
    log.debug("processPdf(): Session " + str(contentObj.session) + ". Running gs on file " + contentObj.contentFile)
    
    
    gsCmd = self.cfg['gsPath'] + " -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile='" + os.path.join(self.cfg['outputDir'], outputfile) + "' -dNoVerifyXref -dPDFSTOPONERROR -dFirstPage=1 -dLastPage=1 -dBATCH '" +  os.path.join(self.cfg['outputDir'], contentObj.contentFile) + "'"
    log.debug("processPdf(): Session " + str(contentObj.session) + ". Ghostscript command line: " + gsCmd)
    args = shlex.split(gsCmd)
    try:
      #process = Popen(gsCmd, stdout=PIPE, stderr=PIPE, shell = True)
      process = Popen(args, stdout=PIPE, stderr=PIPE, shell = False)
      (output, err) = process.communicate()
      exit_code = process.wait()
    
    except OSError as e:
      if ('No such file or directory' in str(e)):
        log.error("Session " + str(contentObj.session) + ". Could not run ghostscript command as " + self.cfg['gsPath'] + " was not found")
      else:
        log.exception(str(e))
      return False

    except Exception as e:
      #Ghostscript couldn't even be run
      log.exception("Session " + str(contentObj.session) + ": Could not run GhostScript command for file " + contentObj.contentFile + " at " + self.cfg['gsPath'] )
      return False

    if exit_code != 0:
      #Ghostscript exited with a non-zero exit code, and thus was unsuccessful
      log.warning("Session " + str(contentObj.session) + ". GhostScript exited abnormally for file " + contentObj.contentFile + " with exit code " + str(exit_code) )
      #log.warning("The 'gs' command was: " + gsCmd)
      log.warning("Session " + str(contentObj.session) + ". The 'gs' command output was: " + output)
      return False

    if exit_code == 0: #this means we successfully generated an image of the pdf and we want to keep it
      keep = True
      ###keep means we want to keep the file.  We choose to not keep the file (by making keep = False) on these conditions:
      ###1: if an error is generated by gs whilst trying to render an image of the first page
      ###2: if we have distillationTerms and/or regexDistillationTerms and they aren't matched

      returnObj = self.getPdfText(contentObj)
      keep = returnObj['keep']
      contentObj = returnObj['contentObj']

      if keep == False:
        return False #return if we've chosen to not keep the file
      
      try:
        #now let's try generating a thumbnail - if we already have an image, this should succeed.  If not, there's something screwy...
        #but we'll keep it anyway and use the original image as the thumbnail and let the browser deal with any potential corruption
        log.debug("processPdf(): Session " + str(contentObj.session) + ". Generating thumbnail for pdf " + outputfile)
        thumbnailName = 'thumbnail_' + outputfile
        pdfim = Image.open(os.path.join(self.cfg['outputDir'], outputfile))
        pdfim.thumbnail(self.cfg['thumbnailSize'], Image.ANTIALIAS)
        pdfim.save(os.path.join(self.cfg['outputDir'], thumbnailName), pdfim.format)
        #pdfim.close()

        #set thumbnail to our generated thumbnail
        contentObj.thumbnail = thumbnailName
        self.thisSession['images'].append( contentObj.get() )
        self.cfg['contentCount'].value += 1
        return True
      except Exception as e:
        log.exception("Session " + str(contentObj.session) + ". Error generating thumbnail for pdf " + contentObj.contentFile)
        #thumbnail generation failed, so set thumbnail to be the original image generated by gs
        contentObj.thumbnail = outputfile
        self.thisSession['images'].append( contentObj.get() )
        self.cfg['contentCount'].value += 1
        return True
        



  def getPdfText(self, contentObj):
    try: #now extract pdf text
      #log.debug('getPdfText(): session: ' + str(contentObj.session))
      sessionId = contentObj.session

      fileToExtractFrom = contentObj.contentFile
      if contentObj.proxyContentFile:
        fileToExtractFrom = contentObj.proxyContentFile

      pdftotextCmd = self.cfg['pdftotextPath'] + " -enc UTF-8 -eol unix -nopgbrk -q '" + os.path.join(self.cfg['outputDir'], fileToExtractFrom) + "' -"
      log.debug("getPdfText(): Session " + str(contentObj.session) + ". pdftotextCmd: " + pdftotextCmd)
      args = shlex.split(pdftotextCmd)
      try:
        #pdftotextProcess = Popen(pdftotextCmd, stdout=PIPE, stderr=PIPE, shell = True)
        pdftotextProcess = Popen(args, stdout=PIPE, stderr=PIPE, shell = False)
        (output, err) = pdftotextProcess.communicate()
        exit_code = pdftotextProcess.wait()
      
      except OSError as e:
        if ('No such file or directory' in str(e)):
          log.error("Session " + str(contentObj.session) + ". Could not run pdftotext command as " + self.cfg['pdftotextPath'] + " was not found")
        else:
          log.exception(str(e))
        if not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled']:
          return { 'keep': True, 'contentObj': contentObj }
        return { 'keep': False, 'contentObj': contentObj }

      except Exception as e:
        log.exception("Session " + str(contentObj.session) + ". Could not run pdftotext command at " + self.cfg['pdftotextPath'] )
        if not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled']:
          return { 'keep': True, 'contentObj': contentObj }
        return { 'keep': False, 'contentObj': contentObj }

      returnObj = { 'keep': False, 'contentObj': {} }
      
      textTermsMatched = []
      regexTermsMatched = []
      contentObj.distillationEnabled = False
      contentObj.regexDistillationEnabled = False
      
      if self.cfg['distillationEnabled'] and 'distillationTerms' in self.cfg and len(self.cfg['distillationTerms']) > 0:
        contentObj.distillationEnabled = True
      if self.cfg['regexDistillationEnabled'] and 'regexDistillationTerms' in self.cfg and len(self.cfg['regexDistillationTerms']) > 0:
        contentObj.regexDistillationEnabled = True

      if exit_code == 0:
        #extracted successfully, get output
        joinedText = output.replace('\n', ' ').replace('\r', '')

        if contentObj.distillationEnabled:
          for term in self.cfg['distillationTerms']:
            #log.debug( "getPdfText(): Text search term: " + term)
            if term.decode('utf-8').lower() in joinedText.decode('utf-8').lower():
              textTermsMatched.append(term)
              log.debug("getPdfText(): Session " + str(contentObj.session) + ". Matched text search term " + term)
        
        if contentObj.regexDistillationEnabled:
          for t in self.cfg['regexDistillationTerms']:
            origTerm =  t.decode('utf-8')
            term = '(' + t.decode('utf-8') + ')'
            #log.debug( "getPdfText(): Regex search term: " + term)
            compiledTerm = re.compile(term)
            res = compiledTerm.search(joinedText.decode('utf-8')) #MatchObject
            if res != None:
              regexTermsMatched.append(origTerm)
              log.debug("getPdfText(): Session " + str(contentObj.session) + ". Matched regex search term " + term)
              log.debug("getPdfText(): Session " + str(contentObj.session) + ". Matched group: " + pformat(res.groups()))

        #'keep' is a variable that gets returned which indicates whether the document and session should be retained as part of a collection, if a term has been matched or if there were no terms
        if not contentObj.distillationEnabled and not contentObj.regexDistillationEnabled: #no search terms defined - distillation is not enabled - definitely keep this session
          returnObj['keep'] = True
        if contentObj.distillationEnabled and len(textTermsMatched) > 0: #we had text search terms and had at least one match, so we will keep this session
          returnObj['keep'] = True
          contentObj.textTermsMatched = textTermsMatched
        if contentObj.regexDistillationEnabled and len(regexTermsMatched) > 0: #we had regex search terms and had at least one match, so we will keep this session
          returnObj['keep'] = True
          contentObj.regexTermsMatched = regexTermsMatched
        
        returnObj['contentObj'] = contentObj #pass our modified contentObj back to the caller

        if returnObj['keep'] == True:
          log.debug("getPdfText(): Session " + str(contentObj.session) + ". Keeping file " + contentObj.contentFile)
          searchObj = { 'id': contentObj.id, 'session': sessionId, 'contentFile': contentObj.contentFile, 'searchString': joinedText }
          if not 'search' in self.thisSession:
            self.thisSession['search'] = []
          #pprint(self.thisSession['search'])
          self.thisSession['search'].append(searchObj)

        return returnObj
        
    except Exception as e:
      log.exception("Session " + str(contentObj.session) + ". Unhandled exception in getPdfText()")
      #print "Error Message:", str(e)
      #continue
      #if searchForText:
      #if len(searchForText) != 0:
      #  return True #keep session if pdftotext has issues.
      return returnObj


  def genHash(self, contentObj): #must specify either part or stringFile
    #print "genHash()"
    contentObj.contentType = 'hash'
    log.debug("genHash(): Session " + str(contentObj.session) + ". Generating " + contentObj.hashType + " hash for " + contentObj.contentFile)

    contentFileObj = contentObj.getFileContent()

    def hashFinder(hash, hashes):
      for h in hashes:
        if hash == h['hash'].lower():
          log.debug("genHash(): Session " + str(contentObj.session) + ". Matched " + contentObj.hashType + " hash " + h['hash'])
          fp = open(os.path.join(self.cfg['outputDir'], contentObj.contentFile), 'wb')
          fp.write(contentFileObj.getvalue())
          fp.close()
          ###imgObj = { 'session': sessionId, 'contentType': 'md5Matched', 'contentFile': filename, 'image': filename, 'md5Hash': hash_md5.hexdigest() }
          contentObj.hashValue = hash
          if 'friendly' in h:
            contentObj.hashFriendly = h['friendly']
          self.thisSession['images'].append( contentObj.get() )
    
    if contentObj.hashType == 'md5':
      hasher = hashlib.md5()
      hashRes = hasher.update(contentFileObj.getvalue()).hexdigest().decode('utf-8').lower()
      log.debug("genHash(): Session " + str(contentObj.session) + ". " + contentObj.hashType + " hash for " + contentObj.contentFile + " is " + hashRes)
      hashFinder(hashRes, self.cfg['md5Hashes'])
    if contentObj.hashType == 'sha1':
      hasher = hashlib.sha1()
      hashRes = hasher.update(contentFileObj.getvalue()).hexdigest().decode('utf-8').lower()
      log.debug("genHash(): Session " + str(contentObj.session) + ". " + contentObj.hashType + " hash for " + contentObj.contentFile + " is " + hashRes)
      hashFinder(hashRes, self.cfg['sha1Hashes'])
    if contentObj.hashType == 'sha256':
      hasher = hashlib.sha256()
      hashRes = hasher.update(contentFileObj.getvalue()).hexdigest().decode('utf-8').lower()
      log.debug("genHash(): Session " + str(contentObj.session) + ". " + contentObj.hashType + " hash for " + contentObj.contentFile + " is " + hashRes)
      hashFinder(hashRes, self.cfg['sha256Hashes'])
      
    
    


        


  def extractFilesFromMultipart(self, fileStr, session, sessionId):
    log.debug("extractFilesFromMultipart(): Extracting files of session ID " + str(sessionId) )
    self.poolId = current_process().name
    #log.debug('My Process Identifier: ' + str(self.processId))
    #print current_process().name
    #print("extractFilesFromMultipart(): Extracting files of session ID " + str(sessionId) )
    msg = email.message_from_string(fileStr)
    counter = 1

    self.thisSession = session


    for part in msg.walk():

      # multipart/* are just containers
      maintype = part.get_content_maintype()
      subtype = part.get_content_subtype()

      log.debug("maintype: " + maintype)
      log.debug("subtype: " + subtype)

      if maintype == 'multipart' and subtype == 'mixed':
        continue
      elif maintype == 'image':
        contentType = 'image'
      elif maintype == 'application' and subtype == 'pdf':
        contentType = 'pdf'
        ext = '.pdf'
      else:
        log.debug("Mime type not recognized.  maintype: " + str(maintype))
        log.debug("subtype:" + str(subtype))
        log.debug("extractFilesFromMultipart(): Detecting content type")
        
        payload = part.get_payload(decode=True)
        mimeType = magic.from_buffer( payload, mime=True)
        magicType = magic.from_buffer( payload, mime=False)
        log.debug("extractFilesFromMultipart(): Magic type is " + mimeType)
        if magicType == 'Microsoft Word 2007+':
          contentType = 'office'
          contentSubType = 'word'
          ext = '.docx'
        elif magicType == 'Microsoft Excel 2007+':
          contentType = 'office'
          contentSubType = 'excel'
          ext = '.xlsx'
        elif magicType == 'Microsoft PowerPoint 2007+':
          contentType = 'office'
          contentSubType = 'powerpoint'
          ext = '.pptx'
        elif mimeType == 'application/zip':
          contentType = 'zip'
          ext = '.zip'
        elif mimeType == 'application/x-rar':
          contentType = 'rar' #confirm this type
          ext = '.rar'
        elif mimeType in ['application/x-msdownload', 'application/x-ms-installer', 'application/x-elf', 'application/x-dosexec', 'application/x-executable']: #and len(md5Hashes) != 0: #fix this for known executable types
          contentType = 'executable'
        else: #should we make else generate hash instead of continue?  stick with just exe's for now
          continue
      
      # Applications should really sanitize the given filename so that an
      # email message can't be used to overwrite important files
      filename = part.get_filename().decode('utf-8')
      if (contentType == 'office'):
        (f, e) = os.path.splitext(filename)
        if contentSubType == 'word' and e != '.docx':
          e = '.docx'
        if contentSubType == 'excel' and e != '.xlsx':
          e = '.xlsx'
        if contentSubType == 'powerpoint' and e != '.pptx':
          e = '.pptx'
        filename = f + e

      if not filename:
        log.debug("No filename")
        if not ext:
          ext = mimetypes.guess_extension(part.get_content_type())
        if not ext:
          # Use a generic bag-of-bits extension
          ext = '.bin'
        filename = 'session-%d-part-%03d%s' % (sessionId, counter, ext)
      counter += 1
      
      #print filename, part.get_content_maintype(), part.get_content_subtype()

      if self.cfg['contentCount'].value >= self.cfg['contentLimit']:
        #return
        log.debug("Reached content limit")
        return self.thisSession

      ##############################################################################
      #We're going to keep the content - so now start doing things with the content#
      ##############################################################################
      contentObj = ContentObj()
      contentObj.session = contentObj.session = sessionId

      if self.hashesAllowed: #hash check everything, including archives
        contentObj.contentFile = filename
        contentObj.setPartContent(part)
        #if len(md5Hashes) != 0:
        if not self.cfg['useHashFeed'] and self.cfg['md5Enabled'] and 'md5Hashes' in self.cfg and len(self.cfg['md5Hashes']) != 0:
          contentObj.hashType = 'md5'
          self.genHash(contentObj)
        #if len(sha1Hashes) != 0:
        if not self.cfg['useHashFeed'] and self.cfg['sha1Enabled'] and 'sha1Hashes' in self.cfg and len(self.cfg['sha1Hashes']) != 0:
          contentObj.hashType = 'sha1'
          self.genHash(contentObj)
        #if len(sha256Hashes) != 0:
        if not self.cfg['useHashFeed'] and self.cfg['sha256Enabled'] and 'sha256Hashes' in self.cfg and len(self.cfg['sha256Hashes']) != 0:
          contentObj.hashType = 'sha256'
          self.genHash(contentObj)

      #if contentType == 'image' and len(self.cfg['distillationTerms']) == 0 and len(self.cfg['regexDistillationTerms']) == 0 and self.imagesAllowed:
      #if contentType == 'image' and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled'] and self.imagesAllowed:
      if contentType == 'image' and self.imagesAllowed:
        contentObj.contentFile = filename
        contentObj.setPartContent(part)
        if not self.processImage(contentObj):
          continue
        
      elif contentType == 'pdf' and self.pdfsAllowed:
        contentObj.contentFile = filename
        contentObj.setPartContent(part)
        if not self.processPdf(contentObj):
          continue

      elif contentType == 'office' and self.officeAllowed:
        contentObj.contentFile = filename
        contentObj.contentSubType = contentSubType
        contentObj.setPartContent(part)
        if not self.processOfficeDoc(contentObj):
          continue
      


      ######################################################
      #################Process ZIP ARCHIVES#################
      ######################################################

      elif contentType == 'zip':
        log.debug("extractFilesFromMultipart(): Attempting to extract zip archive " + filename)
        contentObj.fromArchive = True
        contentObj.archiveType = 'zip'
        saveZipFile = False
        origContentObj = copy(contentObj)
        
        try:
          zipFileHandle = zipfile.ZipFile(self.convertPartToStringIO(part))
        except zipfile.BadZipfile as e:
          log.warning("Bad ZIP File (file was not opened): " + contentObj.archiveFilename)
        except zipfile.LargeZipFile as e:
          log.warning("ZIP file was too large to open: " + contentObj.archiveFilename)
        except NotImplementedError as e:
          log.exception("NotImplemented exception during zip open")
        except Exception as e:
          log.exception("Unhandled exception during zip file open")
         
        try:
          for zinfo in zipFileHandle.infolist():
            contentObj = copy(origContentObj)
            
            archivedFilename = zinfo.filename
            contentObj.contentFile = archivedFilename
            contentObj.archiveFilename = filename
            is_encrypted = zinfo.flag_bits & 0x1
            #print "DEBUG: zip compression type is",str(zinfo.compress_type)
            unsupported_compression = zinfo.compress_type == 99

            if not self.dodgyArchivesAllowed and (is_encrypted or unsupported_compression):
              continue
            
            #elif is_encrypted and len(self.cfg['distillationTerms']) == 0 and len(self.cfg['regexDistillationTerms']) == 0:
            elif is_encrypted and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled']:
              saveZipFile = True
              log.debug('extractFilesFromMultipart(): ZIP contentFile %s from archive %s is encrypted!' % (archivedFilename, filename))
              contentObj.contentType = 'encryptedZipEntry'
              #contentObj.contentFile = filename #this is the zip file itself
              contentObj.fromArchive = True
              self.thisSession['images'].append( contentObj.get() )
              continue

            #elif unsupported_compression and len(self.cfg['distillationTerms']) == 0 and len(self.cfg['regexDistillationTerms']) == 0:
            elif unsupported_compression and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled']:
              saveZipFile = True
              log.debug('extractFilesFromMultipart(): ZIP archive %s uses an unsupported compression type!' % filename)
              contentObj.contentType = 'unsupportedZipEntry'
              contentObj.contentFile = filename #this is the zip file itself
              contentObj.fromArchive = False # if the file is unsupported, it becomes the content itself, not what's inside it,so it's not FROM an archive, it IS the archive
              contentObj.isArchive = True
              self.thisSession['images'].append( contentObj.get() )
              break
            
            else: #identify archived file and save it permanently if a supported file type
              extractedFileObj = StringIO.StringIO() #we will write the extracted file to this buffer

              #extract the file to buffer
              compressedFileHandle = zipFileHandle.open(archivedFilename) #compressedFileHandle is a handle to the file while it's still in the zip file.  we will extract from this object
              extractedFileObj.write(compressedFileHandle.read() )  #this is where we extract the file into
              compressedFileHandle.close()

              contentObj.setStringIOContent(extractedFileObj)
              self.processExtractedFile(contentObj) #now let's process the extracted file
              extractedFileObj.close()
      
        except RuntimeError as e:
          if 'is encrypted, password required for extraction' in e.message:
            pass # do nothing and let our own code take the lead
          else:
            log.exception('Unhandled RuntimeError')
        except Exception as e:
          log.exception("Unhandled exception during zip file extraction")

        if saveZipFile:
          fp = open(os.path.join(self.cfg['outputDir'], filename), 'wb')
          fp.write(part.get_payload(decode=True))
          fp.close()
        continue          



      #################Process RAR ARCHIVES#################
      elif contentType == 'rar':
        log.debug("extractFilesFromMultipart(): Attempting to extract rar archive " + filename)
        contentObj.fromArchive = True
        contentObj.archiveType = 'rar'
        saveRarFile = False
        origContentObj = copy(contentObj)
        
        try:
          rarFileHandle = rarfile.RarFile(self.convertPartToStringIO(part), errors='strict')
        except rarfile.PasswordRequired as e:
          log.exception("RAR requires password: %s" % e)
          pass
        except rarfile.BadRarFile as e:
          log.exception("Bad RAR file")
        except rarfile.NotRarFile as e:
          log.exception("Not a RAR file")
        except rarfile.BadRarName as e:
          log.exception("Cannot guess multipart RAR name components")
        except rarfile.NoRarEntry as e:
          log.exception("File not found in RAR")
        except rarfile.NeedFirstVolume as e:
          log.exception("Need to start from first volume in RAR archive")
        except rarfile.NoCrypto as e:
          log.exception("No crypto services available to parse encrypted headers")
        except rarfile.RarExecError as e:
          log.exception("There was a problem reported by unrar")
        except rarfile.RarCRCError as e:
          log.exception("CRC error during unpacking of RAR")
        except rarfile.RarOpenError as e:
          log.exception("Error opening RAR file")
        except rarfile.RarUserError as e:
          log.exception("RAR user error")
        except rarfile.RarMemoryError as e:
          log.exception("RAR memory error")
        except rarfile.RarNoFilesError as e:
          log.exception("RAR no files that match pattern were found")
        except rarfile.RarUserBreak as e:
          log.exception("RAR user break")
        except rarfile.RarWrongPassword as e:
          log.exception("RAR wrong password")
        except rarfile.RarUnknownError as e:
          log.exception("RAR unknown error")
        except rarfile.RarCannotExec as e:
          log.exception("RAR executable not found")
        except Exception as e:
          log.exception("Unhandled exception during rar extraction")
          if self.cfg['devmode']:
            log.debug("extractFilesFromMultipart(): Exiting with code 1") #we only exit if in dev mode, so we can deal with the problem afterwards
            sys.exit(1)

        #print rarFileHandle.needs_password()
        #print rarFileHandle.namelist()
        #rarFileHandle.printdir()
        #print rarFileHandle.testrar()

        #we need something here for if the entire rar file table is encrypted
        table_len = len(rarFileHandle.namelist())
        #log.debug('table_len: %s' % table_len)
        table_content = rarFileHandle.namelist()
        #log.debug('table_content: %s' % table_content)
        table_needs_password = rarFileHandle.needs_password()
        #log.debug('table_needs_password: %s' % table_needs_password)

        #if table_len == 0 and table_needs_password and len(self.cfg['distillationTerms']) == 0 and len(self.cfg['regexDistillationTerms']) == 0 and self.dodgyArchivesAllowed:
        if table_len == 0 and table_needs_password and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled'] and self.dodgyArchivesAllowed:
          #this means that the archive's table is encrypted and we cannot see anything inside it
          saveRarFile = True
          log.debug('extractFilesFromMultipart(): RAR archive %s has an encrypted table!' % filename)
          contentObj.contentType = 'encryptedRarTable'
          contentObj.contentFile = filename #this is the rar file itself
          contentObj.fromArchive = False # if the file is encrypted, it becomes the content itself, not what's inside it,so it's not FROM an archive, it IS the archive
          contentObj.isArchive = True
          self.thisSession['images'].append( contentObj.get() )

        for rinfo in rarFileHandle.infolist():
          contentObj = copy(origContentObj)

          archivedFilename = rinfo.filename
          contentObj.contentFile = archivedFilename
          contentObj.archiveFilename = filename
          archivedFile_is_encrypted = rinfo.needs_password()

          #if archivedFile_is_encrypted and len(self.cfg['distillationTerms']) == 0 and len(self.cfg['regexDistillationTerms']) == 0 and self.dodgyArchivesAllowed: #this means that the RAR file's table is not encrypted, but individual files within it are
          if archivedFile_is_encrypted and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled'] and self.dodgyArchivesAllowed: #this means that the RAR file's table is not encrypted, but individual files within it are
            saveRarFile = True
            log.debug('extractFilesFromMultipart(): RAR contentFile %s from archive %s is encrypted!' % (archivedFilename,filename))
            contentObj.contentType = 'encryptedRarEntry'
            contentObj.fromArchive = True
            self.thisSession['images'].append( contentObj.get() )
            continue

          else: #identify archived file and save it permanently if a supported file type
            extractedFileObj = StringIO.StringIO() #we will write the extracted file to this buffer

            #extract the file to buffer
            compressedFileHandle = rarFileHandle.open(archivedFilename) #compressedFileHandle is a handle to the file while it's still in the rar file.  we will extract from this object
            extractedFileObj.write(compressedFileHandle.read() ) #this is where we extract the file into
            compressedFileHandle.close()

            contentObj.setStringIOContent(extractedFileObj)
            extractedFileObj.close()
            self.processExtractedFile(contentObj) #now let's process the extracted file
            extractedFileObj.close()

        if saveRarFile:
          fp = open(os.path.join(self.cfg['outputDir'], filename), 'wb')
          fp.write(part.get_payload(decode=True))
          fp.close()
        continue

    return self.thisSession



  def processExtractedFile(self, contentObj):
    log.debug("processExtractedFile(): Attempting to process extracted file " + contentObj.contentFile )
    
    #generate a new uuid for the content object
    contentObj.newId()
    
    #get the file
    fileObj = contentObj.getFileContent()

    #identify the extracted file
    fileType = magic.from_buffer( fileObj.getvalue(), mime=True) #this is where we identify the content file type

    #if fileType.startswith('image/') and len(self.cfg['distillationTerms']) == 0 and len(self.cfg['regexDistillationTerms']) == 0 and self.imagesAllowed:
    #if fileType.startswith('image/') and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled'] and self.imagesAllowed:
    if fileType.startswith('image/') and self.imagesAllowed:
      #log.debug("processExtractedFile(): Processing '" + archivedFilename + "' as image")
      self.processImage(contentObj)

    elif fileType == 'application/pdf' and self.pdfsAllowed:
      #log.debug("processExtractedFile(): processing '" + contentObj.contentType + "' as pdf")
      self.processPdf(contentObj)

    elif fileType in [ 'Microsoft Word 2007+', 'Microsoft Excel 2007+', 'Microsoft PowerPoint 2007+' ] and self.officeAllowed:
      #log.debug("processExtractedFile(): processing '" + contentObj.contentType + "' as office document")
      self.processOfficeDoc(contentObj)

    #else:
      #log.debug() "processExtractedFile(): discarding " + archivedFilename + ' with MIME type ' + fileType)
    #  pass

    if self.hashesAllowed:
      #log.debug("processExtractedFile(): Processing '" + archivedFilename + "' as executable")
      #if len(md5Hashes) != 0:
      if not self.cfg['useHashFeed'] and self.cfg['md5Enabled'] and 'md5Hashes' in self.cfg and len(self.cfg['md5Hashes']) != 0:
        contentObj.hashType = 'md5'
        self.genHash(contentObj)
      #if len(sha1Hashes) != 0:
      if not self.cfg['useHashFeed'] and self.cfg['sha1Enabled'] and 'sha1Hashes' in self.cfg and len(self.cfg['sha1Hashes']) != 0:
        contentObj.hashType = 'sha1'
        self.genHash(contentObj)
      #if len(sha256Hashes) != 0:
      if not self.cfg['useHashFeed'] and self.cfg['sha256Enabled'] and 'sha256Hashes' in self.cfg and len(self.cfg['sha256Hashes']) != 0:
        contentObj.hashType = 'sha256'
        self.genHash(contentObj)

  def convertPartToStringIO(self, part):
    output = StringIO.StringIO()
    output.write(part.get_payload(decode=True))
    return output        
