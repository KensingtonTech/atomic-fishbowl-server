import logging
import os
import sys
import urllib.request, urllib.error, urllib.parse
import ssl
import base64
import email
import mimetypes
from pprint import pprint, pformat
from io import BytesIO
from PIL import Image, ImageFile ##install
ImageFile.LOAD_TRUNCATED_IMAGES = True
from subprocess import Popen, PIPE
import zipfile
import shutil
import magic ##install
import hashlib
import rarfile ##install
import re
from worker_contentobj import ContentObj
from copy import copy
from multiprocessing import Pool, Manager, Value, current_process, cpu_count
import shlex
import socket
from http.client import BadStatusLine
from threading import Thread
import asyncore
import traceback
from worker_feedmanager import FeedManager

log = logging.getLogger(__name__)
logging.getLogger("PIL").setLevel(logging.WARNING)

class ContentProcessor:

  def __init__(self, cfg):
    #log.debug('ContentProcessor: __init__()')
    self.cfg = cfg
    rarfile.UNRAR_TOOL = self.cfg['unrarPath']
    self.imagesAllowed = False
    self.pdfsAllowed = False
    self.dodgyArchivesAllowed = False
    self.hashesAllowed = False
    self.officeAllowed = False
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
    


  def pullFiles(self, session, sessionId):
    self.thisSession = session
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(self.cfg['url'] + '/sdk/content?render=107&session=' + str(sessionId))
    base64string = base64.b64encode('%s:%s' % (self.cfg['user'], self.cfg['dpassword']))
    request.add_header("Authorization", "Basic %s" % base64string)
    request.add_header('Content-type', 'application/json')
    request.add_header('Accept', 'application/json')
    while self.cfg['contentErrors'].value < self.cfg['maxContentErrors']:
      try:
        res = urllib.request.urlopen(request, context=ctx, timeout=self.cfg['contentTimeout'])
        break
      except urllib.error.HTTPError as e:
        if self.cfg['contentErrors'].value == self.cfg['maxContentErrors']:
          log.warning("ContentProcessor: pullFiles(): Maximum allowable errors reached whilst pulling content for session " + str(sessionId) + ".  Try either increasing the Query Delay setting or increasing the Max. Content Errors setting.  Exiting with code 1")
          sys.exit(1)
        self.cfg['contentErrors'].value += 1
        log.warning("ContentProcessor: pullFiles(): HTTP error pulling content for session " + str(sessionId) + ".  Retrying")
        continue
      except urllib.error.URLError as e:
        if self.cfg['contentErrors'].value == self.cfg['maxContentErrors']:
          log.warning("ContentProcessor: pullFiles(): Maximum retries reached whilst pulling content for session " + str(sessionId) + ".  Try either increasing the Query Delay setting or increasing the Max. Content Errors setting.  Exiting with code 1")
          sys.exit(1)
        self.cfg['contentErrors'].value += 1
        log.warning("ContentProcessor: pullFiles(): ERROR: URL error pulling content for session " + str(sessionId) + ".  Retrying")
        continue

    if res.info().getheader('Content-Type').startswith('multipart/mixed'):
      contentType = res.info().getheader('Content-Type')
      mimeVersion = res.info().getheader('Mime-Version')
      payload = 'Content-Type: ' + contentType + '\n' + 'Mime-Version: ' + mimeVersion + '\n' + res.read()
      
      ##############EXTRACT FILES AND DO THE WORK##############
      #log.debug('Launching extractor from pool')
      return self.extractFilesFromMultipart(sessionId, payload)
        

  
  def processImage(self, contentObj): #must specify either part or stringFile
    log.debug("ContentProcessor: processImage(): Analyzing image " + contentObj.contentFile)
    contentObj.contentType = 'image'
    output = contentObj.getFileContent()
      
    try:
      im = Image.open(output)
      (x,y) = im.size
    except Exception as e:
      log.debug("ContentProcessor: Could not identify image file " + contentObj.contentFile + ".  This is likely due to incomplete packet data, leading to file corruption")
      return False
      
    #check file for dimensions and only write if minimum
    if x >= int(self.cfg['minX']) and y >= int(self.cfg['minY']):
      log.debug("ContentProcessor: processImage(): Keeping image " + contentObj.contentFile + " of resolution " + str(x) + ' x ' + str(y) )
      fp = open( bytes(os.path.join(self.cfg['outputDir'], contentObj.contentFile), 'utf-8'), 'wb')
      fp.write(output.getvalue())
      fp.close()

      log.debug("ContentProcessor: processImage(): Generating thumbnail for image " + contentObj.contentFile)
      thumbnailName = 'thumbnail_' + contentObj.contentFile
      
      try:
        im.thumbnail(self.cfg['thumbnailSize'], Image.ANTIALIAS)
      except IOError as e: #we don't want to keep corrupt files.  we know it's corrupt if we can't generate a thumbnail
        log.warning("ContentProcessor: processImage(): Image appears to be corrupt: " + contentObj.contentFile)
        return False
      except Exception as e:
        log.exception("ContentProcessor: processImage(): Unhandled exception whilst generating thumbnail")
        return False
      
      try:
        im.save( bytes(os.path.join(self.cfg['outputDir'], thumbnailName), 'utf-8'), im.format)
      except IOError as e:
        log.warning('ContentProcessor: processImage(): File ' +  + ' was truncated.  Discarding file.')

      contentObj.thumbnail = thumbnailName
      return self.imageLimitDecider(contentObj)

    else:
      log.debug("ContentProcessor: processImage(): Discarding image " + contentObj.contentFile + " due to minimum size requirements")
      return False
    




  


  def processOfficeDoc(self, contentObj):
    contentObj.contentType = 'office'
    #log.debug('ContentProcessor: processOfficeDoc(): contentObj:' + pformat(contentObj.get()) )

    baseName = os.path.splitext(contentObj.contentFile)[0]
    pdfOutName = baseName + '.pdf'
    firstPageOutName = baseName + '.jpg'
    
    #write document to disk
    log.debug("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". Writing document to " + os.path.join(self.cfg['outputDir'], contentObj.contentFile) )
    fp = open( bytes(os.path.join(self.cfg['outputDir'], contentObj.contentFile), 'utf-8'), 'wb')
    shutil.copyfileobj(contentObj.getFileContent(), fp)
    fp.close()
    


    #convert document to PDF
    sofficeCmd = self.cfg['sofficePath'] + " --headless --norestore -env:SingleAppInstance='false' -env:UserInstallation=file://" + self.cfg['sofficeProfilesDir'] + "/" + self.poolId + " --convert-to pdf --outdir " + self.cfg['outputDir'] + " '" + os.path.join(self.cfg['outputDir'], contentObj.contentFile) + "'"
    log.debug("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". soffice command line: " + sofficeCmd)
    args = shlex.split(sofficeCmd)
    try:
      process = Popen(args, stdout=PIPE, stderr=PIPE, shell = False)
      (output, err) = process.communicate()
      exit_code = process.wait()
    except OSError as e:
      if ('No such file or directory' in str(e)):
        log.error("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". Could not run soffice command as " + self.cfg['sofficePath'] + " was not found")
      else:
        log.exception(str(e))
      return False
    except Exception as e:
      #soffice couldn't even be run
      log.exception("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ": Could not run soffice command for file " + contentObj.contentFile + " at " + self.cfg['sofficePath'] )
      return False
    if exit_code != 0:
      #soffice exited with a non-zero exit code, and thus was unsuccessful
      log.warning("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". soffice exited abnormally for file " + contentObj.contentFile + " with exit code " + str(exit_code) )
      log.warning("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". The 'soffice' command output was: " + output.decode('utf-8'))
      return False
    log.debug('ContentProcessor: processOfficeDoc(): returned from soffice')
    contentObj.proxyContentFile = pdfOutName
    log.debug('ContentProcessor: processOfficeDoc(): returned from soffice 2')

    #extract first page of pdf
    #gs -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile="p%o3d.jpg" -dFirstPage=1 -dLastPage=1 -dBATCH "$filename"
    log.debug("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". Extracting first page of pdf " + contentObj.proxyContentFile)
    outputfile = "page1-" + firstPageOutName
    contentObj.pdfImage = outputfile
    log.debug("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". Running gs on file " + contentObj.proxyContentFile)
    
    
    gsCmd = self.cfg['gsPath'] + " -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile='" + os.path.join(self.cfg['outputDir'], outputfile) + "' -dNoVerifyXref -dPDFSTOPONERROR -dFirstPage=1 -dLastPage=1 -dBATCH '" +  os.path.join(self.cfg['outputDir'], contentObj.proxyContentFile) + "'"
    log.debug("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". Ghostscript command line: " + gsCmd)
    args = shlex.split(gsCmd)
    try:
      process = Popen(args, stdout=PIPE, stderr=PIPE, shell = False)
      (output, err) = process.communicate()
      exit_code = process.wait()
    
    except OSError as e:
      if ('No such file or directory' in str(e)):
        log.error("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". Could not run ghostscript command as " + self.cfg['gsPath'] + " was not found")
      else:
        log.exception(str(e))
      return False

    except Exception as e:
      #Ghostscript couldn't even be run
      log.exception("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ": Could not run GhostScript command for file " + contentObj.contentFile + " at " + self.cfg['gsPath'] )
      return False

    if exit_code != 0:
      #Ghostscript exited with a non-zero exit code, and thus was unsuccessful
      log.warning("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". GhostScript exited abnormally for file " + contentObj.contentFile + " with exit code " + str(exit_code) )
      #log.warning("ContentProcessor: processOfficeDoc(): The 'gs' command was: " + gsCmd)
      log.warning("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". The 'gs' command output was: " + output)
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
        log.debug("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". Generating thumbnail for pdf " + outputfile)
        thumbnailName = 'thumbnail_' + outputfile
        pdfim = Image.open(os.path.join(self.cfg['outputDir'], outputfile))
        pdfim.thumbnail(self.cfg['thumbnailSize'], Image.ANTIALIAS)
        pdfim.save(os.path.join(self.cfg['outputDir'], thumbnailName), pdfim.format)

        #set thumbnail to our generated thumbnail
        contentObj.thumbnail = thumbnailName
        return self.imageLimitDecider(contentObj)
      except Exception as e:
        log.exception("ContentProcessor: processOfficeDoc(): Session " + str(contentObj.session) + ". Error generating thumbnail for pdf " + contentObj.proxyContentFile)
        #thumbnail generation failed, so set thumbnail to be the original image generated by gs
        contentObj.thumbnail = outputfile
        return self.imageLimitDecider(contentObj)







  def processPdf(self, contentObj):
    contentObj.contentType = 'pdf'
    # log.debug('ContentProcessor: processPdf(): contentObj:' + pformat(contentObj.get()) )

    # write pdf to disk
    log.debug("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ". Writing pdf to " + os.path.join(self.cfg['outputDir'], contentObj.contentFile) )
    fp = open( bytes(os.path.join(self.cfg['outputDir'], contentObj.contentFile), 'utf-8'), 'wb')
    shutil.copyfileobj(contentObj.getFileContent(), fp)
    fp.close()
    
    # extract first page of pdf
    # gs -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile="p%o3d.jpg" -dFirstPage=1 -dLastPage=1 -dBATCH "$filename"
    log.debug("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ". Extracting first page of pdf " + contentObj.contentFile)
    outputfile = "page1-" + contentObj.contentFile + ".jpg"
    contentObj.pdfImage = outputfile
    log.debug("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ". Running gs on file " + contentObj.contentFile)
    
    
    gsCmd = self.cfg['gsPath'] + " -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile='" + os.path.join(self.cfg['outputDir'], outputfile) + "' -dNoVerifyXref -dPDFSTOPONERROR -dFirstPage=1 -dLastPage=1 -dBATCH '" +  os.path.join(self.cfg['outputDir'], contentObj.contentFile) + "'"
    log.debug("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ". Ghostscript command line: " + gsCmd)
    args = shlex.split(gsCmd)
    try:
      #process = Popen(gsCmd, stdout=PIPE, stderr=PIPE, shell = True)
      process = Popen(args, stdout=PIPE, stderr=PIPE, shell = False)
      (output, err) = process.communicate()
      exit_code = process.wait()
    
    except OSError as e:
      if ('No such file or directory' in str(e)):
        log.error("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ". Could not run ghostscript command as " + self.cfg['gsPath'] + " was not found")
      else:
        log.exception(str(e))
      return False

    except Exception as e:
      #Ghostscript couldn't even be run
      log.exception("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ": Could not run GhostScript command for file " + contentObj.contentFile + " at " + self.cfg['gsPath'] )
      return False

    if exit_code != 0:
      #Ghostscript exited with a non-zero exit code, and thus was unsuccessful
      log.warning("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ". GhostScript exited abnormally for file " + contentObj.contentFile + " with exit code " + str(exit_code) )
      #log.warning("ContentProcessor: processPdf(): The 'gs' command was: " + gsCmd)
      log.warning("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ". The 'gs' command output was: " + output)
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
        log.debug("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ". Generating thumbnail for pdf " + outputfile)
        thumbnailName = 'thumbnail_' + outputfile
        pdfim = Image.open(os.path.join(self.cfg['outputDir'], outputfile))
        pdfim.thumbnail(self.cfg['thumbnailSize'], Image.ANTIALIAS)
        pdfim.save(os.path.join(self.cfg['outputDir'], thumbnailName), pdfim.format)
        #pdfim.close()

        #set thumbnail to our generated thumbnail
        contentObj.thumbnail = thumbnailName
        #self.cfg['contentCount'].value += 1
        #self.thisSession['images'].append( contentObj.get() )
        #return True
        return self.imageLimitDecider(contentObj)
      except Exception as e:
        log.exception("ContentProcessor: processPdf(): Session " + str(contentObj.session) + ". Error generating thumbnail for pdf " + contentObj.contentFile)
        #thumbnail generation failed, so set thumbnail to be the original image generated by gs
        contentObj.thumbnail = outputfile
        #self.cfg['contentCount'].value += 1
        #self.thisSession['images'].append( contentObj.get() )
        #return True
        return self.imageLimitDecider(contentObj)
        



  def getPdfText(self, contentObj):
    try: #now extract pdf text
      #log.debug('ContentProcessor: getPdfText(): session: ' + str(contentObj.session))
      sessionId = contentObj.session

      fileToExtractFrom = contentObj.contentFile
      if contentObj.proxyContentFile:
        fileToExtractFrom = contentObj.proxyContentFile

      pdftotextCmd = self.cfg['pdftotextPath'] + " -enc UTF-8 -eol unix -nopgbrk -q '" + os.path.join(self.cfg['outputDir'], fileToExtractFrom) + "' -"
      log.debug("ContentProcessor: getPdfText(): Session " + str(contentObj.session) + ". pdftotextCmd: " + pdftotextCmd)
      args = shlex.split(pdftotextCmd)
      try:
        #pdftotextProcess = Popen(pdftotextCmd, stdout=PIPE, stderr=PIPE, shell = True)
        pdftotextProcess = Popen(args, stdout=PIPE, stderr=PIPE, shell = False)
        (output, err) = pdftotextProcess.communicate()
        exit_code = pdftotextProcess.wait()
      
      except OSError as e:
        if ('No such file or directory' in str(e)):
          log.error("ContentProcessor: getPdfText(): Session " + str(contentObj.session) + ". Could not run pdftotext command as " + self.cfg['pdftotextPath'] + " was not found")
        else:
          log.exception(str(e))
        if not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled']:
          return { 'keep': True, 'contentObj': contentObj }
        return { 'keep': False, 'contentObj': contentObj }

      except Exception as e:
        log.exception("ContentProcessor: getPdfText(): Session " + str(contentObj.session) + ". Could not run pdftotext command at " + self.cfg['pdftotextPath'] )
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
        joinedText = output.decode('utf-8').replace('\n', ' ').replace('\r', '')

        if contentObj.distillationEnabled:
          for term in self.cfg['distillationTerms']:
            #log.debug( "ContentProcessor: getPdfText(): Text search term: " + term)
            if term.lower() in joinedText.lower():
              textTermsMatched.append(term)
              log.debug("ContentProcessor: getPdfText(): Session " + str(contentObj.session) + ". Matched text search term " + term)
        
        if contentObj.regexDistillationEnabled:
          for t in self.cfg['regexDistillationTerms']:
            origTerm =  t
            term = '(' + t + ')'
            #log.debug( "ContentProcessor: getPdfText(): Regex search term: " + term)
            compiledTerm = re.compile(term)
            res = compiledTerm.search(joinedText) #MatchObject
            if res != None:
              regexTermsMatched.append(origTerm)
              log.debug("ContentProcessor: getPdfText(): Session " + str(contentObj.session) + ". Matched regex search term " + term)
              log.debug("ContentProcessor: getPdfText(): Session " + str(contentObj.session) + ". Matched group: " + pformat(res.groups()))

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
          log.debug("ContentProcessor: getPdfText(): Session " + str(contentObj.session) + ". Keeping file " + contentObj.contentFile)
          searchObj = { 'id': contentObj.id, 'session': sessionId, 'contentFile': contentObj.contentFile, 'searchString': joinedText }
          if not 'search' in self.thisSession:
            self.thisSession['search'] = []
          #pprint(self.thisSession['search'])
          self.thisSession['search'].append(searchObj)

        return returnObj
        
    except Exception as e:
      log.exception("ContentProcessor: getPdfText(): Session " + str(contentObj.session) + ". Unhandled exception in getPdfText()")
      #print("Error Message:", str(e))
      #continue
      #if searchForText:
      #if len(searchForText) != 0:
      #  return True #keep session if pdftotext has issues.
      return returnObj



  def onFeederResponse(self, res, contentObj):
    #log.debug('ContentProcessor: feederResponse():\n' + pformat(res))
    log.debug("ContentProcessor: onFeederResponse(): Session " + str(contentObj.session) + ". Matched " + res['type'] + " hash " + res['hash'])
    fp = open( bytes(os.path.join(self.cfg['outputDir'], contentObj.contentFile), 'utf-8'), 'wb')
    contentFileObj = contentObj.getFileContent()
    fp.write(contentFileObj.getvalue())
    fp.close()
    contentObj.hashValue = res['hash']
    if 'friendlyName' in res:
      contentObj.hashFriendly = res['friendlyName']
    self.thisSession['images'].append( contentObj.get() )



  def genHash(self, contentObj): #must specify either part or stringFile
    #print("genHash()")
    contentObj.contentType = 'hash'
    log.debug("ContentProcessor: genHash(): Session " + str(contentObj.session) + ". Generating " + contentObj.hashType + " hash for " + contentObj.contentFile)

    contentFileObj = contentObj.getFileContent()
    fileContent = contentFileObj.getvalue()

    if self.cfg['useHashFeed']:
      # we first need to know what types of hashes are in this feed
      hashTypes = self.feedManager.getTypes()
      log.debug('ContentProcessor: genHash(): types: ' + pformat(hashTypes))
      
      if 'md5' in hashTypes:
        hasher = hashlib.md5()
        hashRes = hasher.update(fileContent)
        calcHash = hasher.hexdigest().lower()
        contentObj.hashType = 'md5'
        self.feedManager.submit(calcHash, 'md5', contentObj.getCopy() )
        log.debug("ContentProcessor: genHash(): Session " + str(contentObj.session) + ". MD5 hash for " + contentObj.contentFile + " is " + calcHash)
      
      if 'sha1' in hashTypes:
        hasher = hashlib.sha1()
        hashRes = hasher.update(fileContent)
        calcHash = hasher.hexdigest().lower()
        contentObj.hashType = 'sha1'
        log.debug("ContentProcessor: genHash(): Session " + str(contentObj.session) + ". SHA1 hash for " + contentObj.contentFile + " is " + calcHash)
        self.feedManager.submit(calcHash, 'sha1', contentObj.getCopy())
      
      if 'sha256' in hashTypes:
        hasher = hashlib.sha256()
        hashRes = hasher.update(fileContent)
        calcHash = hasher.hexdigest().lower()
        contentObj.hashType = 'sha256'
        log.debug("ContentProcessor: genHash(): Session " + str(contentObj.session) + ". SHA256 hash for " + contentObj.contentFile + " is " + calcHash)
        self.feedManager.submit(calcHash, 'sha256', contentObj.getCopy())


    
    if not self.cfg['useHashFeed']:

      def hashFinder(hash, hashes, contentObj):
        for h in hashes:
          if hash == h['hash'].lower():
            contentObj = contentObj.getCopy()
            log.debug("ContentProcessor: genHash(): Session " + str(contentObj.session) + ". Matched " + contentObj.hashType + " hash " + h['hash'])
            fp = open( bytes(os.path.join(self.cfg['outputDir'], contentObj.contentFile), 'utf-8'), 'wb')
            fp.write(contentFileObj.getvalue())
            fp.close()
            ###imgObj = { 'session': sessionId, 'contentType': 'md5Matched', 'contentFile': filename, 'image': filename, 'md5Hash': hash_md5.hexdigest() }
            contentObj.hashValue = hash
            if 'friendly' in h:
              contentObj.hashFriendly = h['friendly']
            self.thisSession['images'].append( contentObj.get() )
      
      if contentObj.hashType == 'md5':
        hasher = hashlib.md5()
        hashRes = hasher.update(contentFileObj.getvalue())
        calcHash = hasher.hexdigest().lower()
        log.debug("ContentProcessor: genHash(): Session " + str(contentObj.session) + ". " + contentObj.hashType + " hash for " + contentObj.contentFile + " is " + calcHash)
        hashFinder(calcHash, self.cfg['md5Hashes'], contentObj)
      if contentObj.hashType == 'sha1':
        hasher = hashlib.sha1()
        hashRes = hasher.update(contentFileObj.getvalue())
        calcHash = hasher.hexdigest().lower()
        log.debug("ContentProcessor: genHash(): Session " + str(contentObj.session) + ". " + contentObj.hashType + " hash for " + contentObj.contentFile + " is " + calcHash)
        hashFinder(calcHash, self.cfg['sha1Hashes'], contentObj)
      if contentObj.hashType == 'sha256':
        hasher = hashlib.sha256()
        hashRes = hasher.update(contentFileObj.getvalue())
        calcHash = hasher.hexdigest().lower()
        log.debug("ContentProcessor: genHash(): Session " + str(contentObj.session) + ". " + contentObj.hashType + " hash for " + contentObj.contentFile + " is " + calcHash)
        hashFinder(calcHash, self.cfg['sha256Hashes'], contentObj)



  def startThread(self):
    try:
      asyncore.loop(.25, use_poll = False)
    except Exception as e:
      pass



  def stopCommunicator(self):
    asyncore.close_all()



  def go(self, payload, session, sessionId, serviceType, filename=None):
    #log.debug('ContentProcessor: go()')
    try:
      self.thisSession = session
      self.serviceType = serviceType # 'nw' or 'sa'
      if self.hashesAllowed and self.cfg['useHashFeed']:
        log.debug('ContentProcessor: go(): Initializing FeedManager')
        self.socketFile = self.cfg['hashFeederSocket']
        self.hashFeedId = self.cfg['hashFeed']['id']
        self.feedManager = FeedManager(self.socketFile, self.onFeederResponse, self.stopCommunicator, self.hashFeedId)

        self.thread =  Thread(target = self.startThread)
        self.thread.daemon = True
        self.thread.start()

        if self.cfg['serviceType'] == 'nw':
          res = self.extractFilesFromMultipart(sessionId, payload)
        elif self.cfg['serviceType'] == 'sa':
          cPayload = BytesIO()
          cPayload.write(payload)
          cPayload.seek(0)
          res = self.processInboundFile(sessionId, filename, cPayload )
        #raise Exception('test exception')
        self.feedManager.end()
        self.thread.join()
        return res
      else:
        if self.cfg['serviceType'] == 'nw':
          return self.extractFilesFromMultipart(sessionId, payload)
        elif self.cfg['serviceType'] == 'sa':
          cPayload = BytesIO()
          cPayload.write(payload)
          cPayload.seek(0)
          return self.processInboundFile(sessionId, filename, cPayload )
    except Exception as e:
      log.debug("ContentProcessor: go(): caught exception: " + str(e) )
      t, v, tb = sys.exc_info()
      eMessage = traceback.format_exception(t, v, tb)
      if hasattr(self, 'feedManager'):
        self.feedManager.end()
        self.thread.join()
      return eMessage



  def extractFilesFromMultipart(self, sessionId, payload):
    # this method is really just for netwitness multiparts
    log.debug("ContentProcessor: extractFilesFromMultipart(): Extracting files of session ID " + str(sessionId) )

    
    #log.debug('ContentProcessor: extractFilesFromMultiPart(): My Process Identifier: ' + str(self.processId))
    #log.debug( 'ContentProcessor: extractFilesFromMultiPart(): ' + current_process().name )
    #print("extractFilesFromMultipart(): Extracting files of session ID " + str(sessionId) )
    msg = email.parser.BytesParser().parsebytes(payload)
    counter = 1

    for part in msg.walk():

      # multipart/* are just containers
      maintype = part.get_content_maintype()
      subtype = part.get_content_subtype()
      if maintype == 'multipart' and subtype == 'mixed':
        continue

      #log.debug("ContentProcessor: extractFilesFromMultiPart(): maintype: " + maintype)
      #log.debug("ContentProcessor: extractFilesFromMultiPart(): subtype: " + subtype)

      payload = BytesIO()
      payload.write(part.get_payload(decode=True))
      contentType = None

      filename = part.get_filename()
      (base, ext) = os.path.splitext(filename)
      filename = base
      
      if maintype == 'image':
        contentType = 'image'
        filename = filename + '.' + subtype
      elif maintype == 'application' and subtype == 'pdf':
        contentType = 'pdf'
        filename = filename + '.pdf'
      else:
        # our artifact isn't an image or pdf, so allow it to be detected later
        log.debug("ContentProcessor: extractFilesFromMultiPart(): Mime type not recognized.  maintype: " + str(maintype))
        log.debug("ContentProcessor: extractFilesFromMultiPart(): subtype:" + str(subtype))
        if filename:
          filename = base
        else:
          filename = 'session-%d-part-%03d' % (sessionId, counter)
     
      self.processInboundFile(sessionId, filename, payload, contentType)
     
      if self.cfg['contentCount'].value >= self.cfg['contentLimit']:
        log.debug("ContentProcessor: extractFilesFromMultiPart(): Reached content limit")
        return self.thisSession

      counter += 1

    return self.thisSession



  def imageLimitDecider(self, contentObj):
    if self.cfg['contentCount'].value < self.cfg['contentLimit']:
      self.cfg['contentCount'].value += 1
      self.thisSession['images'].append( contentObj.get() )
      return True
    else:
      #we've exceeded the image limit
      return False
      #if self.serviceType == 'nw':
      #  return False
      #elif self.serviceType == 'sa':
      #  sys.exit(0)

  
  
  def processInboundFile(self, sessionId, filename, payload, contentType=None):
    # this method processes a file once it's been extracted from whatever its source is, be it a NW multipart message or a solera zip
    # payload is a BytesIO object

    self.poolId = current_process().name

    if not contentType:
      log.debug("ContentProcessor: processInboundFile(): Detecting content type")
      
      mimeType = magic.from_buffer( payload.getvalue(), mime=True)
      magicType = magic.from_buffer( payload.getvalue(), mime=False)
      log.debug("ContentProcessor: processInboundFile(): Mime type is " + mimeType)
      log.debug("ContentProcessor: processInboundFile(): Magic type is " + magicType)
      ext = None
      if mimeType == 'application/pdf':
        contentType = 'pdf'
        ext = '.pdf'
      elif magicType == 'Microsoft Word 2007+':
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
      elif mimeType.startswith('image'):
        contentType = 'image' #confirm this type
        discard, ext = mimeType.split('/')
        ext = ext.lower()
      elif mimeType in ['application/x-msdownload', 'application/x-ms-installer', 'application/x-elf', 'application/x-dosexec', 'application/x-executable']: #and len(md5Hashes) != 0: #fix this for known executable types
        contentType = 'executable'
      else: #should we make it to else, generate hash instead of continue?  stick with just exe's for now
        log.debug("ContentProcessor: processInboundFile(): No supported content type detected: " + mimeType)
        return
      
      #if not contentType == 'executable' and not filename.endswith(ext):
      #  filename = filename + '.' + ext

    if 'onlyContentFromArchives' in self.cfg and self.cfg['onlyContentFromArchives'] and contentType != 'zip' and contentType != 'rar':
      log.debug('ContentProcessor: processInboundFile(): Skipping file due to onlyContentFromArchives')
      return

    


    ##############################################################################
    #We're going to keep the content - so now start doing things with the content#
    ##############################################################################
    contentObj = ContentObj()
    contentObj.session = contentObj.session = sessionId

    if self.hashesAllowed: #hash check everything, including archives
      contentObj.contentFile = filename
      contentObj.setStringIOContent(payload)
      if not self.cfg['useHashFeed'] and self.cfg['md5Enabled'] and 'md5Hashes' in self.cfg and len(self.cfg['md5Hashes']) != 0:
        contentObj.hashType = 'md5'
        self.genHash(contentObj)
      if not self.cfg['useHashFeed'] and self.cfg['sha1Enabled'] and 'sha1Hashes' in self.cfg and len(self.cfg['sha1Hashes']) != 0:
        contentObj.hashType = 'sha1'
        self.genHash(contentObj)
      if not self.cfg['useHashFeed'] and self.cfg['sha256Enabled'] and 'sha256Hashes' in self.cfg and len(self.cfg['sha256Hashes']) != 0:
        contentObj.hashType = 'sha256'
        self.genHash(contentObj)
      if self.cfg['useHashFeed']:
        self.genHash(contentObj)


    if contentType == 'image' and self.imagesAllowed:
      contentObj.contentFile = filename
      contentObj.setStringIOContent(payload)
      if not self.processImage(contentObj):
        return
      
    elif contentType == 'pdf' and self.pdfsAllowed:
      contentObj.contentFile = filename
      contentObj.setStringIOContent(payload)
      if not self.processPdf(contentObj):
        return

    elif contentType == 'office' and self.officeAllowed:
      contentObj.contentFile = filename
      contentObj.contentSubType = contentSubType
      contentObj.setStringIOContent(payload)
      if not self.processOfficeDoc(contentObj):
        return
    


    ######################################################
    #################Process ZIP ARCHIVES#################
    ######################################################

    elif contentType == 'zip':
      log.debug("ContentProcessor: processInboundFile(): Attempting to extract zip archive " + filename)
      contentObj.fromArchive = True
      contentObj.archiveType = 'zip'
      saveZipFile = False
      #origContentObj = copy(contentObj)
      origContentObj = contentObj.getCopy()
      
      try:
        zipFileHandle = zipfile.ZipFile(payload)
      except zipfile.BadZipfile as e:
        log.warning("ContentProcessor: processInboundFile(): Bad ZIP File (file was not opened): " + contentObj.archiveFilename)
        return
      except zipfile.LargeZipFile as e:
        log.warning("ContentProcessor: processInboundFile(): ZIP file was too large to open: " + contentObj.archiveFilename)
        return
      except NotImplementedError as e:
        log.exception("ContentProcessor: processInboundFile(): NotImplemented exception during zip open")
        return
      except Exception as e:
        log.exception("ContentProcessor: processInboundFile(): Unhandled exception during zip file open")
        return
        
      try:
        for zinfo in zipFileHandle.infolist():
          #contentObj = copy(origContentObj)
          contentObj = origContentObj.getCopy()
          
          archivedFilename = zinfo.filename
          contentObj.contentFile = archivedFilename
          contentObj.archiveFilename = filename
          is_encrypted = zinfo.flag_bits & 0x1
          #print("DEBUG: zip compression type is",str(zinfo.compress_type))
          unsupported_compression = zinfo.compress_type == 99

          if not self.dodgyArchivesAllowed and (is_encrypted or unsupported_compression):
            continue
          
          elif is_encrypted and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled']:
            saveZipFile = True
            log.debug('ContentProcessor: processInboundFile(): ZIP contentFile %s from archive %s is encrypted!' % (archivedFilename, filename))
            contentObj.contentType = 'encryptedZipEntry'
            contentObj.fromArchive = True
            self.thisSession['images'].append( contentObj.get() )
            continue

          elif unsupported_compression and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled']:
            saveZipFile = True
            log.debug('ContentProcessor: processInboundFile(): ZIP archive %s uses an unsupported compression type!' % filename)
            contentObj.contentType = 'unsupportedZipEntry'
            contentObj.contentFile = filename #this is the zip file itself
            contentObj.fromArchive = False # if the file is unsupported, it becomes the content itself, not what's inside it,so it's not FROM an archive, it IS the archive
            contentObj.isArchive = True
            self.thisSession['images'].append( contentObj.get() )
            break
          
          else: #identify archived file and save it permanently if a supported file type
            extractedFileObj = BytesIO() #we will write the extracted file to this buffer

            #extract the file to buffer
            try:
              compressedFileHandle = zipFileHandle.open(archivedFilename) #compressedFileHandle is a handle to the file while it's still in the zip file.  we will extract from this object
            except zipfile.BadZipfile as e:
              log.warning("ContentProcessor: processInboundFile(): Bad ZIP File (file was not opened): " + contentObj.archiveFilename)
              continue
            except zipfile.LargeZipFile as e:
              log.warning("ContentProcessor: processInboundFile(): ZIP file was too large to open: " + contentObj.archiveFilename)
              continue
            except NotImplementedError as e:
              log.warning("ContentProcessor: processInboundFile(): NotImplemented exception during zip extraction.  This is often due to Apple app updates.")
              continue
            except Exception as e:
              log.warning("ContentProcessor: processInboundFile(): Unhandled exception during zip file open")
              continue
            extractedFileObj.write(compressedFileHandle.read() )  #this is where we extract the file into
            compressedFileHandle.close()

            contentObj.setStringIOContent(extractedFileObj)
            self.processExtractedFile(contentObj) #now let's process the extracted file
    
      except RuntimeError as e:
        if 'is encrypted, password required for extraction' in e.message:
          pass # do nothing and let our own code take the lead
        else:
          log.exception('ContentProcessor: processInboundFile(): Unhandled RuntimeError')
      except Exception as e:
        log.exception("ContentProcessor: processInboundFile(): Unhandled exception during zip file extraction")

      if saveZipFile:
        fp = open( bytes(os.path.join(self.cfg['outputDir'], filename), 'utf-8'), 'wb')
        fp.write(payload.getvalue())
        fp.close()
      return self.thisSession



    #################Process RAR ARCHIVES#################
    elif contentType == 'rar':
      log.debug("ContentProcessor: processInboundFile():  Attempting to extract rar archive " + filename)
      contentObj.fromArchive = True
      contentObj.archiveType = 'rar'
      saveRarFile = False
      origContentObj = contentObj.getCopy()
      
      try:
        rarFileHandle = rarfile.RarFile(payload, errors='strict')
      except rarfile.PasswordRequired as e:
        log.debug("ContentProcessor: processInboundFile(): RAR requires password: %s" % e)
        pass
      except rarfile.BadRarFile as e:
        log.debug("ContentProcessor: processInboundFile(): Bad RAR file")
        return
      except rarfile.NotRarFile as e:
        log.debug("ContentProcessor: processInboundFile(): Not a RAR file")
        return
      except rarfile.BadRarName as e:
        log.debug("ContentProcessor: processInboundFile(): Cannot guess multipart RAR name components")
        return
      except rarfile.NoRarEntry as e:
        log.debug("ContentProcessor: processInboundFile(): File not found in RAR")
        return
      except rarfile.NeedFirstVolume as e:
        log.debug("ContentProcessor: processInboundFile(): Need to start from first volume in RAR archive")
        return
      except rarfile.NoCrypto as e:
        log.debug("ContentProcessor: processInboundFile(): No crypto services available to parse encrypted headers")
        return
      except rarfile.RarCRCError as e:
        log.debug("ContentProcessor: processInboundFile(): CRC error during unpacking of RAR")
        return
      except rarfile.RarOpenError as e:
        log.debug("ContentProcessor: processInboundFile(): Error opening RAR file")
        return
      except rarfile.RarUserError as e:
        log.debug("ContentProcessor: processInboundFile(): RAR user error")
        return
      except rarfile.RarMemoryError as e:
        log.debug("ContentProcessor: processInboundFile(): RAR memory error")
        return
      except rarfile.RarNoFilesError as e:
        log.debug("ContentProcessor: processInboundFile(): RAR no files that match pattern were found")
        return
      except rarfile.RarUserBreak as e:
        log.debug("ContentProcessor: processInboundFile(): RAR user break")
        return
      except rarfile.RarWrongPassword as e:
        log.debug("ContentProcessor: processInboundFile(): RAR wrong password")
        return
      except rarfile.RarUnknownError as e:
        log.debug("ContentProcessor: processInboundFile(): RAR unknown error")
        return
      except rarfile.RarCannotExec as e:
        log.debug("ContentProcessor: processInboundFile(): RAR executable not found")
        return
      except rarfile.RarExecError as e:
        log.debug("ContentProcessor: processInboundFile(): There was a problem reported by unrar")
        return
      except Exception as e:
        log.exception("ContentProcessor: processInboundFile(): Unhandled exception during rar extraction")
        if self.cfg['devmode']:
          log.debug("ContentProcessor: processInboundFile(): processInboundFile(): Exiting with code 1") #we only exit if in dev mode, so we can deal with the problem afterwards
          sys.exit(1)

      #print(rarFileHandle.needs_password())
      #print(rarFileHandle.namelist())
      #rarFileHandle.printdir()
      #print(rarFileHandle.testrar())

      #we need something here for if the entire rar file table is encrypted
      table_len = len(rarFileHandle.namelist())
      #log.debug('ContentProcessor: processInboundFile(): table_len: %s' % table_len)
      table_content = rarFileHandle.namelist()
      #log.debug('ContentProcessor: processInboundFile(): table_content: %s' % table_content)
      table_needs_password = rarFileHandle.needs_password()
      #log.debug('ContentProcessor: processInboundFile(): table_needs_password: %s' % table_needs_password)

      if table_len == 0 and table_needs_password and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled'] and self.dodgyArchivesAllowed:
        #this means that the archive's table is encrypted and we cannot see anything inside it
        saveRarFile = True
        log.debug('ContentProcessor: processInboundFile(): RAR archive %s has an encrypted table!' % filename)
        contentObj.contentType = 'encryptedRarTable'
        contentObj.contentFile = filename #this is the rar file itself
        contentObj.fromArchive = False # if the file is encrypted, it becomes the content itself, not what's inside it,so it's not FROM an archive, it IS the archive
        contentObj.isArchive = True
        self.thisSession['images'].append( contentObj.get() )

      for rinfo in rarFileHandle.infolist():
        #contentObj = copy(origContentObj)
        contentObj = origContentObj.getCopy()

        archivedFilename = rinfo.filename
        contentObj.contentFile = archivedFilename
        contentObj.archiveFilename = filename
        archivedFile_is_encrypted = rinfo.needs_password()
        #log.debug('archivedFile_is_encrypted:' + str(archivedFile_is_encrypted))

        if archivedFile_is_encrypted and self.dodgyArchivesAllowed:
          # this means that the RAR file's table is not encrypted, but the file we're trying to extract is, and we don't want to distill it
          saveRarFile = True
          log.debug('ContentProcessor: processInboundFile(): RAR contentFile %s from archive %s is encrypted.  Marking archive for save.' % (archivedFilename,filename))
          contentObj.contentType = 'encryptedRarEntry'
          contentObj.fromArchive = True
          self.thisSession['images'].append( contentObj.get() )
          continue

        elif archivedFile_is_encrypted and not self.dodgyArchivesAllowed:
          # this means that the RAR file's table is not encrypted, but the file we're trying to extract is, and we do want to distill it, so do nothing
          log.debug('ContentProcessor: processInboundFile(): RAR contentFile %s from archive %s is encrypted, but not marking for save.' % (archivedFilename,filename))
          continue

        else: # file isn't encrypted.  identify archived file and process it if a supported file type
          extractedFileObj = BytesIO() #we will write the extracted file to this buffer

          #extract the file to buffer
          compressedFileHandle = rarFileHandle.open(archivedFilename) #compressedFileHandle is a handle to the file while it's still in the rar file.  we will extract from this object
          extractedFileObj.write(compressedFileHandle.read() ) #this is where we extract the file into
          compressedFileHandle.close()

          contentObj.setStringIOContent(extractedFileObj)
          self.processExtractedFile(contentObj) #now let's process the extracted file

      if saveRarFile:
        fp = open( bytes(os.path.join(self.cfg['outputDir'], filename), 'utf-8'), 'wb')
        fp.write(payload.getvalue())
        fp.close()
      return self.thisSession

    return self.thisSession



  def processExtractedFile(self, contentObj):
    log.debug("ContentProcessor: processExtractedFile(): Attempting to process extracted file " + contentObj.contentFile )
    
    # generate a new uuid for the content object
    #contentObj = contentObj.getCopy()
    #contentObj.newId()
    
    #get the file
    fileObj = contentObj.getFileContent()

    #identify the extracted file
    mimeType = magic.from_buffer( fileObj.getvalue(), mime=True) #this is where we identify the content file type
    magicType = magic.from_buffer( fileObj.getvalue(), mime=False) #this is where we identify the content file type

    log.debug("ContentProcessor: processExtractedFile(): mimeType: " + mimeType)

    #if fileType.startswith('image/') and len(self.cfg['distillationTerms']) == 0 and len(self.cfg['regexDistillationTerms']) == 0 and self.imagesAllowed:
    #if fileType.startswith('image/') and not self.cfg['distillationEnabled'] and not self.cfg['regexDistillationEnabled'] and self.imagesAllowed:

    

    if mimeType.startswith('image') and self.imagesAllowed:
      log.debug("ContentProcessor: processExtractedFile(): Processing '" + contentObj.contentFile + "' as image")
      contentObj.contentType = 'image'
      self.processImage(contentObj)

    elif mimeType == 'application/pdf' and self.pdfsAllowed:
      log.debug("ContentProcessor: processExtractedFile(): processing '" + contentObj.contentFile + "' as pdf")
      contentObj.contentType = 'pdf'
      self.processPdf(contentObj)

    elif magicType in [ 'Microsoft Word 2007+', 'Microsoft Excel 2007+', 'Microsoft PowerPoint 2007+' ] and self.officeAllowed:
      log.debug("ContentProcessor: processExtractedFile(): processing '" + contentObj.contentFile + "' as office document")

      if magicType == 'Microsoft Word 2007+':
        contentObj.contentType = 'office'
        contentObj.contentSubType = 'word'
      elif magicType == 'Microsoft Excel 2007+':
        contentObj.contentType = 'office'
        contentObj.contentSubType = 'excel'
      elif magicType == 'Microsoft PowerPoint 2007+':
        contentObj.contentType = 'office'
        contentObj.contentSubType = 'powerpoint'

      self.processOfficeDoc(contentObj)

    if self.hashesAllowed:
      #log.debug("ContentProcessor: processExtractedFile(): Processing '" + archivedFilename + "' as executable")
      if not self.cfg['useHashFeed'] and self.cfg['md5Enabled'] and 'md5Hashes' in self.cfg and len(self.cfg['md5Hashes']) != 0:
        contentObj.hashType = 'md5'
        self.genHash(contentObj)
      if not self.cfg['useHashFeed'] and self.cfg['sha1Enabled'] and 'sha1Hashes' in self.cfg and len(self.cfg['sha1Hashes']) != 0:
        contentObj.hashType = 'sha1'
        self.genHash(contentObj)
      if not self.cfg['useHashFeed'] and self.cfg['sha256Enabled'] and 'sha256Hashes' in self.cfg and len(self.cfg['sha256Hashes']) != 0:
        contentObj.hashType = 'sha256'
        self.genHash(contentObj)
      if self.cfg['useHashFeed']:
          self.genHash(contentObj)

  def convertPartToStringIO(self, part):
    output = BytesIO()
    output.write(part.get_payload(decode=True))
    return output        