import os 
import sys
import urllib2
import ssl
import base64
import json
import email
import mimetypes
from pprint import pprint
import StringIO
from PIL import Image ##install
from communicator import communicator
import time
from subprocess import Popen, PIPE
import zipfile
import shutil
import magic ##install
import hashlib
import rarfile ##install
import re
import logging
from ContentObj import ContentObj

log = logging.getLogger(__name__)

class Fetcher:

  def __init__(self, communicator, url, user, password, directory, minX, minY, gsPath, pdftotextPath, unrarPath, imageLimit):
    self.communicator = communicator
    self.url = url
    self.user = user
    self.password = password
    self.summary = {}
    self.sessions = {}
    self.searchContent = []
    self.directory = directory
    self.minX = int(minX)
    self.minY = int(minY)
    self.gsPath = gsPath
    self.pdftotextPath = pdftotextPath
    #self.unrarPath = unrarPath
    rarfile.UNRAR_TOOL = unrarPath
    self.imageLimit = imageLimit
    self.imageCount = 0
    self.thumbnailSize = 350, 350
    self.devmode = True
    log.info("Minimum dimensions are: " + str(minX) + " x " + str(minY))

  """curl "http://admin:netwitness@172.16.0.55:50104/sdk?msg=query&query=$query&force-content-type=application/json"""

  def fetchSummary(self):
    request = urllib2.Request(self.url + '/sdk?msg=summary')
    base64string = base64.b64encode('%s:%s' % (self.user, self.password))
    request.add_header("Authorization", "Basic %s" % base64string)
    request.add_header('Content-type', 'application/json')
    request.add_header('Accept', 'application/json')
    summaryResult = json.load(urllib2.urlopen(request, timeout=5))
    for e in summaryResult['string'].split():
      (k, v) = e.split('=')
      self.summary[k] = v



  def runQuery(self, query):
    reqStr = self.url + '/sdk?msg=query&query=' + query  #&flags=4096
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib2.Request(reqStr)
    base64string = base64.b64encode('%s:%s' % (self.user, self.password))
    request.add_header("Authorization", "Basic %s" % base64string)
    request.add_header('Content-type', 'application/json')
    request.add_header('Accept', 'application/json')
    try:
      rawQueryRes = json.load(urllib2.urlopen(request, context=ctx, timeout=5))
      #pprint(rawQueryRes)
      #print "length of rawQueryRes", len(rawQueryRes)
      for field in rawQueryRes:
        if 'results' in field and isinstance(field, dict):
          if 'fields' in field['results']:
            metaList = field['results']['fields']
            for meta in metaList:
              key = meta['type']
              value = meta['value']
              sessionId = meta['group']
              if not sessionId in self.sessions:
                self.sessions[sessionId] = { 'images': [], 'session': { 'id': sessionId, 'meta': {} } }
              if not key in self.sessions[sessionId]['session']['meta']:
                self.sessions[sessionId]['session']['meta'][key] = []
              self.sessions[sessionId]['session']['meta'][key].append(value)
    except urllib2.HTTPError as e:
      log.exception("HTTP Error.  Exiting with code 1.")
      sys.exit(1)
    except urllib2.URLError as e:
      log.exception("URL Error.  Exiting with code 1")
      sys.exit(1)
    except Exception as e:
      raise
      log.exception("Exception during runQuery.  Exiting with code 1.")
      sys.exit(1)
    return len(self.sessions)





  def pullFiles(self, distillationTerms, regexDistillationTerms, ignoredSessions, md5Hashes=[], sha1Hashes=[], sha256Hashes=[]):

    for sessionId in self.sessions:
      if not sessionId in ignoredSessions:
        try:
          if not self.imageCount >= self.imageLimit:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            request = urllib2.Request(self.url + '/sdk/content?render=107&session=' + str(sessionId))
            base64string = base64.b64encode('%s:%s' % (self.user, self.password))
            request.add_header("Authorization", "Basic %s" % base64string)
            request.add_header('Content-type', 'application/json')
            request.add_header('Accept', 'application/json')
            res = urllib2.urlopen(request, context=ctx, timeout=5)
            if res.info().getheader('Content-Type').startswith('multipart/mixed'):
              contentType = res.info().getheader('Content-Type')
              mimeVersion = res.info().getheader('Mime-Version')
              newFileStr = 'Content-Type: ' + contentType + '\n' + 'Mime-Version: ' + mimeVersion + '\n' + res.read()
              self.extractFilesFromMultipart(newFileStr, sessionId, distillationTerms, regexDistillationTerms, md5Hashes, sha1Hashes, sha256Hashes)
              if len(self.sessions[sessionId]['images']) != 0:
                log.debug("Worker sending update")
                self.communicator.write_data(json.dumps( { 'collectionUpdate': self.sessions[sessionId] } ) + '\n')
          else:
            log.info("Image limit of " + str(self.imageLimit) + " has been reached.  Ending collection build.  You may want to narrow your result set with a more specific query")
            return
        
        except urllib2.HTTPError as e:
          log.exception("HTTP error pulling content for session " + sessionId + ".  Exiting with code 1.")
          sys.exit(1)
        except urllib2.URLError as e:
          log.exception("ERROR: URL error pulling content for session " + sessionId + ".  Exiting with code 1.")
          sys.exit(1)
    
    
    


  
  def processImage(self, contentObj): #must specify either part or stringFile
    log.debug("Analyzing image " + contentObj.contentFile)
    contentObj.contentType = 'image'
    output = contentObj.getFileContent()
      
    try:
      im = Image.open(output)
      (x,y) = im.size
    except Exception as e:
      log.warning("Could not identify image file " + contentObj.contentFile + ".  This is likely due to file corruption")
      return False
      
    #check file for dimensions and only write if minimum
    if x >= int(self.minX) and y >= int(self.minY):
      log.debug("Keeping image " + contentObj.contentFile + " of resolution " + str(x) + 'x' + str(y) )
      fp = open(os.path.join(self.directory, contentObj.contentFile), 'wb')
      fp.write(output.getvalue())
      fp.close()

      try:
        log.debug("Generating thumbnail for image " + contentObj.contentFile)
        thumbnailName = 'thumbnail_' + contentObj.contentFile
        im.thumbnail(self.thumbnailSize, Image.ANTIALIAS)
        im.save(os.path.join(self.directory, thumbnailName), im.format)
        #overwrite imgObj if we had to make a thumbnail
        contentObj.thumbnail = thumbnailName
        ###imgObj = { 'session': sessionId, 'image': filename, 'thumbnail': thumbnailName, 'contentType': contentType}
        self.sessions[contentObj.session]['images'].append( contentObj.get() )
        self.imageCount += 1

      except Exception as e: #we don't want to keep corrupt files.  we know it's corrupt if we can't generate a thumbnail
        log.exception("Error generating thumbnail for image " + contentObj.contentFile)
        return False

    else:
      log.debug("Discarding image " + contentObj.contentFile + " due to minimum size requirements")
      return False
    
    return True

  


  def processPdf(self, contentObj, distillationTerms, regexDistillationTerms):
    contentObj.contentType = 'pdf'

    #write pdf to disk
    log.debug("Writing pdf to " + os.path.join(self.directory, contentObj.contentFile) )
    fp = open(os.path.join(self.directory, contentObj.contentFile), 'wb')
    shutil.copyfileobj(contentObj.getFileContent(), fp)
    fp.close()
    
    #extract first page of pdf
    #gs -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile="p%o3d.jpg" -dFirstPage=1 -dLastPage=1 -dBATCH "$filename"
    log.debug("Extracting first page of pdf " + contentObj.contentFile)
    outputfile = "page1-" + contentObj.contentFile + ".jpg"
    contentObj.pdfImage = outputfile
    log.debug("Running gs on file " + contentObj.contentFile)
    
    try:
      gsCmd = self.gsPath + " -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile='" + os.path.join(self.directory, outputfile) + "' -dFirstPage=1 -dLastPage=1 -dBATCH '" +  os.path.join(self.directory, contentObj.contentFile) + "'"
      log.debug("Ghostscript command line: " + gsCmd)
      process = Popen(gsCmd, stdout=PIPE, stderr=PIPE, shell = True)
      #print "process opened"
      (output, err) = process.communicate()
      exit_code = process.wait()

      if exit_code == 0: #this means we successfully generated an image of the pdf and we want to keep it
        keep = True
        ###keep means we want to keep the file.  We choose to not keep the file (by making keep = False) on these conditions:
        ###1: if an error is generated by gs whilst trying to render an image of the first page
        ###2: if we have distillationTerms and/or regexDistillationTerms and they aren't matched
        if len(distillationTerms) == 0 and len(regexDistillationTerms) == 0:
          self.getPdfText(contentObj)
        elif len(distillationTerms) != 0 and len(regexDistillationTerms) == 0:
          keep = self.getPdfText(contentObj, searchTerms=distillationTerms)
        elif len(distillationTerms) == 0 and len(regexDistillationTerms) != 0:
          keep = self.getPdfText(contentObj, regexSearchTerms=regexDistillationTerms)
        else:
          keep = self.getPdfText(contentObj, searchTerms=distillationTerms, regexSearchTerms=regexDistillationTerms)
        
        if keep == False:
          return False #return if we've chosen to not keep the file
        
        try:
          #now let's try generating a thumbnail - if we already have an image, this should succeed.  If not, there's something screwy...
          #but we'll keep it anyway and use the original image as the thumbnail and let the browser deal with any potential corruption
          log.debug("Generating thumbnail for pdf " + outputfile)
          thumbnailName = 'thumbnail_' + outputfile
          pdfim = Image.open(os.path.join(self.directory, outputfile))
          pdfim.thumbnail(self.thumbnailSize, Image.ANTIALIAS)
          pdfim.save(os.path.join(self.directory, thumbnailName), pdfim.format)
          #pdfim.close()

          #set thumbnail to our generated thumbnail
          contentObj.thumbnail = thumbnailName
          self.sessions[contentObj.session]['images'].append( contentObj.get() )
          self.imageCount += 1
          return True
        except Exception as e:
          log.exception("Error generating thumbnail for pdf " + contentObj.contentFile)
          #thumbnail generation failed, so set thumbnail to be the original image generated by gs
          contentObj.thumbnail = outputfile
          self.sessions[contentObj.session]['images'].append( contentObj.get() )
          self.imageCount += 1
          return True

      if exit_code != 0:
        #Ghostscript exited with a non-zero exit code, and thus was unsuccessful
        log.warning("GhostScript exited abnormally with code " + str(exit_code) )
        return False
        
    except Exception as e:
      #Ghostscript couldn't even be run
      log.exception("Could not run GhostScript command at " + self.gsPath )
      return False



  def genHash(self, contentObj, hashes): #must specify either part or stringFile
    #print "genHash()"
    contentObj.contentType = 'hash'
    log.debug("genHash(): Generating " + contentObj.hashType + " hash for " + contentObj.contentFile)

    contentFileObj = contentObj.getFileContent()

    if contentObj.hashType == 'md5':
      hash = hashlib.md5()
    if contentObj.hashType == 'sha1':
      hash = hashlib.sha1()
    if contentObj.hashType == 'sha256':
      hash = hashlib.sha256()
    hash.update(contentFileObj.getvalue())
      
    log.debug(contentObj.hashType + " hash for " + contentObj.contentFile + " is " + hash.hexdigest())

    for h in hashes:
      if hash.hexdigest().decode('utf-8').lower() == h['hash'].lower():
        log.debug("Matched " + contentObj.hashType + " hash " + h['hash'])
        fp = open(os.path.join(self.directory, contentObj.contentFile), 'wb')
        fp.write(contentFileObj.getvalue())
        fp.close()
        ###imgObj = { 'session': sessionId, 'contentType': 'md5Matched', 'contentFile': filename, 'image': filename, 'md5Hash': hash_md5.hexdigest() }
        contentObj.hashValue = hash.hexdigest()
        if 'friendly' in h:
          contentObj.hashFriendly = h['friendly']
        self.sessions[contentObj.session]['images'].append( contentObj.get() )

        


  def extractFilesFromMultipart(self, fileStr, sessionId, distillationTerms, regexDistillationTerms, md5Hashes, sha1Hashes, sha256Hashes):
    log.debug("Extracting files of session ID " + str(sessionId) )
    #msgfile = './file3.out'
    #fp = open(msgfile)
    #msg = email.message_from_file(fp)
    msg = email.message_from_string(fileStr)
    #fp.close()
    #print [method for method in dir(msg) if callable(getattr(msg, method))]
    counter = 1
    for part in msg.walk():
      #print [method for method in dir(part) if callable(getattr(part, method))]
  
      # multipart/* are just containers
      if part.get_content_maintype() == 'multipart' and part.get_content_subtype() == 'mixed':
        continue
      #elif part.get_content_maintype() == 'image' and len(distillationTerms) == 0:
      elif part.get_content_maintype() == 'image':
        contentType = 'image'
      elif part.get_content_maintype() == 'application' and part.get_content_subtype() == 'pdf':
        contentType = 'pdf'
      else:
        log.debug("Detecting archives")
        type = magic.from_buffer( part.get_payload(decode=True), mime=True)
        log.debug("Magic type is " + type)
        if type == 'application/zip':
          contentType = 'zip'
        elif type == 'application/x-rar':
          contentType = 'rar' #confirm this type
        elif type in ['application/x-msdownload', 'application/x-ms-installer', 'application/x-elf', 'application/x-dosexec', 'application/x-executable']: #and len(md5Hashes) != 0: #fix this for known executable types
          contentType = 'executable'
        else: #should we make else generate hash instead of continue?  stick with just exe's for now
          continue
      
      # Applications should really sanitize the given filename so that an
      # email message can't be used to overwrite important files
      filename = part.get_filename().decode('utf-8')
      if not filename:
        log.debug("No filename")
        ext = mimetypes.guess_extension(part.get_content_type())
        if not ext:
          # Use a generic bag-of-bits extension
          ext = '.bin'
        filename = 'part-%03d%s' % (counter, ext)
      counter += 1
      
      #print filename, part.get_content_maintype(), part.get_content_subtype()

      if self.imageCount >= self.imageLimit:
        return



      ##########################################################################
      #We're going to keep the content - so now start doing things with the content
      ##########################################################################
      contentObj = ContentObj()
      contentObj.session = contentObj.session = sessionId

      if contentType == 'image':
        contentObj.contentFile = filename
        contentObj.setPartContent(part)
        ###if not self.processImage(filename, sessionId, contentType, part=part):
        if not self.processImage(contentObj):
          continue
        
      elif contentType == 'pdf':
        contentObj.contentFile = filename
        contentObj.setPartContent(part)
        ###if not self.processPdf(filename, sessionId, contentType, distillationTerms, regexDistillationTerms, part=part):
        if not self.processPdf(contentObj, distillationTerms, regexDistillationTerms):
          continue
        
      elif contentType == 'executable':
        contentObj.contentFile = filename
        contentObj.setPartContent(part)
        if len(md5Hashes) != 0:
          contentObj.hashType = 'md5'
          #self.genMd5(contentObj, md5Hashes)
          self.genHash(contentObj, md5Hashes)
        if len(sha1Hashes) != 0:
          contentObj.hashType = 'sha1'
          #self.genSha1(contentObj, sha1Hashes)
          self.genHash(contentObj, sha1Hashes)
        if len(sha256Hashes) != 0:
          contentObj.hashType = 'sha256'
          ###self.genSha256(filename, sessionId, contentType, sha256Hashes, part=part)
          #self.genSha256(contentObj, sha256Hashes)
          self.genHash(contentObj, sha256Hashes)
      



      #################Process ZIP ARCHIVES#################
      elif contentType == 'zip':
        log.debug("Attempting to extract zip archive " + filename)
        contentObj.fromArchive = True
        contentObj.archiveType = 'zip'
        saveZipFile = False
        
        try:
          zipFileHandle = zipfile.ZipFile(self.convertPartToStringIO(part))

          for zinfo in zipFileHandle.infolist():
            
            archivedFilename = zinfo.filename
            contentObj.contentFile = archivedFilename
            contentObj.archiveFilename = filename
            is_encrypted = zinfo.flag_bits & 0x1
            #print "DEBUG: zip compression type is",str(zinfo.compress_type)
            unsupported_compression = zinfo.compress_type == 99
            
            if is_encrypted:
              saveZipFile = True
              log.debug('ZIP contentFile %s from archive %s is encrypted!' % (archivedFilename, filename))
              contentObj.contentType = 'encryptedZipEntry'
              #contentObj.contentFile = filename #this is the zip file itself
              contentObj.fromArchive = True
              self.sessions[sessionId]['images'].append( contentObj.get() )
              continue

            elif unsupported_compression:
              saveZipFile = True
              log.debug('ZIP archive %s uses an unsupported compression type!' % filename)
              contentObj.contentType = 'unsupportedZipEntry'
              contentObj.contentFile = filename #this is the zip file itself
              contentObj.fromArchive = False # if the file is unsupported, it becomes the content itself, not what's inside it,so it's not FROM an archive, it IS the archive
              contentObj.isArchive = True
              self.sessions[sessionId]['images'].append( contentObj.get() )
              break
            
            else: #identify archived file and save it permanently if a supported file type
              #print("Got to 1")
              extractedFileObj = StringIO.StringIO() #we will write the extracted file to this buffer

              #extract the file to buffer
              compressedFileHandle = zipFileHandle.open(archivedFilename) #compressedFileHandle is a handle to the file while it's still in the zip file.  we will extract from this object
              extractedFileObj.write(compressedFileHandle.read() )  #this is where we extract the file into
              compressedFileHandle.close()

              contentObj.setStringIOContent(extractedFileObj)
              self.processExtractedFile(contentObj, distillationTerms, regexDistillationTerms, md5Hashes, sha1Hashes, sha256Hashes) #now let's process the extracted file
              extractedFileObj.close()

        except zipfile.BadZipfile as e:
          log.exception("Exception during zip open (file was not opened)") 
        except zipfile.LargeZipFile as e:
          log.exception("Exception during zip open (file was not opened)")
        except NotImplementedError as e:
          log.exception("NotImplemented exception during zip extraction")
        except Exception as e:
          log.exception("Unhandled exception during zip extraction")
        if saveZipFile:
          fp = open(os.path.join(self.directory, filename), 'wb')
          fp.write(part.get_payload(decode=True))
          fp.close()
        continue          



      #################Process RAR ARCHIVES#################
      elif contentType == 'rar':
        log.debug("Attempting to extract rar archive " + filename)
        contentObj.fromArchive = True
        contentObj.archiveType = 'rar'
        saveRarFile = False
        
        try:
          rarFileHandle = rarfile.RarFile(self.convertPartToStringIO(part))

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

          if table_len == 0 and table_needs_password: #this means that the archive's table is encrypted and we cannot see anything inside it
            saveRarFile = True
            log.debug('RAR archive %s has an encrypted table!' % filename)
            contentObj.contentType = 'encryptedRarTable'
            contentObj.contentFile = filename #this is the rar file itself
            contentObj.fromArchive = False # if the file is encrypted, it becomes the content itself, not what's inside it,so it's not FROM an archive, it IS the archive
            contentObj.isArchive = True
            self.sessions[sessionId]['images'].append( contentObj.get() )

          for rinfo in rarFileHandle.infolist():
        
            archivedFilename = rinfo.filename
            contentObj.contentFile = archivedFilename
            contentObj.archiveFilename = filename
            archivedFile_is_encrypted = rinfo.needs_password()

            if archivedFile_is_encrypted: #this means that the RAR file's table is not encrypted, but individual files within it are
              saveRarFile = True
              log.debug('RAR contentFile %s from archive %s is encrypted!' % (archivedFilename,filename))
              contentObj.contentType = 'encryptedRarEntry'
              contentObj.fromArchive = True
              self.sessions[sessionId]['images'].append( contentObj.get() )
              continue

            else: #identify archived file and save it permanently if a supported file type
              extractedFileObj = StringIO.StringIO() #we will write the extracted file to this buffer

              #extract the file to buffer
              compressedFileHandle = rarFileHandle.open(archivedFilename) #compressedFileHandle is a handle to the file while it's still in the rar file.  we will extract from this object
              extractedFileObj.write(compressedFileHandle.read() ) #this is where we extract the file into
              compressedFileHandle.close()

              contentObj.setStringIOContent(extractedFileObj)
              self.processExtractedFile(contentObj, distillationTerms, regexDistillationTerms, md5Hashes, sha1Hashes, sha256Hashes) #now let's process the extracted file
              extractedFileObj.close()

        except rarfile.PasswordRequired as e:
          log.exception("RAR requires password: %s" % e)
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
          if self.devmode:
            log.debug("Exiting with code 1") #we only exit if in dev mode, so we can deal with the problem afterwards
            sys.exit(1)
        if saveRarFile:
          fp = open(os.path.join(self.directory, filename), 'wb')
          fp.write(part.get_payload(decode=True))
          fp.close()
        continue



  def processExtractedFile(self, contentObj, distillationTerms, regexDistillationTerms, md5Hashes, sha1Hashes, sha256Hashes):
    log.debug("processExtractedFile() Attempting to process extracted file " + contentObj.contentFile )
    #get the file
    fileObj = contentObj.getFileContent()

    #identify the extracted file
    fileType = magic.from_buffer( fileObj.getvalue(), mime=True) #this is where we identify the content file type

    if fileType.startswith('image/'):
      #log.debug("Processing '" + archivedFilename + "' as image")
      self.processImage(contentObj)

    elif fileType == 'application/pdf':
      #log.debug("processing '" + contentObj.contentType + "' as pdf")
      self.processPdf(contentObj, distillationTerms, regexDistillationTerms)

    elif fileType.startswith('application/'): #fix for executable
      #log.debug("Processing '" + archivedFilename + "' as executable")
      if len(md5Hashes) != 0:
        contentObj.hashType = 'md5'
        self.genHash(contentObj, md5Hashes)
      if len(sha1Hashes) != 0:
        contentObj.hashType = 'sha1'
        self.genHash(contentObj, sha1Hashes)
      if len(sha256Hashes) != 0:
        contentObj.hashType = 'sha256'
        self.genHash(contentObj, sha256Hashes)
        
    else:
      #print "DEBUG: discarding " + archivedFilename + ' with MIME type ' + fileType
      pass



  def convertPartToStringIO(self, part):
    output = StringIO.StringIO()
    output.write(part.get_payload(decode=True))
    return output

  def getPdfText(self, contentObj, searchTerms=[], regexSearchTerms=[]):
    try: #now extract pdf text
      sessionId = contentObj.session
      pdftotextCmd = self.pdftotextPath + " -enc UTF-8 -eol unix -nopgbrk -q '" + os.path.join(self.directory, contentObj.contentFile) + "' -"
      log.debug("pdftotextCmd: " + pdftotextCmd)
      pdftotextProcess = Popen(pdftotextCmd, stdout=PIPE, stderr=PIPE, shell = True)
      (output, err) = pdftotextProcess.communicate()
      exit_code = pdftotextProcess.wait()
      if exit_code == 0:
        #extracted successfully, get output
        joinedText = output.replace('\n', ' ').replace('\r', '')

        found = 0
        for term in searchTerms:
          #print "term:", term.lower()
          if term.decode('utf-8').lower() in joinedText.decode('utf-8').lower():
            found += 1
        for t in regexSearchTerms:
          term = t.decode('utf-8')
          log.debug( "Regex search term: " + term)
          compiledTerm = re.compile(term)
          if compiledTerm.search(joinedText.decode('utf-8')) != None:
            found += 1
            log.debug("Matched regex search term " + term)

        #'keep' is a variable that gets returned which indicates whether the document and session should be retained as part of a collection, if a term has been matched or if there were no terms
        if len(searchTerms) == 0 and len(regexSearchTerms) == 0: #no search terms defined - definitely keep this session
          keep = True
        elif ( len(searchTerms) != 0 or len(regexSearchTerms) != 0 ) and found > 0: #we had search terms and had at least one match, so we will keep this session
          keep = True 
          #print "found " + str(found) + " match(es)"
        elif ( len(searchTerms) != 0 or len(regexSearchTerms) != 0 ) and found == 0: #we had search terms but got no matches, so we won't keep this session
          keep = False
        
        if keep:
          log.debug("getPdfText(): keeping file " + contentObj.contentFile)
          searchObj = { 'session': sessionId, 'contentFile': contentObj.contentFile, 'searchString': joinedText }
          if not 'search' in self.sessions[sessionId]:
            self.sessions[sessionId]['search'] = []
          #pprint(self.sessions[sessionId]['search'])
          self.sessions[sessionId]['search'].append(searchObj)

        return keep
        
    except Exception as e:
      log.exception("Could not run pdftotext command at " + self.pdftotextPath)
      #print "Error Message:", str(e)
      #continue
      #if searchForText:
      #if len(searchForText) != 0:
      #  return True #keep session if pdftotext has issues.
      return False
        
   