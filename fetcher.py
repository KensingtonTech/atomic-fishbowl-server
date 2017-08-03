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
from PIL import Image
from communicator import communicator
import time
from subprocess import Popen, PIPE
import zipfile
import shutil
import magic
import hashlib
import rarfile
import re
import logging

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
    log.info("Minimum dimensions are: " + str(minX) + " x " + str(minY) )
    

  """curl "http://admin:netwitness@172.16.0.55:50104/sdk?msg=query&query=$query&force-content-type=application/json"""

  def fetchSummary(self):
    request=urllib2.Request(self.url + '/sdk?msg=summary')
    base64string = base64.b64encode('%s:%s' % (self.user, self.password))
    request.add_header("Authorization", "Basic %s" % base64string)  
    request.add_header('Content-type','application/json') 
    request.add_header('Accept','application/json')
    summaryResult = json.load(urllib2.urlopen(request, timeout=5))
    for e in summaryResult['string'].split():
      (k,v) = e.split('=')
      self.summary[k] = v
      
      
      
  def runQuery(self, query):
    reqStr = self.url + '/sdk?msg=query&query=' + query  #&flags=4096
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE 
    request=urllib2.Request(reqStr)
    base64string = base64.b64encode('%s:%s' % (self.user, self.password))
    request.add_header("Authorization", "Basic %s" % base64string)  
    request.add_header('Content-type','application/json') 
    request.add_header('Accept','application/json')
    try:
      rawQueryRes = json.load(urllib2.urlopen(request, context=ctx, timeout=5))
      #pprint(rawQueryRes)
      #print "length of rawQueryRes", len(rawQueryRes)
      for field in rawQueryRes:
        #pprint(field)
        #print "type: " + str(type(field))
        if 'results' in field and isinstance(field, dict):
          if 'fields' in field['results']:
            metaList = field['results']['fields']
            for meta in metaList:
              key=meta['type']
              value=meta['value']
              sessionId=meta['group']
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
            request=urllib2.Request(self.url + '/sdk/content?render=107&session=' + str(sessionId))
            base64string = base64.b64encode('%s:%s' % (self.user, self.password))
            request.add_header("Authorization", "Basic %s" % base64string)  
            request.add_header('Content-type','application/json') 
            request.add_header('Accept','application/json')
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
    
    
    


  def processImage(self, filename, sessionId, contentType, fromArchive='', part='', stringFile=''): #must specify either part or stringFile
    log.debug("Analyzing image " + filename)

    if part != '':
      output = StringIO.StringIO()
      output.write(part.get_payload(decode=True))
    elif stringFile != '':
      output = stringFile
      
    try:
      im = Image.open(output)
      (x,y) = im.size
    except Exception as e:
      log.warning("Could not identify image file " + filename + ".  This is likely due to file corruption")
      output.close()
      return False

    #print "minX, minY:",self.minX,self.minY
    #check file for dimensions and only write if minimum

    if x >= int(self.minX) and y >= int(self.minY):
      log.debug("Keeping image " + filename + " of resolution " + str(x) + 'x' + str(y) )
      fp = open(os.path.join(self.directory, filename), 'wb')
      fp.write(output.getvalue())
      fp.close()
      #imgObj = { 'session': sessionId, 'image': filename, 'thumbnail': filename, 'contentType': contentType}

      try:
        #if x > 350 or y > 350: #our thumbnail size is max 350x350
        log.debug("Generating thumbnail for " + filename)
        thumbnailName = 'thumbnail_' + filename
        im.thumbnail(self.thumbnailSize, Image.ANTIALIAS)
        im.save(os.path.join(self.directory, thumbnailName), im.format)
        #overwrite imgObj if we had to make a thumbnail
        imgObj = { 'session': sessionId, 'image': filename, 'thumbnail': thumbnailName, 'contentType': contentType}
        if fromArchive != '':
          imgObj['fromArchive'] = fromArchive
        self.sessions[sessionId]['images'].append( imgObj )
        self.imageCount += 1

      except Exception as e: #we don't want to keep corrupt files.  we know it's corrupt if we can't generate a thumbnail
        log.exception("Error generating thumbnail for " + filename)
      

    else:
      log.debug("Discarding image " + filename + " due to minimum size requirements")
    im.close()
    output.close()
    #fp = open(os.path.join(self.directory, filename), 'wb')
    #fp.write(part.get_payload(decode=True))
    #fp.close()
    return True
    









  def processPdf(self, filename, sessionId, contentType, distillationTerms, regexDistillationTerms, fromArchive='', part='', stringFile=''):
    log.debug("Extracting first page of pdf " + filename)
    #write pdf to disk
    log.debug("Writing pdf to " + os.path.join(self.directory, filename) )

    fp = open(os.path.join(self.directory, filename), 'wb')
    if part != '':
      fp.write(part.get_payload(decode=True))
    elif stringFile != '':
      shutil.copyfileobj(stringFile, fp)
    fp.close()
    #extract first page of pdf
    #gs -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile="p%o3d.jpg" -dFirstPage=1 -dLastPage=1 -dBATCH "$filename"
    outputfile = "page1-" + filename + ".jpg"
    log.debug("Running gs on file " + filename)
    
    try:
      gsCmd = self.gsPath + " -dNOPAUSE -sDEVICE=jpeg -r144 -sOutputFile='" + os.path.join(self.directory, outputfile) + "' -dFirstPage=1 -dLastPage=1 -dBATCH '" +  os.path.join(self.directory, filename) + "'"
      log.debug("Ghostscript command line: " + gsCmd)
      process = Popen(gsCmd, stdout=PIPE, stderr=PIPE, shell = True)
      #print "process opened"
      (output, err) = process.communicate()
      exit_code = process.wait()
      if exit_code == 0:
        
        keep = True
        if len(distillationTerms) == 0 and len(regexDistillationTerms) == 0:
          self.getPdfText(filename, sessionId)
        elif len(distillationTerms) != 0 and len(regexDistillationTerms) == 0:
          keep = self.getPdfText(filename, sessionId, searchTerms=distillationTerms)
        elif len(distillationTerms) == 0 and len(regexDistillationTerms) != 0:
          keep = self.getPdfText(filename, sessionId, regexSearchTerms=regexDistillationTerms)
        else:
          keep = self.getPdfText(filename, sessionId, searchTerms=distillationTerms, regexSearchTerms=regexDistillationTerms)
        
        imgObj = {}
        try:
          log.debug("Generating thumbnail for pdf " + outputfile)
          thumbnailName = 'thumbnail_' + outputfile
          pdfim = Image.open(os.path.join(self.directory, outputfile))
          pdfim.thumbnail(self.thumbnailSize, Image.ANTIALIAS)
          pdfim.save(os.path.join(self.directory, thumbnailName), pdfim.format)
          pdfim.close()
          #overwrite imgObj if we had to make a thumbnail
          #imgObj = { 'session': sessionId, 'image': filename, 'thumbnail': thumbnailName, 'contentType': contentType}
          if keep:
            imgObj = { 'session': sessionId, 'image': outputfile, 'thumbnail': thumbnailName, 'contentFile': filename, 'contentType': contentType}
            if fromArchive != '':
              imgObj['fromArchive'] = fromArchive
            self.sessions[sessionId]['images'].append( imgObj )
            self.imageCount += 1
            return True
        except Exception as e:
          log.exception("Error generating thumbnail for pdf " + filename)
          if keep:
            imgObj = { 'session': sessionId, 'image': outputfile, 'thumbnail': outputfile, 'contentFile': filename, 'contentType': contentType}
            if fromArchive != '':
              imgObj['fromArchive'] = fromArchive
            self.sessions[sessionId]['images'].append( imgObj )
            self.imageCount += 1
            return True

      if exit_code != 0:
        #processed unsuccessfully
        log.warning("GhostScript exited abnormally with code " + str(exit_code) )
        return False
        
    except Exception as e:
      log.exception("Could not run GhostScript command at " + self.gsPath )
      return False



  def genMd5(self, filename, sessionId, contentType, md5Hashes, fromArchive='', part='', stringFile=''): #must specify either part or stringFile
    log.debug("genMd5(): Generating md5 hash for " + filename)

    if part != '':
      output = StringIO.StringIO()
      output.write(part.get_payload(decode=True))
    elif stringFile != '':
      output = stringFile
 
    hash_md5 = hashlib.md5()
    hash_md5.update(output.getvalue())
      
    #hash_md5.hexdigest()

    log.debug("MD5 hash for " + filename + " is " + hash_md5.hexdigest())

    for h in md5Hashes:
      if hash_md5.hexdigest().decode('utf-8').lower() == h.lower():
      #if hash_md5.digest().lower() == h.lower():
        log.debug("Matched hash " + h)
        fp = open(os.path.join(self.directory, filename), 'wb')
        fp.write(output.getvalue())
        fp.close()
        imgObj = { 'session': sessionId, 'contentType': 'md5Matched', 'contentFile': filename, 'image': filename, 'md5Hash': hash_md5.hexdigest() }
        if fromArchive != '':
          imgObj['fromArchive'] = fromArchive #fromArchive is the type of archive (either 'zip' or 'rar')
        self.sessions[sessionId]['images'].append( imgObj )
    
    


  def genSha1(self, filename, sessionId, contentType, sha1Hashes, fromArchive='', part='', stringFile=''): #must specify either part or stringFile
    log.debug("genSha1(): Generating sha1 hash for " + filename)

    if part != '':
      output = StringIO.StringIO()
      output.write(part.get_payload(decode=True))
    elif stringFile != '':
      output = stringFile
 
    hash_sha1 = hashlib.sha1()
    hash_sha1.update(output.getvalue())
      
    #hash_sha1.hexdigest()

    log.debug("SHA1 hash for " + filename + " is " + hash_sha1.hexdigest() )

    for h in sha1Hashes:
      if hash_sha1.hexdigest().decode('utf-8').lower() == h.lower():
      #if hash_sha1.digest().lower() == h.lower():
        log.debug("Matched hash " + h)
        fp = open(os.path.join(self.directory, filename), 'wb')
        fp.write(output.getvalue())
        fp.close()
        imgObj = { 'session': sessionId, 'contentType': 'sha1Matched', 'contentFile': filename, 'image': filename, 'sha1Hash': hash_sha1.hexdigest() }
        if fromArchive != '':
          imgObj['fromArchive'] = fromArchive #fromArchive is the type of archive (either 'zip' or 'rar')
        self.sessions[sessionId]['images'].append( imgObj )




  def genSha256(self, filename, sessionId, contentType, sha256Hashes, fromArchive='', part='', stringFile=''): #must specify either part or stringFile
    log.debug("genSha256(): Generating sha256 hash for " + filename)

    if part != '':
      output = StringIO.StringIO()
      output.write(part.get_payload(decode=True))
    elif stringFile != '':
      output = stringFile
 
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(output.getvalue())
      
    #hash_sha256.hexdigest()

    log.debug("SHA256 hash for " + filename + " is " + hash_sha256.hexdigest() )

    for h in sha256Hashes:
      if hash_sha256.hexdigest().decode('utf-8').lower() == h.lower():
      #if hash_sha256.digest().lower() == h.lower():
        log.debug("Matched hash " + h)
        fp = open(os.path.join(self.directory, filename), 'wb')
        fp.write(output.getvalue())
        fp.close()
        imgObj = { 'session': sessionId, 'contentType': 'sha256Matched', 'contentFile': filename, 'image': filename, 'sha256Hash': hash_sha256.hexdigest() }
        if fromArchive != '':
          imgObj['fromArchive'] = fromArchive #fromArchive is the type of archive (either 'zip' or 'rar')
        self.sessions[sessionId]['images'].append( imgObj )
        
        


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
      
      if contentType == 'zip':
        log.debug("Attempting to extract zip file " + filename)
        output = StringIO.StringIO()
        output.write(part.get_payload(decode=True))
        try:
          zf = zipfile.ZipFile(output)
          saveZipFile = False
          for zinfo in zf.infolist():
            is_encrypted = zinfo.flag_bits & 0x1
            #print "DEBUG: zip compression type is",str(zinfo.compress_type)
            unsupported_compression = zinfo.compress_type == 99
            if is_encrypted:
              saveZipFile = True
              log.debug('%s is encrypted!' % filename)
              imgObj = { 'session': sessionId, 'contentType': 'encryptedZipEntry', 'contentFile': filename, 'image': zinfo.filename}
              self.sessions[sessionId]['images'].append( imgObj )
              break
            elif unsupported_compression:
              saveZipFile = True
              log.debug('%s uses an unsupported compression type!' % filename)
              imgObj = { 'session': sessionId, 'contentType': 'unsupportedZipEntry', 'contentFile': filename, 'image': zinfo.filename}
              self.sessions[sessionId]['images'].append( imgObj )
              break
            else: #identify archived file and save it permanently if a supported file type
              archivedFilename = zinfo.filename
              archivedFile = StringIO.StringIO()
              #extract the file to buffer
              zipArchiveFileObject = zf.open(archivedFilename)
              archivedFile.write(zipArchiveFileObject.read() )
              zipArchiveFileObject.close()
              #identify the file
              archivedFile.seek(0)
              archivedFileType = magic.from_buffer( archivedFile.getvalue(), mime=True)
              log.debug("archivedFileType:", archivedFileType)
              archivedFile.seek(0)
              if archivedFileType == 'application/pdf':
                #fp = open(os.path.join(self.directory, filename), 'wb')
                #shutil.copyfileobj(archivedFile, fp)
                #fp.close()
                log.debug("Processing '" + archivedFilename + "' as pdf")
                contentType='pdf'
                self.processPdf(archivedFilename, sessionId, contentType, distillationTerms, regexDistillationTerms, stringFile=archivedFile, fromArchive='zip')
              elif archivedFileType.startswith('image/'):
                log.debug("Processing '" + archivedFilename + "' as image")
                contentType='image'
                self.processImage(archivedFilename, sessionId, contentType, stringFile=archivedFile, fromArchive='zip')
              #####################################################################
              #elif archivedFileType.startswith('application/') and len(md5Hashes) != 0: #fix for executable
              elif archivedFileType in ['application/x-msdownload', 'application/x-ms-installer', 'application/x-elf', 'application/x-dosexec', 'application/x-executable']:
              #####################################################################
                log.debug("Processing '" + archivedFilename + "' as executable")
                contentType='executable'
                #self.processImage(archivedFilename, sessionId, contentType, stringFile=archivedFile, fromArchive='zip')
                if len(md5Hashes) != 0:
                  self.genMd5(archivedFilename, sessionId, contentType, md5Hashes, stringFile=archivedFile, fromArchive='zip')
                if len(sha1Hashes) != 0:
                  self.genSha1(archivedFilename, sessionId, contentType, sha1Hashes, stringFile=archivedFile, fromArchive='zip')
                if len(sha256Hashes) != 0:
                  self.genSha256(archivedFilename, sessionId, contentType, sha256Hashes, stringFile=archivedFile, fromArchive='zip')
              else:
                #print "DEBUG: discarding " + archivedFilename + ' with MIME type ' + archivedFileType
                pass
              archivedFile.close()
        except zipfile.BadZipfile as e:
          log.exception("Exception during zip open (file was not opened)") 
        except zipfile.LargeZipFile as e:
          log.exception("Exception during zip open (file was not opened)")
        except NotImplementedError as e:
          log.exception("NotImplemented exception during zip extraction")
        except Exception as e:
          log.exception("Unhandled exception during zip extraction")
        continue
            
        if saveZipFile:
          fp = open(os.path.join(self.directory, filename), 'wb')
          fp.write(part.get_payload(decode=True))
          fp.close()
          
          
      if contentType == 'rar':
        log.debug("Attempting to extract rar file " + filename)
        output = StringIO.StringIO()
        output.write(part.get_payload(decode=True))
        
        try:
          rf = rarfile.RarFile(output)
          saveRarFile = False
        
          for rinfo in rf.infolist():
            is_encrypted = rinfo.needs_password()
            if is_encrypted:
              saveRarFile = True
              log.debug('%s is encrypted!' % filename)
              imgObj =  { 'session': sessionId, 'contentType': 'encryptedRarEntry', 'contentFile': filename, 'image': rinfo.filename}
              self.sessions[sessionId]['images'].append( imgObj )
              break
            else: #identify archived file and save it permanently if a supported file type
              archivedFilename = rinfo.filename
              archivedFile = StringIO.StringIO()
              #extract the file to buffer
              rarArchiveFileObject = rf.open(archivedFilename)
              archivedFile.write(rarArchiveFileObject.read() )
              rarArchiveFileObject.close()
              #identify the file
              archivedFile.seek(0)
              archivedFileType = magic.from_buffer( archivedFile.getvalue(), mime=True)
              archivedFile.seek(0)
              if archivedFileType == 'application/pdf':
                #fp = open(os.path.join(self.directory, filename), 'wb')
                #shutil.copyfileobj(archivedFile, fp)
                #fp.close()
                log.debug("processing '" + archivedFilename + "' as pdf")
                contentType='pdf'
                self.processPdf(archivedFilename, sessionId, contentType, distillationTerms, regexDistillationTerms, stringFile=archivedFile, fromArchive='rar')
              elif archivedFileType.startswith('image/'):
                log.debug("Processing '" + archivedFilename + "' as image")
                contentType='image'
                self.processImage(archivedFilename, sessionId, contentType, stringFile=archivedFile, fromArchive='rar')
              #####################################################################
              elif archivedFileType.startswith('application/'): #fix for executable
              #####################################################################
                log.debug("Processing '" + archivedFilename + "' as executable")
                contentType='executable'
                if len(md5Hashes) != 0:
                 #self.processImage(archivedFilename, sessionId, contentType, stringFile=archivedFile, fromArchive='zip')
                 self.genMd5(archivedFilename, sessionId, contentType, md5Hashes, stringFile=archivedFile, fromArchive='rar')
                if len(sha1Hashes) != 0:
                 self.genSha1(archivedFilename, sessionId, contentType, sha1Hashes, stringFile=archivedFile, fromArchive='rar')
                if len(sha256Hashes) != 0:
                 self.genSha256(archivedFilename, sessionId, contentType, sha256Hashes, stringFile=archivedFile, fromArchive='rar')
              else:
                #print "DEBUG: discarding " + archivedFilename + ' with MIME type ' + archivedFileType
                pass
              archivedFile.close()
        except rarfile.BadRarFile as e:
          log.exception("Bad RAR file")
        except rarfile.NotRarFile as e:
          log.exception("Not a RAR file")
        except rarfile.BadRarName as e:
          log.exception("Cannot guess multipart RAR name components")
        except rarfile.NoRarEntry as e:
          log.exception("File not found in RAR")
        except rarfile.PasswordRequired as e:
          log.exception("RAR requires password")
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
        continue
            
        if saveRarFile:
          fp = open(os.path.join(self.directory, filename), 'wb')
          fp.write(part.get_payload(decode=True))
          fp.close()          

        
      if contentType == 'image':
        if not self.processImage(filename, sessionId, contentType, part=part):
          continue
        
        
      if contentType == 'pdf':
        if not self.processPdf(filename, sessionId, contentType, distillationTerms, regexDistillationTerms, part=part):
          continue
        
      if contentType == 'executable':
        if len(md5Hashes) != 0:
          self.genMd5(filename, sessionId, contentType, md5Hashes, part=part)
        if len(sha1Hashes) != 0:
          self.genSha1(filename, sessionId, contentType, sha1Hashes, part=part)
        if len(sha256Hashes) != 0:
          self.genSha256(filename, sessionId, contentType, sha256Hashes, part=part)


  def getPdfText(self, filename, sessionId, searchTerms=[], regexSearchTerms=[]):
    try: #now extract pdf text
      pdftotextCmd = self.pdftotextPath + " -enc UTF-8 -eol unix -nopgbrk -q '" + os.path.join(self.directory, filename) + "' -"
      log.debug("pdftotextCmd: " + pdftotextCmd)
      pdftotextProcess = Popen(pdftotextCmd, stdout=PIPE, stderr=PIPE, shell = True)
      (output, err) = pdftotextProcess.communicate()
      exit_code = pdftotextProcess.wait()
      if exit_code == 0:
        #extracted successfully, get output
        joinedText = output.replace('\n', ' ').replace('\r', '')
        #print "joinedText:", joinedText
        #print "joinedText:", type(joinedText)

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
          log.debug("getPdfText(): keeping file " + filename)
          searchObj = { 'session': sessionId, 'contentFile': filename, 'searchString': joinedText }
          if not 'search' in self.sessions[sessionId]:
            self.sessions[sessionId]['search'] = []
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
        
   