import email
import StringIO
from uuid import uuid4

class ContentObj:

    def __init__(self, session=0, contentType='', contentFile='', proxyContentFile='', image='', thumbnail='', hashType='', hashValue='', hashFriendly='', fromArchive=False, archiveType='', archiveFilename='', isArchive=False, textDistillationEnabled=False, regexDistillationEnabled=False, textTermsMatched=[], regexTermsMatched=[]):
        self.session = session                   # number: session id
        self.contentType = contentType           # should be image, pdf, office, or hash, unsupportedZipEntry, encryptedZipEntry, encryptedRarEntry, encryptedRarTable

        self.contentFile = contentFile           # the image or office or pdf or exe filename
        self.proxyContentFile = proxyContentFile # this is a pdf document which we may substitute for a converted original office doc.  This will be rendered by the client instead
        self.pdfImage = image                    # the PDF gs-generated image filename
        self.thumbnail = thumbnail               # thumbnail image file
        self.archiveFilename = archiveFilename   # the name of the zip or rar archive

        # Hash
        self.hashType = hashType   
        self.hashValue = hashValue               # sha1, sha256, md5
        self.hashFriendly = hashFriendly         # friendly name of hash, if there is one
        
        #Archives
        self.fromArchive = fromArchive           # boolean, whether the content file came from a zip or rar archive
        self.isArchive = isArchive               # boolean, whether the file IS an archive rather than came from an archive
        self.archiveType = archiveType           # either zip or rar

        #Distillation
        self.textDistillationEnabled = textDistillationEnabled
        self.regexDistillationEnabled = regexDistillationEnabled
        self.textTermsMatched = textTermsMatched
        self.regexTermsMatched = regexTermsMatched

        self.id = str(uuid4()) # generate a unique identifier for this content

    def newId(self):
        self.id = str(uuid4())
        

    def get(self):
        o = {}
        o['session'] = self.session
        if self.contentType:
            o['contentType'] = self.contentType
        if self.contentFile:
            o['contentFile'] = self.contentFile
        if self.proxyContentFile:
            o['proxyContentFile'] = self.proxyContentFile
        if self.pdfImage:
            o['pdfImage'] = self.pdfImage
        if self.thumbnail:
            o['thumbnail'] = self.thumbnail
        if self.hashType:
            o['hashType'] = self.hashType
        if self.hashValue:
            o['hashValue'] = self.hashValue
        if self.hashFriendly:
            o['hashFriendly'] = self.hashFriendly
        o['fromArchive'] = self.fromArchive
        o['isArchive'] = self.isArchive
        if self.archiveType:
            o['archiveType'] = self.archiveType
        if self.archiveFilename:
            o['archiveFilename'] = self.archiveFilename
        
        o['textDistillationEnabled'] = self.textDistillationEnabled
        o['regexDistillationEnabled'] = self.regexDistillationEnabled
        if len(self.textTermsMatched) != 0:
            o['textTermsMatched'] = self.textTermsMatched
        if len(self.regexTermsMatched) != 0:
            o['regexTermsMatched'] = self.regexTermsMatched
        o['id'] = self.id
        return o

    def setPartContent(self, content): # takes an email part object
        self.fileContent = StringIO.StringIO()
        self.fileContent.write(content.get_payload(decode=True))

    def setStringIOContent(self, content): #takes a StringIO object
        self.fileContent = content


    def getFileContent(self):
        self.fileContent.seek(0)
        return self.fileContent
        #return self.fileContent.getvalue()
