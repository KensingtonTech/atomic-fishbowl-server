import email
import StringIO

class ContentObj:

    def __init__(self, session=0, contentType='', contentFile='', image='', thumbnail='', hashType='', hashValue='', hashFriendly='', fromArchive=False, archiveType='', archiveFilename='', isArchive=False):
        self.session = session                  # number: session id
        self.contentType = contentType          # should be image, pdf, or hash, unsupportedZipEntry, encryptedZipEntry, encryptedRarEntry, encryptedRarTable

        # Files
        self.contentFile = contentFile          # the image or pdf or exe filename
        self.pdfImage = image                   # the PDF gs-generated image filename
        self.thumbnail = thumbnail              # thumbnail image file
        self.archiveFilename = archiveFilename  # the name of the zip or rar archive

        # Hash
        self.hashType = hashType   
        self.hashValue = hashValue              # sha1, sha256, md5
        self.hashFriendly = hashFriendly        # friendly name of hash, if there is one
        
        #Archives
        self.fromArchive = fromArchive          # boolean, whether the content file came from a zip or rar archive
        self.isArchive = isArchive              # boolean, whether the file IS an archive rather than came from an archive
        self.archiveType = archiveType          # either zip or rar
        

    def get(self):
        o = {}
        o['session'] = self.session
        if self.contentType:
            o['contentType'] = self.contentType
        if self.contentFile:
            o['contentFile'] = self.contentFile
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
