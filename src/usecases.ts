// A use-case consists of a name (mandatory), a friendly name (mandatory), a query (mandatory), its allowed content types[] (mandatory), distillation terms (optional), regex distillation terms (optional), and a description (mandatory)
// { name: '', friendlyName: '', query: "", contentTypes: [], description: '', distillationTerms: [], regexTerms: [] }

export const UseCases = [

  {
    name: 'outboundDocuments',
    friendlyName: 'Outbound Documents',
    nwquery: `direction = 'outbound' && filetype = 'pdf','office 2007 document'`,
    saquery: '[ { "any" : [ "ipv4_initiator=172.16.0.0/12", "ipv4_initiator=192.168.0.0/16", "ipv4_initiator=192.168.0.0/16" ] }, { "all" : [ "ipv4_responder!=172.16.0.0/12", "ipv4_responder!=192.168.0.0/16", "ipv4_responder!=192.168.0.0/16" ] }, { "any" : [ "file_type=PDF", "file_extension=\\"pdf\\"", "mime_type=\\"application/pdf\\"", "file_type=ZIP", "file_extension=\\"docx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\\"", "file_extension=\\"xlsx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\\"", "file_extension=\\"pptx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.presentationml.presentation\\"" ] } ]',
    contentTypes: [ 'pdfs', 'officedocs' ],
    description: 'Displays documents which are being transferred outbound',
    onlyContentFromArchives: false
  },
  
  {
    name: 'ssns',
    friendlyName: 'Social Security Numbers',
    nwquery: `filetype = 'pdf','office 2007 document','zip','rar'`,
    saquery: '[ { "any" : [ "file_type=PDF", "file_extension=\\"pdf\\"", "mime_type=\\"application/pdf\\"", "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"", "file_extension=\\"docx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\\"", "file_extension=\\"xlsx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\\"", "file_extension=\\"pptx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.presentationml.presentation\\"" ] } ]',
    contentTypes: [ 'pdfs', 'officedocs' ],
    description: 'Displays documents which contain social security numbers.  It will look inside ZIP and RAR archives, as well',
    regexTerms: [ '\\d\\d\\d-\\d\\d-\\d\\d\\d\\d' ],
    onlyContentFromArchives: false
  },

  {
    name: 'dob',
    friendlyName: 'Date of Birth',
    nwquery: `filetype = 'pdf','office 2007 document','zip','rar'`,
    saquery: '[ { "any" : [ "file_type=PDF", "file_extension=\\"pdf\\"", "mime_type=\\"application/pdf\\"", "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"", "file_extension=\\"docx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\\"", "file_extension=\\"xlsx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\\"", "file_extension=\\"pptx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.presentationml.presentation\\"" ] } ]',
    contentTypes: [ 'pdfs', 'officedocs' ],
    description: 'Displays documents which contain dates of birth', 
    regexTerms: [ 
      '(?i)(dob|date of birth|birth date|birthdate|birthday|birth day).*\\d\\d?[-/]\\d\\d?[-/]\\d{2}(?:\\d{2})?\\W',
      '(?i)(dob|date of birth|birth date|birthdate|birthday|birth day).*\\d\\d? \\w+,? \\d{2}(?:\\d{2})?\\W',
      '(?i)(dob|date of birth|birth date|birthdate|birthday|birth day).*\\w+ \\d\\d?,? \\d{2}(?:\\d{2})?\\W'
    ],
    onlyContentFromArchives: false
  },

  {
    name: 'contentinarchives',
    friendlyName: 'All Content Contained in Archives',
    nwquery: `filetype = 'zip','rar'`,
    saquery: '[ { "any" : [ "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"" ] } ]',
    contentTypes: [ 'images', 'pdfs', 'officedocs' ],
    description: 'Displays any content type contained within a ZIP or RAR archive.  It does not display dodgy archives',
    onlyContentFromArchives: true
  },
  
  {
    name: 'contentinarchivesdodgy',
    friendlyName: 'All Content Contained in Archives (with Dodgy Archives)',
    nwquery: `filetype = 'zip','rar'`,
    saquery: '[ { "any" : [ "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"" ] } ]',
    contentTypes: [ 'images', 'pdfs', 'officedocs', 'dodgyarchives' ],
    description: 'Displays any content type contained within a ZIP or RAR archive.  It also displays dodgy archives',
    onlyContentFromArchives: true
  },

  {
    name: 'suspiciousdestcountries',
    friendlyName: 'Documents to Suspicious Destination Countries',
    nwquery: `country.dst = 'russian federation','china','romania','belarus','iran, islamic republic of',"korea, democratic people's republic of",'ukraine','syrian arab republic','yemen' && filetype = 'zip','rar','pdf','office 2007 document'`,
    saquery: '[ { "any" : [ "responder_country=\\"russian federation\\"", "responder_country=\\"china\\"", "responder_country=\\"romania\\"", "responder_country=\\"belarus\\"", "responder_country=\\"iran, islamic republic of\\"", "responder_country=\\"korea, democratic people\'s republic of\\"", "responder_country=\\"ukraine\\"", "responder_country=\\"syrian arab republic\\"", "responder_country=\\"yemen\\"" ] }, { "any" : [ "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"", "file_extension=\\"docx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\\"", "file_extension=\\"xlsx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\\"", "file_extension=\\"pptx\\"", "mime_type=\\"application/vnd.openxmlformats-officedocument.presentationml.presentation\\"" ] } ]',
    contentTypes: [ 'pdfs', 'officedocs', 'dodgyarchives' ],
    description: 'Displays documents and dodgy archives transferred to suspicious destination countries: Russia, China, Romania, Belarus, Iran, North Korea, Ukraine, Syra, or Yemen',
    onlyContentFromArchives: false
  },

  {
    name: 'dodgyarchives',
    friendlyName: 'Dodgy Archives',
    nwquery: `filetype = 'zip','rar'`,
    saquery: '[ { "any" : [ "file_type=ZIP", "file_extension=\\"zip\\"", "mime_type=\\"application/zip\\"", "file_type=RAR", "file_extension=\\"rar\\"", "mime_type=\\"application/x-rar-compressed\\"" ] } ]',
    contentTypes: [ 'dodgyarchives' ],
    description: 'Displays ZIP and RAR Archives which are encrypted or which contain some encrypted files',
    onlyContentFromArchives: false
  },

  {
    name: 'outboundwebmonitoring',
    friendlyName: 'Outbound Web Usage Monitoring',
    nwquery: `direction = 'outbound' && service = 80 && filetype = 'jpg','gif','png'`,
    saquery: '[ { "any" : [ "ipv4_initiator=172.16.0.0/12", "ipv4_initiator=192.168.0.0/16", "ipv4_initiator=192.168.0.0/16" ] }, { "all" : [ "ipv4_responder!=172.16.0.0/12", "ipv4_responder!=192.168.0.0/16", "ipv4_responder!=192.168.0.0/16" ] }, { "any" : [ "file_type~GIF", "file_extension=\\"gif\\"", "mime_type=\\"image/gif\\"", "file_type=PNG", "file_extension=\\"png\\"", "mime_type=\\"image/png\\"", "file_type=JPEG", "file_extension=\\"jpg\\"", "file_extension=\\"jpeg\\"", "mime_type=\\"image/jpeg\\"", "mime_type=\\"image/jpg\\"", "mime_type=\\"image/pjpeg\\"", "mime_type=\\"image/jp2\\"" ] } ]',
    contentTypes: [ 'images' ],
    description: 'Displays images from outbound web usage.  Recommended for use in a Monitoring Collection',
    onlyContentFromArchives: false
  }

];