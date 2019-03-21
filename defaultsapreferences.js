var saDefaultPreferences = { // solera
  url: '',
  presetQuery: '[ { "any" : [ "file_type=PDF", "file_extension=\"pdf\"", "mime_type=\"application/pdf\"", "file_type=ZIP", "file_extension=\"docx\"", "mime_type=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document\"", "file_extension=\"xlsx\"", "mime_type=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\"", "file_extension=\"pptx\"",  "mime_type=\"application/vnd.openxmlformats-officedocument.presentationml.presentation\"" ] } ]',
  defaultQuerySelection : "All Supported File Types",
  sessionLimit: 2000,
  queryTimeout: 5,
  contentTimeout: 5,
  queryDelayMinutes: 1,
  maxContentErrors: 10,
  displayedKeys : [ 
    "total_bytes", 
    "protocol_family", 
    "initiator_ip", 
    "responder_ip", 
    "aggregate_http_server_hooks", 
    "responder_country", 
    "aggregate_http_method_hooks", 
    "aggregate_file_type_hooks", 
    // "filename", 
    "aggregate_user_agent_hooks"
  ],
  masonryKeys : [
    {
      key : "aggregate_http_server_hooks",
      friendly : "Hostname"
    }, 
    {
      key : "responder_country",
      friendly : "Responder Country"
    }, 
    /*{
      key : "aggregate_http_uri_hooks",
      friendly : "URL"
    },*/ 
    {
      key : "protocol_family",
      friendly : "Protocol Family"
    }
  ]
};

module.exports = saDefaultPreferences;