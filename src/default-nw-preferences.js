const DefaultNwPreferences = {
  url: '',
  summaryTimeout: 5,
  sessionLimit: 2000,
  queryTimeout: 5,
  contentTimeout: 5,
  queryDelayMinutes: 1,
  maxContentErrors: 10,
  presetQuery: "filetype = 'jpg','gif','png','pdf','zip','rar','windows executable','x86 pe','windows dll','x64pe','apple executable (pef)','apple executable (mach-o)'",
  defaultQuerySelection : "All Supported File Types",
  displayedKeys : [ 
    "size", 
    "service", 
    "ip.src", 
    "ip.dst", 
    "alias.host", 
    "city.dst", 
    "country.dst", 
    "action", 
    "content", 
    "ad.username.src", 
    "ad.computer.src", 
    "filename", 
    "client"
  ],
  masonryKeys : [
    {
      key : "alias.host",
      friendly : "Hostname"
    }, 
    {
      key : "ad.username.src",
      friendly : "AD User"
    }, 
    {
      key : "ad.computer.src",
      friendly : "AD Computer"
    }, 
    {
      key : "ad.domain.src",
      friendly : "AD Domain"
    }
  ]
};

module.exports = DefaultNwPreferences;