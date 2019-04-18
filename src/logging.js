const Winston = (function() {

  const winston = require('winston');
  const sprintf = require('sprintf-js').sprintf;

  function systemdLevelFormatter(level) {
    switch (level) {
      case 'emerg': 
        return '<0>';
      case 'alert': 
        return '<1>';
      case 'crit': 
        return '<2>';
      case 'error': 
        return '<3>';
      case 'warning': 
        return '<4>';
      case 'notice': 
        return '<5>';
      case 'info': 
        return '<6>';
      case 'debug': 
        return '<7>';
    }
  }
  
  winston.remove(winston.transports.Console);
  
  let tOptions = {
    timestamp: () => moment().format('YYYY-MM-DD HH:mm:ss,SSS') + ' ',
    formatter: (options) => options.timestamp() + 'afb_server    ' + sprintf('%-10s', options.level.toUpperCase()) + ' ' + (options.message ? options.message : '') +(options.meta && Object.keys(options.meta).length ? '\n\t'+ JSON.stringify(options.meta) : '' )
  };
  if ('SYSTEMD' in process.env) {
    // systemd journal adds its own timestamp
    // delete tOptions.timestamp;
    tOptions['timestamp'] = null;
    // tOptions.formatter = (options) => systemdLevelFormatter(options.level) + (options.message ? options.message : '') + (options.meta && Object.keys(options.meta).length ? '\n\t'+ JSON.stringify(options.meta) : '' );
    tOptions['formatter'] = (options) => systemdLevelFormatter(options.level) + 'afb_server    ' + (options.message ? options.message : '') + (options.meta && Object.keys(options.meta).length ? '\n\t'+ JSON.stringify(options.meta) : '' );
    // tOptions['formatter'] = (options) => 'afb_server    ' + (options.message ? options.message : '') + (options.meta && Object.keys(options.meta).length ? '\n\t'+ JSON.stringify(options.meta) : '' );
    // var journald = require('winston-journald').Journald;
    // winston.add(journald);
  }
  winston.add(winston.transports.Console, tOptions);
  return winston;
}());

module.exports = Winston;