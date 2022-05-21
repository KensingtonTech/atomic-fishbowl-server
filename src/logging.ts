import winston from 'winston';
import { sprintf } from 'sprintf-js';
import moment from 'moment';

const Winston = (function() {
  winston.remove(winston.transports.Console);
  const transportOptions: winston.TransportOptions = {
    timestamp: () => `${moment().format('YYYY-MM-DD HH:mm:ss,SSS')} `,
    formatter: (options) => `${options.timestamp()}afb_server    ${sprintf('%-10s', options.level.toUpperCase())} ${options.message ?? ''} ${options.meta && Object.keys(options.meta).length ? '\n\t' + JSON.stringify(options.meta) : ''}`
  };
  winston.add(winston.transports.Console, transportOptions);
  return winston;
}());

 export default Winston;