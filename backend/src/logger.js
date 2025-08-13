const pino = require('pino');

const level = process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug');

const logger = pino({
  level,
  base: null, // don't add pid/hostname
  redact: {
  paths: ['req.headers.authorization', 'req.headers.cookie', 'res.headers'],
    remove: true
  }
});

module.exports = logger;
