const helmet = require('helmet');

const isProd = process.env.NODE_ENV === 'production';

const csp = isProd
    ? {
            useDefaults: true,
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:'],
                connectSrc: ["'self'"],
                objectSrc: ["'none'"],
                frameAncestors: ["'self'"]
            }
        }
    : false; // keep disabled for development

module.exports = helmet({
    contentSecurityPolicy: csp,
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    }
});
