const helmet = require('helmet');

module.exports = helmet({
    contentSecurityPolicy: false, // Disable CSP for now; configure as needed
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    }
});
