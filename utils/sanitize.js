/**
 * sanitize.js
 * 
 * Sanitizes user input to prevent XSS.
 * We don’t allow rich HTML, but if we did, this would stop it from breaking everything.
 * 
 * Like my mental state: stripped of all unnecessary tags.
 */

const xss = require('xss');

module.exports = {
  clean: (str) => {
    if (typeof str !== 'string') return '';
    return xss(str, {
      whiteList: [],                    // No HTML allowed
      stripIgnoreTag: true,             // Remove unknown tags
      escapeHtml: true,                 // Escape <, >, &, etc.
      noHtmlAttrs: true                 // Strip all attributes
    });
  },

  // Optional: Allow minimal formatting in future
  safeFormat: (str) => {
    if (typeof str !== 'string') return '';
    return xss(str, {
      whiteList: {
        'b': [],
        'i': [],
        'u': [],
        'strong': [],
        'em': [],
        'br': []
      },
      stripIgnoreTagBody: ['script', 'style'],
      escapeHtml: true
    });
  }
};
