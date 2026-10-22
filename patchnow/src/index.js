'use strict';
/** Programmatic API. */
module.exports = {
  scan: require('./scan').scan,
  run: require('./runner').run,
  loadConfig: require('./config').load,
  evaluatePolicy: require('./policy').evaluate,
  report: require('./report'),
  core: require('./core'),
  parsers: require('./parsers'),
};
