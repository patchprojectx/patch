#!/usr/bin/env node
'use strict';
const [major] = process.versions.node.split('.').map(Number);
if (major < 20) { process.stderr.write('patchnow requires Node.js 20 or newer (found ' + process.version + ')\n'); process.exit(2); }
require('../src/cli').main().then((code) => { process.exitCode = code; }, (e) => { process.stderr.write('patchnow: ' + e.message + '\n'); process.exitCode = e.exit || 2; });
