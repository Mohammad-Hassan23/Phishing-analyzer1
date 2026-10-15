#!/usr/bin/env node
/* =========================================================================
   Phishing Email Analyser - tests/run-tests.js
   -------------------------------------------------------------------------
   Runs the automated checks from the command line, so the engine can be
   tested without opening a browser:

       node tests/run-tests.js

   It exits with status 1 if anything fails, which is what a continuous
   integration service would look at. It needs Node.js, which is only a
   development convenience - the website itself needs nothing but a browser.
   ========================================================================= */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

/* The same files the browser loads, in the same order. They are plain scripts
   that attach themselves to the global object, so requiring them here is
   enough to make PEA available. */
require(path.join(ROOT, 'js', 'patterns.js'));
require(path.join(ROOT, 'js', 'analyzer.js'));
require(path.join(ROOT, 'js', 'samples.js'));

/* The privacy checks read the project's own files. That is only possible here,
   so the reader is handed to the shared test file. */
globalThis.PEA_FILE_READER = function (relativePath) {
  const full = path.join(ROOT, relativePath);
  try {
    return fs.readFileSync(full, 'utf8');
  } catch (error) {
    return null;
  }
};

require(path.join(__dirname, 'test-cases.js'));

const cases = globalThis.PEA_TESTS;
let passed = 0;
const failures = [];

console.log('');
console.log('Phishing Email Analyser - automated checks');
console.log('==========================================');
console.log('');

cases.forEach(function (item, index) {
  const label = String(index + 1).padStart(2, ' ') + '. ' + item.name;
  try {
    const detail = item.run();
    passed++;
    console.log('  PASS  ' + label + (detail ? '\n          -> ' + detail : ''));
  } catch (error) {
    failures.push({ name: item.name, message: error.message });
    console.log('  FAIL  ' + label + '\n          -> ' + error.message);
  }
});

console.log('');
console.log('------------------------------------------');
console.log(passed + ' passed, ' + failures.length + ' failed, ' + cases.length + ' total');
console.log('');

if (failures.length) {
  console.log('Failures:');
  failures.forEach(function (f) {
    console.log('  * ' + f.name + ': ' + f.message);
  });
  console.log('');
  process.exit(1);
}
