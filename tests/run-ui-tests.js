#!/usr/bin/env node
/* =========================================================================
   Phishing Email Analyser - tests/run-ui-tests.js
   -------------------------------------------------------------------------
   Checks the interface code (js/app.js) without a browser, using the small
   document stand-in in tests/dom-stub.js:

       node tests/run-ui-tests.js

   The most important check in here is the one about pasted HTML. A phishing
   analyser is handed hostile input by design, so if a pasted email could ever
   become live markup inside the report, the tool would itself be the
   vulnerability. These checks prove that it cannot.
   ========================================================================= */

'use strict';

const fs = require('fs');
const path = require('path');
const { createStubDocument } = require('./dom-stub.js');

const ROOT = path.join(__dirname, '..');
let passed = 0;
const failures = [];

function check(name, fn) {
  try {
    const detail = fn();
    passed++;
    console.log('  PASS  ' + name + (detail ? '\n          -> ' + detail : ''));
  } catch (error) {
    failures.push({ name: name, message: error.message });
    console.log('  FAIL  ' + name + '\n          -> ' + error.message);
  }
}

function expect(condition, message) {
  if (!condition) throw new Error(message || 'expected condition to be true');
}

/* A fresh environment per check: a stub document, then the real application
   files, loaded in the same order the page loads them. Each file is written
   as an IIFE that receives (window, document), so running it with those two
   arguments is exactly what a browser does. */
function freshApp() {
  const document = createStubDocument();
  const resultsHost = document.__register('results', document.createElement('section'));
  document.__register('email-body', document.createElement('textarea'));
  document.__register('email-headers', document.createElement('textarea'));
  document.__register('analyse-button', document.createElement('button'));
  document.__register('sample-select', document.createElement('select'));
  document.__register('input-error', document.createElement('p'));
  document.__register('input-error-text', document.createElement('span'));
  document.__register('headers-block', document.createElement('details'));
  document.__register('theme-toggle', document.createElement('button'));
  document.__register('theme-icon', document.createElement('span'));

  const sandboxWindow = {
    localStorage: null,
    matchMedia: null,
    /* The page uses setTimeout to animate the score dial and to clear status
       messages. Passing it straight through keeps that behaviour realistic. */
    setTimeout: setTimeout,
    clearTimeout: clearTimeout
  };
  sandboxWindow.window = sandboxWindow;
  sandboxWindow.document = document;

  ['js/patterns.js', 'js/analyzer.js', 'js/samples.js', 'js/app.js'].forEach(function (file) {
    const code = fs.readFileSync(path.join(ROOT, file), 'utf8');
    const factory = new Function('window', 'document', 'globalThis', code);
    factory(sandboxWindow, document, sandboxWindow);
  });

  return { window: sandboxWindow, document: document, host: resultsHost };
}

function walk(node, visit) {
  visit(node);
  (node.childNodes || []).forEach(function (child) { walk(child, visit); });
}

console.log('');
console.log('Phishing Email Analyser - interface checks (no browser needed)');
console.log('=============================================================');
console.log('');

check('The interface code loads and exposes its entry points', function () {
  const app = freshApp();
  expect(app.window.PEA && app.window.PEA.app, 'PEA.app was not created');
  expect(typeof app.window.PEA.app.renderReport === 'function', 'renderReport is missing');
  expect(typeof app.window.PEA.app.buildReportText === 'function', 'buildReportText is missing');
  return 'loaded';
});

check('A full report renders for every demonstration email without error', function () {
  const app = freshApp();
  app.window.PEA.samples.forEach(function (sample) {
    const result = app.window.PEA.analyse({ body: sample.body, headers: sample.headers });
    app.window.PEA.app.renderReport(result, { sampleName: sample.name, sampleNote: sample.blurb });
    const text = app.host.textContent;
    expect(text.indexOf(sample.name) !== -1, sample.id + ': the sample name is missing from the report');
    expect(text.indexOf(String(result.score)) !== -1, sample.id + ': the score is missing from the report');
    expect(text.indexOf(result.classification) !== -1, sample.id + ': the classification is missing from the report');
  });
  return app.window.PEA.samples.length + ' reports rendered';
});

check('The report contains the sections a reader needs', function () {
  const app = freshApp();
  const sample = app.window.PEA.samples[0];
  const result = app.window.PEA.analyse({ body: sample.body, headers: sample.headers });
  app.window.PEA.app.renderReport(result, {});
  const text = app.host.textContent;
  [
    'Where the warning signs come from',
    'Warning signs found',
    'What to do next',
    'Links found in the message',
    'Attachments mentioned',
    'Sender authenticity',
    'Technical details and the full calculation',
    'What this result does and does not mean'
  ].forEach(function (heading) {
    expect(text.indexOf(heading) !== -1, 'the report is missing the section "' + heading + '"');
  });
  return 'all sections present';
});

check('A clean email renders the "nothing found" wording instead of an empty page', function () {
  const app = freshApp();
  const sample = app.window.PEA.samples.filter(function (s) { return s.id === 'legitimate'; })[0];
  const result = app.window.PEA.analyse({ body: sample.body, headers: sample.headers });
  app.window.PEA.app.renderReport(result, {});
  const text = app.host.textContent;
  expect(text.indexOf('Warning signs found: none') !== -1, 'the empty-result wording is missing');
  expect(text.indexOf('This is not a guarantee') !== -1, 'the warning about a low score is missing');
  expect(text.indexOf('Low Risk') !== -1, 'the classification is missing');
  return 'handled';
});

check('The plain-text report can be built and contains the key facts', function () {
  const app = freshApp();
  const sample = app.window.PEA.samples[2];
  const result = app.window.PEA.analyse({ body: sample.body, headers: sample.headers });
  const text = app.window.PEA.app.buildReportText(result, { sampleName: sample.name, timestamp: 'test' });
  expect(text.indexOf('PHISHING EMAIL ANALYSER - REPORT') === 0, 'the report does not start with its title');
  expect(text.indexOf('Score:          ' + result.score) !== -1, 'the score is missing');
  expect(text.indexOf('SPF:') !== -1, 'the authentication section is missing');
  expect(text.indexOf('IMPORTANT') !== -1, 'the disclaimer section is missing');
  expect(text.length > 800, 'the report looks too short to be complete');
  return text.split('\n').length + ' lines of text';
});

check('Pasted HTML can never become a live element in the report', function () {
  const app = freshApp();
  const payload = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
  const result = app.window.PEA.analyse({
    body: 'Subject: ' + payload + '\n\nDear Customer, your account will be suspended. ' +
      'Please enter your password at http://192.0.2.45/verify ' + payload,
    headers: 'From: "' + payload + '" <a@example.test>\nSubject: ' + payload
  });
  app.window.PEA.app.renderReport(result, { sampleName: payload, sampleNote: payload });

  const offenders = [];
  walk(app.host, function (node) {
    if (node._html && /<\s*(img|script|iframe|svg|object|embed|style)/i.test(node._html)) {
      offenders.push(node.tagName + ': ' + node._html);
    }
    if (node.attributes && node.attributes.onerror) {
      offenders.push(node.tagName + ' has an onerror attribute');
    }
  });
  expect(offenders.length === 0, 'pasted markup became an element: ' + offenders.join(' | '));
  expect(app.host.textContent.indexOf('onerror') !== -1, 'the payload text is missing entirely, so this check proved nothing');
  expect(app.host.textContent.indexOf('<script>') !== -1, 'the payload text is missing entirely, so this check proved nothing');
  return 'hostile markup stayed as text';
});

check('The only innerHTML written anywhere is the hand-written icon set', function () {
  const app = freshApp();
  const result = app.window.PEA.analyse({ body: 'Hello there.', headers: '' });
  app.window.PEA.app.renderReport(result, {});

  const offenders = [];
  walk(app.host, function (node) {
    if (!node._html) return;
    const isIcon = /^<(path|circle|rect|line|polyline)\b/.test(node._html.trim());
    if (!isIcon) offenders.push(node.tagName + ': ' + node._html.slice(0, 60));
  });
  expect(offenders.length === 0, 'innerHTML was used for something other than an icon: ' + offenders.join(' | '));
  return 'icons only';
});

check('Links in the report are shown as text, never as clickable anchors', function () {
  const app = freshApp();
  const result = app.window.PEA.analyse({
    body: 'Please verify your account at http://192.0.2.45/login and also https://bit.ly/EXAMPLE-ONLY',
    headers: ''
  });
  app.window.PEA.app.renderReport(result, {});

  let anchors = 0;
  walk(app.host, function (node) {
    if (node.tagName === 'A') anchors++;
  });
  expect(anchors === 0, 'the report contains ' + anchors + ' clickable link(s), which it must not');
  expect(app.host.textContent.indexOf('http://192.0.2.45/login') !== -1, 'the address is not shown as text');
  return 'no clickable links in the report';
});

console.log('');
console.log('------------------------------------------');
console.log(passed + ' passed, ' + failures.length + ' failed, ' + (passed + failures.length) + ' total');
console.log('');

if (failures.length) {
  console.log('Failures:');
  failures.forEach(function (failure) {
    console.log('  * ' + failure.name + ': ' + failure.message);
  });
  console.log('');
  process.exit(1);
}

