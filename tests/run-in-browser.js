/* =========================================================================
   Phishing Email Analyser - tests/run-in-browser.js
   -------------------------------------------------------------------------
   Runs the shared checks from tests/test-cases.js and shows the outcome on
   tests/self-test.html, so anyone can verify the tool's behaviour without
   installing anything. Kept in its own file rather than inline so the same
   rules about no inline scripts apply everywhere.
   ========================================================================= */

(function (root, document) {
  'use strict';

  function stat(value, label) {
    const box = document.createElement('div');
    box.className = 'stat';
    const big = document.createElement('b');
    big.textContent = value;
    const small = document.createElement('span');
    small.textContent = label;
    box.appendChild(big);
    box.appendChild(small);
    return box;
  }

  function init() {
    const list = document.getElementById('results');
    const summary = document.getElementById('summary');
    if (!list || !summary) return;

    const cases = root.PEA_TESTS || [];
    let passed = 0;
    let failed = 0;

    cases.forEach(function (item) {
      let ok = true;
      let detail = '';
      try {
        detail = item.run() || '';
      } catch (error) {
        ok = false;
        detail = error.message;
      }
      if (ok) passed++; else failed++;

      const row = document.createElement('li');
      row.className = 'test-item ' + (ok ? 'pass' : 'fail');

      const verdict = document.createElement('span');
      verdict.className = 'test-verdict';
      verdict.textContent = ok ? 'Pass' : 'Fail';

      const body = document.createElement('span');
      body.appendChild(document.createTextNode(item.name));
      if (detail) {
        const note = document.createElement('span');
        note.className = 'test-detail';
        note.textContent = detail;
        body.appendChild(note);
      }

      row.appendChild(verdict);
      row.appendChild(body);
      list.appendChild(row);
    });

    summary.appendChild(stat(String(passed), 'checks passed'));
    summary.appendChild(stat(String(failed), 'checks failed'));
    summary.appendChild(stat(String(cases.length), 'checks in total'));
    summary.appendChild(stat(failed ? 'Something is wrong' : 'All good', 'verdict'));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})(typeof window !== 'undefined' ? window : globalThis, document);
