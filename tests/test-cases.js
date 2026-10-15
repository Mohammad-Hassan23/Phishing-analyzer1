/* =========================================================================
   Phishing Email Analyser - tests/test-cases.js
   -------------------------------------------------------------------------
   The automated checks, written once and run in two places:

     * tests/run-tests.js   - from the command line, while developing
     * tests/self-test.html - in the browser, so anyone can see for themselves
                              that the tool behaves as described

   Each check returns a short note on success, and throws on failure. Nothing
   here touches the screen or the network, so the same file works in both.
   ========================================================================= */

(function (root) {
  'use strict';

  const PEA = root.PEA;
  const CASES = [];

  function test(name, fn) {
    CASES.push({ name: name, run: fn });
  }

  function expect(condition, message) {
    if (!condition) throw new Error(message || 'expected condition to be true');
  }

  function expectEqual(actual, expected, label) {
    const a = JSON.stringify(actual);
    const b = JSON.stringify(expected);
    if (a !== b) throw new Error((label || 'value') + ': expected ' + b + ' but got ' + a);
  }

  function analyse(body, headers) {
    return PEA.analyse({ body: body, headers: headers || '' });
  }

  function findingIds(result) {
    return result.findings.map(function (f) { return f.id; }).sort();
  }

  /* =======================================================================
     1. THE SIX DEMONSTRATION EMAILS
     These are the headline checks: the examples in the interface must produce
     the results the interface claims they produce.
     ===================================================================== */

  PEA.samples.forEach(function (sample) {
    test('Example email "' + sample.name + '" lands in the expected band', function () {
      const result = analyse(sample.body, sample.headers);
      const expected = sample.expected;
      expect(result.score >= expected.min, 'score ' + result.score + ' is below the expected minimum of ' + expected.min);
      if (expected.max !== undefined) {
        expect(result.score <= expected.max, 'score ' + result.score + ' is above the expected maximum of ' + expected.max);
      }
      expect(expected.classifications.indexOf(result.classification) !== -1,
        'classification "' + result.classification + '" is not one of ' + expected.classifications.join(', '));
      return result.score + '/100, ' + result.classification;
    });

    test('Example email "' + sample.name + '" produces exactly the expected warning signs', function () {
      const result = analyse(sample.body, sample.headers);
      expectEqual(findingIds(result), sample.expected.shouldFire.slice().sort(), 'scored warning signs');
      return result.findings.length + ' warning signs';
    });
  });

  /* =======================================================================
     2. THE SCORING MATHS
     If the arithmetic is wrong, every explanation in the interface is wrong
     too, so it is checked directly.
     ===================================================================== */

  test('The scoring formula behaves as documented', function () {
    const combine = PEA.analyzerUtils.combine;
    expectEqual(combine([]), 0, 'no warning signs');
    expectEqual(combine([25]), 25, 'one 25-point warning sign');
    expectEqual(combine([25, 25, 25]), 58, 'three 25-point warning signs');
    expectEqual(combine([100]), 100, 'a 100-point warning sign');
    expectEqual(combine([50, 50]), 75, 'two 50-point warning signs');
    return 'documented examples match';
  });

  test('The score does not depend on the order warning signs are found', function () {
    const combine = PEA.analyzerUtils.combine;
    expectEqual(combine([8, 15, 25, 20]), combine([20, 25, 15, 8]), 'order independence');
    return 'order-independent';
  });

  test('Weak signals alone cannot produce a false 100', function () {
    const combine = PEA.analyzerUtils.combine;
    const twentyWeak = [];
    for (let i = 0; i < 20; i++) twentyWeak.push(5);
    const score = combine(twentyWeak);
    expect(score < 100, 'twenty weak signals reached ' + score + ', which should not be possible');
    expect(score > 50, 'twenty weak signals produced only ' + score + ', which is unexpectedly low');
    return '20 x 5-point signals = ' + score + '/100';
  });

  test('Every warning sign reports a contribution to the final score', function () {
    const result = analyse(PEA.samples[0].body, PEA.samples[0].headers);
    expect(result.findings.length > 0, 'the sample produced no findings at all');
    result.findings.forEach(function (f) {
      expect(f.contribution > 0, f.id + ' reported a contribution of ' + f.contribution);
      expect(f.contribution <= result.score, f.id + ' contributed more than the whole score');
    });
    const sum = result.findings.reduce(function (a, f) { return a + f.contribution; }, 0);
    return sum + ' points of contribution across ' + result.findings.length + ' warning signs (score ' + result.score + ')';
  });

  test('Severity is derived from weight, consistently', function () {
    const sev = PEA.analyzerUtils.severityFromWeight;
    expectEqual(sev(25), 'critical', 'weight 25');
    expectEqual(sev(20), 'high', 'weight 20');
    expectEqual(sev(15), 'high', 'weight 15');
    expectEqual(sev(12), 'medium', 'weight 12');
    expectEqual(sev(5), 'low', 'weight 5');
    expectEqual(sev(0), 'info', 'weight 0');
    return 'thresholds 25 / 15 / 8 hold';
  });

  test('A safety floor raises the result when critical signs are present', function () {
    /* Two critical signs alone come to about 44 by arithmetic, which would be
       "Suspicious". The floor exists so that a password request plus an
       executable attachment is never described as anything less than High
       Risk, and the report says that it happened. */
    const result = analyse('Please enter your password below. See the attached Account_Update.exe for details.');
    expect(result.rawScore < 60, 'the raw score was ' + result.rawScore + ', so this check is no longer exercising the floor');
    expectEqual(result.score, 60, 'floored score');
    expect(result.floors.length > 0, 'no floor was recorded even though one was applied');
    return 'raw ' + result.rawScore + ' raised to ' + result.score + ', with an explanation shown';
  });

  test('Analysing the same email twice gives the same answer', function () {
    const a = analyse(PEA.samples[2].body, PEA.samples[2].headers);
    const b = analyse(PEA.samples[2].body, PEA.samples[2].headers);
    expectEqual(a.score, b.score, 'score');
    expectEqual(findingIds(a), findingIds(b), 'warning signs');
    return 'score ' + a.score + ' both times';
  });

  /* =======================================================================
     3. INDIVIDUAL WARNING SIGNS
     One check per kind of trick, so a broken rule is easy to find.
     ===================================================================== */

  function fires(result, id) {
    return result.findings.some(function (f) { return f.id === id; });
  }

  function observes(result, id) {
    return result.observations.some(function (f) { return f.id === id; });
  }

  test('Detects a request for a password', function () {
    const result = analyse('To continue, please enter your password on the page below.');
    expect(fires(result, 'REQUEST_PASSWORD'), 'REQUEST_PASSWORD did not fire');
    return 'detected';
  });

  test('Does not flag genuine advice about never sharing a password', function () {
    /* A bank telling you not to share your password is good practice, not an
       attack. The "guards" in the rulebook exist for exactly this. */
    const result = analyse('Security reminder: never share your password with anyone. We will never ask you to enter your password.');
    expect(!fires(result, 'REQUEST_PASSWORD'), 'REQUEST_PASSWORD fired on a security warning');
    return 'correctly ignored';
  });

  test('Detects a request for a one-time code, and ignores a warning not to share one', function () {
    const bad = analyse('Please reply with the verification code we just sent to your phone.');
    expect(fires(bad, 'REQUEST_MFA_CODE'), 'REQUEST_MFA_CODE did not fire on a code request');
    const good = analyse('Never share your one-time code with anyone. Our staff will never ask you for it.');
    expect(!fires(good, 'REQUEST_MFA_CODE'), 'REQUEST_MFA_CODE fired on a warning not to share a code');
    return 'detected, and correctly ignored in the warning';
  });

  test('Detects a request to change bank details', function () {
    const result = analyse('Our bank details have changed - please use the new account for this payment.');
    expect(fires(result, 'CHANGE_BANK_DETAILS'), 'CHANGE_BANK_DETAILS did not fire');
    return 'detected';
  });

  test('Detects a request to enable macros', function () {
    const result = analyse('If the document does not display, click Enable Content to view it.');
    expect(fires(result, 'ENABLE_MACROS_LANGUAGE'), 'ENABLE_MACROS_LANGUAGE did not fire');
    return 'detected';
  });

  test('Detects a bare IP address used as a link', function () {
    const result = analyse('Log in here: http://192.0.2.45/portal');
    expect(fires(result, 'URL_RAW_IP'), 'URL_RAW_IP did not fire');
    return 'detected';
  });

  test('Detects a shortened link', function () {
    const result = analyse('Your receipt is here: https://tinyurl.com/EXAMPLE-ONLY');
    expect(fires(result, 'URL_SHORTENER'), 'URL_SHORTENER did not fire');
    return 'detected';
  });

  test('Detects the "@" trick used to disguise a link', function () {
    const result = analyse('Verify here: https://www.example-bank.test@192.0.2.9/login');
    expect(fires(result, 'URL_USERINFO_TRICK'), 'URL_USERINFO_TRICK did not fire');
    return 'detected';
  });

  test('Detects a punycode lookalike domain', function () {
    const result = analyse('Sign in at https://xn--pypal-4ve.test/login to review the request.');
    expect(fires(result, 'URL_PUNYCODE_LOOKALIKE'), 'URL_PUNYCODE_LOOKALIKE did not fire');
    return 'detected';
  });

  test('Detects link text that does not match its destination', function () {
    const markdown = analyse('Please review the document at [example-bank.test](https://evil.test/login).');
    expect(fires(markdown, 'LINK_TEXT_MISMATCH'), 'LINK_TEXT_MISMATCH did not fire on a Markdown link');
    const html = analyse('<p>Confirm your address at <a href="https://evil.test/x">example-bank.test</a></p>');
    expect(fires(html, 'LINK_TEXT_MISMATCH'), 'LINK_TEXT_MISMATCH did not fire on an HTML link');
    return 'detected in Markdown and HTML';
  });

  test('Only reports an unencrypted link when the link really says http://', function () {
    const explicit = analyse('See http://portal.example.test/help for details.');
    expect(fires(explicit, 'URL_INSECURE_HTTP'), 'URL_INSECURE_HTTP did not fire on an explicit http:// link');
    const bare = analyse('See portal.example.test/help for details.');
    expect(!fires(bare, 'URL_INSECURE_HTTP'), 'URL_INSECURE_HTTP fired on a link with no scheme at all, where the scheme was only assumed');
    return 'explicit only';
  });

  test('Detects an executable attachment, including a double extension', function () {
    const result = analyse('Please open the attached Invoice_8842.pdf.exe and confirm.');
    expect(fires(result, 'ATTACH_EXECUTABLE'), 'ATTACH_EXECUTABLE did not fire');
    expect(fires(result, 'ATTACH_DOUBLE_EXTENSION'), 'ATTACH_DOUBLE_EXTENSION did not fire');
    return 'both signs detected';
  });

  test('Detects a macro-enabled document named in the message', function () {
    const result = analyse('The file is called Q3_Statement.docm and is attached.');
    expect(fires(result, 'ATTACH_MACRO_ENABLED'), 'ATTACH_MACRO_ENABLED did not fire');
    return 'detected';
  });

  test('Does not mistake an ordinary web address for an attachment', function () {
    /* "com" is also a file extension, so this is a trap the engine must not
       fall into. */
    const result = analyse('Our website is https://portal.example.com/home and our intranet is intranet.example.com.');
    expect(result.attachments.length === 0, 'found attachments where there are none: ' + result.attachments.map(function (a) { return a.name; }).join(', '));
    return 'no false attachment';
  });

  test('Detects a declared file type that contradicts the file name', function () {
    const headers = 'From: sender@example.test\nTo: victim@example.com\nSubject: Invoice\n' +
      'Content-Type: application/pdf; name="Invoice_8842.exe"\n' +
      'Content-Disposition: attachment; filename="Invoice_8842.exe"';
    const result = analyse('Please see the attached invoice.', headers);
    expect(fires(result, 'ATTACH_TYPE_MISMATCH'), 'ATTACH_TYPE_MISMATCH did not fire');
    return 'detected';
  });

  test('Reads SPF, DKIM and DMARC failures from pasted headers', function () {
    const headers = 'From: "Example Bank" <alerts@example-bank.test>\nTo: victim@example.com\n' +
      'Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=example-bank.test; dkim=fail; dmarc=fail';
    const result = analyse('Please review your account.', headers);
    expect(fires(result, 'HDR_SPF_FAIL'), 'HDR_SPF_FAIL did not fire');
    expect(fires(result, 'HDR_DKIM_FAIL'), 'HDR_DKIM_FAIL did not fire');
    expect(fires(result, 'HDR_DMARC_FAIL'), 'HDR_DMARC_FAIL did not fire');
    return 'all three read';
  });

  test('Never invents an authentication result when no headers are pasted', function () {
    const result = analyse('Please review your account.');
    expectEqual(result.headers.spf, null, 'spf');
    expectEqual(result.headers.dkim, null, 'dkim');
    expectEqual(result.headers.dmarc, null, 'dmarc');
    expectEqual(result.headers.provided, false, 'headers provided');
    expect(!fires(result, 'HDR_SPF_FAIL') && !fires(result, 'HDR_DMARC_FAIL'), 'an authentication rule fired without headers');
    return 'stayed quiet, as it should';
  });

  test('Says so when headers are supplied but contain no authentication results', function () {
    const headers = 'From: sender@example.test\nTo: victim@example.com\nSubject: Hello';
    const result = analyse('Hello there.', headers);
    expect(observes(result, 'HDR_NO_AUTH_RESULTS'), 'HDR_NO_AUTH_RESULTS did not appear as an observation');
    expect(!fires(result, 'HDR_NO_AUTH_RESULTS'), 'the observation was scored, but observations must never score');
    return 'reported as an observation, not a score';
  });

  test('Detects a reply-to address on a different domain', function () {
    const headers = 'From: "Supplier Accounts" <accounts@supplier.test>\nReply-To: supplier.accounts@mailbox.example\nTo: finance@example.com';
    const result = analyse('Please confirm the payment.', headers);
    expect(fires(result, 'HDR_FROM_REPLYTO_MISMATCH'), 'HDR_FROM_REPLYTO_MISMATCH did not fire');
    return 'detected';
  });

  test('Detects a fake address hidden in the sender name', function () {
    const headers = 'From: "support@example-bank.test" <billing.notice@mailbox.example>\nTo: victim@example.com';
    const result = analyse('Your statement is ready.', headers);
    expect(fires(result, 'HDR_DISPLAYNAME_IS_EMAIL'), 'HDR_DISPLAYNAME_IS_EMAIL did not fire');
    return 'detected';
  });

  test('Does not treat ordinary message text as email headers', function () {
    const result = analyse('Note: this is just a message.\nFrom: my point of view it is fine.\nReply: whenever suits you.');
    expectEqual(result.headers.provided, false, 'headers provided');
    return 'correctly ignored';
  });

  test('Detects invisible characters hidden in the text', function () {
    const result = analyse('Please enter your pass\u200bword to continue.');
    expect(fires(result, 'INVISIBLE_CHARACTERS'), 'INVISIBLE_CHARACTERS did not fire');
    return 'detected';
  });

  test('Reports security-alert wording as an observation, never as a score', function () {
    const result = analyse('We detected a new sign-in to your account from an unfamiliar device.');
    expect(observes(result, 'SECURITY_ALERT_WORDING'), 'SECURITY_ALERT_WORDING did not appear as an observation');
    expect(!fires(result, 'SECURITY_ALERT_WORDING'), 'the wording was scored, but it must never score on its own');
    return 'observation only';
  });

  /* =======================================================================
     4. ROBUSTNESS
     A tool that crashes on strange input is worse than no tool, and a tool
     that returns 120 out of 100 destroys trust in every other number it
     shows. These checks feed it the awkward cases.
     ===================================================================== */

  const AWKWARD_INPUTS = [
    ['empty message', ''],
    ['only whitespace', '   \n\t  \n '],
    ['only punctuation', '....!!!!----'],
    ['emoji only', '😀🔒📧👍🏽'],
    ['a very long single line', new Array(4000).join('word ')],
    ['a very long unbroken token', new Array(2000).join('x')],
    ['broken HTML', '<div><a href="http://"><p>unclosed <span>'],
    ['an unfinished URL', 'Visit http:// and also https://'],
    ['Windows line endings', 'Line one\r\nLine two\r\n'],
    ['null bytes', 'Hello\u0000world\u0000test'],
    ['an email address with no body', 'someone@example.com'],
    ['a bare IP address', '192.0.2.1'],
    ['a wall of URLs', 'https://a.test https://b.test http://c.test'],
    ['only a signature', 'Regards,\nSomeone'],
    ['mixed scripts', 'PayPal paypal'],
    ['right-to-left override', '\u202Egnp.exe\u202C'],
    ['a thousand dots', new Array(1000).join('.')],
    ['only numbers', '1234567890']
  ];

  test('Never crashes and always returns a score between 0 and 100', function () {
    AWKWARD_INPUTS.forEach(function (pair) {
      const result = PEA.analyse({ body: pair[1], headers: '' });
      expect(typeof result.score === 'number' && !isNaN(result.score), pair[0] + ': score was not a number');
      expect(result.score >= 0 && result.score <= 100, pair[0] + ': score was ' + result.score);
      expect(['Low Risk', 'Suspicious', 'High Risk'].indexOf(result.classification) !== -1,
        pair[0] + ': unexpected classification ' + result.classification);
    });
    return AWKWARD_INPUTS.length + ' awkward inputs handled';
  });

  test('Handles missing, empty and wrongly typed input without crashing', function () {
    const cases = [undefined, null, {}, { body: null, headers: null }, { body: 12345, headers: 678 }, '', 42];
    cases.forEach(function (input, index) {
      const result = PEA.analyse(input);
      expect(result.score >= 0 && result.score <= 100, 'input ' + index + ' produced score ' + result.score);
    });
    return cases.length + ' input shapes handled';
  });

  test('Reports an empty message as empty rather than scoring it', function () {
    const result = PEA.analyse({ body: '   ', headers: '' });
    expectEqual(result.isEmpty, true, 'isEmpty');
    expectEqual(result.score, 0, 'score');
    expectEqual(result.findings.length, 0, 'findings');
    return 'empty input handled cleanly';
  });

  test('Stays fast on a large message', function () {
    const big = new Array(1200).join('Please review the attached invoice and confirm the payment details.\n');
    const started = Date.now();
    const result = PEA.analyse({ body: big, headers: '' });
    const elapsed = Date.now() - started;
    expect(result.score >= 0 && result.score <= 100, 'score out of range');
    expect(elapsed < 3000, 'took ' + elapsed + 'ms, which is too slow to feel instant');
    return big.length + ' characters analysed in ' + elapsed + 'ms';
  });

  /* =======================================================================
     5. SAFETY WORDING AND HONESTY
     The tool must never claim to know for certain, and the visitor must
     always be told what to do instead of testing links themselves.
     ===================================================================== */

  test('Always carries the honest disclaimer', function () {
    const result = analyse('Hello there.');
    const text = result.disclaimer.toLowerCase();
    expect(text.indexOf('educational') !== -1, 'the disclaimer does not say the tool is educational');
    expect(text.indexOf('cannot') !== -1, 'the disclaimer does not say what the tool cannot do');
    expect(text.indexOf('never click') !== -1, 'the disclaimer does not warn against clicking to test');
    expect(text.indexOf('official') !== -1, 'the disclaimer does not recommend verifying through official channels');
    return 'disclaimer present and complete';
  });

  test('Every warning sign carries an explanation and a recommendation', function () {
    const rules = PEA.patterns.TEXT_RULES
      .concat(PEA.patterns.URL_RULES, PEA.patterns.ATTACHMENT_RULES, PEA.patterns.HEADER_RULES, PEA.patterns.STRUCTURAL_RULES);
    rules.forEach(function (rule) {
      expect(typeof rule.title === 'string' && rule.title.length > 8, rule.id + ' has no usable title');
      expect(typeof rule.what === 'string' && rule.what.length > 40, rule.id + ' has no plain-English explanation');
      expect(typeof rule.advice === 'string' && rule.advice.length > 30, rule.id + ' has no advice for the reader');
    });
    return rules.length + ' rules all explained';
  });

  test('Always offers recommendations, without repeating itself', function () {
    const result = analyse(PEA.samples[0].body, PEA.samples[0].headers);
    expect(result.recommendations.length >= 3, 'only ' + result.recommendations.length + ' recommendations were offered');
    expect(result.recommendations.length <= 8, 'too many recommendations: ' + result.recommendations.length);
    const uniqueCount = result.recommendations.filter(function (r, i, all) { return all.indexOf(r) === i; }).length;
    expectEqual(uniqueCount, result.recommendations.length, 'duplicate recommendations');
    return result.recommendations.length + ' recommendations, all distinct';
  });

  test('Shows all six categories, even when a category found nothing', function () {
    const result = analyse('Hello there.');
    expectEqual(result.categories.length, 6, 'category count');
    result.categories.forEach(function (c) {
      expect(c.strength >= 0 && c.strength <= 100, c.id + ' had strength ' + c.strength);
      expect(typeof c.blurb === 'string' && c.blurb.length > 10, c.id + ' has no description');
    });
    return '6 categories reported';
  });

  /* =======================================================================
     6. THE RULEBOOK ITSELF
     Housekeeping that keeps the rulebook safe to edit by hand.
     ===================================================================== */

  test('Every warning sign has a unique id and a sensible weight', function () {
    const rules = PEA.patterns.TEXT_RULES
      .concat(PEA.patterns.URL_RULES, PEA.patterns.ATTACHMENT_RULES, PEA.patterns.HEADER_RULES, PEA.patterns.STRUCTURAL_RULES);
    const ids = rules.map(function (r) { return r.id; });
    const duplicates = ids.filter(function (id, index) { return ids.indexOf(id) !== index; });
    expectEqual(duplicates, [], 'duplicate rule ids');
    const categoryIds = PEA.patterns.CATEGORIES.map(function (c) { return c.id; });
    rules.forEach(function (rule) {
      expect(typeof rule.weight === 'number' && rule.weight >= 0 && rule.weight <= 100, rule.id + ' has weight ' + rule.weight);
      expect(categoryIds.indexOf(rule.category) !== -1, rule.id + ' belongs to unknown category "' + rule.category + '"');
      expect(typeof rule.test === 'function' || Array.isArray(rule.patterns), rule.id + ' has neither patterns nor a test function');
    });
    return rules.length + ' rules, ' + categoryIds.length + ' categories, no duplicates';
  });

  test('The calculation shown to the visitor matches the score', function () {
    const result = analyse(PEA.samples[1].body, PEA.samples[1].headers);
    expectEqual(result.calculation.terms.length, result.findings.length, 'number of terms shown');
    expectEqual(result.calculation.rawScore, result.rawScore, 'raw score');
    expectEqual(result.calculation.score, result.score, 'final score');
    expect(result.calculation.formula.indexOf('100') !== -1, 'the formula is not shown');
    return 'calculation matches the report';
  });

  /* =======================================================================
     7. PRIVACY
     These checks read the project's own files, so they run only where file
     reading is available - that is, in the command-line runner. They are the
     evidence behind the privacy promise made on the page itself.
     ===================================================================== */

  if (root.PEA_FILE_READER) {
    const SHIPPED_FILES = ['index.html', 'css/style.css', 'js/patterns.js', 'js/analyzer.js', 'js/samples.js', 'js/app.js', 'tests/self-test.html', 'tests/run-in-browser.js'];

    function readShipped(file) {
      return root.PEA_FILE_READER(file);
    }

    /* Prose is not code: comments are stripped before scanning, so that a
       comment explaining which APIs are blocked does not itself look like a
       network call. Only whole-line JavaScript comments are removed, so that
       nothing hidden after real code can slip through. */
    function codeOnly(text, isHtml) {
      let out = text;
      if (isHtml) out = out.replace(/<!--[\s\S]*?-->/g, ' ');
      out = out.replace(/\/\*[\s\S]*?\*\//g, ' ');
      out = out.split('\n').map(function (line) {
        return /^\s*(\/\/|\*)/.test(line) ? '' : line;
      }).join('\n');
      return out;
    }

    test('No shipped file can contact the network', function () {
      const banned = [
        [/\bfetch\s*\(/, 'a fetch() call'],
        [/\bnew\s+XMLHttpRequest\b/, 'XMLHttpRequest'],
        [/\bnew\s+WebSocket\b/, 'a WebSocket'],
        [/\bnew\s+EventSource\b/, 'EventSource'],
        [/sendBeacon\s*\(/, 'sendBeacon'],
        [/\bimport\s*\(/, 'a dynamic import']
      ];
      let checked = 0;
      SHIPPED_FILES.forEach(function (file) {
        const text = readShipped(file);
        if (text === null) return;
        checked++;
        const code = codeOnly(text, /\.html?$/i.test(file));
        banned.forEach(function (pair) {
          expect(!pair[0].test(code), file + ' contains ' + pair[1]);
        });
      });
      return checked + ' files checked for network calls';
    });

    test('No shipped file contains analytics or tracking code', function () {
      const tracking = /google-analytics|googletagmanager|gtag\s*\(|mixpanel|segment\.io|hotjar|plausible|matomo|amplitude|fullstory|sentry/i;
      let checked = 0;
      SHIPPED_FILES.forEach(function (file) {
        const text = readShipped(file);
        if (text === null) return;
        checked++;
        expect(!tracking.test(text), file + ' contains something that looks like analytics or tracking');
      });
      return checked + ' files checked for tracking';
    });

    test('The page loads nothing from outside the project', function () {
      const html = readShipped('index.html');
      if (html === null) return 'index.html not present yet';
      const external = html.match(/(?:src|href)\s*=\s*["']https?:\/\/[^"']+/gi) || [];
      expectEqual(external, [], 'external references found');
      const css = readShipped('css/style.css');
      if (css !== null) {
        const cssImports = css.match(/@import\s+url\(\s*["']?https?:/gi) || [];
        expectEqual(cssImports, [], 'external font or stylesheet imports found');
      }
      return 'no external references';
    });

    test('The page forbids outbound connections with a Content Security Policy', function () {
      const html = readShipped('index.html');
      if (html === null) return 'index.html not present yet';
      expect(/http-equiv\s*=\s*["']Content-Security-Policy["']/i.test(html), 'no Content-Security-Policy meta tag found');
      expect(/connect-src\s+'none'/i.test(html), 'the policy does not forbid outbound connections with connect-src \'none\'');
      return 'connect-src \'none\' is set';
    });
  }

  /* @@NEXT@@ */

  root.PEA_TESTS = CASES;

})(typeof window !== 'undefined' ? window : globalThis);
