/* =========================================================================
   Phishing Email Analyser - js/analyzer.js
   -------------------------------------------------------------------------
   THE ENGINE.

   This file takes the text a visitor pasted, applies the rulebook from
   js/patterns.js, and produces the report: a 0-100 score, a classification,
   the warning signs that fired, and what each one contributed.

   It is deliberately free of anything to do with the screen - no buttons, no
   page elements. It is a plain function that turns text into an object, so the
   automated tests can call it directly, and it can never make a network
   request even by accident.

   THE SCORING, IN PLAIN ENGLISH
   ----------------------------
   Every warning sign carries a weight, meaning "how strongly does this one
   sign, on its own, suggest phishing?" The weights are combined as if each
   sign were independent evidence, rather than simply added together:

       score = 100 x ( 1 - (1-w1) x (1-w2) x ... x (1-wn) )

   Why not just add them up? Because adding saturates. Six mild signals would
   add up to 48 and shout "Suspicious" at a perfectly normal marketing email.
   Combining them this way means one strong signal gives a modest score, while
   several strong signals climb steeply - and twenty weak ones still cannot
   reach a false 100. It is also order-independent, which matters for trust:
   the same email always scores the same.

   Each warning sign also reports its own "contribution": the difference it
   makes to the final score, measured by recalculating with that sign removed.
   Because the signs overlap slightly, contributions do not add up to exactly
   the total, and the interface says so rather than pretending otherwise.
   ========================================================================= */

(function (root) {
  'use strict';

  const PEA = (root.PEA = root.PEA || {});
  const P = PEA.patterns;
  const H = PEA.helpers;

  /* The three bands the visitor is shown. The boundaries live here, in one
     place, so the labels and the numbers can never disagree with each other. */
  const BANDS = [
    {
      id: 'low',
      min: 0,
      max: 24,
      label: 'Low Risk',
      tone: 'low',
      summary: 'No warning signs that we treat as serious were found.',
      detail: 'That is not a clean bill of health. A skilled attacker can write a message that trips none of these checks, so an unexpected email asking for money, credentials or a change of payment details is still worth verifying, whatever the score says.'
    },
    {
      id: 'suspicious',
      min: 25,
      max: 59,
      label: 'Suspicious',
      tone: 'medium',
      summary: 'This message shows several warning signs and should be treated with caution.',
      detail: 'Do not act on it directly. Verify it through a channel you choose yourself - the organisation\'s official app or website, or a phone number you already hold - before doing anything the message asks.'
    },
    {
      id: 'high',
      min: 60,
      max: 100,
      label: 'High Risk',
      tone: 'high',
      summary: 'This message shows a strong pattern of phishing and social-engineering warning signs.',
      detail: 'Do not click links, open attachments, reply or send anything. If you have already acted on the message, tell whoever handles security where you work straight away, and change any password you entered.'
    }
  ];

  const DISCLAIMER = 'This is an educational triage tool. It identifies warning signs in text; it cannot and does not determine whether an email is genuinely malicious, and a low score is not a guarantee that a message is safe. Never click a suspicious link or open an attachment in order to test it. Verify important messages independently, using the organisation\'s official website or app, or a phone number you already know.';

  /* -----------------------------------------------------------------------
     Small utilities
     --------------------------------------------------------------------- */

  function now() {
    if (typeof performance !== 'undefined' && performance && typeof performance.now === 'function') {
      return performance.now();
    }
    return Date.now();
  }

  /* Tidy a working copy of the text so that trivial tricks do not help an
     attacker: hidden zero-width characters removed, curly quotes and dashes
     turned into plain ones, runs of whitespace collapsed. The visitor's own
     text is never modified - only this working copy is. */
  function normalise(text) {
    return String(text == null ? '' : text)
      .replace(/\r\n?/g, '\n')
      .replace(/[\u200B-\u200D\u2060\uFEFF]/g, '')
      .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
      .replace(/[\u2018\u2019\u201B\u2032]/g, "'")
      .replace(/[\u201C\u201D\u2033]/g, '"')
      .replace(/[\u2010-\u2015]/g, '-')
      .replace(/\u00A0/g, ' ')
      .replace(/[ \t]+/g, ' ')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  }

  function severityFromWeight(weight) {
    if (!weight) return 'info';
    if (weight >= 25) return 'critical';
    if (weight >= 15) return 'high';
    if (weight >= 8) return 'medium';
    return 'low';
  }

  const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  /* The combining formula described at the top of this file. */
  function combine(weights) {
    let remaining = 1;
    for (let i = 0; i < weights.length; i++) {
      const w = Math.min(Math.max(Number(weights[i]) || 0, 0), 100);
      remaining *= (1 - w / 100);
    }
    return Math.min(100, Math.max(0, Math.round(100 * (1 - remaining))));
  }

  /* A readable snippet around a match, so the visitor can see exactly what was
     found in their own words. The snippet is returned as plain text: the
     interface highlights the match by splitting the string, never by
     injecting HTML, so pasted content can never become code. */
  function contextAround(text, index, length, padding) {
    const pad = padding || 60;
    const start = Math.max(0, index - pad);
    const end = Math.min(text.length, index + length + pad);
    let snippet = text.slice(start, end).replace(/\s+/g, ' ').trim();
    if (start > 0) snippet = '\u2026' + snippet;
    if (end < text.length) snippet = snippet + '\u2026';
    return snippet;
  }

  function unique(list) {
    const seen = {};
    const out = [];
    for (let i = 0; i < list.length; i++) {
      const key = String(list[i]);
      if (!seen[key]) {
        seen[key] = true;
        out.push(list[i]);
      }
    }
    return out;
  }

  PEA.analyzerUtils = {
    BANDS: BANDS,
    DISCLAIMER: DISCLAIMER,
    normalise: normalise,
    severityFromWeight: severityFromWeight,
    combine: combine,
    contextAround: contextAround,
    unique: unique
  };

  /* =======================================================================
     STEP 1 - FINDING LINKS
     Links are gathered from four places: HTML anchors, Markdown links, plain
     http(s) addresses, and bare domain names. Each match is blanked out of a
     working copy once found, so the same link is never reported twice.
     ===================================================================== */

  /* Domain endings we will accept in a bare domain such as "example.com"
     written without http://. Keeping a list is deliberate: without it,
     ordinary words and file names would be misread as web addresses. */
  const BARE_HOST_TLDS = ['com', 'net', 'org', 'io', 'co', 'uk', 'de', 'fr', 'nl', 'au', 'ca', 'in', 'us', 'ru', 'cn', 'br', 'jp', 'eu', 'info', 'biz', 'xyz', 'top', 'online', 'site', 'shop', 'link', 'click', 'live', 'support', 'gov', 'edu', 'mil', 'app', 'dev', 'me', 'tv', 'cc', 'ly', 'to', 'gl', 'be', 'it', 'es', 'se', 'no', 'dk', 'fi', 'pl', 'ch', 'at', 'ie', 'nz', 'za', 'mx', 'ar', 'tr', 'hk', 'sg', 'my', 'ph', 'vn', 'th', 'id', 'kr', 'tw', 'tk', 'ml', 'ga', 'cf', 'gq', 'test', 'invalid', 'example', 'onion', 'zip', 'mov'];

  const BARE_DOMAIN_RE = new RegExp('\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:' + BARE_HOST_TLDS.join('|') + ')\\b(?:/[^\\s<>"\'`]*)?', 'gi');

  function stripHtmlText(value) {
    return String(value || '')
      .replace(/<[^>]*>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&#39;|&apos;/gi, "'")
      .replace(/\s+/g, ' ')
      .trim();
  }

  function trimUrlPunctuation(value) {
    return String(value || '')
      .trim()
      .replace(/^[<(\['"]+/, '')
      .replace(/[.,;:!?'")\]]+$/, '');
  }

  function buildUrlInfo(rawInput, anchorText, sourceKind) {
    const raw = trimUrlPunctuation(rawInput);
    if (!raw) return null;

    const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(raw);
    const schemeWasExplicit = !!schemeMatch;
    let candidate = raw;
    if (!schemeWasExplicit) {
      candidate = /^\/\//.test(raw) ? 'http:' + raw : 'http://' + raw;
    }

    let parsed;
    try {
      parsed = new URL(candidate);
    } catch (e) {
      return null;
    }

    const hostname = String(parsed.hostname || '').replace(/\.$/, '').toLowerCase();
    if (!hostname) return null;
    const ipv6 = H.isIpv6(hostname);
    if (!ipv6 && hostname.indexOf('.') === -1) return null;

    return {
      raw: raw,
      href: candidate,
      protocol: parsed.protocol,
      schemeWasExplicit: schemeWasExplicit,
      hostname: hostname,
      port: parsed.port || '',
      pathname: parsed.pathname || '',
      search: parsed.search || '',
      hasUserInfo: !!(parsed.username || parsed.password),
      anchorText: anchorText ? stripHtmlText(anchorText).slice(0, 300) : null,
      source: sourceKind,
      registrableDomain: H.registrableDomain(hostname),
      tld: H.topLevelDomain(hostname),
      isIpv4: H.isIpv4(hostname),
      isIpv6: ipv6,
      isIp: H.isIpv4(hostname) || ipv6,
      flags: []
    };
  }

  function extractUrls(text, options) {
    const opts = options || {};
    const source = String(text == null ? '' : text);
    const work = source.split('');
    const found = [];
    const seen = {};

    function mask(start, end) {
      for (let i = start; i < end && i < work.length; i++) work[i] = ' ';
    }

    function add(rawUrl, anchorText, sourceKind) {
      const info = buildUrlInfo(rawUrl, anchorText, sourceKind);
      if (!info) return;
      const key = info.href.toLowerCase() + '|' + String(info.anchorText || '').toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      found.push(info);
    }

    /* (a) HTML anchors: <a href="...">visible words</a> */
    const anchorRe = /<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = anchorRe.exec(source)) !== null) {
      add(m[1] || m[2] || m[3], m[4], 'html');
      mask(m.index, m.index + m[0].length);
    }

    /* (b) Markdown links: [visible words](https://...) */
    const mdRe = /\[([^\]\n]{0,200})\]\(\s*<?([^)\s>]+)>?\s*\)/g;
    while ((m = mdRe.exec(source)) !== null) {
      if (work[m.index] === ' ') continue;
      add(m[2], m[1], 'markdown');
      mask(m.index, m.index + m[0].length);
    }

    const masked = work.join('');

    /* (c) Anything with an explicit scheme, and bare "www." addresses. */
    const schemeRe = /(?:https?|ftp):\/\/[^\s<>"'`]+/gi;
    while ((m = schemeRe.exec(masked)) !== null) {
      add(m[0], null, 'text');
      mask(m.index, m.index + m[0].length);
    }
    const afterSchemes = work.join('');

    const wwwRe = /\bwww\.[^\s<>"'`]+/gi;
    while ((m = wwwRe.exec(afterSchemes)) !== null) {
      add(m[0], null, 'text');
      mask(m.index, m.index + m[0].length);
    }

    /* (d) Bare domains such as "example.com/verify" with no scheme at all.
           Skipped when the match is part of an email address or a file path,
           so "someone@example.com" is not reported as a link. Also skipped
           entirely for header text, where bare host names appear in Received
           and Message-ID lines and are not links the visitor can follow. */
    if (opts.bareDomains === false) return found;

    const bareText = work.join('');
    while ((m = BARE_DOMAIN_RE.exec(bareText)) !== null) {
      const before = bareText.charAt(m.index - 1);
      if (before === '@' || before === '/' || before === '.' || before === '\\') continue;
      const after = bareText.charAt(m.index + m[0].length);
      if (after === '@') continue;
      if (work[m.index] === ' ') continue;
      add(m[0], null, 'text');
      mask(m.index, m.index + m[0].length);
    }

    return found;
  }

  PEA.analyzerUtils.extractUrls = extractUrls;
  PEA.analyzerUtils.buildUrlInfo = buildUrlInfo;

  /* =======================================================================
     STEP 2 - FINDING ATTACHMENTS
     Filenames turn up in two places: written in the message body ("see
     Invoice_8842.pdf attached"), and in the MIME headers when headers are
     pasted. A few extensions are deliberately excluded from the body scan
     because they are also domain endings: "example.com" is a website, not a
     program, and calling it an attachment would be a false alarm.
     ===================================================================== */

  const AMBIGUOUS_AS_FILE = ['com', 'app', 'img', 'zip', 'mov'];

  const TEXT_FILE_EXTENSIONS = unique(
    P.EXECUTABLE_EXTENSIONS
      .concat(P.MACRO_EXTENSIONS, P.ARCHIVE_EXTENSIONS, P.WEBPAGE_EXTENSIONS)
      .filter(function (ext) { return AMBIGUOUS_AS_FILE.indexOf(ext) === -1; })
  );

  const TEXT_FILE_RE = new RegExp(
    '\\b([a-z0-9][\\w\\-]*\\.(?:[a-z0-9]{1,6}\\.)?(' + TEXT_FILE_EXTENSIONS.join('|') + '))\\b',
    'gi'
  );

  function makeAttachment(name, declaredType, sourceKind) {
    const extension = H.extensionOf(name);
    const stem = name.slice(0, Math.max(0, name.length - extension.length - 1));
    return {
      name: name,
      extension: extension,
      previousExtension: H.extensionOf(stem),
      declaredType: declaredType || null,
      source: sourceKind,
      flags: []
    };
  }

  function extractAttachmentsFromText(text) {
    const source = String(text == null ? '' : text);
    const out = [];
    const seen = {};
    let m;
    while ((m = TEXT_FILE_RE.exec(source)) !== null) {
      const before = source.charAt(m.index - 1);
      if (before === '@' || before === '/' || before === '\\' || before === ':') continue;
      const name = m[1];
      const key = name.toLowerCase();
      if (seen[key]) continue;
      seen[key] = true;
      out.push(makeAttachment(name, null, 'text'));
      if (out.length >= 25) break;
    }
    return out;
  }

  PEA.analyzerUtils.extractAttachmentsFromText = extractAttachmentsFromText;

  /* =======================================================================
     STEP 3 - READING THE HEADERS
     Everything here is "read only, never guess". If a value is not present,
     it stays null and the report says it was not available. An analyser that
     invents an SPF failure is worse than one that stays quiet.
     ===================================================================== */

  const KNOWN_HEADERS = ['from', 'to', 'cc', 'bcc', 'subject', 'date', 'message-id', 'reply-to', 'return-path', 'received', 'received-spf', 'authentication-results', 'arc-authentication-results', 'dkim-signature', 'content-type', 'content-disposition', 'content-transfer-encoding', 'mime-version', 'x-mailer', 'user-agent', 'list-unsubscribe', 'delivered-to', 'x-originating-ip', 'x-spam-status'];

  const HEADER_LINE_RE = /^([A-Za-z][A-Za-z0-9-]{0,40}):[ \t]*(.*)$/;

  function unfoldHeaderLines(raw) {
    const unfolded = [];
    String(raw).split('\n').forEach(function (line) {
      if (/^[ \t]+\S/.test(line) && unfolded.length) {
        unfolded[unfolded.length - 1] += ' ' + line.trim();
      } else {
        unfolded.push(line);
      }
    });
    return unfolded;
  }

  function parseAddress(value) {
    if (value == null) return null;
    const raw = String(value).trim();
    if (!raw || raw === '<>') return null;

    let address = null;
    let displayName = null;

    const angle = /^(.*?)[<]\s*([^>]*)\s*[>]\s*$/.exec(raw);
    if (angle) {
      displayName = angle[1].trim().replace(/^["']|["']$/g, '').trim() || null;
      address = angle[2].trim() || null;
    } else {
      const bare = /([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/i.exec(raw);
      if (bare) {
        address = bare[1];
        const remainder = raw.replace(bare[1], '').trim().replace(/^["']|["']$/g, '').trim();
        displayName = remainder || null;
      } else {
        displayName = raw;
      }
    }

    if (address && address.indexOf('@') !== -1) {
      address = address.replace(/^[<]|[>]$/g, '').trim();
    } else {
      address = null;
    }

    const domain = address ? address.split('@').pop().toLowerCase().replace(/[^a-z0-9.-]/g, '') : null;
    const registrable = domain ? H.registrableDomain(domain) : null;

    return {
      raw: raw,
      displayName: displayName,
      address: address,
      domain: domain,
      registrable: registrable,
      isFreeMail: registrable ? P.FREE_MAIL_DOMAINS.indexOf(registrable) !== -1 : false
    };
  }

  function authVerdict(blob, name) {
    const re = new RegExp('(?:^|[;\\s(])' + name + '=([a-z]+)', 'i');
    const m = re.exec(blob);
    return m ? m[1].toLowerCase() : null;
  }

  PEA.analyzerUtils.parseAddress = parseAddress;

  function parseHeaders(text) {
    const raw = String(text == null ? '' : text).replace(/\r\n?/g, '\n');
    const result = {
      hasHeaders: false,
      headerLines: [],
      values: {},
      from: null,
      replyTo: null,
      returnPath: null,
      spf: null,
      dkim: null,
      dmarc: null,
      hasDkimSignature: false,
      authResults: '',
      receivedCount: 0,
      attachments: []
    };

    if (!raw.trim()) return result;

    const unfolded = unfoldHeaderLines(raw);

    /* Is this actually a header block? We insist on several header-shaped
       lines, at least one of which is a header we recognise. Otherwise a
       visitor's ordinary message would be misread as headers. */
    let headerLike = 0;
    let knownHits = 0;
    unfolded.forEach(function (line) {
      const m = HEADER_LINE_RE.exec(line);
      if (m) {
        headerLike++;
        if (KNOWN_HEADERS.indexOf(m[1].toLowerCase()) !== -1) knownHits++;
      }
    });
    if (headerLike < 2 || knownHits < 1) return result;
    result.hasHeaders = true;

    unfolded.forEach(function (line) {
      const m = HEADER_LINE_RE.exec(line);
      if (!m) return;
      const name = m[1].toLowerCase();
      const value = m[2].trim();
      if (result.values[name] === undefined) result.values[name] = value;
      result.headerLines.push(line.trim());
      if (name === 'received') result.receivedCount++;
    });

    result.from = parseAddress(result.values['from']);
    result.replyTo = parseAddress(result.values['reply-to']);
    result.returnPath = parseAddress(result.values['return-path']);
    result.hasDkimSignature = Object.prototype.hasOwnProperty.call(result.values, 'dkim-signature');

    /* SPF, DKIM and DMARC verdicts. We read the first result we find, because
       headers are added hop by hop and the first one is the verdict of the
       server closest to the recipient - the one with the most to go on. */
    const authLines = [];
    unfolded.forEach(function (line) {
      if (/^(authentication-results|arc-authentication-results|received-spf)\b/i.test(line)) {
        authLines.push(line.trim());
      }
    });
    const blob = authLines.join('\n');
    result.authResults = blob;
    result.spf = authVerdict(blob, 'spf');
    if (!result.spf) {
      const receivedSpf = /^received-spf:\s*([a-z]+)/im.exec(blob);
      if (receivedSpf) result.spf = receivedSpf[1].toLowerCase();
    }
    result.dkim = authVerdict(blob, 'dkim');
    result.dmarc = authVerdict(blob, 'dmarc');

    /* Attachment declarations in MIME headers, with the content type that was
       declared for each one, so a name/type contradiction can be spotted. */
    let lastContentType = null;
    unfolded.forEach(function (line) {
      const m = HEADER_LINE_RE.exec(line);
      if (!m) return;
      const name = m[1].toLowerCase();
      const value = m[2];
      if (name === 'content-type') {
        lastContentType = String(value.split(';')[0]).trim().toLowerCase() || null;
      }
      const fileMatch = /(?:filename|name)\s*=\s*(?:"([^"]+)"|([^\s;]+))/i.exec(value);
      if (fileMatch) {
        const fileName = String(fileMatch[1] || fileMatch[2] || '').trim();
        if (fileName) result.attachments.push(makeAttachment(fileName, lastContentType, 'headers'));
      }
    });

    return result;
  }

  PEA.analyzerUtils.parseHeaders = parseHeaders;

  /* =======================================================================
     STEP 4 - RUNNING THE RULES
     Each block below produces "findings": one object per warning sign that
     fired, carrying the weight, the plain-English explanation, the advice,
     and the evidence quoted back from the visitor's own text.
     ===================================================================== */

  function baseFinding(rule) {
    return {
      id: rule.id,
      category: rule.category,
      title: rule.title,
      what: rule.what,
      advice: rule.advice,
      weight: Number(rule.weight) || 0,
      severity: severityFromWeight(Number(rule.weight) || 0),
      observational: !rule.weight,
      evidence: [],
      matchCount: 0,
      contribution: 0
    };
  }

  function guardBlocks(rule, text) {
    if (!rule.guards || !rule.guards.length) return false;
    for (let i = 0; i < rule.guards.length; i++) {
      if (rule.guards[i].test(text)) return true;
    }
    return false;
  }

  function runTextRules(texts) {
    const findings = [];
    P.TEXT_RULES.forEach(function (rule) {
      const maxEvidence = rule.maxEvidence || 5;
      const quotes = [];
      const snippets = [];
      let total = 0;

      rule.patterns.forEach(function (pattern) {
        texts.forEach(function (text) {
          const re = new RegExp(pattern.source, pattern.flags.indexOf('g') === -1 ? pattern.flags + 'g' : pattern.flags);
          let m;
          while ((m = re.exec(text)) !== null) {
            if (m[0] === '') { re.lastIndex++; continue; }
            const snippet = contextAround(text, m.index, m[0].length);
            if (guardBlocks(rule, snippet)) continue;
            total++;
            if (quotes.length < maxEvidence && quotes.indexOf(m[0].trim()) === -1) {
              quotes.push(m[0].trim());
              snippets.push({ value: m[0].trim(), context: snippet, kind: 'text' });
            }
          }
        });
      });

      if (!total) return;
      const finding = baseFinding(rule);
      finding.matchCount = total;
      finding.evidence = snippets;
      findings.push(finding);
    });
    return findings;
  }

  function runStructuralRules(raw, normalised) {
    const findings = [];
    P.STRUCTURAL_RULES.forEach(function (rule) {
      const outcome = rule.test({ raw: raw, normalised: normalised });
      if (!outcome) return;
      const finding = baseFinding(rule);
      finding.matchCount = 1;
      finding.note = outcome.note;
      finding.evidence = (outcome.evidence || []).map(function (text) {
        return { value: text, context: outcome.note, kind: 'text' };
      });
      findings.push(finding);
    });
    return findings;
  }

  /* One finding per link rule, listing every link that tripped it. Grouping
     keeps the report readable: ten bad links produce one clear finding, not
     ten near-identical ones. */
  function runUrlRules(urls) {
    const buckets = {};
    const order = [];

    urls.forEach(function (u) {
      if (!u.notes) u.notes = [];
      P.URL_RULES.forEach(function (rule) {
        const note = rule.test(u);
        if (!note) return;
        u.flags.push(rule.id);
        u.notes.push(note);
        if (!buckets[rule.id]) {
          buckets[rule.id] = { rule: rule, items: [] };
          order.push(rule.id);
        }
        buckets[rule.id].items.push({ url: u, note: note });
      });
    });

    return order.map(function (id) {
      const bucket = buckets[id];
      const finding = baseFinding(bucket.rule);
      finding.matchCount = bucket.items.length;
      finding.note = bucket.items[0].note;
      const maxEvidence = bucket.rule.maxEvidence || 4;
      finding.evidence = bucket.items.slice(0, maxEvidence).map(function (item) {
        return { value: item.url.raw, context: item.note, kind: 'url' };
      });
      return finding;
    });
  }

  function runAttachmentRules(attachments) {
    const buckets = {};
    const order = [];

    attachments.forEach(function (a) {
      if (!a.notes) a.notes = [];
      P.ATTACHMENT_RULES.forEach(function (rule) {
        const note = rule.test(a);
        if (!note) return;
        a.flags.push(rule.id);
        a.notes.push(note);
        if (!buckets[rule.id]) {
          buckets[rule.id] = { rule: rule, items: [] };
          order.push(rule.id);
        }
        buckets[rule.id].items.push({ attachment: a, note: note });
      });
    });

    return order.map(function (id) {
      const bucket = buckets[id];
      const finding = baseFinding(bucket.rule);
      finding.matchCount = bucket.items.length;
      finding.note = bucket.items[0].note;
      const maxEvidence = bucket.rule.maxEvidence || 4;
      finding.evidence = bucket.items.slice(0, maxEvidence).map(function (item) {
        return { value: item.attachment.name, context: item.note, kind: 'attachment' };
      });
      return finding;
    });
  }

  function runHeaderRules(facts) {
    const findings = [];
    P.HEADER_RULES.forEach(function (rule) {
      const outcome = rule.test(facts);
      if (!outcome) return;
      const finding = baseFinding(rule);
      finding.matchCount = 1;
      if (typeof outcome === 'string') {
        finding.note = outcome;
      } else {
        finding.note = outcome.note;
        finding.evidence = (outcome.evidence || []).map(function (text) {
          return { value: text, context: outcome.note, kind: 'header' };
        });
      }
      findings.push(finding);
    });
    return findings;
  }

  function buildFacts(headers, urls) {
    return {
      hasHeaders: headers.hasHeaders,
      headerLines: headers.headerLines,
      from: headers.from,
      replyTo: headers.replyTo,
      returnPath: headers.returnPath,
      spf: headers.spf,
      dkim: headers.dkim,
      dmarc: headers.dmarc,
      hasDkimSignature: headers.hasDkimSignature,
      authResults: headers.authResults,
      linkDomains: unique(urls.map(function (u) { return u.registrableDomain; }).filter(Boolean))
    };
  }

  /* Links from the body and links from the headers (a "List-Unsubscribe"
     address, for instance) are combined into one list, without duplicates. */
  function mergeUrlLists(primary, secondary) {
    const seen = {};
    const out = [];
    primary.concat(secondary).forEach(function (u) {
      const key = u.href.toLowerCase() + '|' + String(u.anchorText || '').toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      if (secondary.indexOf(u) !== -1 && u.source === 'text') u.source = 'header';
      out.push(u);
    });
    return out;
  }

  /* Merge the same file seen twice - once named in the body, once declared in
     the headers - so the visitor is told about one attachment, not two. */
  function mergeAttachments(fromText, fromHeaders) {
    const byName = {};
    const out = [];
    fromText.concat(fromHeaders).forEach(function (a) {
      const key = a.name.toLowerCase();
      if (byName[key]) {
        const existing = byName[key];
        if (!existing.declaredType && a.declaredType) existing.declaredType = a.declaredType;
        if (existing.source !== a.source) existing.source = 'text+headers';
        return;
      }
      byName[key] = a;
      out.push(a);
    });
    return out;
  }

  /* =======================================================================
     STEP 5 - WHAT TO DO ABOUT IT
     The universal advice comes first, because it applies whatever the score
     says. Then the specific advice from the warning signs that fired, most
     serious first, with duplicates removed.
     ===================================================================== */

  const UNIVERSAL_ADVICE = {
    high: [
      'Do not click any links, open any attachments, reply, or send anything this message asks for.',
      'Verify it independently: open the organisation\'s official app or website, or call a number you already hold. Never use contact details taken from the email.',
      'Report it to whoever handles security where you work, or forward it to your national phishing reporting service.',
      'If you have already entered a password, a code, or payment details, change that password now and tell your security team straight away.'
    ],
    suspicious: [
      'Do not act on the message yet. Verify it through a channel you choose yourself - the organisation\'s app, its website typed by hand, or a number you already have.',
      'Read the sender\'s real address rather than the display name.',
      'Report anything you are unsure about. Reporting a message that turns out to be genuine is a small cost; acting on a fake one can be very expensive.'
    ],
    low: [
      'No warning signs were found, which is not the same as safe. Stay alert for unexpected requests for money, credentials, or changes to payment details.',
      'Verify unexpected messages independently, using contact details you already hold rather than ones inside the message.',
      'If anything feels off, ask a colleague or your security team before you act.'
    ]
  };

  function buildRecommendations(bandId, scoredFindings) {
    const out = (UNIVERSAL_ADVICE[bandId] || UNIVERSAL_ADVICE.low).slice();
    const ordered = scoredFindings.slice().sort(function (a, b) {
      const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (bySeverity) return bySeverity;
      return b.weight - a.weight;
    });
    for (let i = 0; i < ordered.length && out.length < 8; i++) {
      const advice = ordered[i].advice;
      if (advice && out.indexOf(advice) === -1) out.push(advice);
    }
    return out;
  }

  /* Did the visitor paste a whole message source into the body box? If so we
     tell them, rather than silently skipping the header checks they were
     hoping for. */
  function looksLikeHeaderBlock(text) {
    const lines = unfoldHeaderLines(String(text == null ? '' : text).replace(/\r\n?/g, '\n'));
    let headerLike = 0;
    let known = 0;
    lines.slice(0, 60).forEach(function (line) {
      const m = HEADER_LINE_RE.exec(line);
      if (m) {
        headerLike++;
        if (KNOWN_HEADERS.indexOf(m[1].toLowerCase()) !== -1) known++;
      }
    });
    return headerLike >= 4 && known >= 2;
  }

  /* =======================================================================
     STEP 6 - THE MAIN FUNCTION
     Text in, report out. No page elements, no network, no state kept.
     ===================================================================== */

  function analyse(input) {
    const started = now();
    const body = String((input && input.body) || '');
    const headerText = String((input && input.headers) || '');
    const combined = headerText ? body + '\n' + headerText : body;
    const normalised = normalise(combined);

    const headers = parseHeaders(headerText);
    const urls = mergeUrlLists(extractUrls(body), extractUrls(headerText, { bareDomains: false }));
    const attachments = mergeAttachments(extractAttachmentsFromText(body), headers.attachments);
    const facts = buildFacts(headers, urls);

    /* Text rules run against two views of the message. Real emails are wrapped
       across lines, so "the attached" and "invoice" can end up on different
       lines and a phrase search would miss them. The flattened copy joins the
       lines back up; the original copy is kept so that patterns anchored to
       the start of a line ("Dear Customer,") still work. */
    const flattened = normalised.replace(/\n+/g, ' ');

    const findings = runTextRules([normalised, flattened])
      .concat(runStructuralRules(combined, normalised))
      .concat(runUrlRules(urls))
      .concat(runAttachmentRules(attachments))
      .concat(runHeaderRules(facts));

    const scored = findings.filter(function (f) { return f.weight > 0; });
    const observations = findings.filter(function (f) { return f.weight === 0; });

    /* The score, and what each warning sign contributed to it. */
    const weights = scored.map(function (f) { return f.weight; });
    const rawScore = combine(weights);
    scored.forEach(function (f, index) {
      const without = weights.filter(function (w, j) { return j !== index; });
      f.contribution = Math.max(0, rawScore - combine(without));
    });

    /* Safety floors. Some warning signs are so strong that we refuse to label
       the message Low Risk while one is present, even when the arithmetic
       alone would allow it. This is a deliberate, explained intervention - not
       a hidden adjustment - and the report always says when it happened. */
    const criticalCount = scored.filter(function (f) { return f.severity === 'critical'; }).length;
    let score = rawScore;
    const floors = [];
    if (criticalCount >= 2 && score < 60) {
      score = 60;
      floors.push({
        id: 'two-critical',
        reason: 'Two or more critical warning signs were found, so the result is raised to High Risk even though the combined score alone came to ' + rawScore + '.'
      });
    } else if (criticalCount === 1 && score < 25) {
      score = 25;
      floors.push({
        id: 'one-critical',
        reason: 'A critical warning sign was found, so the result is raised to Suspicious even though the combined score alone came to ' + rawScore + '.'
      });
    }

    const band = BANDS.filter(function (b) { return score >= b.min && score <= b.max; })[0] || BANDS[0];

    scored.sort(function (a, b) {
      const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (bySeverity) return bySeverity;
      return b.contribution - a.contribution;
    });
    observations.sort(function (a, b) { return a.title < b.title ? -1 : 1; });

    const categories = P.CATEGORIES.map(function (cat) {
      const inCat = findings.filter(function (f) { return f.category === cat.id; });
      const scoredInCat = inCat.filter(function (f) { return f.weight > 0; });
      let maxSeverity = 'info';
      scoredInCat.forEach(function (f) {
        if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[maxSeverity]) maxSeverity = f.severity;
      });
      return {
        id: cat.id,
        label: cat.label,
        blurb: cat.blurb,
        icon: cat.icon,
        strength: combine(scoredInCat.map(function (f) { return f.weight; })),
        findingCount: inCat.length,
        scoredCount: scoredInCat.length,
        maxSeverity: maxSeverity
      };
    });

    const elapsedMs = Math.round((now() - started) * 100) / 100;

    return {
      isEmpty: !combined.trim(),
      score: score,
      rawScore: rawScore,
      band: band,
      classification: band.label,
      tone: band.tone,
      summary: band.summary,
      findings: scored,
      observations: observations,
      categories: categories,
      recommendations: buildRecommendations(band.id, scored),
      urls: urls,
      attachments: attachments,
      headers: {
        provided: headers.hasHeaders,
        lineCount: headers.headerLines.length,
        from: headers.from,
        replyTo: headers.replyTo,
        returnPath: headers.returnPath,
        spf: headers.spf,
        dkim: headers.dkim,
        dmarc: headers.dmarc,
        hasDkimSignature: headers.hasDkimSignature,
        receivedCount: headers.receivedCount,
        authResults: headers.authResults
      },
      floors: floors,
      calculation: {
        formula: 'score = 100 \u00d7 (1 \u2212 (1\u2212w\u2081) \u00d7 (1\u2212w\u2082) \u00d7 \u2026 \u00d7 (1\u2212w\u2099))',
        terms: scored.map(function (f) {
          return { id: f.id, title: f.title, weight: f.weight, contribution: f.contribution };
        }),
        rawScore: rawScore,
        score: score,
        floors: floors
      },
      stats: {
        characters: combined.length,
        words: (combined.trim().match(/\S+/g) || []).length,
        urlsFound: urls.length,
        attachmentsFound: attachments.length,
        headersProvided: headers.hasHeaders,
        rulesEvaluated: P.TEXT_RULES.length + P.STRUCTURAL_RULES.length + P.URL_RULES.length + P.ATTACHMENT_RULES.length + P.HEADER_RULES.length,
        rulesTriggered: findings.length,
        scoredRulesTriggered: scored.length,
        elapsedMs: elapsedMs,
        headersLikelyInBody: !headers.hasHeaders && looksLikeHeaderBlock(body)
      },
      bands: BANDS,
      disclaimer: DISCLAIMER
    };
  }

  PEA.analyse = analyse;
  PEA.analyzerUtils.analyse = analyse;

})(typeof window !== 'undefined' ? window : globalThis);
