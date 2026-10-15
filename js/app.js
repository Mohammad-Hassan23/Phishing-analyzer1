/* =========================================================================
   Phishing Email Analyser - js/app.js
   -------------------------------------------------------------------------
   THE INTERFACE.

   This file connects the pasted text and the analysis engine to the page.
   Two rules govern everything in here:

     1. Nothing typed by a visitor is ever inserted into the page as HTML.
        Pasted emails are hostile by definition, so every piece of text that
        came from the visitor - or from a rule that matched it - is placed on
        the page with textContent, or split into safe text nodes. The only
        innerHTML in this file writes icons that are hard-coded constants
        above. That is what stops a malicious email from becoming a malicious
        web page.

     2. Nothing is sent anywhere, and nothing is stored. The only value kept
        between visits is the light or dark theme preference.
   ========================================================================= */

(function (root, document) {
  'use strict';

  const PEA = (root.PEA = root.PEA || {});

  /* -----------------------------------------------------------------------
     Icons. Static markup written by hand here - never anything a visitor
     typed - so writing it with innerHTML is safe.
     --------------------------------------------------------------------- */
  const ICONS = {
    low: '<path d="M12 2.5 4.5 5.5v5.5c0 4.8 3.2 8.9 7.5 10.5 4.3-1.6 7.5-5.7 7.5-10.5V5.5z"/><path d="M8.8 11.8l2.4 2.4 4.4-4.8"/>',
    medium: '<path d="M12 3l9 16H3z"/><path d="M12 9.5v4"/><circle cx="12" cy="16.6" r="0.6"/>',
    high: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5"/><circle cx="12" cy="16.4" r="0.7"/>',
    warning: '<path d="M12 3l9 16H3z"/><path d="M12 9.5v4"/><circle cx="12" cy="16.6" r="0.6"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="7.8" r="0.7"/>',
    advice: '<path d="M9 18h6"/><path d="M10 21h4"/><path d="M12 3a6 6 0 0 0-3.6 10.8c.5.4.8 1 .9 1.6l.1.6h5.2l.1-.6c.1-.6.4-1.2.9-1.6A6 6 0 0 0 12 3z"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
    download: '<path d="M12 3v12"/><path d="M7.5 10.5 12 15l4.5-4.5"/><path d="M4 20h16"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19"/>',
    moon: '<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/>',
    link: '<path d="M10.5 13.5a4.5 4.5 0 0 0 6.4.4l2-2a4.5 4.5 0 0 0-6.4-6.4l-1 1"/><path d="M13.5 10.5a4.5 4.5 0 0 0-6.4-.4l-2 2a4.5 4.5 0 0 0 6.4 6.4l1-1"/>',
    paperclip: '<path d="M21 12.5 12.6 20.9a5 5 0 0 1-7.1-7.1l8.5-8.5a3.4 3.4 0 0 1 4.8 4.8l-8.5 8.5a1.8 1.8 0 0 1-2.5-2.5l7.8-7.8"/>',
    shield: '<path d="M12 2.5 4.5 5.5v5.5c0 4.8 3.2 8.9 7.5 10.5 4.3-1.6 7.5-5.7 7.5-10.5V5.5z"/>'
  };

  const SVG_NS = 'http://www.w3.org/2000/svg';

  function svgIcon(name) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    svg.innerHTML = ICONS[name] || '';
    return svg;
  }

  /* -----------------------------------------------------------------------
     Tiny DOM helpers. Everything a visitor could influence goes through
     textContent and therefore cannot execute anything.
     --------------------------------------------------------------------- */

  function el(tag, options, children) {
    const node = document.createElement(tag);
    const opts = options || {};
    if (opts.className) node.className = opts.className;
    if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
    if (opts.html !== undefined) node.innerHTML = opts.html;
    if (opts.attrs) {
      Object.keys(opts.attrs).forEach(function (key) {
        if (opts.attrs[key] !== null && opts.attrs[key] !== undefined) node.setAttribute(key, opts.attrs[key]);
      });
    }
    if (opts.on) {
      Object.keys(opts.on).forEach(function (event) {
        node.addEventListener(event, opts.on[event]);
      });
    }
    append(node, children);
    return node;
  }

  function append(parent, children) {
    if (children === undefined || children === null) return parent;
    const list = Array.isArray(children) ? children : [children];
    list.forEach(function (child) {
      if (child === null || child === undefined || child === false) return;
      if (typeof child === 'string') {
        parent.appendChild(document.createTextNode(child));
      } else {
        parent.appendChild(child);
      }
    });
    return parent;
  }

  /* Highlight the phrase that triggered a rule inside the surrounding text.
     The context is split into plain text nodes and a single <mark>, so no part
     of the visitor's email is ever parsed as HTML. */
  function highlighted(context, phrase) {
    const text = String(context == null ? '' : context);
    const needle = String(phrase == null ? '' : phrase).trim();
    const frag = document.createDocumentFragment();
    if (!needle) {
      frag.appendChild(document.createTextNode(text));
      return frag;
    }
    const at = text.toLowerCase().indexOf(needle.toLowerCase());
    if (at === -1) {
      frag.appendChild(document.createTextNode(text));
      return frag;
    }
    if (at > 0) frag.appendChild(document.createTextNode(text.slice(0, at)));
    frag.appendChild(el('mark', { text: text.slice(at, at + needle.length) }));
    const rest = text.slice(at + needle.length);
    if (rest) frag.appendChild(document.createTextNode(rest));
    return frag;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function scrollToResults(node) {
    if (!node || typeof node.scrollIntoView !== 'function') return;
    node.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }

  /* -----------------------------------------------------------------------
     Theme. The only thing this application remembers between visits, and it
     contains nothing about any email.
     --------------------------------------------------------------------- */

  const THEME_KEY = 'pea-theme';

  function readStoredTheme() {
    try {
      return root.localStorage ? root.localStorage.getItem(THEME_KEY) : null;
    } catch (error) {
      return null;
    }
  }

  function storeTheme(theme) {
    try {
      if (root.localStorage) root.localStorage.setItem(THEME_KEY, theme);
    } catch (error) {
      /* Storage may be unavailable; the theme simply will not be remembered. */
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const button = document.getElementById('theme-toggle');
    const iconHost = document.getElementById('theme-icon');
    const light = theme === 'light';
    if (button) {
      button.setAttribute('aria-pressed', light ? 'true' : 'false');
      button.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
    }
    if (iconHost) {
      iconHost.innerHTML = light ? ICONS.sun : ICONS.moon;
    }
  }

  function initTheme() {
    const stored = readStoredTheme();
    let theme = stored;
    if (theme !== 'light' && theme !== 'dark') {
      const prefersLight = root.matchMedia && root.matchMedia('(prefers-color-scheme: light)').matches;
      theme = prefersLight ? 'light' : 'dark';
    }
    applyTheme(theme);
    return theme;
  }

  PEA.app = {
    el: el,
    append: append,
    svgIcon: svgIcon,
    highlighted: highlighted,
    clear: clear,
    initTheme: initTheme,
    applyTheme: applyTheme,
    storeTheme: storeTheme,
    scrollToResults: scrollToResults,
    /* Exposed so the automated checks can drive the whole report rendering
       without a browser (see tests/run-ui-tests.js). */
    renderReport: renderReport,
    buildReportText: buildReportText,
    renderFinding: renderFinding
  };

  /* =======================================================================
     RENDERING THE REPORT
     ===================================================================== */

  const SEVERITY_WORD = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Note'
  };

  const TONE_ICON = { low: 'low', medium: 'medium', high: 'high' };

  function panelHead(badge, title, description, headingId) {
    const heading = el('h3', { text: title });
    if (headingId) heading.id = headingId;
    return el('div', { className: 'panel-head' }, [
      el('span', { className: 'step-badge', attrs: { 'aria-hidden': 'true' }, text: badge }),
      el('div', {}, [
        heading,
        description ? el('p', { text: description }) : null
      ])
    ]);
  }

  function renderScoreCard(result) {
    const card = el('div', { className: 'score-card tone-' + result.tone });

    /* The dial is a plain SVG circle: no chart library, no image, just maths.
       The filled portion is the score as a share of the circumference. */
    const radius = 54;
    const circumference = 2 * Math.PI * radius;
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 120 120');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Risk score ' + result.score + ' out of 100. Classification: ' + result.classification + '.');

    const track = document.createElementNS(SVG_NS, 'circle');
    track.setAttribute('class', 'dial-track');
    track.setAttribute('cx', '60');
    track.setAttribute('cy', '60');
    track.setAttribute('r', String(radius));

    const arc = document.createElementNS(SVG_NS, 'circle');
    arc.setAttribute('class', 'dial-value');
    arc.setAttribute('cx', '60');
    arc.setAttribute('cy', '60');
    arc.setAttribute('r', String(radius));
    arc.style.strokeDasharray = '0 ' + circumference;

    svg.appendChild(track);
    svg.appendChild(arc);

    const dial = el('div', { className: 'dial' }, [
      svg,
      el('div', { className: 'dial-centre' }, [
        el('span', { className: 'dial-number', text: String(result.score) }),
        el('span', { className: 'dial-out-of', text: 'out of 100' })
      ])
    ]);

    /* Animate the arc filling, a moment after it appears. */
    root.setTimeout(function () {
      arc.style.strokeDasharray = (circumference * result.score / 100) + ' ' + circumference;
    }, 60);

    const pill = el('span', { className: 'classification' }, [
      svgIcon(TONE_ICON[result.tone] || 'info'),
      el('span', { text: result.classification })
    ]);

    const summary = el('div', { className: 'score-summary' }, [
      pill,
      el('h2', { text: result.summary }),
      el('p', { text: result.band.detail })
    ]);

    /* The three bands, with the current one marked. Colour is never the only
       signal: the current step is also the one that is highlighted. */
    const scale = el('div', { className: 'score-scale' });
    result.bands.forEach(function (band) {
      const isCurrent = band.id === result.band.id;
      scale.appendChild(el('div', {
        className: 'scale-step' + (isCurrent ? ' is-current' : ''),
        attrs: { 'aria-current': isCurrent ? 'true' : null }
      }, [
        el('b', { text: band.label }),
        el('span', { text: band.min + '\u2013' + band.max })
      ]));
    });
    summary.appendChild(scale);

    result.floors.forEach(function (floor) {
      summary.appendChild(el('div', { className: 'floor-note' }, [
        svgIcon('warning'),
        el('p', { text: floor.reason })
      ]));
    });

    card.appendChild(dial);
    card.appendChild(summary);
    return card;
  }

  function renderCategoryPanel(result) {
    const panel = el('section', {
      className: 'panel',
      attrs: { 'aria-labelledby': 'categories-heading' }
    });
    panel.appendChild(panelHead(
      '2',
      'Where the warning signs come from',
      'Each category is scored the same way as the whole report. A category showing zero means nothing in that family was found - not that the message is safe.',
      'categories-heading'
    ));

    const grid = el('div', { className: 'category-grid' });
    result.categories.forEach(function (category) {
      grid.appendChild(el('div', { className: 'category-card sev-' + category.maxSeverity }, [
        el('div', { className: 'category-top' }, [
          /* The icon markup is a constant written by hand in patterns.js. */
          el('span', { className: 'category-icon', html: category.icon }),
          el('span', {}, [
            el('span', { className: 'category-name', text: category.label }),
            el('span', {
              className: 'category-count',
              text: category.scoredCount === 0
                ? 'nothing found'
                : category.scoredCount + (category.scoredCount === 1 ? ' warning sign' : ' warning signs')
            })
          ])
        ]),
        el('div', { className: 'meter' }, [
          el('div', { className: 'meter-fill', attrs: { style: 'width:' + category.strength + '%' } })
        ]),
        el('p', { className: 'category-blurb', text: category.blurb })
      ]));
    });

    panel.appendChild(grid);
    return panel;
  }



  /* -----------------------------------------------------------------------
     One warning sign, as an expandable card. Everything the visitor could
     have influenced is inserted as text, never as markup.
     --------------------------------------------------------------------- */

  function evidenceItem(item) {
    const box = el('li', { className: 'evidence' });
    if (item.kind === 'text') {
      box.appendChild(highlighted(item.context, item.value));
    } else {
      box.appendChild(el('span', { className: 'raw-url', text: item.value }));
      if (item.context) {
        box.appendChild(el('span', { className: 'evidence-note', text: item.context }));
      }
    }
    return box;
  }

  function renderFinding(finding, openByDefault) {
    const card = el('details', { className: 'finding sev-' + finding.severity });
    if (openByDefault) card.setAttribute('open', 'open');

    const points = el('span', { className: 'finding-points' }, [
      el('span', { className: 'sev-word', text: SEVERITY_WORD[finding.severity] || finding.severity }),
      el('span', { text: 'weight ' + finding.weight })
    ]);

    if (finding.weight > 0) {
      points.appendChild(el('span', { text: '\u00b7 added ' + finding.contribution + ' to the score' }));
    } else {
      points.textContent = 'Not scored';
    }

    const summary = el('summary', {}, [
      el('span', { className: 'finding-title', text: finding.title }),
      points
    ]);

    if (finding.note) {
      summary.appendChild(el('p', { className: 'finding-note', text: finding.note }));
    } else if (finding.matchCount > 1) {
      summary.appendChild(el('p', {
        className: 'finding-note',
        text: 'Found ' + finding.matchCount + ' times in this message.'
      }));
    }

    card.appendChild(summary);

    const body = el('div', { className: 'finding-body' });

    if (finding.evidence && finding.evidence.length) {
      body.appendChild(el('h4', { text: 'What we found in the message' }));
      const list = el('ul', { className: 'evidence-list' });
      finding.evidence.forEach(function (item) { list.appendChild(evidenceItem(item)); });
      body.appendChild(list);
    }

    body.appendChild(el('h4', { text: 'Why this matters' }));
    body.appendChild(el('p', { text: finding.what }));

    body.appendChild(el('h4', { text: 'What to do' }));
    body.appendChild(el('div', { className: 'advice-box' }, [
      svgIcon('advice'),
      el('p', { text: finding.advice })
    ]));

    card.appendChild(body);
    return card;
  }

  function renderFindingsPanel(result) {
    const panel = el('section', {
      className: 'panel',
      attrs: { 'aria-labelledby': 'findings-heading' }
    });

    if (!result.findings.length) {
      panel.appendChild(panelHead(
        '3',
        'Warning signs found: none',
        'None of the checks in the rulebook were triggered by this text.',
        'findings-heading'
      ));
      panel.appendChild(el('div', { className: 'notice' }, [
        svgIcon('info'),
        el('div', {}, [
          el('h3', { text: 'This is not a guarantee' }),
          el('p', {
            text: 'An empty list means the message did not use any of the wording or link patterns this tool knows about. A carefully written attack can achieve exactly that, so an unexpected email that asks for money, credentials or a change of payment details still deserves an independent check.'
          })
        ])
      ]));
      return panel;
    }

    panel.appendChild(panelHead(
      '3',
      'Warning signs found: ' + result.findings.length,
      'Expand any warning sign to see the words that triggered it, why it matters and what to do. The most serious are listed first.',
      'findings-heading'
    ));

    const list = el('div', { className: 'finding-list' });
    result.findings.forEach(function (finding, index) {
      list.appendChild(renderFinding(finding, index === 0));
    });
    panel.appendChild(list);

    panel.appendChild(el('p', {
      className: 'hint',
      text: 'The contributions shown here are each warning sign\'s own effect on the final score, measured by recalculating without it. Because the warning signs overlap slightly, they do not add up to exactly ' + result.score + '.'
    }));

    return panel;
  }

  /* -----------------------------------------------------------------------
     Recommendations
     --------------------------------------------------------------------- */

  function renderRecommendationsPanel(result) {
    const panel = el('section', {
      className: 'panel',
      attrs: { 'aria-labelledby': 'recommendations-heading' }
    });
    panel.appendChild(panelHead(
      '4',
      'What to do next',
      'Ordered from the most important action downwards.',
      'recommendations-heading'
    ));

    const list = el('ol', { className: 'recommendations' });
    result.recommendations.forEach(function (item) {
      list.appendChild(el('li', {}, el('span', { text: item })));
    });
    panel.appendChild(list);
    return panel;
  }

  /* -----------------------------------------------------------------------
     Links and attachments: shown as inert text, never as clickable links.
     The whole point is to read them, not to follow them.
     --------------------------------------------------------------------- */

  function renderLinksPanel(result) {
    const panel = el('section', {
      className: 'panel',
      attrs: { 'aria-labelledby': 'links-heading' }
    });
    panel.appendChild(panelHead(
      '5',
      'Links found in the message',
      'Listed for reading only. They are deliberately not clickable - do not paste them into your browser to see where they go.',
      'links-heading'
    ));

    const table = el('table');
    table.appendChild(el('thead', {}, el('tr', {}, [
      el('th', { attrs: { scope: 'col' }, text: 'Address as written' }),
      el('th', { attrs: { scope: 'col' }, text: 'Registered domain' }),
      el('th', { attrs: { scope: 'col' }, text: 'What we noticed' })
    ])));

    const tbody = el('tbody');
    result.urls.forEach(function (url) {
      const assessment = el('div', { className: 'tag-row' });
      if (url.flags && url.flags.length) {
        url.notes.forEach(function (note) {
          assessment.appendChild(el('span', { className: 'tag flagged', text: note }));
        });
      } else {
        assessment.appendChild(el('span', { className: 'tag clean', text: 'no warning signs in this link' }));
      }
      tbody.appendChild(el('tr', {}, [
        el('td', { className: 'cell-url', text: url.raw }),
        el('td', {}, [
          el('span', { text: url.registrableDomain || url.hostname }),
          url.anchorText ? el('span', { className: 'evidence-note', text: 'link text: "' + url.anchorText + '"' }) : null
        ]),
        el('td', {}, assessment)
      ]));
    });
    table.appendChild(tbody);

    panel.appendChild(el('div', { className: 'table-wrap' }, table));
    return panel;
  }

  function renderAttachmentsPanel(result) {
    const panel = el('section', {
      className: 'panel',
      attrs: { 'aria-labelledby': 'attachments-heading' }
    });
    panel.appendChild(panelHead(
      '6',
      'Attachments mentioned',
      'File names found in the message text or in the headers you pasted. The tool cannot see inside a file - it only reads the name and the type the email claims it is.',
      'attachments-heading'
    ));

    const table = el('table');
    table.appendChild(el('thead', {}, el('tr', {}, [
      el('th', { attrs: { scope: 'col' }, text: 'File name' }),
      el('th', { attrs: { scope: 'col' }, text: 'Type' }),
      el('th', { attrs: { scope: 'col' }, text: 'What we noticed' })
    ])));

    const tbody = el('tbody');
    result.attachments.forEach(function (attachment) {
      const assessment = el('div', { className: 'tag-row' });
      if (attachment.flags && attachment.flags.length) {
        attachment.notes.forEach(function (note) {
          assessment.appendChild(el('span', { className: 'tag flagged', text: note }));
        });
      } else {
        assessment.appendChild(el('span', { className: 'tag clean', text: 'nothing unusual in the name' }));
      }
      tbody.appendChild(el('tr', {}, [
        el('td', { className: 'cell-url', text: attachment.name }),
        el('td', {}, [
          el('span', { text: '.' + attachment.extension }),
          attachment.declaredType ? el('span', { className: 'evidence-note', text: 'declared as ' + attachment.declaredType }) : null
        ]),
        el('td', {}, assessment)
      ]));
    });
    table.appendChild(tbody);

    panel.appendChild(el('div', { className: 'table-wrap' }, table));
    return panel;
  }

  /* -----------------------------------------------------------------------
     Sender authenticity: only ever reports what the headers actually said.
     --------------------------------------------------------------------- */

  function authState(value) {
    if (!value) return { className: 'state-absent', label: 'not available' };
    if (value === 'pass') return { className: 'state-pass', label: 'pass' };
    if (value === 'fail') return { className: 'state-fail', label: 'FAIL' };
    if (value === 'softfail') return { className: 'state-partial', label: 'soft fail' };
    if (value === 'none') return { className: 'state-absent', label: 'none published' };
    return { className: 'state-partial', label: value };
  }

  function authItem(label, value, state) {
    const item = el('div', { className: 'auth-item' + (state ? ' ' + state.className : '') });
    item.appendChild(el('span', { className: 'auth-label', text: label }));
    item.appendChild(el('span', { className: 'auth-value', text: value }));
    return item;
  }

  function renderAuthenticityPanel(result) {
    const panel = el('section', {
      className: 'panel',
      attrs: { 'aria-labelledby': 'authenticity-heading' }
    });
    panel.appendChild(panelHead(
      '7',
      'Sender authenticity',
      'SPF, DKIM and DMARC are checks the receiving mail server performs. They can only be read from the email headers.',
      'authenticity-heading'
    ));

    const headers = result.headers;

    if (!headers.provided) {
      panel.appendChild(el('div', { className: 'notice is-warning' }, [
        svgIcon('warning'),
        el('div', {}, [
          el('h3', { text: 'Not available - no headers were pasted' }),
          el('p', {
            text: result.stats.headersLikelyInBody
              ? 'It looks as though the text you pasted contains email headers. Paste them into the "email headers" box above to unlock the SPF, DKIM and DMARC checks, along with the From and Reply-To comparison.'
              : 'Without headers this tool cannot check SPF, DKIM or DMARC, and it will not guess. Open the email\'s original source (Gmail: "Show original"; Outlook: "View message source") and paste the top of it into the headers box above.'
          }),
          el('p', {
            text: 'Those checks matter because they answer a question the message text alone cannot: did this mail really come from the domain it claims to come from?'
          })
        ])
      ]));
      return panel;
    }

    const grid = el('div', { className: 'auth-grid' });
    grid.appendChild(authItem('From', headers.from ? (headers.from.address || headers.from.raw) : 'not found'));
    if (headers.from && headers.from.displayName) {
      grid.appendChild(authItem('Sender name shown', headers.from.displayName));
    }
    grid.appendChild(authItem('Reply-To', headers.replyTo ? (headers.replyTo.address || headers.replyTo.raw) : 'not present'));
    grid.appendChild(authItem('Return-Path', headers.returnPath ? (headers.returnPath.address || headers.returnPath.raw) : 'not present'));
    grid.appendChild(authItem('SPF', authState(headers.spf).label, authState(headers.spf)));
    grid.appendChild(authItem('DKIM', authState(headers.dkim).label, authState(headers.dkim)));
    grid.appendChild(authItem('DMARC', authState(headers.dmarc).label, authState(headers.dmarc)));
    grid.appendChild(authItem(
      'DKIM signature present',
      headers.hasDkimSignature ? 'yes' : 'no',
      headers.hasDkimSignature ? { className: 'state-pass', label: 'yes' } : { className: 'state-absent', label: 'no' }
    ));
    grid.appendChild(authItem('Headers read', headers.lineCount + ' lines, ' + headers.receivedCount + ' Received hops'));

    panel.appendChild(grid);

    panel.appendChild(el('div', { className: 'notice', attrs: { style: 'margin-top:1rem' } }, [
      svgIcon('info'),
      el('div', {}, [
        el('h3', { text: 'A pass is not an all-clear' }),
        el('p', {
          text: 'Passing SPF, DKIM and DMARC proves the message really was sent by the domain it claims to come from. It does not prove the message is safe: a criminal who has taken over a real mailbox, or who uses a legitimate bulk-mailing service, will pass every one of these checks. That is exactly what happens in the business-email-compromise example in this tool.'
        })
      ])
    ]));

    return panel;
  }

  function renderObservationsPanel(result) {
    const panel = el('section', {
      className: 'panel',
      attrs: { 'aria-labelledby': 'observations-heading' }
    });
    panel.appendChild(panelHead(
      '8',
      'Notes that did not affect the score',
      'These are things worth understanding, but they are not evidence either way, so they add no points.',
      'observations-heading'
    ));

    const list = el('ul', { className: 'observation-list' });
    result.observations.forEach(function (observation) {
      list.appendChild(el('li', {}, [
        el('strong', { text: observation.title }),
        el('span', { text: observation.note || observation.what })
      ]));
    });
    panel.appendChild(list);
    return panel;
  }

  /* -----------------------------------------------------------------------
     Technical details, and the calculation written out in full. This is the
     part that makes the score auditable rather than mysterious.
     --------------------------------------------------------------------- */

  function renderTechnicalPanel(result) {
    const wrapper = el('details', { className: 'tech-details' });
    wrapper.appendChild(el('summary', { text: 'Technical details and the full calculation' }));

    const body = el('div', { className: 'tech-body' });

    const stats = el('ul', { className: 'stat-grid' });
    [
      ['Characters analysed', String(result.stats.characters)],
      ['Words', String(result.stats.words)],
      ['Links found', String(result.stats.urlsFound)],
      ['Attachments mentioned', String(result.stats.attachmentsFound)],
      ['Rules evaluated', String(result.stats.rulesEvaluated)],
      ['Rules triggered', String(result.stats.rulesTriggered)],
      ['Headers supplied', result.stats.headersProvided ? 'yes' : 'no'],
      ['Analysis time', result.stats.elapsedMs + ' ms']
    ].forEach(function (pair) {
      stats.appendChild(el('li', { className: 'stat' }, [
        el('b', { text: pair[1] }),
        el('span', { text: pair[0] })
      ]));
    });
    body.appendChild(stats);

    /* The arithmetic, written out with the actual weights that fired. */
    const terms = result.calculation.terms;
    const expression = terms.length
      ? '100 \u00d7 (1 \u2212 ' + terms.map(function (t) { return '(1\u2212' + (t.weight / 100).toFixed(2) + ')'; }).join(' \u00d7 ') + ') = ' + result.calculation.rawScore
      : '100 \u00d7 (1 \u2212 1) = 0';

    body.appendChild(el('h4', { text: 'The calculation', attrs: { style: 'margin-top:1.1rem' } }));
    body.appendChild(el('p', { className: 'formula', text: result.calculation.formula }));
    body.appendChild(el('p', { className: 'formula', text: expression }));

    if (terms.length) {
      const table = el('table');
      table.appendChild(el('thead', {}, el('tr', {}, [
        el('th', { attrs: { scope: 'col' }, text: 'Warning sign' }),
        el('th', { attrs: { scope: 'col' }, text: 'Weight' }),
        el('th', { attrs: { scope: 'col' }, text: 'Contribution' })
      ])));
      const tbody = el('tbody');
      terms.forEach(function (term) {
        tbody.appendChild(el('tr', {}, [
          el('td', { text: term.title }),
          el('td', { text: String(term.weight) }),
          el('td', { text: '+' + term.contribution })
        ]));
      });
      table.appendChild(tbody);
      body.appendChild(el('div', { className: 'table-wrap', attrs: { style: 'margin-top:0.6rem' } }, table));
    }

    body.appendChild(el('p', {
      className: 'hint',
      text: 'Contributions are measured one at a time: the score is recalculated with that single warning sign removed, and the difference is what it contributed. That is why they do not add up to exactly the total - the signs overlap, and two strong signs together are worth slightly less than the sum of their parts.'
    }));

    wrapper.appendChild(body);
    return wrapper;
  }

  /* -----------------------------------------------------------------------
     The standing disclaimer, shown with every single result.
     --------------------------------------------------------------------- */

  function renderDisclaimer(result) {
    return el('div', { className: 'disclaimer' }, [
      el('strong', { text: 'What this result does and does not mean' }),
      el('p', { text: result.disclaimer })
    ]);
  }

  /* -----------------------------------------------------------------------
     The report as plain text, for copying or saving locally. Nothing here
     touches the network: the clipboard and the download are both handled by
     the browser on the visitor's own machine.
     --------------------------------------------------------------------- */

  const REPORT_RULE = '--------------------------------------------------------------';

  function buildReportText(result, meta) {
    const lines = [];
    const push = function (line) { lines.push(line === undefined ? '' : line); };

    push('PHISHING EMAIL ANALYSER - REPORT');
    push('Produced locally in the browser. No email content left this device.');
    if (meta && meta.timestamp) push('Generated: ' + meta.timestamp);
    if (meta && meta.sampleName) push('Demonstration email: ' + meta.sampleName);
    push('');
    push(REPORT_RULE);
    push('RESULT');
    push(REPORT_RULE);
    push('Score:          ' + result.score + ' / 100');
    push('Classification: ' + result.classification);
    push('Summary:        ' + result.summary);
    if (result.rawScore !== result.score) {
      push('Score before the safety floor: ' + result.rawScore);
    }
    result.floors.forEach(function (floor) {
      push('Safety floor:   ' + floor.reason);
    });
    push('');

    push(REPORT_RULE);
    push('WARNING SIGNS (' + result.findings.length + ')');
    push(REPORT_RULE);
    if (!result.findings.length) {
      push('None of the checks in the rulebook were triggered by this text.');
      push('That is not a guarantee that the message is safe.');
    }
    result.findings.forEach(function (finding, index) {
      push((index + 1) + '. ' + finding.title);
      push('   Severity: ' + (SEVERITY_WORD[finding.severity] || finding.severity) +
        ' | weight ' + finding.weight + ' | contributed +' + finding.contribution);
      if (finding.note) push('   Observed: ' + finding.note);
      finding.evidence.forEach(function (item) {
        if (item.kind === 'text') {
          push('   Found: "' + item.value + '"');
          push('   Context: ' + item.context);
        } else {
          push('   Found: ' + item.value);
        }
      });
      push('   Why it matters: ' + finding.what);
      push('   What to do: ' + finding.advice);
      push('');
    });

    if (result.urls.length) {
      push(REPORT_RULE);
      push('LINKS FOUND (' + result.urls.length + ')');
      push(REPORT_RULE);
      result.urls.forEach(function (url) {
        push('- ' + url.raw);
        push('    domain: ' + (url.registrableDomain || url.hostname) +
          (url.anchorText ? ' | link text: "' + url.anchorText + '"' : ''));
        push('    ' + (url.notes && url.notes.length ? url.notes.join('; ') : 'no warning signs in this link'));
      });
      push('');
    }

    if (result.attachments.length) {
      push(REPORT_RULE);
      push('ATTACHMENTS MENTIONED (' + result.attachments.length + ')');
      push(REPORT_RULE);
      result.attachments.forEach(function (attachment) {
        push('- ' + attachment.name + ' (.' + attachment.extension + ')' +
          (attachment.declaredType ? ' declared as ' + attachment.declaredType : ''));
        push('    ' + (attachment.notes && attachment.notes.length ? attachment.notes.join('; ') : 'nothing unusual in the name'));
      });
      push('');
    }

    push(REPORT_RULE);
    push('SENDER AUTHENTICITY');
    push(REPORT_RULE);
    if (!result.headers.provided) {
      push('Not available - no email headers were pasted.');
    } else {
      const h = result.headers;
      push('From:        ' + (h.from ? (h.from.address || h.from.raw) : 'not found'));
      if (h.from && h.from.displayName) push('Sender name: ' + h.from.displayName);
      push('Reply-To:    ' + (h.replyTo ? (h.replyTo.address || h.replyTo.raw) : 'not present'));
      push('Return-Path: ' + (h.returnPath ? (h.returnPath.address || h.returnPath.raw) : 'not present'));
      push('SPF:         ' + (h.spf || 'not available'));
      push('DKIM:        ' + (h.dkim || 'not available'));
      push('DMARC:       ' + (h.dmarc || 'not available'));
      push('DKIM signature present: ' + (h.hasDkimSignature ? 'yes' : 'no'));
      push('Note: passing these checks proves the message came from that domain. It does not prove the request inside it is genuine.');
    }
    push('');

    if (result.observations.length) {
      push(REPORT_RULE);
      push('NOTES THAT DID NOT AFFECT THE SCORE');
      push(REPORT_RULE);
      result.observations.forEach(function (observation) {
        push('- ' + observation.title + ': ' + (observation.note || observation.what));
      });
      push('');
    }

    push(REPORT_RULE);
    push('WHAT TO DO NEXT');
    push(REPORT_RULE);
    result.recommendations.forEach(function (item, index) {
      push((index + 1) + '. ' + item);
    });
    push('');

    push(REPORT_RULE);
    push('IMPORTANT');
    push(REPORT_RULE);
    push(result.disclaimer);

    return lines.join('\n');
  }

  /* -----------------------------------------------------------------------
     Actions: copy and save. Both are entirely local.
     --------------------------------------------------------------------- */

  function flashStatus(node, message) {
    if (!node) return;
    node.textContent = message;
    root.setTimeout(function () {
      if (node.textContent === message) node.textContent = '';
    }, 4000);
  }

  /* Older browsers, and pages opened from a file on disk, may not allow the
     modern clipboard call, so there is a fallback using a hidden text box. */
  function fallbackCopy(text) {
    try {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', 'readonly');
      area.style.position = 'fixed';
      area.style.top = '-2000px';
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand ? document.execCommand('copy') : false;
      document.body.removeChild(area);
      return !!ok;
    } catch (error) {
      return false;
    }
  }

  function copyReport(text, status) {
    const failed = function () {
      flashStatus(status, fallbackCopy(text)
        ? 'Report copied to the clipboard.'
        : 'Copying was blocked by the browser - the save button should still work.');
    };
    if (root.navigator && root.navigator.clipboard && root.navigator.clipboard.writeText) {
      root.navigator.clipboard.writeText(text).then(
        function () { flashStatus(status, 'Report copied to the clipboard.'); },
        failed
      );
      return;
    }
    failed();
  }

  function fileStamp() {
    const now = new Date();
    const pad = function (value) { return String(value).padStart(2, '0'); };
    return now.getFullYear() + pad(now.getMonth() + 1) + pad(now.getDate()) + '-' + pad(now.getHours()) + pad(now.getMinutes());
  }

  function saveReport(text, status) {
    try {
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'phishing-analysis-' + fileStamp() + '.txt';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      root.setTimeout(function () { URL.revokeObjectURL(url); }, 5000);
      flashStatus(status, 'Report saved to your downloads folder.');
    } catch (error) {
      flashStatus(status, 'This browser would not let the file be created. The copy button should still work.');
    }
  }

  function renderActions(result, meta) {
    const status = el('span', { className: 'copy-status', attrs: { role: 'status' } });
    const text = buildReportText(result, meta || {});

    const copyButton = el('button', {
      className: 'button ghost',
      attrs: { type: 'button' }
    }, [svgIcon('copy'), el('span', { text: 'Copy report' })]);
    copyButton.addEventListener('click', function () { copyReport(text, status); });

    const saveButton = el('button', {
      className: 'button ghost',
      attrs: { type: 'button' }
    }, [svgIcon('download'), el('span', { text: 'Save as a text file' })]);
    saveButton.addEventListener('click', function () { saveReport(text, status); });

    return el('div', { className: 'actions' }, [copyButton, saveButton, status]);
  }

  /* -----------------------------------------------------------------------
     Putting the whole report together
     --------------------------------------------------------------------- */

  function renderReport(result, meta) {
    const host = document.getElementById('results');
    if (!host) return;
    clear(host);

    if (meta && meta.sampleName) {
      host.appendChild(el('div', { className: 'notice', attrs: { style: 'margin-bottom:1rem' } }, [
        svgIcon('info'),
        el('div', {}, [
          el('h3', { text: 'Demonstration email: ' + meta.sampleName }),
          el('p', { text: meta.sampleNote || 'A completely fictional message, safe to analyse as often as you like.' })
        ])
      ]));
    }

    host.appendChild(renderScoreCard(result));
    host.appendChild(renderCategoryPanel(result));
    host.appendChild(renderFindingsPanel(result));
    host.appendChild(renderRecommendationsPanel(result));
    if (result.urls.length) host.appendChild(renderLinksPanel(result));
    if (result.attachments.length) host.appendChild(renderAttachmentsPanel(result));
    host.appendChild(renderAuthenticityPanel(result));
    if (result.observations.length) host.appendChild(renderObservationsPanel(result));
    host.appendChild(renderTechnicalPanel(result));
    host.appendChild(renderDisclaimer(result));
    host.appendChild(renderActions(result, meta || {}));
  }

  /* -----------------------------------------------------------------------
     Wiring the page up
     --------------------------------------------------------------------- */

  function init() {
    initTheme();

    const bodyBox = document.getElementById('email-body');
    const headerBox = document.getElementById('email-headers');
    const analyseButton = document.getElementById('analyse-button');
    const clearButton = document.getElementById('clear-button');
    const sampleSelect = document.getElementById('sample-select');
    const errorBox = document.getElementById('input-error');
    const errorText = document.getElementById('input-error-text');
    const headersBlock = document.getElementById('headers-block');
    const themeButton = document.getElementById('theme-toggle');
    const resultsHost = document.getElementById('results');

    if (!bodyBox || !analyseButton || !resultsHost) return;

    /* Fill the demonstration list from js/samples.js, so the two can never
       fall out of step with each other. */
    if (sampleSelect) {
      (PEA.samples || []).forEach(function (sample) {
        sampleSelect.appendChild(el('option', {
          text: sample.name,
          attrs: { value: sample.id }
        }));
      });
    }

    let currentMeta = {};

    function showError(message) {
      if (!errorBox || !errorText) return;
      errorText.textContent = message;
      errorBox.hidden = false;
    }

    function hideError() {
      if (errorBox) errorBox.hidden = true;
    }

    function runAnalysis() {
      const body = bodyBox.value;
      const headers = headerBox ? headerBox.value : '';

      if (!String(body).trim() && !String(headers).trim()) {
        showError('Paste the text of an email first - or choose one of the demonstration emails to see how the analyser works.');
        bodyBox.focus();
        return;
      }

      hideError();
      const result = PEA.analyse({ body: body, headers: headers });
      renderReport(result, currentMeta);
      scrollToResults(resultsHost);
    }

    analyseButton.addEventListener('click', runAnalysis);

    if (clearButton) {
      clearButton.addEventListener('click', function () {
        bodyBox.value = '';
        if (headerBox) headerBox.value = '';
        currentMeta = {};
        hideError();
        clear(resultsHost);
        bodyBox.focus();
      });
    }

    if (sampleSelect) {
      sampleSelect.addEventListener('change', function () {
        const id = sampleSelect.value;
        if (!id) return;
        const sample = (PEA.samples || []).filter(function (item) { return item.id === id; })[0];
        if (!sample) return;

        bodyBox.value = sample.body;
        if (headerBox) headerBox.value = sample.headers || '';
        if (headersBlock) {
          if (sample.headers) headersBlock.setAttribute('open', 'open');
          else headersBlock.removeAttribute('open');
        }
        currentMeta = { sampleName: sample.name, sampleNote: sample.blurb };
        hideError();
        runAnalysis();

        /* Reset the picker so the same example can be chosen again later. */
        sampleSelect.value = '';
      });
    }

    function onKeyDown(event) {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        runAnalysis();
      }
    }
    bodyBox.addEventListener('keydown', onKeyDown);
    if (headerBox) headerBox.addEventListener('keydown', onKeyDown);

    if (themeButton) {
      themeButton.addEventListener('click', function () {
        const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        applyTheme(next);
        storeTheme(next);
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})(typeof window !== 'undefined' ? window : globalThis, document);







