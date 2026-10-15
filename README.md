# Phishing Email Analyser

A polished, deliberately simple web application that reads the text of a suspicious
email and explains, in plain English, every phishing warning sign it can find.

**It is an educational triage tool.** It identifies warning signs; it cannot and
does not determine whether an email is malicious. A low score is not a guarantee
that a message is safe, and a high score is not proof of guilt.

---

## The privacy promise

**Nothing you paste is uploaded anywhere.** There is no server, no database, no
account, no AI service, no analytics and no cookies. The entire analysis happens
inside your browser, on your own device.

You do not have to take that on trust:

- **Check the network yourself.** Press `F12`, open the *Network* tab, then paste
  an email and analyse it. You will see no requests being made.
- **The browser enforces it.** The page sends a `Content-Security-Policy`
  instruction containing `connect-src 'none'`, which forbids *all* outbound
  connections. Even if somebody later added code that tried to send your email
  somewhere, the browser would refuse.
- **The automated tests check it.** One of the tests scans every file in this
  project for any network call (`fetch`, `XMLHttpRequest`, `WebSocket`,
  `EventSource`, `sendBeacon`, dynamic imports) and for anything resembling
  analytics. It fails if it finds any.
- **Nothing is stored.** Your email text is never written to storage and is gone
  the moment you close or refresh the page. The only thing this site remembers is
  whether you prefer the light or the dark theme.

---

## Trying it out

**The simplest way:** double-click `index.html`. It opens in your browser and works
immediately.

**If it looks unstyled, or nothing happens when you click the button**, your
browser is being strict about a page opened straight from a file. Use a one-line
local web server instead, from inside the project folder:

```bash
python3 -m http.server 8000
```

Then open <http://localhost:8000> in your browser. (Press `Ctrl` + `C` in the
terminal to stop it afterwards.)

---

## Putting it on the internet, for free

The site is completely static, so free hosting services will serve it exactly as it
is. With GitHub Pages, for example:

1. Open the repository on GitHub and go to **Settings → Pages**.
2. Under *Build and deployment*, set **Source** to *Deploy from a branch*.
3. Choose the branch you want to publish (normally `main`) and the folder
   `/(root)`, then press **Save**.
4. Wait a minute. GitHub will show you the public address of your site.

There is nothing to build, nothing to compile and no configuration to write.

---

## What the analysis looks for

Every warning sign belongs to one of six families:

| Family | What it covers |
|---|---|
| **Urgency & Pressure** | Deadlines, fear, threats of suspension or closure |
| **Credentials & Identity** | Requests for passwords, codes, "verify your account" wording, impersonation |
| **Money & Payment** | Payment demands, gift cards and crypto, changed bank details, unexpected invoices |
| **Links & Domains** | Where links really go: raw IP addresses, shorteners, lookalike domains, the `@` trick, mismatched link text |
| **Attachments & Macros** | Programmes, macro-enabled documents, double extensions, "enable content" |
| **Sender Authenticity** | From / Reply-To / Return-Path mismatches, and SPF, DKIM and DMARC results from pasted headers |

### The scoring, in plain English

Each warning sign carries a **weight**: how strongly that one sign, on its own,
suggests phishing. The weights are combined as independent pieces of evidence
rather than simply added together:

```
score = 100 × (1 − (1−w₁) × (1−w₂) × … × (1−wₙ))
```

- One 25-point warning sign gives a score of **25**.
- Three 25-point warning signs give **58**.
- Six give **82**.
- Twenty weak 5-point signals can never reach a false 100.

This is order-independent, so the same email always produces the same score, and it
cannot saturate the way plain addition would.

**Every warning sign reports its own contribution.** The score is recalculated with
that one sign removed, and the difference is what it contributed. Because the signs
overlap slightly, those contributions do not add up to exactly the total - and the
report says so rather than pretending otherwise.

**Two safety floors.** Some signs are so strong that the tool refuses to call an
email low risk while one is present:

- one or more *critical* signs (weight 25) → at least **Suspicious**;
- two or more *critical* signs → at least **High Risk**.

Whenever a floor is applied, the report says so and shows what the raw score was.

### The full list of warning signs and weights

Generated from the rulebook itself, so this table cannot drift away from what the
code actually does. All 46 rules, highest weight first.

| Weight | Warning sign | Family |
|---|---|---|
| 25 | Asks for a verification code (MFA / one-time code) | Credentials & Identity |
| 25 | Asks for your password | Credentials & Identity |
| 25 | Asks you to change bank or payment details | Money & Payment |
| 25 | Asks you to enable macros or content | Attachments & Macros |
| 25 | Attachment is a file type that runs code when opened | Attachments & Macros |
| 25 | Attachment is a macro-enabled Office document | Attachments & Macros |
| 20 | Attachment is declared as one file type but named as another | Attachments & Macros |
| 20 | DMARC check failed | Sender Authenticity |
| 20 | Link points at a bare IP address | Links & Domains |
| 20 | Link uses the "@" trick to disguise its real destination | Links & Domains |
| 20 | Replies would go to a different domain than the sender's | Sender Authenticity |
| 20 | Requests payment, gift cards or cryptocurrency | Money & Payment |
| 20 | Sender name is a fake email address | Sender Authenticity |
| 20 | SPF check failed | Sender Authenticity |
| 18 | Asks you to verify or confirm your account details | Credentials & Identity |
| 15 | DKIM signature check failed | Sender Authenticity |
| 15 | Link mentions a well-known brand on a domain that is not that brand's | Links & Domains |
| 15 | Link text does not match where the link actually goes | Links & Domains |
| 15 | Link uses an internationalised (lookalike) domain | Links & Domains |
| 15 | Message contains bidirectional text override characters | Credentials & Identity |
| 15 | Return-Path domain does not match the From domain | Sender Authenticity |
| 15 | Sender name claims a company the address does not belong to | Sender Authenticity |
| 15 | Threatens to suspend, close or lock your account | Urgency & Pressure |
| 12 | Attachment is a web page | Attachments & Macros |
| 12 | Combines a request for secrecy with authority | Credentials & Identity |
| 12 | Link is hidden behind a URL shortener | Links & Domains |
| 12 | Organisation-looking sender, but replies go to a free email account | Sender Authenticity |
| 12 | SPF check soft-failed | Sender Authenticity |
| 10 | Attachment name uses a double extension | Attachments & Macros |
| 10 | Links point somewhere unrelated to the sender | Sender Authenticity |
| 10 | Unexpected invoice or payment demand | Money & Payment |
| 8 | Attachment is a compressed archive | Attachments & Macros |
| 8 | Attachment name looks machine-generated | Attachments & Macros |
| 8 | Impersonation language | Credentials & Identity |
| 8 | Link uses a domain ending that is heavily used by phishing | Links & Domains |
| 8 | Message contains invisible characters | Credentials & Identity |
| 8 | Sender presents itself as a support or security function on a consumer mailbox | Sender Authenticity |
| 8 | Text is deliberately disguised | Credentials & Identity |
| 8 | Urgency and pressure language | Urgency & Pressure |
| 6 | Link hostname is unusually long or padded with extra parts | Links & Domains |
| 5 | Generic greeting or no greeting at all | Credentials & Identity |
| 5 | Link is not using an encrypted connection (http://) | Links & Domains |
| 5 | Link uses a non-standard network port | Links & Domains |
| 0 | Headers contain no DKIM signature at all *(note only)* | Sender Authenticity |
| 0 | No authentication results found in the headers *(note only)* | Sender Authenticity |
| 0 | Uses security-alert wording *(note only)* | Sender Authenticity |

The three zero-weight entries are deliberately not scored. They are shown because
they are worth understanding - "we detected a new sign-in" appears in genuine
alerts and in phishing - but they are not evidence either way, so they add nothing.
The interface lists them separately under *Notes that did not affect the score*.

---

## The six demonstration emails

Load any of them from the drop-down on the page. **Every one is completely
fictional and inert**, so nothing can happen if you experiment with them:

- all domains are reserved by internet standard and can never exist
  (`example.com`, `.test`, `.invalid`, `.example`);
- all IP addresses come from the documentation ranges (`192.0.2.x`, `203.0.113.x`),
  which are guaranteed never to route anywhere;
- the shortened link in the parcel example points at a real shortener's address
  with a deliberately invalid code, so it leads nowhere. The report never makes
  links clickable in any case.

| Example | Score | What it teaches |
|---|---|---|
| Obvious phishing | 74, High Risk | The unsubtle kind: fear, a deadline, a password request, a bare IP link and a programme attached |
| Sophisticated phishing | 81, High Risk | Calm and polite, no urgency at all - and still scores highly. The score measures how many strong signs are present, not how alarming the message feels |
| Fake Microsoft 365 account warning | 89, High Risk | A one-time code request, a lookalike domain, and SPF, DKIM and DMARC all failing |
| Fake parcel-delivery message | 31, Suspicious | A small hidden link and a small fee. Not every phish screams |
| Fake invoice / BEC-style email | 62, High Risk | **SPF, DKIM and DMARC all pass here.** The mail really was sent from a compromised account. Authentication proves where a message came from; it never proves the request inside it is genuine |
| Legitimate email | 0, Low Risk | The most important test of all. A tool that shouts at everything is useless |

---

## Classification bands

| Score | Classification |
|---|---|
| 0–24 | **Low Risk** |
| 25–59 | **Suspicious** |
| 60–100 | **High Risk** |

---

## Teaching the analyser something new

The rulebook is deliberately readable. If you spot a phishing phrase in the wild
that the tool does not catch, you can add it yourself in about a minute. Open
`js/patterns.js` in any text editor, find the rule you want to extend, and add a
line to its `patterns` list.

For example, this is a real rule from the file (shortened here):

```js
{
  id: 'URGENCY_PRESSURE',                 // must be unique
  category: 'urgency',                    // one of the six families
  weight: 8,                              // how strong is this sign on its own?
  title: 'Urgency and pressure language',
  what: 'Plain-English explanation of why this matters...',
  advice: 'What the reader should actually do...',
  patterns: [
    /\burgent(?:ly)?\b/i,
    /\bimmediately\b/i
    // <- add your new phrase here, with a comma after the line above
  ]
}
```

To add a phrase such as "your access will lapse", you would write:

```js
    /\byour access will lapse\b/i,
```

A few things worth knowing:

- The letters `\b` mean "word boundary", so `\burgent\b` matches the word "urgent"
  but not "urgently". Both forms are usually worth having.
- The `/i` at the end means the match ignores capital letters.
- If your new phrase turns out to cause false alarms, add it to the rule's
  `guards` list instead. A guard cancels a match - that is how the tool avoids
  flagging a genuine bank email that says "we will *never* ask you to enter your
  password".
- After any change, run the tests (below). If you have accidentally made a rule
  fire on the legitimate example email, the tests will tell you straight away.

You can also change any `weight` to reflect how serious you think a sign is. The
scale used throughout is 25 = very strong on its own, 15–20 = strong, 8–12 = worth
noticing, 5–7 = weak, 0 = shown but never scored.

---

## Testing

There are two sets of automated checks, and neither of them needs anything
installed except Node.js (which is only a convenience for development - the
website itself needs nothing but a browser).

```bash
node tests/run-tests.js        # the engine: 56 checks
node tests/run-ui-tests.js     # the interface: 8 checks, no browser needed
```

Or open `tests/self-test.html` in your browser to watch the same engine checks run
on your own machine. (It is also linked from the footer of the page.)

What they check:

- **The six demonstration emails produce the results the page claims.** Including
  the legitimate one scoring exactly zero, and the exact set of warning signs each
  one triggers - so a new rule that starts firing on ordinary mail fails loudly.
- **The scoring arithmetic**, including the documented examples (25 → 25,
  three 25s → 58) and the fact that twenty weak signals cannot reach 100.
- **Every individual warning sign**, one check per trick, including the cases
  where a rule must stay silent (genuine advice about never sharing a code).
- **That the engine never invents an authentication result** when no headers were
  pasted, and that observations are never scored.
- **Robustness**: empty input, huge input, emoji, broken HTML, right-to-left
  override characters, null bytes, and wrongly typed input - never crashing, and
  always returning a score between 0 and 100.
- **Privacy**: that no shipped file contains a network call or any tracking code,
  that the page loads nothing from outside the project, and that the
  `Content-Security-Policy` really does forbid outbound connections.
- **That pasted HTML can never become live markup in the report.** A phishing
  analyser is handed hostile input by design; this check proves that a pasted
  `<img onerror=...>` stays as harmless text.
---

## What each file is

```
index.html                 the page itself - the whole application
css/style.css              all the styling, with the colours defined at the top
js/patterns.js             THE RULEBOOK: every warning sign, its weight, its
                           explanation and its advice
js/analyzer.js             THE ENGINE: applies the rulebook and calculates the
                           score. Contains nothing about the screen, so it can be
                           tested on its own
js/samples.js              the six fictional demonstration emails
js/app.js                  THE INTERFACE: connects the text and the engine to
                           the page
favicon.svg                the little shield in the browser tab
tests/test-cases.js        the shared checks (engine, safety wording, robustness,
                           privacy) used by both test runners
tests/run-tests.js         runs those checks from the command line
tests/run-ui-tests.js      runs the interface checks, without a browser
tests/dom-stub.js          a tiny stand-in for the browser, so the interface can
                           be tested in plain Node.js
tests/run-in-browser.js    shows the results on the self-test page
tests/self-test.html       the self-test page, linked from the footer
```

Three design decisions are worth explaining, because they are the reason the code
looks the way it does:

1. **The rulebook is separated from the engine.** You can edit phishing knowledge
   without touching any machinery. This is the file to play with.
2. **The engine is separated from the screen.** `analyzer.js` knows nothing about
   buttons or colours, which is what makes it possible to test it thoroughly and
   to prove it cannot make a network request.
3. **Everything is written as plain, old-fashioned script files.** No modules, no
   bundler, no package manager, no build step. That is why you can double-click
   `index.html` and it simply works, and why this project will still run in ten
   years without being updated.

---

## Honest limitations

This tool reads text. That is both its strength and its limit.

- **It cannot open or inspect attachments.** It only reads file names and the type
  the email claims a file is. A real `.pdf` full of links is invisible to it.
- **It cannot check a domain's age, reputation or certificates.** It has no
  internet access, by design, so it cannot ask "was this domain registered last
  week?" - which is one of the strongest signals available in practice.
- **Its brand list is short and hand-written.** A link to a fake domain of a
  company not on that list will not be flagged as a brand imitation.
- **It cannot see through images.** Phishing that puts its message in a picture
  is invisible to text analysis.
- **It has no idea what is normal for you.** An invoice from your actual supplier
  will still be flagged, and a perfectly-crafted attack against you personally
  may score zero.
- **Header checks need the headers.** Without them, SPF, DKIM and DMARC are simply
  reported as unavailable. The tool never guesses.
- **It reads the first SPF/DKIM/DMARC result it finds.** Genuine forwarded mail can
  fail SPF, and some mail systems strip the signature line while keeping the
  verdict - both are noted in the explanations rather than hidden.

Because of all of this, the tool says the same thing in the interface, in every
report, and in the footer: **it identifies warning signs, it does not determine
whether an email is malicious, and you should never click a link or open an
attachment in order to test it.** Verify important messages independently, using
an organisation's official website or app, or a phone number you already know.

---

## Design and accessibility notes

- Dark "operations console" theme by default, with a light theme that follows your
  system preference and a toggle in the header.
- **Colour is never the only signal.** Every result is also spelled out in words
  and marked with a shape, so it still makes sense in greyscale or to a visitor
  who cannot distinguish the colours.
- The score is drawn as a hand-written SVG circle - no chart library.
- Works from a small phone upwards; the layout reflows rather than shrinking.
- Real keyboard support: a skip link, visible focus outlines, `Ctrl`/`Cmd` +
  `Enter` to analyse, and expandable sections that respond to the keyboard.
- Respects the operating system's "reduce motion" setting, and prints sensibly if
  you want the report on paper.
- Every warning sign, category and statistic is read out with its own explanation,
  so a screen reader hears the reasoning rather than just a number.

---

## If you want to take this further

The natural next steps, roughly in order of difficulty:

1. **Add rules from real phishing you receive.** Use the reporting address your
   employer or mail provider offers, collect the wording, and add the phrases.
   Run the tests each time and watch that the legitimate example still scores zero.
2. **Build a second, harder legitimate example** - a real-style marketing email
   full of urgency - and tune the weights until it lands in *Low Risk* without
   losing the genuine signals. That tension is the whole craft of detection.
3. **Add an indicator with a `test` function** rather than a phrase list. The URL
   rules in `js/patterns.js` show the pattern: a small function that receives one
   parsed link and decides.
4. **Write your own scoring model** and compare it with this one on the six
   examples. If yours is better, you will have learned something real about
   detection engineering.


