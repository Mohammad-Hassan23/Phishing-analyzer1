/* =========================================================================
   Phishing Email Analyser - js/patterns.js
   -------------------------------------------------------------------------
   THIS FILE IS THE RULEBOOK.

   Every warning sign the analyser knows about lives in this one file, and
   nothing in here talks to the network. If you want to teach the analyser a
   new trick later, this is the only file you need to edit:

     1. Add a keyword or phrase to an existing rule, or
     2. Copy a whole rule block, give it a new "id", and change the details.

   Rule anatomy (one rule = one warning sign):

     id      A unique short name. Never reuse an id.
     category Which family it belongs to (see CATEGORIES below).
     weight  Its point value, 0-100, meaning: "how strongly does this single
             warning sign, on its own, suggest phishing?"
             Guidelines used throughout this file:
               25    = on its own, a very strong sign of an attack
               15-20 = strong
               8-12  = worth noticing
               5-7   = weak, only meaningful in combination with others
               0     = informational only (shown in the report, never scored)
     title   The short label the visitor sees.
     what    Plain-English explanation of WHY this matters.
     advice  What the reader should actually do about it.
     patterns A list of text patterns to search for. These are "regular
             expressions" - a compact way of describing text to match. For
             example,
               /phish/i      contains "phish", ignoring capital letters
               /\bphish\b/i the word "phish" (\b = word boundary)
               /pay(ment)?/i "pay" or "payment"
     guards  Optional. "False alarm" patterns. If a match also matches a
             guard, that match is discarded. Example: an email saying
             "never share your verification code" is good advice, not an
             attack - so that wording is guarded.
     maxEvidence Optional cap on how many examples we quote back to the user.

   Patterns are matched against a "normalised" copy of the email (lowercased,
   whitespace tidied, curly quotes straightened, invisible zero-width
   characters removed) so trivial tricks do not help an attacker.
   ========================================================================= */

(function (root) {
  'use strict';

  const PEA = (root.PEA = root.PEA || {});

  /* -----------------------------------------------------------------------
     The six families of warning sign, used for the category breakdown.
     "icon" is inline SVG markup written by hand here - never anything typed
     by a visitor. The viewbox is 24x24 and the icons are drawn with strokes.
     --------------------------------------------------------------------- */
  const CATEGORIES = [
    {
      id: 'urgency',
      label: 'Urgency & Pressure',
      blurb: 'Language designed to rush you past your own judgement.',
      icon: '<path d="M13 2 4 14h6l-1 8 9-12h-6z"/>'
    },
    {
      id: 'credentials',
      label: 'Credentials & Identity',
      blurb: 'Attempts to obtain logins, codes or personal details.',
      icon: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M7.5 10V7a4.5 4.5 0 0 1 9 0v3"/>'
    },
    {
      id: 'money',
      label: 'Money & Payment',
      blurb: 'Attempts to move money, or to change where money goes.',
      icon: '<rect x="2" y="6" width="20" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 12h.01M18 12h.01"/>'
    },
    {
      id: 'links',
      label: 'Links & Domains',
      blurb: 'Where the links really go, and what is hidden inside them.',
      icon: '<path d="M10.5 13.5a4.5 4.5 0 0 0 6.4.4l2-2a4.5 4.5 0 0 0-6.4-6.4l-1 1"/><path d="M13.5 10.5a4.5 4.5 0 0 0-6.4-.4l-2 2a4.5 4.5 0 0 0 6.4 6.4l1-1"/>'
    },
    {
      id: 'attachments',
      label: 'Attachments & Macros',
      blurb: 'Files that can run code on your device when opened.',
      icon: '<path d="M21 12.5 12.6 20.9a5 5 0 0 1-7.1-7.1l8.5-8.5a3.4 3.4 0 0 1 4.8 4.8l-8.5 8.5a1.8 1.8 0 0 1-2.5-2.5l7.8-7.8"/>'
    },
    {
      id: 'authenticity',
      label: 'Sender Authenticity',
      blurb: 'Whether the sender is really who they claim to be.',
      icon: '<path d="M12 2.5 4.5 5.5v5.5c0 4.8 3.2 8.9 7.5 10.5 4.3-1.6 7.5-5.7 7.5-10.5V5.5z"/><path d="M8.8 11.8l2.4 2.4 4.4-4.8"/>'
    }
  ];

  /* -----------------------------------------------------------------------
     The analyser is strictly offline, so it cannot ask the internet "is this
     the real Microsoft domain?". Instead it carries a small, hand-checked
     list of well-known official domains. This is a deliberate limitation, and
     the interface says so: a domain that is not on this list is reported as
     "not a domain we recognise for that brand", never as "definitely fake".
     --------------------------------------------------------------------- */
  const BRAND_OFFICIAL_DOMAINS = {
    microsoft: ['microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'microsoft365.com', 'live.com', 'outlook.com', 'sharepoint.com', 'onmicrosoft.com', 'windows.net', 'azure.com', 'msn.com', 'hotmail.com'],
    paypal: ['paypal.com', 'paypal.me', 'paypal-community.com'],
    apple: ['apple.com', 'icloud.com'],
    amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazonaws.com', 'a.co', 'amzn.to'],
    netflix: ['netflix.com'],
    google: ['google.com', 'gmail.com', 'youtube.com', 'google.co.uk', 'googleapis.com', 'withgoogle.com'],
    dhl: ['dhl.com', 'dhl.de', 'dhlparcel.co.uk'],
    fedex: ['fedex.com'],
    ups: ['ups.com'],
    usps: ['usps.com'],
    royalmail: ['royalmail.com'],
    evri: ['evri.com', 'myhermes.co.uk'],
    hermes: ['hermesworld.com', 'myhermes.co.uk'],
    dpd: ['dpd.com', 'dpd.co.uk', 'dpdlocal.co.uk'],
    linkedin: ['linkedin.com', 'lnkd.in'],
    dropbox: ['dropbox.com'],
    adobe: ['adobe.com'],
    docusign: ['docusign.com', 'docusign.net'],
    salesforce: ['salesforce.com'],
    atlassian: ['atlassian.com', 'atlassian.net'],
    github: ['github.com', 'githubusercontent.com'],
    slack: ['slack.com'],
    zoom: ['zoom.us'],
    stripe: ['stripe.com'],
    hsbc: ['hsbc.com', 'hsbc.co.uk'],
    barclays: ['barclays.co.uk', 'barclays.com'],
    natwest: ['natwest.com'],
    lloyds: ['lloydsbank.com', 'lloydsbank.co.uk'],
    santander: ['santander.com', 'santander.co.uk'],
    chase: ['chase.com'],
    bankofamerica: ['bankofamerica.com'],
    wellsfargo: ['wellsfargo.com'],
    citibank: ['citibank.com', 'citi.com'],
    coinbase: ['coinbase.com'],
    binance: ['binance.com'],
    hmrc: ['hmrc.gov.uk', 'gov.uk', 'tax.service.gov.uk'],
    irs: ['irs.gov']
  };

  /* Free consumer mail providers. Never suspicious on their own, but a
     corporate-looking sender whose replies go to a free mailbox is a classic
     business-email-compromise pattern. */
  const FREE_MAIL_DOMAINS = ['gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'outlook.com', 'hotmail.com', 'hotmail.co.uk', 'live.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com', 'zoho.com', 'yandex.com', 'icloud.com', 'me.com', 'tutanota.com'];

  /* Well-known link shorteners. A shortener is not proof of an attack, but it
     hides the true destination, which is why phishing uses them so heavily. */
  const SHORTENER_HOSTS = ['bit.ly', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'goo.gl', 'rebrand.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'trib.al', 'lnkd.in', 's.id', 'bl.ink', 'short.io', 'tiny.cc', 'adf.ly', 'bc.vc', 'pt.ms'];

  /* TLDs (the part after the last dot) that appear disproportionately in
     phishing campaigns, usually because they are cheap or given away free.
     Being on this list is a weak signal, never a verdict. */
  const RISKY_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link', 'work', 'loan', 'review', 'country', 'stream', 'download', 'racing', 'party', 'science', 'rest', 'buzz', 'monster', 'quest', 'cyou', 'sbs', 'bar', 'shop', 'support', 'live', 'digital', 'online', 'site', 'website', 'space', 'host', 'zip', 'mov'];

  /* File extensions grouped by how dangerous they are if opened. */
  const EXECUTABLE_EXTENSIONS = ['exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'cpl', 'dll', 'reg', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'lnk', 'ps1', 'psm1', 'jar', 'apk', 'app', 'iso', 'img', 'vhd', 'vhdx', 'ade', 'adp', 'msp', 'msc'];

  /* Office files that are allowed to carry macros (little programmes). */
  const MACRO_EXTENSIONS = ['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'sldm'];

  const ARCHIVE_EXTENSIONS = ['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'bz2', 'cab', 'ace', 'lzh'];

  /* Attachments that are really web pages. They can host a fake login form
     entirely offline, on the victim's own machine. */
  const WEBPAGE_EXTENSIONS = ['html', 'htm', 'xhtml', 'svg', 'mht', 'mhtml', 'hta'];

  /* Ordinary, everyday document extensions. Used to spot "double extension"
     names such as invoice.pdf.exe, where the extension that matters is the
     last one. */
  const INNOCENT_EXTENSIONS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tif', 'tiff', 'webp', 'mp3', 'mp4', 'wav', 'avi', 'mov', 'bak', 'dat', 'p7s', 'xml'];

  PEA.patterns = {
    CATEGORIES: CATEGORIES,
    BRAND_OFFICIAL_DOMAINS: BRAND_OFFICIAL_DOMAINS,
    FREE_MAIL_DOMAINS: FREE_MAIL_DOMAINS,
    SHORTENER_HOSTS: SHORTENER_HOSTS,
    RISKY_TLDS: RISKY_TLDS,
    EXECUTABLE_EXTENSIONS: EXECUTABLE_EXTENSIONS,
    MACRO_EXTENSIONS: MACRO_EXTENSIONS,
    ARCHIVE_EXTENSIONS: ARCHIVE_EXTENSIONS,
    WEBPAGE_EXTENSIONS: WEBPAGE_EXTENSIONS,
    INNOCENT_EXTENSIONS: INNOCENT_EXTENSIONS,
    /* Filled in below. */
    TEXT_RULES: [],
    URL_RULES: [],
    ATTACHMENT_RULES: [],
    HEADER_RULES: []
  };

  const R = PEA.patterns;

  /* =======================================================================
     PART 1 - TEXT RULES
     These are run over the email body (and over the subject line if you paste
     it in as part of the text).
     ===================================================================== */

  R.TEXT_RULES.push(
    {
      id: 'URGENCY_PRESSURE',
      category: 'urgency',
      weight: 8,
      title: 'Urgency and pressure language',
      what: 'Phishing emails try to make you act before you think. A deadline measured in hours, or words like "immediately" and "final warning", are there to stop you reading carefully, checking the sender, or asking a colleague.',
      advice: 'Treat a deadline as a warning sign in itself. Slow down, and verify the message through a channel you chose, not one the email gave you.',
      maxEvidence: 5,
      patterns: [
        /\burgent(?:ly)?\b/i,
        /\bimmediately\b/i,
        /\bat once\b/i,
        /\bact (?:now|fast|today)\b/i,
        /\baction (?:is )?required\b/i,
        /\bimmediate action\b/i,
        /\bwithin (?:the next )?\d+ ?(?:minutes|hours|days|working hours)\b/i,
        /\b(?:final|last) (?:warning|notice|reminder|chance)\b/i,
        /\btime[ -]?sensitive\b/i,
        /\bdo not (?:delay|ignore|delete)\b/i,
        /\bexpires? (?:today|tonight|soon|in \d+ (?:hours|days))\b/i,
        /\b(?:today|tonight) only\b/i,
        /\b24 hours\b/i,
        /\brespond (?:immediately|now|today|within)\b/i,
        /\byour (?:prompt )?(?:response|reply|action) is (?:required|needed|requested)\b/i,
        /\bas soon as possible\b/i,
        /\bdon'?t wait\b/i,
        /\basap\b/i
      ],
      guards: [
        /\bno (?:urgent|rush|hurry)\b/i
      ]
    },
    {
      id: 'THREAT_ACCOUNT_SUSPENSION',
      category: 'urgency',
      weight: 15,
      title: 'Threatens to suspend, close or lock your account',
      what: 'Threatening to take something away (access, money, a service) is the most common way phishing creates fear. Real providers rarely announce a suspension by email with a link, and they do not give you a countdown to fix it.',
      advice: 'Do not follow the email\'s link to "prevent" the loss. Open the service\'s official app or type its address into your browser yourself, and check whether anything is actually wrong.',
      maxEvidence: 4,
      patterns: [
        /\bsuspend(?:ed|sion|ing)?\b/i,
        /\b(?:account|access|service|profile|subscription) (?:has been|have been|will be|is|was|may be|might be) (?:locked|closed|disabled|deactivated|terminated|restricted|blocked|frozen|suspended)\b/i,
        /\b(?:locked|closed|disabled|deactivated|terminated|restricted|blocked|suspended|frozen) (?:your |the )?(?:account|access|service|profile|subscription)\b/i,
        /\bpermanently (?:closed|deleted|disabled|suspended|removed|blocked)\b/i,
        /\bwill result in (?:the )?(?:closure|suspension|termination|deletion|loss)\b/i,
        /\bterminate (?:your |the )?(?:account|service|access|subscription)\b/i,
        /\bfailure to (?:respond|comply|verify|confirm|act)\b/i,
        /\bunauthori[sz]ed (?:login|access|activity|sign-?in|transaction) (?:attempt|detected|was|has been|is)\b/i,
        /\blegal action\b/i,
        /\blaw enforcement\b/i,
        /\b(?:final|last) (?:warning|notice) before\b/i
      ],
      guards: [
        /\byour (?:account|data) (?:is|remains) (?:safe|secure)\b/i
      ]
    }
  );

  R.TEXT_RULES.push(
    {
      id: 'REQUEST_PASSWORD',
      category: 'credentials',
      weight: 25,
      title: 'Asks for your password',
      what: 'No legitimate organisation asks you to type, confirm or send your password by email. Not a bank, not Microsoft, not your IT department, not your boss. If an email asks, treat it as an attack with near certainty.',
      advice: 'Never reply with your password. If the message claims to be from a service you use, open that service from your own bookmark or app and check there. If you already typed it in, change that password now, anywhere you have reused it.',
      maxEvidence: 3,
      patterns: [
        /\b(?:enter|provide|confirm|verify|update|re-?enter|type|submit|send|share|give|supply)\b[^.\n]{0,45}\bpassword\b/i,
        /\bpassword\b[^.\n]{0,45}\b(?:has expired|expired|expiring|will expire|is due)\b/i,
        /\b(?:your |existing |current )?password (?:below|here|now|is required)\b/i,
        /\bwe need your (?:password|credentials|login details)\b/i,
        /\b(?:verify|confirm) (?:your identity|it'?s you|your details)[^.\n]{0,45}\bpassword\b/i,
        /\bupdate your (?:account )?password (?:now|here|below|immediately)\b/i,
        /\busername and password\b/i
      ],
      guards: [
        /\bnever (?:share|send|give|disclose|reveal)\b/i,
        /\bdo not (?:share|send|give|disclose|reveal)\b/i,
        /\b(?:we|no one) (?:will|would) never ask\b/i,
        /\bpassword (?:change|reset) (?:successful|complete)\b/i
      ]
    },
    {
      id: 'REQUEST_MFA_CODE',
      category: 'credentials',
      weight: 25,
      title: 'Asks for a verification code (MFA / one-time code)',
      what: 'This is the fastest-growing attack of all. The criminal already has your password and is trying to log in; they need the one-time code that your bank or workplace just sent to YOU. If you hand it over, you let them straight into your account, and your multi-factor protection stops protecting you.',
      advice: 'Never share a code with anyone, no matter who the message claims to be from. A one-time code is for you to type into the real website or app, and nothing else.',
      maxEvidence: 3,
      patterns: [
        /\b(?:share|send|give|tell|provide|forward|confirm|enter|reply with|paste|type|text|read)\b[^.\n]{0,60}\b(?:one[ -]?time|verification|authentication|security|confirmation|otp|2fa|mfa|sms|login)\b[^.\n]{0,25}\b(?:code|passcode|pin|token|number)\b/i,
        /\b(?:one[ -]?time|verification|authentication|security|confirmation|otp|2fa|mfa|login)\b[^.\n]{0,25}\b(?:code|passcode|pin|token)\b[^.\n]{0,60}\b(?:to us|to me|back to (?:us|me)|repl(?:y|ies)|share|send|confirm|approve|verify)\b/i,
        /\b(?:code|number|pin) (?:we|that we|i) (?:just )?(?:sent|texted|emailed|generated)[^.\n]{0,60}\b(?:share|send|give|tell|confirm|enter|forward|read)\b/i,
        /\b(?:read|give|send) (?:me|us) the (?:code|number|pin)\b/i,
        /\b(?:approve|confirm) the (?:sign-?in|login|push) request\b/i
      ],
      guards: [
        /\bnever (?:share|give|send|disclose)\b/i,
        /\bdo not (?:share|give|send|disclose|reveal)\b/i,
        /\bdon'?t share\b/i,
        /\b(?:we|no one) (?:will|would) never ask\b/i,
        /\bif you did not request\b/i
      ]
    },
    {
      id: 'CREDENTIAL_HARVESTING',
      category: 'credentials',
      weight: 18,
      title: 'Asks you to verify or confirm your account details',
      what: '"Verify your account", "confirm your identity", "your session has expired, sign in again" - these phrases exist to move you onto a fake login page that copies whatever you type. Genuine services usually just act, or ask you to come back later; they rarely demand confirmation of details they already hold.',
      advice: 'Go to the website by typing its address yourself, or through your own bookmark or app. Do not reach it through the email.',
      maxEvidence: 4,
      patterns: [
        /\b(?:verify|confirm|validate|update|restore|reactivate|unlock|secure) your (?:account|identity|details|information|billing|payment|profile|credentials|email|address|subscription|access|login)\b/i,
        /\bsign ?in to (?:confirm|verify|restore|update|continue|unlock|review)\b/i,
        /\blog ?in (?:here|now|below|to (?:verify|confirm|continue|restore|unlock))\b/i,
        /\bclick here to (?:verify|confirm|log ?in|sign ?in|restore|unlock|secure|update|validate)\b/i,
        /\bfailure to (?:verify|confirm|update)\b/i,
        /\bconfirm your (?:identity|account|details|password|information|billing)\b/i,
        /\bkeep your account (?:secure|active|safe)\b/i,
        /\bfor (?:security|verification) purposes\b[^.\n]{0,40}\b(?:click|confirm|verify|log ?in|sign ?in|update)\b/i,
        /\byour (?:session|access|link) (?:has )?expired\b/i,
        /\benter your (?:user ?name|email|login|account number) (?:and|below|here)\b/i
      ]
    }
  );

  R.TEXT_RULES.push(
    {
      id: 'CHANGE_BANK_DETAILS',
      category: 'money',
      weight: 25,
      title: 'Asks you to change bank or payment details',
      what: 'A request to pay into a different account is the single most expensive form of email fraud (business email compromise). The criminal impersonates a supplier, landlord or colleague and redirects a real payment into their own account.',
      advice: 'Never change payment details based on an email alone. Telephone the organisation or person on a number you already had, or that you look up independently, and read the new details back to them. Confirm with a second person if you can.',
      maxEvidence: 3,
      patterns: [
        /\b(?:new|updated?|revised|changed?|correct) (?:bank|banking|payment|remittance|wire|transfer|account|payout|direct deposit) (?:details|information|instructions|account|numbers?|info)\b/i,
        /\bchange of (?:bank|banking|account) (?:details|information)\b/i,
        /\bnew (?:sort code|iban|bic|swift|account number|routing number|account)\b/i,
        /\bplease (?:use|send (?:it )?to|pay (?:in)?to) the (?:new|updated|following|attached) (?:account|bank|details)\b/i,
        /\b(?:payment|bank|banking) details (?:have|has) changed\b/i,
        /\bupdate (?:our|the|my) (?:payment|bank|banking|remittance) (?:details|information)\b/i,
        /\b(?:remit|pay|transfer) (?:the )?(?:funds|payment|money|balance) (?:to|into) (?:the )?(?:account|new account)\b/i,
        /\bour bank account (?:has |details have )?(?:changed|been updated)\b/i,
        /\b(?:bank|banking|payment|remittance|account|wire|payout) details (?:have|has|had) (?:been )?(?:changed|updated|amended)\b/i,
        /\b(?:bank|banking|payment|account) details (?:are|is) (?:below|as follows|attached)\b/i
      ],
      guards: [
        /\b(?:call|telephone|phone|verify) (?:us|me|before|to confirm)\b/i
      ]
    },
    {
      id: 'PAYMENT_GIFTCARD_REQUEST',
      category: 'money',
      weight: 20,
      title: 'Requests payment, gift cards or cryptocurrency',
      what: 'Gift cards, wire transfers and cryptocurrency have two things in common: they are hard to trace, and they cannot be reversed. That is exactly why criminals ask for them, and why a request for them in an email is treated as highly suspicious.',
      advice: 'Do not buy gift cards or send money because an email asked. No genuine organisation, IT department or executive requests payment by gift card or crypto, ever.',
      maxEvidence: 4,
      patterns: [
        /\bgift ?cards?\b/i,
        /\b(?:itunes|apple|google play|amazon|steam|netflix|ebay) (?:card|gift ?card|voucher|credit)\b/i,
        /\b(?:scratch|reveal) (?:off|the) (?:back|panel|code)\b/i,
        /\b(?:wire|bank) transfer\b/i,
        /\b(?:bitcoin|btc|ethereum|eth|crypto|usdt|wallet address)\b/i,
        /\bremit (?:the )?(?:payment|funds|amount)\b/i,
        /\bsettle (?:the )?(?:outstanding )?(?:invoice|balance|amount)\b/i,
        /\bbank transfer details (?:are|below|attached)\b/i,
        /\b(?:purchase|buy|send) (?:me |us )?(?:some )?(?:gift ?cards?|vouchers?)\b/i,
        /\bpayment (?:of|amount of) [\u00a3$€]\s?\d/i
      ]
    },
    {
      id: 'UNEXPECTED_INVOICE',
      category: 'money',
      weight: 10,
      title: 'Unexpected invoice or payment demand',
      what: 'An invoice you were not expecting is a favourite starting point, because invoices feel official and people pay them without asking questions. The attached "invoice" is often the actual attack, or the account details inside it belong to the criminal.',
      advice: 'Match any invoice against a purchase order or a person who can confirm it, and check the bank details against the ones you already hold. Do not open the attachment to find out what it is.',
      maxEvidence: 4,
      patterns: [
        /\b(?:see|find|please find|kindly find) (?:the )?attached (?:invoice|statement|remittance|bill)\b/i,
        /\binvoice (?:is )?attached\b/i,
        /\b(?:attached|enclosed) (?:is|are) (?:the )?(?:invoice|statement|bill|purchase order)/i,
        /\boutstanding (?:balance|payment|invoice|amount|debt)\b/i,
        /\boverdue (?:invoice|payment|balance|account|amount)\b/i,
        /\bunpaid (?:invoice|balance|account)\b/i,
        /\bpayment (?:is )?(?:now )?(?:due|overdue)\b/i,
        /\binvoice\s*#?\s*\d{3,}/i,
        /\bremittance advice\b/i,
        /\bpurchase order (?:number|no|#)\b/i,
        /\bthe attached (?:invoice|statement|bill|remittance)\b/i,
        /\b(?:invoice|statement|bill|remittance)\b[^.\n]{0,25}\b(?:attached|enclosed)\b/i,
        /\b(?:small|minor|outstanding) (?:fee|charge|payment|amount)\b/i,
        /\b(?:redelivery|handling|customs|clearance|release|processing|administrative) fee\b/i
      ]
    }
  );

  R.TEXT_RULES.push(
    {
      id: 'ENABLE_MACROS_LANGUAGE',
      category: 'attachments',
      weight: 25,
      title: 'Asks you to enable macros or content',
      what: '"Enable macros", "enable editing", "click enable content" - macros are small programmes embedded in Office documents. Asking a reader to switch them on is how a document becomes an attack: the moment macros run, the code runs as you. Normal documents do not need this, and modern Office blocks it by default precisely because it is so abused.',
      advice: 'Never enable macros or content in a document that arrived by email. If a real colleague needs you to use macros, they can tell you in person and share the file through a trusted system.',
      maxEvidence: 3,
      patterns: [
        /\benable (?:macros|editing|content|active content|external content)\b/i,
        /\bmacros? (?:must|need to|should) be enabled\b/i,
        /\bclick (?:enable|allow|yes) (?:content|editing|macros|when prompted)\b/i,
        /\bif the (?:document|file|attachment) (?:does not|doesn'?t) (?:display|open|show)\b/i,
        /\bcontent is (?:blocked|disabled|turned off)\b/i,
        /\bprotected view\b/i,
        /\byou must (?:first )?(?:enable|allow)\b[^.\n]{0,30}\b(?:macro|content|editing)\b/i
      ]
    },
    {
      id: 'IMPERSONATION_LANGUAGE',
      category: 'credentials',
      weight: 8,
      title: 'Impersonation language',
      what: 'Claims to come from a named department, an executive, or an authority figure, and often asks for secrecy or speed. Authority plus secrecy is a combination that real organisations almost never use in email.',
      advice: 'Verify unusual requests by contacting the person or department using a number or address you already know. Never reply to the email to "confirm" who they are.',
      maxEvidence: 4,
      patterns: [
        /\bthis is the (?:it|help ?desk|helpdesk|support|security|payroll|hr|human resources|billing) (?:department|team|desk)\b/i,
        /\b(?:it|help ?desk|security) (?:department|team|desk) (?:here|requires|has detected)\b/i,
        /\bon behalf of\b/i,
        /\bfrom the (?:office|desk) of\b/i,
        /\b(?:ceo|cfo|cto|managing director|chief executive|director|your boss)\b[^.\n]{0,40}\b(?:asked|requested|needs|would like|requires|wants)\b/i,
        /\b(?:hi|hello|hey)[, ]+(?:this is|i am|i'?m) (?:your )?(?:it|ceo|manager|boss|director|landlord)\b/i,
        /\bdo not (?:discuss|tell|inform|mention (?:this )?to)\b[^.\n]{0,20}\b(?:anyone|anybody|any one|others|the team|colleagues)\b/i,
        /\bkeep (?:this|it) (?:confidential|between us|quiet|private)\b/i,
        /\bconfidential (?:matter|request|business)\b/i,
        /\bthis (?:request|message) is (?:urgent|confidential|private)\b/i
      ]
    },
    {
      id: 'SECRECY_AND_AUTHORITY',
      category: 'credentials',
      weight: 12,
      title: 'Combines a request for secrecy with authority',
      what: 'When a message tells you to keep something from colleagues AND invokes a senior person or a security team, you are looking at the classic shape of a impersonation attack. Legitimate business requests survive being discussed out loud; fraudulent ones cannot.',
      advice: 'Talk to a colleague or your manager before acting, especially where money is involved. Genuine business does not need to be a secret.',
      maxEvidence: 3,
      patterns: [
        /\bconfidential\b[^.\n]{0,60}\b(?:payment|transfer|invoice|gift ?card|urgent request|matter)\b/i,
        /\b(?:do not|don'?t|please don'?t) (?:call|telephone|phone|mention)\b[^.\n]{0,40}\b(?:confirm|anyone|anybody|colleagues)\b/i,
        /\bkeep this (?:between us|confidential|quiet)\b/i,
        /\bi (?:cannot|can'?t) (?:talk|discuss|speak)\b[^.\n]{0,40}\b(?:now|right now|at the moment|about this)\b/i,
        /\bunavailable (?:in meetings|for calls|by phone)\b[^.\n]{0,60}\b(?:email|transfer|payment|gift)\b/i,
        /\b(?:i'?m|i am|will be) (?:in|at) (?:meetings?|a meeting|conference|all-?day)\b/i,
        /\b(?:email|whats?app|text message|texting) (?:is|works) (?:best|better)\b/i
      ]
    }
  );

  R.TEXT_RULES.push(
    {
      id: 'GENERIC_GREETING',
      category: 'credentials',
      weight: 5,
      title: 'Generic greeting or no greeting at all',
      what: 'A company you actually have an account with usually knows your name. "Dear Customer" and "Dear Sir/Madam" are signs the message was sent to a bought list, or that the sender does not know who you are. On its own this proves nothing - plenty of legitimate marketing does the same - so it only carries a few points.',
      advice: 'Note it as one small clue among many, and never let it be the only reason you trust or distrust a message.',
      maxEvidence: 2,
      patterns: [
        /^\s*(?:dear|hello|hi|greetings)[, ]+(?:customer|client|user|valued (?:customer|client|user)|member|account holder|applicant|sir|madam|sir\/madam|sir or madam|all)\b/im,
        /^\s*(?:dear|hello|greetings)\s*[,!.]\s*$/im,
        /\bvalued customer\b/i,
        /\bdear (?:account|email) (?:holder|user|owner)\b/i
      ]
    },
    {
      id: 'OBFUSCATED_TEXT',
      category: 'credentials',
      weight: 8,
      title: 'Text is deliberately disguised',
      what: 'The message contains invisible characters, or letters spaced out one by one, or unusual lettering used to smuggle hostile wording past filters and past readers skimming quickly. Ordinary email has no reason to do this.',
      advice: 'Treat disguised text as a strong hint that the sender is hiding something. Do not act on the message; report it.',
      maxEvidence: 3,
      patterns: [
        /(?:\b[a-z]\b[ \t]+){4,}[a-z]\b/i
      ]
    },
    {
      id: 'SECURITY_ALERT_WORDING',
      category: 'authenticity',
      weight: 0,
      title: 'Uses security-alert wording',
      what: 'This is an observation, not a scored warning sign, and it is worth understanding why. Genuine providers do send "new sign-in" and "unusual activity" alerts - and phishing copies exactly that wording. The wording alone tells you nothing about whether the message is real; what matters is where the links go, who it really came from, and whether anything is being asked of you.',
      advice: 'Do not use the presence of an alert as evidence either way. Check for the account activity by opening the service yourself rather than through this email.',
      maxEvidence: 3,
      patterns: [
        /\bsecurity alert\b/i,
        /\bunusual (?:sign-?in|login|activity|device)\b/i,
        /\bnew (?:sign-?in|login|device|browser) (?:detected|from|on)\b/i,
        /\bsuspicious (?:activity|sign-?in|login)\b/i,
        /\byour account (?:was|has been) accessed\b/i,
        /\bwe detected (?:a )?(?:new|an? unusual|a suspicious)\b/i
      ]
    }
  );

  /* =======================================================================
     SHARED HELPERS
     Small, pure functions used by the rule tests below and by the engine.
     They never touch the network - they only reason about text.
     ===================================================================== */

  /* Multi-part "public suffixes" such as co.uk, so that we can work out the
     registrable domain (the part someone actually had to register) without
     needing the full Public Suffix List. It is an approximation, and the
     report never presents it as more than one. */
  const MULTI_PART_SUFFIXES = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'com.br', 'com.mx', 'com.ar', 'com.co', 'com.tr', 'com.cn', 'com.hk', 'com.sg', 'com.my', 'com.tw', 'co.jp', 'co.kr', 'co.in', 'co.za', 'co.il', 'co.id', 'com.eg', 'com.sa', 'com.ua', 'com.pl', 'gov.in', 'nic.in', 'ac.in', 'org.in', 'co.th', 'com.ph', 'com.vn'];

  function hostLabels(host) {
    return String(host || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  }

  /* "support.account.mail.example.co.uk" -> "example.co.uk" */
  function registrableDomain(host) {
    const parts = hostLabels(host);
    if (parts.length <= 2) return parts.join('.');
    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.indexOf(lastTwo) !== -1 && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return lastTwo;
  }

  function topLevelDomain(host) {
    const parts = hostLabels(host);
    return parts.length ? parts[parts.length - 1] : '';
  }

  /* Words attackers commonly glue onto a brand name to build a convincing
     domain: "dhlparcel.example", "mydhl.example", "ups-secure.example". A
     short brand name is only treated as glued on when the remainder is one of
     these, which keeps "upsilon.example" from being flagged. */
  const BRAND_GLUE_WORDS = ['secure', 'security', 'verify', 'verification', 'confirm', 'login', 'signin', 'signon', 'account', 'accounts', 'support', 'service', 'services', 'billing', 'update', 'updates', 'tracking', 'track', 'delivery', 'deliveries', 'parcel', 'parcels', 'shipping', 'team', 'help', 'helpdesk', 'invoice', 'invoices', 'online', 'payment', 'payments', 'pay', 'my', 'the', 'mail', 'email', 'notice', 'alert', 'alerts', 'info', 'portal', 'center', 'centre', 'office', 'cloud', 'web', 'app', 'id', 'auth', 'sso'];

  /* Does one label of a hostname look like it is using a brand name? */
  function labelMatchesToken(label, token) {
    if (label === token) return true;
    if (label.indexOf(token + '-') === 0) return true;

    /* Note the -1 checks. "not found" is also -1, so without them a short
       brand name would appear to match a numeric label such as "192". */
    const hyphenBefore = label.lastIndexOf('-' + token);
    if (hyphenBefore !== -1 && hyphenBefore === label.length - token.length - 1) return true;

    if (new RegExp('^' + token + '[0-9]+$').test(label)) return true;

    if (label.indexOf(token) === 0) {
      const rest = label.slice(token.length);
      if (token.length >= 5) return true;
      if (BRAND_GLUE_WORDS.indexOf(rest) !== -1) return true;
    }

    const gluedAfter = label.lastIndexOf(token);
    if (gluedAfter !== -1 && gluedAfter === label.length - token.length) {
      const before = label.slice(0, gluedAfter);
      if (token.length >= 5) return true;
      if (BRAND_GLUE_WORDS.indexOf(before) !== -1) return true;
    }

    return false;
  }

  /* "micros0ft" and "paypa1" are the same brand name with a letter swapped for
     a lookalike digit. Undoing the usual substitutions lets us catch those
     character-substitution lookalikes as well as plain ones. */
  function deSubstitute(label) {
    return label
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/7/g, 't')
      .replace(/8/g, 'b')
      .replace(/9/g, 'g');
  }

  /* Does a hostname appear to use a brand name, without simply containing it
     inside an unrelated word? "ups.com" and "ups-tracking.example" mention
     "ups"; "groups.example" does not. Long brand names (5+ letters, such as
     "paypal" or "microsoft") are also allowed to be glued onto another word,
     because "paypalsecure.example" is exactly the kind of thing attackers
     buy. Short tokens must line up more precisely to avoid false alarms. */
  function hostMentionsBrand(host, token) {
    const lower = String(host || '').toLowerCase();
    if (!lower || !token) return false;
    return hostLabels(lower).some(function (label) {
      if (labelMatchesToken(label, token)) return true;
      if (token.length >= 4) {
        const plain = deSubstitute(label);
        if (plain !== label && labelMatchesToken(plain, token)) return true;
      }
      return false;
    });
  }

  /* Does the host genuinely belong to one of a brand's official domains? */
  function isOfficialBrandDomain(host, token) {
    const official = BRAND_OFFICIAL_DOMAINS[token] || [];
    const domains = hostLabels(host);
    return official.some(function (officialDomain) {
      const officialLabels = hostLabels(officialDomain);
      if (domains.length < officialLabels.length) return false;
      const tail = domains.slice(-officialLabels.length).join('.');
      return tail === officialDomain;
    });
  }

  function isIpv4(host) {
    const value = String(host || '').replace(/^\[|\]$/g, '');
    const parts = value.split('.');
    if (parts.length !== 4) return false;
    return parts.every(function (p) {
      return /^\d{1,3}$/.test(p) && Number(p) <= 255;
    });
  }

  function isIpv6(host) {
    const value = String(host || '').replace(/^\[|\]$/g, '');
    return value.indexOf(':') !== -1 && /^[0-9a-f:.]+$/i.test(value);
  }

  function extensionOf(filename) {
    const match = /\.([a-z0-9]{1,5})\s*$/i.exec(String(filename || '').trim());
    return match ? match[1].toLowerCase() : '';
  }

  PEA.helpers = {
    hostLabels: hostLabels,
    registrableDomain: registrableDomain,
    topLevelDomain: topLevelDomain,
    hostMentionsBrand: hostMentionsBrand,
    isOfficialBrandDomain: isOfficialBrandDomain,
    isIpv4: isIpv4,
    isIpv6: isIpv6,
    extensionOf: extensionOf,
    MULTI_PART_SUFFIXES: MULTI_PART_SUFFIXES
  };

  /* =======================================================================
     PART 2 - URL RULES
     Each rule receives one parsed link and returns either null (no problem)
     or a short note explaining what it saw. The engine groups the results,
     so one rule produces one finding listing every link that tripped it.
     ===================================================================== */

  R.URL_RULES.push(
    {
      id: 'URL_RAW_IP',
      category: 'links',
      weight: 20,
      title: 'Link points at a bare IP address',
      what: 'Reputable organisations publish a domain name such as example.com. A link that goes straight to a numeric address like 192.0.2.45 skips all of that: there is no company name to check, no certificate issued to anybody meaningful, and the address is usually a hacked server that will be gone in a week.',
      advice: 'Do not open it. If the message claims to come from a service you use, reach that service through your own bookmark or app instead.',
      test: function (u) {
        if (!u.isIp) return null;
        return 'Host is the bare IP address ' + u.hostname + (u.isIpv6 ? ' (IPv6)' : ' (IPv4)');
      }
    },
    {
      id: 'URL_SHORTENER',
      category: 'links',
      weight: 12,
      title: 'Link is hidden behind a URL shortener',
      what: 'A shortener replaces a long address with a short one so you cannot see where you are going until you are already there. Marketing teams use them legitimately, so this is not proof of anything on its own - but combined with a message you were not expecting, it is a common way to disguise a hostile destination.',
      advice: 'Do not click to "see where it goes". If you must know, expand the link using a service you already trust, or simply contact the sender another way.',
      test: function (u) {
        if (SHORTENER_HOSTS.indexOf(u.registrableDomain) === -1) return null;
        return u.hostname + ' is a link-shortening service, so the real destination is hidden';
      }
    },
    {
      id: 'URL_PUNYCODE_LOOKALIKE',
      category: 'links',
      weight: 15,
      title: 'Link uses an internationalised (lookalike) domain',
      what: 'The "xn--" in a hostname means the domain contains non-Latin characters. Attackers use this to build addresses that look identical to a real one on screen - for example a Cyrillic "a" in place of a Latin one - while being a completely different domain. Many real, legitimate sites use xn-- addresses too, so this is a strong hint rather than a verdict.',
      advice: 'Do not enter any credentials on a page reached this way. Compare the address very carefully, or navigate to the site from your own bookmark.',
      test: function (u) {
        if (u.hostname.indexOf('xn--') === -1) return null;
        return u.hostname + ' contains non-Latin characters (punycode), which is often used to imitate another domain';
      }
    },
    {
      id: 'URL_BRAND_MISMATCH',
      category: 'links',
      weight: 15,
      title: 'Link mentions a well-known brand on a domain that is not that brand\'s',
      what: 'This link has a famous company name inside it, but the domain was not registered by that company. "microsoft-account-verify.example-login.test" reads like Microsoft and belongs to somebody else entirely. Note the honesty here: the tool only knows a short hand-checked list of official domains, so it reports "not a domain we recognise for that brand" rather than "definitely fake".',
      advice: 'Reach the company through its official app or by typing its address yourself. Never trust a link just because the brand name appears inside it.',
      test: function (u) {
        /* A bare IP address has no brand name in it and its "parts" are just
           octets, so the brand and obfuscation checks below skip it. */
        if (u.isIp) return null;
        const tokens = Object.keys(BRAND_OFFICIAL_DOMAINS);
        for (let i = 0; i < tokens.length; i++) {
          const token = tokens[i];
          if (hostMentionsBrand(u.hostname, token) && !isOfficialBrandDomain(u.hostname, token)) {
            return u.hostname + ' mentions "' + token + '" but is not one of the domains we recognise as official for it';
          }
        }
        return null;
      }
    },
    {
      id: 'URL_USERINFO_TRICK',
      category: 'links',
      weight: 20,
      title: 'Link uses the "@" trick to disguise its real destination',
      what: 'In a web address, anything before an "@" is just a username and can be ignored - browsers jump straight to what comes after it. Attackers abuse this to write something like "https://www.yourbank.com@evil.example/login", which looks like your bank until you know to read right to left. Anything before the @ is decoration.',
      advice: 'Read the address from the right: the part immediately before the first single slash is the real destination. Do not enter any details on a page reached this way.',
      test: function (u) {
        if (!u.hasUserInfo) return null;
        return 'Everything before the "@" in ' + u.hostname + ' is decorative; the real host is ' + u.hostname;
      }
    }
  );

  R.URL_RULES.push(
    {
      id: 'URL_INSECURE_HTTP',
      category: 'links',
      weight: 5,
      title: 'Link is not using an encrypted connection (http://)',
      what: 'An "http://" address sends data in the clear, and any page asking for a password should be using "https://". Be careful not to over-read this signal, though: https on its own proves nothing at all, because criminals can obtain certificates easily. It is the missing padlock that is mildly interesting, not the padlock that is reassuring.',
      advice: 'Never type a password into a page that is not https, and remember that https alone does not make a site trustworthy.',
      test: function (u) {
        if (!u.schemeWasExplicit || u.protocol !== 'http:') return null;
        return u.hostname + ' is linked over plain http:// rather than https://';
      }
    },
    {
      id: 'URL_RISKY_TLD',
      category: 'links',
      weight: 8,
      title: 'Link uses a domain ending that is heavily used by phishing',
      what: 'Some domain endings are cheap or free, and they dominate phishing statistics. That does not make every site on them hostile - plenty of real businesses use them - so this carries only a few points, and it is here mostly so you learn to notice the ending of an address before the middle of it.',
      advice: 'Notice the ending of the domain, not just the company name inside it. The last two parts of the address are the part somebody actually registered.',
      test: function (u) {
        if (RISKY_TLDS.indexOf(u.tld) === -1) return null;
        return u.registrableDomain + ' ends in ".' + u.tld + '", an ending that appears often in phishing campaigns';
      }
    },
    {
      id: 'URL_OBFUSCATED_HOST',
      category: 'links',
      weight: 6,
      title: 'Link hostname is unusually long or padded with extra parts',
      what: 'Genuine addresses are usually short and to the point. Attackers stuff extra subdomains, hyphens and numbers in to push the real domain out of sight - in a narrow browser bar or on a phone, "login.microsoft.com.secure-auth-verify.example" may look like it starts with Microsoft when it ends somewhere else entirely.',
      advice: 'Find the last two parts before the first single slash. Everything to the left of them is just a label the owner of that domain chose, and anyone can choose anything.',
      test: function (u) {
        if (u.isIp) return null;
        const labels = hostLabels(u.hostname);
        const hyphens = (u.hostname.match(/-/g) || []).length;
        const digits = (u.hostname.match(/\d/g) || []).length;
        const reasons = [];
        if (labels.length >= 4) reasons.push(labels.length + ' dot-separated parts');
        if (hyphens >= 3) reasons.push(hyphens + ' hyphens');
        if (digits >= 5) reasons.push(digits + ' digits');
        if (u.hostname.length > 40) reasons.push('a very long hostname (' + u.hostname.length + ' characters)');
        if (!reasons.length) return null;
        return u.hostname + ' contains ' + reasons.join(', ');
      }
    },
    {
      id: 'URL_NONSTANDARD_PORT',
      category: 'links',
      weight: 5,
      title: 'Link uses a non-standard network port',
      what: 'Websites are normally served on port 443 (or 80). A link with ":8080" or ":8443" tacked on is usually a temporary server someone stood up in a hurry, which is typical of a short-lived phishing kit.',
      advice: 'Treat a port number in a link as a mild warning sign, and do not log in on a page served that way.',
      test: function (u) {
        if (!u.port || u.port === '80' || u.port === '443') return null;
        return u.hostname + ' is served on port ' + u.port + ' instead of the standard web port';
      }
    },
    {
      id: 'LINK_TEXT_MISMATCH',
      category: 'links',
      weight: 15,
      title: 'Link text does not match where the link actually goes',
      what: 'The words you see and the address you travel to are two different things, and attackers exploit that gap. If the visible text says one company and the address behind it belongs to another, the text was written to fool you. (This can only be checked when the pasted email includes link formatting, such as the original HTML or Markdown.)',
      advice: 'Hover over any link, or long-press it on a phone, before deciding anything, and compare what you see with where it really goes.',
      test: function (u) {
        if (!u.anchorText) return null;
        const text = u.anchorText.trim();
        if (!text) return null;

        /* Case 1: the visible text spells out a domain of its own. */
        const found = text.match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi) || [];
        for (let i = 0; i < found.length; i++) {
          const shownDomain = registrableDomain(found[i]);
          if (shownDomain.split('.').length >= 2 && shownDomain !== u.registrableDomain) {
            return 'The link says "' + truncate(found[i], 40) + '" but actually goes to ' + u.hostname;
          }
        }

        /* Case 2: the visible text names a brand the link does not belong to. */
        const tokens = Object.keys(BRAND_OFFICIAL_DOMAINS);
        const lowerText = text.toLowerCase();
        for (let j = 0; j < tokens.length; j++) {
          const token = tokens[j];
          if (lowerText.indexOf(token) !== -1 && !isOfficialBrandDomain(u.hostname, token)) {
            return 'The link text says "' + truncate(text, 40) + '" but the address belongs to ' + u.hostname;
          }
        }
        return null;
      }
    }
  );

  function truncate(value, max) {
    const text = String(value == null ? '' : value);
    return text.length <= max ? text : text.slice(0, max - 1) + '\u2026';
  }

  PEA.helpers.truncate = truncate;

  /* =======================================================================
     PART 3 - ATTACHMENT RULES
     Filenames are collected from the email text and, when headers are
     supplied, from the "filename=" / "name=" parts of MIME headers.
     Each rule is handed one attachment:
        {name, extension, previousExtension, declaredType}
     ===================================================================== */

  R.ATTACHMENT_RULES.push(
    {
      id: 'ATTACH_EXECUTABLE',
      category: 'attachments',
      weight: 25,
      title: 'Attachment is a file type that runs code when opened',
      what: 'This extension is a programme, not a document. Double-clicking it can install malware immediately, with no further warning. There is no legitimate reason to send a programme as an unexpected email attachment - real software is distributed through websites and app stores. Windows hides known extensions by default, which is why a file can look like "Invoice.pdf" when it is really "Invoice.pdf.exe".',
      advice: 'Do not open it, do not preview it, and do not "check" it. Delete the message, or report it to whoever handles security where you work. If you already opened it, disconnect from the network and get help.',
      maxEvidence: 4,
      test: function (a) {
        return EXECUTABLE_EXTENSIONS.indexOf(a.extension) === -1 ? null : '".' + a.extension + '" is an executable file type';
      }
    },
    {
      id: 'ATTACH_MACRO_ENABLED',
      category: 'attachments',
      weight: 25,
      title: 'Attachment is a macro-enabled Office document',
      what: 'Files ending in things like .docm or .xlsm are ordinary Word and Excel documents with the macro facility deliberately switched on. Macros are programmes inside the document, usually one click away from running, which makes these a leading way for ransomware to get in. An ordinary .docx could have been sent instead.',
      advice: 'Do not enable anything when the document opens. Ask the sender, through a channel you already trust, whether they really sent it. If the document is genuine but macros are not needed, ask for a plain .docx instead.',
      maxEvidence: 4,
      test: function (a) {
        return MACRO_EXTENSIONS.indexOf(a.extension) === -1 ? null : '".' + a.extension + '" is a macro-enabled Office format';
      }
    },
    {
      id: 'ATTACH_WEB_PAGE',
      category: 'attachments',
      weight: 12,
      title: 'Attachment is a web page',
      what: 'An HTML or SVG attachment contains a web page that opens locally, straight off your own disk, with no address bar telling you where you are. That makes it an ideal home for a fake login form, because there is no padlock and no domain to check. It is also a well-known way to slip past email filters that remove links from messages.',
      advice: 'Do not open it. If a real colleague needs to share a page, they can send a link through a trusted system you are able to inspect first.',
      maxEvidence: 3,
      test: function (a) {
        return WEBPAGE_EXTENSIONS.indexOf(a.extension) === -1 ? null : '".' + a.extension + '" is a web page, which opens locally without an address bar';
      }
    },
    {
      id: 'ATTACH_ARCHIVE',
      category: 'attachments',
      weight: 8,
      title: 'Attachment is a compressed archive',
      what: 'Archives such as .zip exist for legitimate reasons, so they score low on their own. They matter because they hide their contents from many email security scanners, and because the file inside is often the actual threat.',
      advice: 'Never open an archive that arrived unexpectedly, and never type a password into one to "see what is inside" - the usual payload is a programme or a script.',
      maxEvidence: 3,
      test: function (a) {
        return ARCHIVE_EXTENSIONS.indexOf(a.extension) === -1 ? null : '".' + a.extension + '" is a compressed archive';
      }
    }
  );

  R.ATTACHMENT_RULES.push(
    {
      id: 'ATTACH_DOUBLE_EXTENSION',
      category: 'attachments',
      weight: 10,
      title: 'Attachment name uses a double extension',
      what: 'A name such as "Invoice_8842.pdf.exe" is built to be misread. The eye stops at ".pdf" and assumes a document, while the operating system runs the last extension. Because Windows hides extensions by default, many people would never see the deception at all.',
      advice: 'Do not open it. Report it - this filename pattern is about as close to a confession as an attacker writes.',
      maxEvidence: 3,
      test: function (a) {
        if (!a.previousExtension || INNOCENT_EXTENSIONS.indexOf(a.previousExtension) === -1) return null;
        if (a.previousExtension === a.extension) return null;
        return '"' + a.name + '" looks like a .' + a.previousExtension + ' file but is really .' + a.extension;
      }
    },
    {
      id: 'ATTACH_UNUSUAL_NAME',
      category: 'attachments',
      weight: 8,
      title: 'Attachment name looks machine-generated',
      what: 'Names such as SCAN_2024_11_7741_XQ_0001.pdf are stamped out in bulk by criminal tooling, which gives every victim a slightly different filename so that spam filters cannot simply block one. Be fair about this one, though: some real automated systems generate names like this too, so on its own it is only a hint.',
      advice: 'Judge it alongside everything else in the message, and treat an unexpected automated-looking attachment with particular caution.',
      maxEvidence: 3,
      test: function (a) {
        const underscores = (a.name.match(/_/g) || []).length;
        const digits = (a.name.match(/\d/g) || []).length;
        if (underscores < 3 && digits < 8) return null;
        return '"' + truncate(a.name, 46) + '" has a machine-generated appearance';
      }
    },
    {
      id: 'ATTACH_TYPE_MISMATCH',
      category: 'attachments',
      weight: 20,
      title: 'Attachment is declared as one file type but named as another',
      what: 'The email\'s own technical headers claim this file is something harmless, while the filename says it is something that runs code. That contradiction has no innocent explanation in ordinary mail. It can only be checked when you paste the email headers.',
      advice: 'Do not open the file. This is a deliberately disguised attachment; report the message.',
      maxEvidence: 3,
      test: function (a) {
        if (!a.declaredType) return null;
        const declared = String(a.declaredType).toLowerCase();
        const dangerous = MACRO_EXTENSIONS.concat(EXECUTABLE_EXTENSIONS, ARCHIVE_EXTENSIONS);
        if (dangerous.indexOf(a.extension) === -1) return null;
        if (declared.indexOf(a.extension) !== -1) return null;
        if (declared.indexOf('octet-stream') !== -1 || declared.indexOf('multipart') !== -1) return null;
        return '"' + a.name + '" is declared as "' + a.declaredType + '" but is named as a .' + a.extension + ' file';
      }
    }
  );

  /* =======================================================================
     PART 4 - STRUCTURAL RULES
     These do not look for phrases. They inspect the raw text for tricks that
     cannot be written down as an ordinary search phrase.
     ===================================================================== */

  const STRUCTURAL_RULES = [
    {
      id: 'INVISIBLE_CHARACTERS',
      category: 'credentials',
      weight: 8,
      title: 'Message contains invisible characters',
      what: 'Zero-width characters are Unicode characters that take up no space on screen. They are invisible in every email client, yet they break up words such as "password" or a domain name so that security filters no longer recognise them. You can never see them, and you have no reason to receive them.',
      advice: 'Treat this as deliberate evasion. Do not act on the message; report it.',
      test: function (ctx) {
        const found = ctx.raw.match(/[\u200B-\u200D\u2060\uFEFF]/g) || [];
        if (!found.length) return null;
        return {
          note: 'Found ' + found.length + ' invisible zero-width character' + (found.length === 1 ? '' : 's') + ', which no legitimate sender needs',
          evidence: ['(invisible zero-width characters were removed before analysis)']
        };
      }
    },
    {
      id: 'BIDI_OVERRIDE',
      category: 'credentials',
      weight: 15,
      title: 'Message contains bidirectional text override characters',
      what: 'A handful of Unicode characters reverse the direction text is displayed in. They are used almost exclusively to make a filename or link appear to end in something harmless when it does not, which is the "Trojan Source" technique. Ordinary email has no reason to contain them.',
      advice: 'Do not open attachments or links from this message. Report it as deliberately concealed.',
      test: function (ctx) {
        const found = ctx.raw.match(/[\u202A-\u202E\u2066-\u2069]/g) || [];
        if (!found.length) return null;
        return {
          note: 'Found ' + found.length + ' hidden direction-override character' + (found.length === 1 ? '' : 's') + ', a technique used to disguise file names and links',
          evidence: ['(direction-override characters were found in the message)']
        };
      }
    }
  ];

  PEA.patterns.STRUCTURAL_RULES = STRUCTURAL_RULES;

  /* =======================================================================
     PART 5 - HEADER RULES
     These run only when the visitor pastes the email's technical headers,
     which is where SPF, DKIM, DMARC, From, Reply-To and Return-Path live.
     If no headers were supplied, the engine records "not available" instead
     of guessing - guessing here would be worse than saying nothing.
     ===================================================================== */

  R.HEADER_RULES.push(
    {
      id: 'HDR_FROM_REPLYTO_MISMATCH',
      category: 'authenticity',
      weight: 20,
      title: 'Replies would go to a different domain than the sender\'s',
      what: 'The From address is what you see; Reply-To is where your answer actually goes. When the two sit on different domains, anything you send - including exactly what the attacker is fishing for - is delivered somewhere the visible sender does not control. This is the classic shape of business email compromise, where a real supplier account is used but the reply is diverted.',
      advice: 'Do not reply to the email. Contact the person or organisation using an address or number you already have. Do not use any contact details contained in the message.',
      test: function (f) {
        if (!f.from || !f.replyTo || !f.from.domain || !f.replyTo.domain) return null;
        if (f.from.domain === f.replyTo.domain) return null;
        return {
          note: 'Replies would go to ' + f.replyTo.domain + ' while the sender claims to be ' + f.from.domain,
          evidence: ['From: ' + (f.from.address || f.from.raw), 'Reply-To: ' + (f.replyTo.address || f.replyTo.raw)]
        };
      }
    },
    {
      id: 'HDR_RETURNPATH_MISMATCH',
      category: 'authenticity',
      weight: 15,
      title: 'Return-Path domain does not match the From domain',
      what: 'Return-Path is the hidden address where undelivered mail goes, added by the mail system itself rather than typed by the sender. In genuine mail it usually shares a domain with the From address. When it does not, the message may have travelled through an unrelated system, or been written to look like somebody else.',
      advice: 'Treat the message with caution. If it asks for anything at all - money, details, a login - verify it another way before responding.',
      test: function (f) {
        if (!f.from || !f.returnPath || !f.from.domain || !f.returnPath.domain) return null;
        if (f.from.domain === f.returnPath.domain) return null;
        return {
          note: 'The hidden return path is ' + f.returnPath.domain + ' but the sender claims ' + f.from.domain,
          evidence: ['From: ' + (f.from.address || f.from.raw), 'Return-Path: ' + (f.returnPath.address || f.returnPath.raw)]
        };
      }
    }
  );

  R.HEADER_RULES.push(
    {
      id: 'HDR_DISPLAYNAME_IMPERSONATION',
      category: 'authenticity',
      weight: 15,
      title: 'Sender name claims a company the address does not belong to',
      what: 'In most email apps the display name is all you see, and it can say anything the sender types. An address can be labelled "Microsoft Account Team" while being an unrelated domain registered days ago. The name is a label, not evidence.',
      advice: 'Always read the actual address, not the name. On a phone, tap the sender name to reveal the full address.',
      test: function (f) {
        if (!f.from || !f.from.displayName || !f.from.domain) return null;
        const name = f.from.displayName.toLowerCase();
        const tokens = Object.keys(BRAND_OFFICIAL_DOMAINS);
        for (let i = 0; i < tokens.length; i++) {
          const token = tokens[i];
          if (name.indexOf(token) !== -1 && !isOfficialBrandDomain(f.from.domain, token)) {
            return {
              note: 'The sender name mentions "' + token + '" but the address is on ' + f.from.domain + ', which we do not recognise as belonging to that brand',
              evidence: ['From: ' + f.from.raw]
            };
          }
        }
        return null;
      }
    },
    {
      id: 'HDR_DISPLAYNAME_ROLE_CLAIM',
      category: 'authenticity',
      weight: 8,
      title: 'Sender presents itself as a support or security function on a consumer mailbox',
      what: 'The message is signed by an IT, security, helpdesk or account-support function, yet the address behind it is a free consumer mailbox. A real support desk answers from its own domain. This is a soft signal, so it carries few points - departments sometimes do work out of shared mailboxes - but it is worth noticing.',
      advice: 'Do not treat an authority claim as proof. Look up the organisation\'s real support contact and use that instead.',
      test: function (f) {
        if (!f.from || !f.from.displayName || !f.from.registrable) return null;
        if (FREE_MAIL_DOMAINS.indexOf(f.from.registrable) === -1 && !f.from.isFreeMail) return null;
        const name = f.from.displayName.toLowerCase();
        if (!/\b(it|help ?desk|helpdesk|security|support|service desk|administrator|admin|accounts? (?:team|department)|billing)\b/.test(name)) return null;
        return {
          note: 'Signs itself "' + f.from.displayName + '" but sends from a free email account on ' + f.from.registrable,
          evidence: ['From: ' + f.from.raw]
        };
      }
    },
    {
      id: 'HDR_DISPLAYNAME_IS_EMAIL',
      category: 'authenticity',
      weight: 20,
      title: 'Sender name is a fake email address',
      what: 'This message puts an address in the sender-name area, but that text is not the address the mail actually came from. The name might say "support@yourbank.example" while the real technical address is something else entirely. It is written so that you read one thing and believe another.',
      advice: 'Do not trust anything in the message. Delete it, then reach the organisation through its own app or by typing its address yourself.',
      test: function (f) {
        if (!f.from || !f.from.displayName || !f.from.address) return null;
        if (f.from.displayName.indexOf('@') === -1) return null;
        const shown = f.from.displayName.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i);
        if (!shown) return null;
        if (shown[0].toLowerCase() === f.from.address.toLowerCase()) return null;
        return {
          note: 'The sender name shows "' + shown[0] + '" but the message actually came from ' + f.from.address,
          evidence: ['From: ' + f.from.raw]
        };
      }
    }
  );

  R.HEADER_RULES.push(
    {
      id: 'HDR_SPF_FAIL',
      category: 'authenticity',
      weight: 20,
      title: 'SPF check failed',
      what: 'SPF lets a domain publish a list of servers that are allowed to send email on its behalf. The receiving mail server checked that list and did not find this sender on it, so the message probably did not come from the organisation it claims. Be aware of the limit here: SPF also fails for legitimately forwarded mail, which is why this is a warning sign rather than a verdict.',
      advice: 'Treat the message as unverified. Do not open links or attachments, and do not act on any request inside it.',
      test: function (f) {
        if (f.spf !== 'fail') return null;
        return {
          note: 'The receiving server recorded spf=fail, meaning the sender was not authorised to send mail for that domain',
          evidence: authEvidence(f, 'spf=fail')
        };
      }
    },
    {
      id: 'HDR_SPF_SOFTFAIL',
      category: 'authenticity',
      weight: 12,
      title: 'SPF check soft-failed',
      what: 'A soft fail means the receiving server was not satisfied that this sender is authorised to send mail for the claimed domain, but the domain has asked for such mail to be treated cautiously rather than rejected outright. It is a weaker result than a hard failure, and still worth noticing.',
      advice: 'Verify the message through a channel you trust before acting on it.',
      test: function (f) {
        if (f.spf !== 'softfail') return null;
        return {
          note: 'The receiving server recorded spf=softfail, meaning the sender was not clearly authorised for that domain',
          evidence: authEvidence(f, 'spf=softfail')
        };
      }
    },
    {
      id: 'HDR_DKIM_FAIL',
      category: 'authenticity',
      weight: 15,
      title: 'DKIM signature check failed',
      what: 'DKIM is a tamper-evident signature attached to a message. If the check fails, the message was either altered after it was signed, or the signature was forged. Either way, what you are reading is not a message the claimed domain provably sent.',
      advice: 'Do not act on the message. If it appears to come from a colleague or supplier, confirm the contents another way.',
      test: function (f) {
        if (f.dkim !== 'fail') return null;
        return {
          note: 'The receiving server recorded dkim=fail, so the message\'s signature did not validate',
          evidence: authEvidence(f, 'dkim=fail')
        };
      }
    },
    {
      id: 'HDR_DMARC_FAIL',
      category: 'authenticity',
      weight: 20,
      title: 'DMARC check failed',
      what: 'DMARC is the domain owner\'s overall instruction for how to treat mail that fails SPF or DKIM, and it is the strongest of the three checks. A DMARC failure means the domain has asked the world to reject or quarantine mail like this, and this message matched that description. Spoofing a domain that is properly protected is the hardest form of impersonation, which is why this scores highly.',
      advice: 'Delete or report the message. Do not reply to it, do not use its contact details, and never enter credentials from a link inside it.',
      test: function (f) {
        if (f.dmarc !== 'fail') return null;
        return {
          note: 'The receiving server recorded dmarc=fail, meaning this message broke the sending domain\'s own authentication policy',
          evidence: authEvidence(f, 'dmarc=fail')
        };
      }
    }
  );

  function authEvidence(f, token) {
    const raw = String((f && f.authResults) || '').replace(/\s+/g, ' ').trim();
    const evidence = [];
    if (raw) {
      const index = raw.toLowerCase().indexOf(token);
      const window = index === -1 ? raw : raw.slice(Math.max(0, index - 40), index + token.length + 30);
      evidence.push('Authentication-Results: ...' + truncate(window.trim(), 120) + '...');
    } else {
      evidence.push('Recorded authentication result: ' + token);
    }
    return evidence;
  }

  R.HEADER_RULES.push(
    {
      id: 'HDR_FREEMAIL_REPLYTO',
      category: 'authenticity',
      weight: 12,
      title: 'Organisation-looking sender, but replies go to a free email account',
      what: 'The message presents itself as coming from an organisation, yet replies are directed to a free consumer mailbox such as Gmail or Outlook.com. Real organisations handle customer replies on their own domain. Free mailboxes are anonymous, can be created in minutes, and cannot be traced back to a company.',
      advice: 'Do not reply. Contact the organisation using details you already have, and tell whoever handles security where you work.',
      test: function (f) {
        if (!f.hasHeaders || !f.replyTo || !f.replyTo.registrable) return null;
        if (FREE_MAIL_DOMAINS.indexOf(f.replyTo.registrable) === -1) return null;
        if (!f.from || !f.from.registrable) return null;
        if (FREE_MAIL_DOMAINS.indexOf(f.from.registrable) !== -1) return null;
        return {
          note: 'The sender is on ' + f.from.registrable + ' but replies would go to a free email account on ' + f.replyTo.registrable,
          evidence: ['From: ' + (f.from.address || f.from.raw), 'Reply-To: ' + (f.replyTo.address || f.replyTo.raw)]
        };
      }
    },
    {
      id: 'HDR_LINK_DOMAIN_MISMATCH',
      category: 'authenticity',
      weight: 10,
      title: 'Links point somewhere unrelated to the sender',
      what: 'The sender\'s domain and the destinations of the links inside the message have nothing in common. Genuine organisations usually link to their own sites, even if they use a separate tracking domain for marketing. This carries a modest number of points, because plenty of real messages link to partner sites, form builders and newsletter services.',
      advice: 'Check each destination before you use it. If the organisation matters to you, go to it through your own bookmark rather than through the email.',
      test: function (f) {
        if (!f.hasHeaders || !f.from || !f.from.registrable) return null;
        const domains = f.linkDomains || [];
        if (!domains.length) return null;
        if (domains.indexOf(f.from.registrable) !== -1) return null;
        return {
          note: 'The sender is on ' + f.from.registrable + ', but every link in the message points to ' + domains.slice(0, 3).join(', ') + (domains.length > 3 ? ' and others' : ''),
          evidence: domains.slice(0, 4).map(function (d) { return 'Link domain: ' + d; })
        };
      }
    },
    {
      id: 'HDR_NO_AUTH_RESULTS',
      category: 'authenticity',
      weight: 0,
      title: 'No authentication results found in the headers',
      what: 'This is an observation, not a scored warning sign. You supplied headers, but they did not contain the receiving server\'s verdict on SPF, DKIM or DMARC - the fields usually labelled Authentication-Results or Received-SPF. That often just means the headers were copied from a different part of the message, or trimmed on the way here. With nothing to read, the tool says so rather than inventing a result.',
      advice: 'To get the full picture, copy the complete original message source from your mail provider, including every Received and Authentication-Results line.',
      test: function (f) {
        if (!f.hasHeaders) return null;
        if (f.spf || f.dkim || f.dmarc) return null;
        return {
          note: 'The pasted headers contained no SPF, DKIM or DMARC results, so sender authentication could not be checked',
          evidence: (f.headerLines || []).slice(0, 3)
        };
      }
    },
    {
      id: 'HDR_DKIM_SIGNATURE_ABSENT',
      category: 'authenticity',
      weight: 0,
      title: 'Headers contain no DKIM signature at all',
      what: 'An observation, not a score. The headers have no DKIM-Signature field, which is the actual cryptographic signature added by the sending server. Some legitimate mail genuinely arrives unsigned, and some mail systems strip the signature line while keeping the verdict, so this on its own means very little.',
      advice: 'Use it only as context. A missing signature is interesting; a failed signature is what matters.',
      test: function (f) {
        if (!f.hasHeaders) return null;
        if (f.hasDkimSignature) return null;
        return {
          note: 'No DKIM-Signature field was present in the pasted headers',
          evidence: []
        };
      }
    }
  );

  /* =======================================================================
     End of the rulebook. Everything above is data plus small pure functions;
     the engine in js/analyzer.js does the scoring and turns these into the
     report the visitor sees.
     ===================================================================== */

})(typeof window !== 'undefined' ? window : globalThis);
