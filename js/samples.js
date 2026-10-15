/* =========================================================================
   Phishing Email Analyser - js/samples.js
   -------------------------------------------------------------------------
   THE DEMONSTRATION EMAILS.

   Six made-up messages for learning and for testing. Every one of them is
   completely fictional and completely inert:

     * All domains are reserved by internet standard and can never exist:
       example.com, example.org, .test, .invalid, and .example.
     * All IP addresses come from the documentation ranges (192.0.2.0/24 and
       203.0.113.0/24), which are guaranteed never to route anywhere.
     * The shortened link in the parcel sample points at a real shortener's
       address but with a deliberately invalid code, so it leads nowhere. The
       application never makes links clickable in any case, so it cannot be
       followed by accident from the report.

   Each sample declares the result it should produce. The automated tests
   (tests/test-cases.js) check that the engine still agrees, which is how we
   notice if a future change to the rulebook starts producing nonsense.
   ========================================================================= */

(function (root) {
  'use strict';

  const PEA = (root.PEA = root.PEA || {});

  const SAMPLES = [
    {
      id: 'obvious',
      name: 'Obvious phishing',
      blurb: 'The unsubtle kind: fear, a deadline, a password request, a bare IP address for a link, and a program attached.',
      expected: {
        min: 60,
        max: 100,
        classifications: ['High Risk'],
        /* The exact set of scored warning signs this sample should produce.
           The tests compare the whole set, so if a future change to the
           rulebook makes a new rule fire on an ordinary email, that shows up
           as a test failure rather than slipping past unnoticed. */
        shouldFire: ['ATTACH_EXECUTABLE', 'CREDENTIAL_HARVESTING', 'GENERIC_GREETING', 'REQUEST_PASSWORD', 'THREAT_ACCOUNT_SUSPENSION', 'URGENCY_PRESSURE', 'URL_INSECURE_HTTP', 'URL_RAW_IP']
      },
      body: `Subject: URGENT - your account will be suspended

Dear Customer,

We detected unusual activity on your account and it has been suspended for
security reasons. Unless you verify your account immediately, it will be
permanently closed within 24 hours.

To restore access, click the link below and enter your username and password:

http://192.0.2.45/secure-verify/login

Failure to verify your account will result in permanent closure. This is your
final notice.

Please also open the attached Account_Update.exe to install our security tool.

Thank you,
Account Security Team`,
      headers: ''
    },
    {
      id: 'sophisticated',
      name: 'Sophisticated phishing',
      blurb: 'No urgency at all, correct-looking branding and a polite tone. It still scores highly, which is the lesson: the score measures how many strong warning signs are present, not how alarming the message feels. It asks for a payment to a changed account, and it does it calmly.',
      expected: {
        min: 60,
        max: 100,
        classifications: ['High Risk'],
        shouldFire: ['ATTACH_MACRO_ENABLED', 'CHANGE_BANK_DETAILS', 'ENABLE_MACROS_LANGUAGE', 'GENERIC_GREETING', 'HDR_FROM_REPLYTO_MISMATCH', 'HDR_LINK_DOMAIN_MISMATCH', 'HDR_RETURNPATH_MISMATCH', 'UNEXPECTED_INVOICE', 'URL_BRAND_MISMATCH']
      },
      body: `Subject: Your quarterly invoice from Northwind Supplies

Hello,

Thank you for your continued business with Northwind Supplies. Please find your
quarterly invoice attached for your records. The document is named
Northwind_Q3_Invoice.docm.

For your convenience our banking details have been updated, so please use the
new account for this quarter's payment. The full details are on the attached
invoice.

You can also view your invoice online:
https://northwind-supplies.example-portal.test/invoice/8842

Or pay straight away through our secure payment portal:
https://paypa1-secure.test/northwind/pay

If the document does not display correctly, you may need to enable content.

Kind regards,
Accounts Receivable
Northwind Supplies`,
      headers: `From: "Northwind Supplies Accounts" <accounts@northwind-supplies.test>
Reply-To: northwind.accounts@secure-inbox.example
Return-Path: <bounce@mailer-relay.invalid>
To: finance@example.com
Subject: Your quarterly invoice from Northwind Supplies
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=mailer-relay.invalid;
 dkim=pass header.d=northwind-supplies.test; dmarc=pass
Received: from mailer-relay.invalid (203.0.113.24) by mx.example.com`
    }
  ];

  SAMPLES.push(
    {
      id: 'microsoft365',
      name: 'Fake Microsoft 365 account warning',
      blurb: 'Impersonates a security alert and asks for a one-time code. With headers pasted, SPF, DKIM and DMARC all fail and the reply-to address belongs to somebody else.',
      expected: {
        min: 75,
        max: 100,
        classifications: ['High Risk'],
        shouldFire: ['CREDENTIAL_HARVESTING', 'HDR_DISPLAYNAME_IMPERSONATION', 'HDR_DKIM_FAIL', 'HDR_DMARC_FAIL', 'HDR_FROM_REPLYTO_MISMATCH', 'HDR_LINK_DOMAIN_MISMATCH', 'HDR_SPF_FAIL', 'REQUEST_MFA_CODE', 'REQUEST_PASSWORD', 'URGENCY_PRESSURE', 'URL_BRAND_MISMATCH', 'URL_OBFUSCATED_HOST']
      },
      body: `Subject: Action required - unusual sign-in activity on your Microsoft 365 account

Microsoft 365

We detected a new sign-in to your account from an unrecognised device.

If this was not you, your account may be compromised. To secure your account,
sign in to confirm your identity within 12 hours:

https://microsoft-account-verify.example-login.test/auth/signin

You will be asked to enter your password and then confirm the verification code
we send to your phone.

Microsoft 365 Security Team`,
      headers: `From: "Microsoft 365 Security" <no-reply@office365-security.test>
Reply-To: security-team@secure-mail-alerts.example
Return-Path: <bounce@office365-security.test>
To: you@example.com
Subject: Action required - unusual sign-in activity on your Microsoft 365 account
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=office365-security.test;
 dkim=fail (signature verification failed); dmarc=fail action=quarantine
Received: from unknown (203.0.113.77) by mx.example.com
Received: from relay.office365-security.test by unknown`
    },
    {
      id: 'parcel',
      name: 'Fake parcel-delivery message',
      blurb: 'A short, friendly delivery notice with a hidden destination and a small fee to pay. Scores lower than the others, which is a useful reminder that not every phish is a screaming one.',
      expected: {
        min: 25,
        max: 59,
        classifications: ['Suspicious'],
        shouldFire: ['GENERIC_GREETING', 'UNEXPECTED_INVOICE', 'URGENCY_PRESSURE', 'URL_SHORTENER']
      },
      body: `Subject: Your parcel could not be delivered - action required

Dear Customer,

We attempted to deliver your parcel (tracking reference DHL-4471-8823) today but
nobody was available at the address.

A small redelivery fee of 1.99 is required before we can attempt delivery again.

Reschedule your delivery here: https://bit.ly/EXAMPLE-NOT-A-REAL-CODE

If the fee is not paid within 48 hours the parcel will be returned to sender.

DHL Express Customer Service`,
      headers: ''
    }
  );

  SAMPLES.push(
    {
      id: 'bec',
      name: 'Fake invoice / BEC-style email',
      blurb: 'Business email compromise. Note that SPF, DKIM and DMARC all PASS here, because the mail really was sent from a compromised account. Authentication only tells you the message is genuine; it never tells you the request is.',
      expected: {
        min: 60,
        max: 100,
        classifications: ['High Risk'],
        shouldFire: ['CHANGE_BANK_DETAILS', 'HDR_FREEMAIL_REPLYTO', 'HDR_FROM_REPLYTO_MISMATCH', 'IMPERSONATION_LANGUAGE', 'SECRECY_AND_AUTHORITY', 'UNEXPECTED_INVOICE']
      },
      body: `Subject: Re: Payment - updated bank details

Hi,

Following up on our conversation last week - please note that our bank details
have changed. The new details are below, and they are also on the attached
invoice.

Bank: Example Trust Bank
Sort code: 00-00-00
Account number: 00000000
IBAN: GB00 XXXX 0000 0000 0000 00

Could you make the transfer today? I'm in meetings all afternoon so email is
best, and please keep this between us for now.

Thanks,
David`,
      headers: `From: "David Whitmore" <david.whitmore@northwind-supplies.test>
Reply-To: david.whitmore.accounts@gmail.com
Return-Path: <david.whitmore@northwind-supplies.test>
To: finance@example.com
Subject: Re: Payment - updated bank details
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=northwind-supplies.test;
 dkim=pass header.d=northwind-supplies.test; dmarc=pass header.from=northwind-supplies.test
DKIM-Signature: v=1; a=rsa-sha256; d=northwind-supplies.test; s=selector1;
 h=from:to:subject; bh=AAAA; b=BBBB
Received: from mail.northwind-supplies.test (192.0.2.31) by mx.example.com`
    },
    {
      id: 'legitimate',
      name: 'Legitimate email',
      blurb: 'An ordinary internal message with a clean header check. It should score zero - which is the most important test of all, because a tool that shouts at everything is useless.',
      expected: {
        min: 0,
        max: 0,
        classifications: ['Low Risk'],
        shouldFire: []
      },
      body: `Subject: Quarterly all-hands - Thursday 10:00, Cedar Room

Hi Priya,

Thanks for sending the agenda. Two small additions from my side: a five-minute
update on the support desk rota, and a short demo of the new expense form.

I have added both to the shared document here:
https://portal.example.com/team/all-hands-q3

Notes from the last session are on the intranet, under Operations > All-hands.

See you Thursday,
Daniel`,
      headers: `From: "Daniel Okafor" <daniel.okafor@example.com>
To: priya.raman@example.com
Subject: Quarterly all-hands - Thursday 10:00, Cedar Room
Date: Mon, 12 Oct 2026 09:14:00 +0100
Message-ID: <20261012091400.4821@example.com>
Return-Path: <daniel.okafor@example.com>
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com;
 dkim=pass header.d=example.com; dmarc=pass header.from=example.com
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
 h=from:to:subject; bh=AAAA; b=BBBB
Received: from mail.example.com (192.0.2.10) by mx.example.com`
    }
  );

  PEA.samples = SAMPLES;


})(typeof window !== 'undefined' ? window : globalThis);
