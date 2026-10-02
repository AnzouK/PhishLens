# PhishLens terms of use

Last updated: October 2, 2026.

These terms cover the PhishLens Chrome extension, the website
`anzouk.duckdns.org` and PhishLens Cloud, the hosted analysis server.
By using them you accept these terms. The code itself is published under
the [MIT license](LICENSE), which governs copying and modifying it.

## The service

PhishLens checks emails for signs of phishing and explains its verdict.
It is a final-year student project from Nile University of Nigeria,
offered free of charge, without accounts and without advertising.

## What PhishLens is not

- **Not a guarantee.** The verdict is an estimate from statistical
  models and public threat-intelligence lists. PhishLens can miss a
  phishing email and can flag a legitimate one. Keep your usual
  judgement, and check with the sender through another channel before
  acting on a request for money, passwords or personal data.
- **Not a replacement** for your email provider's spam and malware
  filtering, your antivirus or your organisation's security team.

## Acceptable use

You agree not to:

- send emails or files to PhishLens Cloud that you are not allowed to
  share, such as other people's confidential messages;
- overload the server: automated bulk requests, load tests or attempts
  to get around the rate limits;
- use PhishLens to test, train or improve phishing campaigns;
- attack, probe or disrupt the server, except through the responsible
  disclosure process in [SECURITY.md](SECURITY.md).

Requests that break these rules can be blocked.

## Availability

PhishLens Cloud runs on a single server and can be slow, interrupted or
changed at any time, without notice. For guaranteed availability or for
sensitive mail, run your own backend (see the README); nothing then
leaves your machine except the threat-intelligence lookups described in
the privacy policy.

## Your data

What the extension and the server handle, and what is kept, is described
in the [privacy policy](PRIVACY.md). In short: emails are analysed and
not stored, and your scan history stays in your browser.

## Liability

PhishLens is provided "as is", without warranty of any kind, as stated
in the MIT license. To the extent the law allows, the authors are not
liable for any loss or damage arising from its use, including a missed
phishing email or a legitimate email flagged by mistake.

## Changes and contact

These terms may change; the date at the top shows the last update, and
changes are listed in the [changelog](CHANGELOG.md). Questions: open an
issue at https://github.com/AnzouK/PhishLens/issues.
