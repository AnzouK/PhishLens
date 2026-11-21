# PhishLens privacy policy

Last updated: November 21, 2026.

PhishLens is a Chrome extension that checks emails for phishing. This
page explains what data it handles, where that data goes and what is
kept. It applies to the extension and to the hosted backend, PhishLens Cloud, at
`phishlens.dev`.

## In short

- PhishLens reads an email only when you ask it to (the **Scan**
  buttons), or automatically if you turn on **Scan new emails
  automatically** in the settings (off by default).
- The email is sent to the backend you chose in the settings: your own
  computer (local Docker or Python), your own server, or PhishLens
  Cloud. Nothing is sent anywhere else by the extension, except the
  reports you choose to send (below).
- The backend analyses the email and returns a verdict. It does not
  store email content, senders or subjects.
- Your scan history stays in your browser. It is never uploaded.
- There are no accounts, no analytics, no advertising and no sale of
  data.
- You can report a wrong verdict, or share your review statistics. Only
  what you see and confirm is sent: the email text with names,
  addresses, numbers and link paths removed, or statistics without any
  email content.

## What the extension reads

When a scan runs, the extension reads from the open Gmail or Outlook page:

- the text of the message, its subject and the sender's name and address;
- the targets of the links in the message;
- the authentication hints Gmail shows (mailed-by, signed-by);
- with **Read full headers** on (default), the original message as
  Gmail's "Show original" page provides it: all headers and the text
  parts, without the attachment files;
- for an attachment scan, the attachment file.

The popup also reads files you drop into it and text you paste.

## Where the data goes

All analysis requests go to one backend, selected in the extension
settings:

| Choice | Where your email goes |
| --- | --- |
| Local backend | Your own computer (`127.0.0.1:8000`). Nothing leaves it, except the threat-intelligence lookups below. |
| Custom URL | The server you entered. Its owner's policy applies. |
| PhishLens Cloud | The hosted server run by the PhishLens author, on Google Cloud in Belgium, reached through Cloudflare. Nothing is stored (see below). |

The backend checks the links found in an email against
threat-intelligence services. For this it sends the **link addresses
only** (never the email text, sender or subject):

- Google Safe Browsing (full URLs, when an API key is configured);
- URLhaus by abuse.ch (full URLs);
- Spamhaus DBL (domain names, through DNS);
- PhishTank (checked against a list downloaded to the server; no
  per-email request).

## Reports you choose to send

Under each verdict PhishLens shows the language it detected and a
**Wrong verdict? Report it** link; Insights has the same link for the
scans you marked **Wrong**, and a **Share my statistics** button.
Nothing is sent until you press **Send** after reading what will be
sent.

| Report | What is sent | What is never sent |
| --- | --- | --- |
| Wrong verdict | The subject, text and link domains of that email after redaction (names after a greeting or a title, your own name and address as shown on the mail page, email addresses, phone numbers, long numbers such as accounts, cards and codes, IBANs, @handles and usernames, the path and query of every link), the text as you edited it, the verdict, the scores, the scoring path, the detected language and your answer, the extension version and interface language | The sender's address, the original email, its headers and attachments |
| Statistics | For each scan in your history: the day, where it was scanned (Gmail, Outlook, popup), the verdict, the scores, whether the sender was trusted, your Right / Wrong review, the detected language and your answer | Subjects, senders, text, links |

Reports go to PhishLens Cloud whatever server you use for scanning. The
server redacts the text again with the same rules, stores the report
without your IP address or any other request data (the request logs
described below still record the request for 30 days), and returns a
reference.
A short notice of each new report goes to the maintainer through a push
notification service (ntfy): its kind, the reported verdict, the
language, where it was scanned and its reference (for statistics, the
number of scans), never any email content. Reports are used only to measure and improve
PhishLens (for example to train the text model on legitimate mail it got
wrong); they are never published or shared. They are kept for at most
two years. To have a report deleted, write to privacy@phishlens.dev with
its reference, or open an issue at
https://github.com/AnzouK/PhishLens/issues (the reference alone says
nothing about the report).

To make reporting possible from Insights, the redacted text of your last
Gmail and Outlook scans is kept in your browser for 7 days (50 emails at
most). It never leaves the browser unless you report that scan.

## What is kept, and for how long

| Data | Where | How long |
| --- | --- | --- |
| Scan history (subject, sender, verdict, scores, top explanation words, detected language and your answer) | Your browser (`chrome.storage.local`) | Until you clear it (Insights, **Clear**), up to the last 500 scans |
| Explanation cache (the words that explain a verdict, keyed by a hash of the text) | Your browser | 30 days, 200 entries at most; cleared with the history |
| Redacted text of recent Gmail and Outlook scans, for reporting | Your browser | 7 days, 50 emails at most; cleared with the history |
| Reports you sent (redacted text or statistics, see above) | PhishLens Cloud (Google Cloud Storage, United States; one file per report) | At most two years; deleted on request with the reference |
| Automatic-scan results (thread id, verdict, score, a short print of the inbox row) | Your browser | Last 500 emails; cleared with the history |
| Settings | Your browser | Until changed |
| Link verdicts (URL, verdict, source) | Backend cache (SQLite) | 24 hours |
| Results sent back (verdict, scores, link verdicts, explanation words), keyed by a hash of the email; not the email itself | Backend memory | 24 hours, or until the server restarts |
| Email text, headers, attachments | Backend memory, during the request | Not stored |
| Request metadata (time, path, status, IP address, browser) | PhishLens Cloud application and request logs (Google Cloud) | 30 days; request bodies are never logged |

PhishLens Cloud also counts verdicts per scoring path for monitoring
(Prometheus counters). These are numbers only, with no email data.

## This website

`phishlens.dev` sets no cookies and uses no tracking scripts, so
there is nothing to consent to. The site is served by Cloudflare Pages:
Cloudflare processes each request (page, time, referrer, browser type,
IP address) to deliver it, and PhishLens sees only Cloudflare's
aggregated visit counts, which are never shared. The page
asks GitHub's public API for the latest version number, which GitHub
sees as a normal request from your browser.

## Permissions

| Permission | Why |
| --- | --- |
| `storage` | Keep your settings, scan history and caches in the browser. |
| `notifications` | Warn you when the automatic scan finds a phishing email. |
| `scripting` | After an update, put the new version of the scan buttons into Gmail and Outlook tabs that are already open, so you do not have to refresh them. |
| Access to `mail.google.com` | Add the scan buttons and banners to Gmail and read the email you scan. |
| Access to Outlook on the web (`outlook.office.com`, `outlook.office365.com`, `outlook.live.com`) | Same, in Outlook (manual scans only). |
| Access to `phishlens.dev` | Send scans to PhishLens Cloud, the default backend. |
| Optional: `127.0.0.1`, `localhost`, or the address of your own server | Asked for only when you choose a local or custom backend in the settings, for that host alone, on any port. |

## Your choices

- Turn off **Read full headers** or **Scan new emails automatically** in
  the settings at any time.
- Use the local backend so emails never leave your computer.
- Clear the history from the Insights view, or remove the extension to
  delete everything it stored.
- If you never send a report, nothing leaves your browser except the
  scans themselves, to the server you chose.

## Children

PhishLens is not directed at children and does not knowingly collect
data about them.

## Who is responsible

PhishLens is a personal, non-commercial project maintained by an
individual, who is responsible for PhishLens Cloud and this website.
Two service providers handle the traffic:

- **Cloudflare** (Cloudflare, Inc., San Francisco, California, United
  States) serves this website, runs the domain's DNS and forwards the
  PhishLens Cloud requests sent to `phishlens.dev` to the analysis
  server. A request goes through the Cloudflare data centre nearest to
  you.
- **Google Cloud** (Google LLC, Mountain View, California, United
  States) runs the analysis on Cloud Run, in its europe-west1 region in
  Belgium, where emails are analysed in memory and not stored. The
  reports you choose to send are kept in a private Google Cloud Storage
  bucket in the United States (us-central1 region).

Contact: privacy@phishlens.dev.

## Your rights

You can ask what PhishLens Cloud keeps that relates to you, and have it
deleted: a report you sent (give its reference), or the log entries of
your requests, kept 30 days (give the date and your IP
address). Write to privacy@phishlens.dev; you get an answer within 30
days. PhishLens keeps no email, no account and no profile, so there is
usually nothing else to return or delete.

## Changes and contact

Changes to this policy are listed in the project's
[changelog](CHANGELOG.md). Questions and requests about your data:
privacy@phishlens.dev. Bugs and suggestions: open an issue at
https://github.com/AnzouK/PhishLens/issues. Security problems: report
them privately as described in [SECURITY.md](SECURITY.md).
