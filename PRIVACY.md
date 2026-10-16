# PhishLens privacy policy

Last updated: October 16, 2026.

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
| PhishLens Cloud | The hosted server run by the PhishLens author, on Oracle Cloud. Nothing is stored (see below). |

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
without your IP address or any other request data (the web server's
access log described below still records the request for 30 days), and
returns a reference. Reports are used only to measure and improve PhishLens (for
example to train the text model on legitimate mail it got wrong); they
are never published or shared. They are kept for at most two years.
To have a report deleted, open an issue at
https://github.com/AnzouK/PhishLens/issues with its reference (the
reference alone says nothing about the report).

To make reporting possible from Insights, the redacted text of your last
Gmail and Outlook scans is kept in your browser for 7 days (50 emails at
most). It never leaves the browser unless you report that scan.

## What is kept, and for how long

| Data | Where | How long |
| --- | --- | --- |
| Scan history (subject, sender, verdict, scores, top explanation words, detected language and your answer) | Your browser (`chrome.storage.local`) | Until you clear it (Insights, **Clear**), up to the last 500 scans |
| Explanation cache | Your browser | Until the extension is removed |
| Redacted text of recent Gmail and Outlook scans, for reporting | Your browser | 7 days, 50 emails at most; cleared with the history |
| Reports you sent (redacted text or statistics, see above) | PhishLens Cloud | At most two years; deleted on request with the reference |
| Automatic-scan results (thread id, verdict, score) | Your browser | Last 500 emails |
| Settings | Your browser | Until changed |
| Link verdicts (URL, verdict, source) | Backend cache (SQLite) | 24 hours |
| Results sent back (verdict, scores, link verdicts, explanation words), keyed by a hash of the email; not the email itself | Backend memory | 24 hours, or until the server restarts |
| Email text, headers, attachments | Backend memory, during the request | Not stored |
| Request metadata (time, path, status, IP address, browser) | PhishLens Cloud application and web-server logs | 30 days; request bodies are never logged |

PhishLens Cloud also counts verdicts per scoring path for monitoring
(Prometheus counters). These are numbers only, with no email data.

## This website

`phishlens.dev` sets no cookies and uses no tracking scripts, so
there is nothing to consent to. Visit counts come from the web server's
own logs (page, time, referrer, browser type, IP address), read with a
self-hosted tool; they are kept for 30 days and never shared. The page
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
| Access to `127.0.0.1:8000`, `localhost:8000`, `phishlens.dev` | Send scans to the backend you chose. |

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

## Changes and contact

Changes to this policy are listed in the project's
[changelog](CHANGELOG.md). Questions: open an issue at
https://github.com/AnzouK/PhishLens/issues, or report a security problem
privately as described in [SECURITY.md](SECURITY.md).
