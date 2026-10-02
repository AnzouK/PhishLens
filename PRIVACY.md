# PhishLens privacy policy

Last updated: October 2, 2026.

PhishLens is a Chrome extension that checks emails for phishing. This
page explains what data it handles, where that data goes and what is
kept. It applies to the extension and to the hosted backend, PhishLens Cloud, at
`anzouk.duckdns.org`.

## In short

- PhishLens reads an email only when you ask it to (the **Scan**
  buttons), or automatically if you turn on **Scan new emails
  automatically** in the settings (off by default).
- The email is sent to the backend you chose in the settings: your own
  computer (local Docker or Python), your own server, or PhishLens
  Cloud. Nothing is sent anywhere else by the extension.
- The backend analyses the email and returns a verdict. It does not
  store email content, senders or subjects.
- Your scan history stays in your browser. It is never uploaded.
- There are no accounts, no analytics, no advertising and no sale of
  data.

## What the extension reads

When a scan runs, the extension reads from the open Gmail or Outlook page:

- the text of the message, its subject and the sender's address;
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

## What is kept, and for how long

| Data | Where | How long |
| --- | --- | --- |
| Scan history (subject, sender, verdict, scores, top explanation words) | Your browser (`chrome.storage.local`) | Until you clear it (Insights, **Clear**), up to the last 500 scans |
| Explanation cache | Your browser | Until the extension is removed |
| Automatic-scan results (thread id, verdict, score) | Your browser | Last 500 emails |
| Settings | Your browser | Until changed |
| Link verdicts (URL, verdict, source) | Backend cache (SQLite) | 24 hours |
| Email text, headers, attachments | Backend memory, during the request | Not stored |
| Request metadata (time, path, status, IP address) | PhishLens Cloud application and web-server logs, when enabled | Rotated by the server; request bodies are never logged |

PhishLens Cloud also counts verdicts per scoring path for monitoring
(Prometheus counters). These are numbers only, with no email data.

## Permissions

| Permission | Why |
| --- | --- |
| `storage` | Keep your settings, scan history and caches in the browser. |
| `alarms` | Ping the backend now and then so the first scan is not slow. |
| `notifications` | Warn you when the automatic scan finds a phishing email. |
| `scripting` | After an update, put the new version of the scan buttons into Gmail and Outlook tabs that are already open, so you do not have to refresh them. |
| Access to `mail.google.com` | Add the scan buttons and banners to Gmail and read the email you scan. |
| Access to Outlook on the web (`outlook.office.com`, `outlook.office365.com`, `outlook.live.com`) | Same, in Outlook (manual scans only). |
| Access to `127.0.0.1:8000`, `localhost:8000`, `anzouk.duckdns.org` | Send scans to the backend you chose. |

## Your choices

- Turn off **Read full headers** or **Scan new emails automatically** in
  the settings at any time.
- Use the local backend so emails never leave your computer.
- Clear the history from the Insights view, or remove the extension to
  delete everything it stored.

## Children

PhishLens is not directed at children and does not knowingly collect
data about them.

## Changes and contact

Changes to this policy are listed in the project's
[changelog](CHANGELOG.md). Questions: open an issue at
https://github.com/AnzouK/PhishLens/issues, or report a security problem
privately as described in [SECURITY.md](SECURITY.md).
