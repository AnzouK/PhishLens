# Security policy

PhishLens is a cybersecurity research project — please help keep it
honest by reporting anything that looks off.

## Reporting a vulnerability

**Use GitHub Security Advisories.** Go to
[https://github.com/AnzouK/PhishLens/security/advisories/new](https://github.com/AnzouK/PhishLens/security/advisories/new)
and open a private advisory. This starts a thread visible only to
maintainers, and (with your approval) becomes a public CVE with credit
to you when the fix ships.

Please don't open a regular public issue for an unpatched security
issue, and don't post proof-of-concept payloads in public places
before we've had a chance to fix them.

## What's in scope

- The FastAPI backend (`backend/`) — API endpoints, model loading,
  attachment parsing, URL reputation cascade.
- The Chrome extension (`extension/`) — content script running inside
  Gmail, popup, background service worker.
- The landing page (`site/`) — anything that lets an attacker execute
  code or persist data in another visitor's browser.
- Any pipe from an untrusted input (email body, attachment, URL, DOM
  scrape) to code execution, arbitrary file read/write, or SSRF.

## What's not in scope

- The static allowlist (`TRUSTED_DOMAINS`) — it's a curated set of
  well-known senders and giving it a wider trust radius is a product
  decision, not a security bug.
- The public Cloud demo (`https://anzouk.duckdns.org`) is intentionally
  a shared open backend with permissive CORS. Rate-limiting bypass is
  a bug, but "someone can query the API without signing up" is not.
- Model-quality issues (false positives / false negatives on specific
  emails) — those go in regular issues, not security.
- Attachments larger than 10 MB being rejected is intentional (defense
  against CPU-exhaustion attacks).

## What we'll do

- Acknowledge your report within 72 h.
- Investigate and confirm or reject within 14 days.
- If confirmed, land a fix on `main` and cut a patch release. Credit
  you in the release notes and the advisory unless you ask to stay
  anonymous.

## What we won't do

- Pay a bounty (this is a Nile University final-year project, not a
  funded product).
- Sign an NDA in advance of a report.

Thanks for helping.
