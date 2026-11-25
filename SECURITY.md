# Security policy

PhishLens is a security tool, so its own security matters. Please
report anything that looks off.

## Reporting a vulnerability

Open a private advisory on GitHub at
[https://github.com/AnzouK/PhishLens/security/advisories/new](https://github.com/AnzouK/PhishLens/security/advisories/new).
Only maintainers can see the thread. With your approval it becomes a
public CVE with credit to you when the fix ships.

Please don't open a regular public issue for an unpatched security
issue, and don't post proof-of-concept payloads in public places
before we've had a chance to fix them.

## What's in scope

- The FastAPI backend (`backend/`), including the API endpoints, model
  loading, attachment parsing and the URL reputation cascade.
- The Chrome extension (`extension/`), including the content scripts in
  Gmail and Outlook, the popup and the service worker.
- The website (`site/`), for anything that lets an attacker run code or
  store data in another visitor's browser.
- Any pipe from an untrusted input (email body, attachment, URL, DOM
  scrape) to code execution, arbitrary file read/write, or SSRF.

## What's not in scope

- The content of the allowlist (`backend/trusted_domains.py`). Which
  domains are listed is a product decision. Getting the allowlist's
  softer verdict without authenticating as a listed domain is a
  security bug, though.
- PhishLens Cloud (`https://phishlens.dev`) is intentionally
  a shared open backend with permissive CORS. Rate-limiting bypass is
  a bug, but "someone can query the API without signing up" is not.
- Model quality, such as false positives or false negatives on specific
  emails. Those go in regular issues.
- Attachments over 10 MB are rejected on purpose, to limit
  CPU-exhaustion attacks.

## What we'll do

- Acknowledge your report within 72 h.
- Investigate and confirm or reject within 14 days.
- If confirmed, land a fix on `main` and cut a patch release. Credit
  you in the release notes and the advisory unless you ask to stay
  anonymous.

## What we won't do

- Pay a bounty (PhishLens is a free, independent open-source project,
  not a funded product).
- Sign an NDA in advance of a report.

Thanks for helping.
