---
title: PhishLens Backend
emoji: 🛡
colorFrom: red
colorTo: pink
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Detect phishing emails with DistilBERT and LIME.
---

# PhishLens — Backend Space

This Space hosts the **public-facing FastAPI backend** for
[PhishLens](https://github.com/Sonje03/PhishLens), a Chrome extension that
detects phishing emails and explains why.

The model — a `distilbert-base-uncased` fine-tuned on ~30 000 emails —
lives at [`Sonje03/phishlens-distilbert`](https://huggingface.co/Sonje03/phishlens-distilbert)
and is downloaded by this Space the first time it boots.

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/` | GET | Health check |
| `/analyse` | POST | Run all 3 agents + fused verdict |
| `/explain` | POST | Top-K LIME tokens for the text agent |

### Request

```json
{
  "raw_email_b64": "<base64-encoded .eml file>",
  "raw_text":      "<plain-text email body, alternative>",
  "sender_email":  "<optional explicit sender>"
}
```

### Response (success)

```json
{
  "verdict": "phishing" | "safe",
  "trusted_sender": false,
  "sender_domain": "example.com",
  "agents": {
    "text":     {"phishing_probability": 0.92, "verdict": "Phishing"},
    "url":      {"phishing_probability": 0.05, "verdict": "Safe"},
    "metadata": {"phishing_probability": 0.15, "verdict": "Safe"}
  }
}
```

## Free-tier limits

- ~30–60 s cold start after long inactivity (the Space goes to sleep).
- CPU only — expect 3–5 s per `/analyse` and 10–15 s per `/explain`.
- Public endpoint, no auth — please don't feed it sensitive email content.
  For private use, self-host with the [PhishLens Docker image](https://github.com/Sonje03/PhishLens).

## License

MIT.
