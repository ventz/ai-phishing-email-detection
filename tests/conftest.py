from __future__ import annotations

from email.message import EmailMessage
from email.policy import SMTP

import pytest

from phishing_detector.config import Settings

SES_AUTH = (
    "amazonses.com; spf=pass (spfCheck: domain of example.org designates 192.0.2.1 as permitted sender) "
    "client-ip=192.0.2.1; envelope-from=alice@example.org; helo=mail.example.org; "
    "dkim=pass header.i=@example.org; dmarc=pass header.from=example.org;"
)


def phish(html: bool = True) -> EmailMessage:
    m = EmailMessage()
    m["From"] = '"PayPal Support" <service@paypa1-secure.com>'
    m["Reply-To"] = "collect@evil.example"
    m["To"] = "alice@example.org"
    m["Subject"] = "Your account is suspended"
    m["Authentication-Results"] = "mx.example.org; spf=fail smtp.mailfrom=paypa1-secure.com; dmarc=fail"
    m.set_content("Your account is fine. No action needed.")  # harmless plain alternative
    if html:
        m.add_alternative(
            "<html><body><p>Verify within 24 hours or lose access.</p>"
            '<a href="http://198.51.100.7/login">https://www.paypal.com/verify</a>'
            "<script>alert(1)</script></body></html>",
            subtype="html",
        )
    return m


def forward_as_attachment(
    original: EmailMessage, *, sender: str = "Alice <alice@example.org>", auth: str | None = SES_AUTH
) -> bytes:
    outer = EmailMessage()
    if auth:
        outer["Authentication-Results"] = auth
    outer["From"] = sender
    outer["To"] = "phishing@example.org"
    outer["Subject"] = "Fwd: Your account is suspended"
    outer.set_content("Is this real?")
    outer.add_attachment(original)
    return outer.as_bytes(policy=SMTP)


def forward_inline(auth: str | None = SES_AUTH) -> bytes:
    outer = EmailMessage()
    if auth:
        outer["Authentication-Results"] = auth
    outer["From"] = "alice@example.org"
    outer["To"] = "phishing@example.org"
    outer["Subject"] = "Fwd: Invoice overdue"
    outer.set_content(
        "Please check this one, see https://intranet.example.org/help\n\n"
        "---------- Forwarded message ---------\n"
        "From: Billing <billing@invoices-example.net>\n"
        "Subject: Invoice overdue\n\n"
        "Pay now at https://pay.invoices-example.net/x or your service stops today.\n"
    )
    return outer.as_bytes(policy=SMTP)


@pytest.fixture
def cfg() -> Settings:
    return Settings(
        sender="noreply@example.org", receiver="phishing@example.org", catch_all=None, help_contact="help@example.org"
    )
