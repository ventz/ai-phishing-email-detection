from email.message import EmailMessage
from email.policy import SMTP

import pytest

from conftest import SES_AUTH, forward_as_attachment, forward_inline, phish
from phishing_detector.parsing import parse_email


def test_attachment_forward_extracts_original_headers_links_and_both_parts():
    email = parse_email(forward_as_attachment(phish()))

    assert email.forward_kind == "attachment"
    assert email.forwarder == "alice@example.org"
    assert email.subject == "Your account is suspended"
    assert email.headers["Reply-To"] == "collect@evil.example"
    assert "dmarc=fail" in email.headers["Authentication-Results"]
    # Anchor text vs real destination is preserved.
    assert any(l.href == "http://198.51.100.7/login" and "paypal.com" in l.text for l in email.links)
    # The harmless text/plain alternative does not hide the malicious HTML.
    assert "Verify within 24 hours" in email.body
    assert "text/plain alternative differs" in email.body
    assert "alert(1)" not in email.body


def test_sender_auth_trusts_only_the_topmost_ses_header():
    outer = EmailMessage()
    outer["Authentication-Results"] = "amazonses.com; spf=fail; dkim=fail; dmarc=fail header.from=evil.example;"
    outer["Authentication-Results"] = SES_AUTH  # attacker-supplied, below the SES one
    outer["From"] = "alice@example.org"
    outer.set_content("hi")
    email = parse_email(outer.as_bytes(policy=SMTP))

    assert email.sender_auth.dmarc == "fail"
    assert not email.sender_auth.dmarc_pass_for("alice@example.org")


def test_dmarc_pass_must_match_forwarder_domain():
    email = parse_email(forward_as_attachment(phish(), sender="mallory@evil.example"))
    assert email.sender_auth.dmarc == "pass"
    assert not email.sender_auth.dmarc_pass_for(email.forwarder)


def test_inline_forward_analyzes_text_below_the_marker():
    email = parse_email(forward_inline())

    assert email.forward_kind == "inline"
    assert email.subject == "Invoice overdue"
    assert email.body.startswith("From: Billing")
    assert "intranet.example.org" not in email.body
    assert all("intranet" not in l.href for l in email.links)
    assert email.headers == {}


def test_first_attached_message_wins_over_nested_decoy():
    decoy = EmailMessage()
    decoy["From"] = "friend@example.org"
    decoy["Subject"] = "harmless"
    decoy.set_content("nothing to see")
    carrier = phish(html=False)
    carrier.add_attachment(decoy)
    email = parse_email(forward_as_attachment(carrier))
    assert email.subject == "Your account is suspended"


def test_multiple_from_addresses_yield_no_forwarder():
    raw = forward_as_attachment(phish(), sender="a@example.org, b@example.org")
    assert parse_email(raw).forwarder is None


def test_body_truncation_is_flagged():
    big = phish(html=False)
    big.set_content("x " * 50_000)
    email = parse_email(forward_as_attachment(big), max_body_chars=1_000)
    assert email.truncated and len(email.body) == 1_000
    assert "(truncated)" in email.to_prompt()


def test_auto_submitted_is_detected():
    m = EmailMessage()
    m["From"] = "mailer-daemon@example.org"
    m["Auto-Submitted"] = "auto-replied"
    m.set_content("bounce")
    assert parse_email(m.as_bytes(policy=SMTP)).auto_submitted


def test_attachments_are_listed_with_hash():
    carrier = phish(html=False)
    carrier.add_attachment(b"MZ\x90\x00", maintype="application", subtype="octet-stream", filename="invoice.exe")
    email = parse_email(forward_as_attachment(carrier))
    [att] = email.attachments
    assert att.filename == "invoice.exe" and att.size == 4 and len(att.sha256) == 64


def test_envelope_from_cannot_forge_dmarc_verdict():
    # MAIL FROM:<dmarc=pass@attacker.example> echoed by SES before the real dmarc=fail clause.
    auth = (
        "amazonses.com; spf=pass (spfCheck: ok) client-ip=192.0.2.9; envelope-from=dmarc=pass@attacker.example; "
        "helo=x; dkim=none; dmarc=fail header.from=victim.org;"
    )
    raw = forward_as_attachment(phish(), sender="ceo@victim.org", auth=auth)
    email = parse_email(raw)
    assert email.sender_auth.dmarc == "fail"
    assert not email.sender_auth.dmarc_pass_for("ceo@victim.org")


def test_comment_and_quoted_text_cannot_forge_dmarc():
    auth = 'amazonses.com; spf=pass (x; dmarc=pass header.from=victim.org) smtp.mailfrom="a;dmarc=pass header.from=victim.org"@x; dmarc=fail header.from=victim.org;'
    email = parse_email(forward_as_attachment(phish(), sender="ceo@victim.org", auth=auth))
    assert email.sender_auth.dmarc == "fail"


def test_ses_header_must_be_first_authentication_results():
    outer = EmailMessage()
    outer["Authentication-Results"] = "mx.other; dmarc=fail"
    outer["Authentication-Results"] = SES_AUTH
    outer["From"] = "alice@example.org"
    outer.set_content("hi")
    assert parse_email(outer.as_bytes(policy=SMTP)).sender_auth.dmarc == "none"


def test_duplicate_from_headers_yield_no_forwarder():
    raw = forward_as_attachment(phish()).replace(b"From: Alice", b"From: ceo@victim.org\r\nFrom: Alice", 1)
    assert parse_email(raw).forwarder is None


def test_inline_forward_wins_over_reattached_decoy_eml():
    decoy = EmailMessage()
    decoy["From"] = "friend@example.org"
    decoy["Subject"] = "harmless"
    decoy.set_content("nothing to see")
    outer = EmailMessage()
    outer["From"] = "alice@example.org"
    outer["Subject"] = "Fwd: urgent"
    outer.set_content(
        "---------- Forwarded message ---------\nFrom: x@evil.example\nSubject: urgent\n\nWire $5,000 now."
    )
    outer.add_attachment(decoy)
    email = parse_email(outer.as_bytes(policy=SMTP))
    assert email.forward_kind == "inline" and "Wire $5,000" in email.body


def test_html_attachment_and_form_targets_reach_the_model():
    carrier = phish(html=False)
    carrier.add_attachment(
        b'<html><body><p>Sign in to view your invoice</p><form action="https://collect.evil.example/p">'
        b'<meta http-equiv="refresh" content="0;url=https://redirect.evil.example"></form></body></html>',
        maintype="text",
        subtype="html",
        filename="Invoice.htm",
    )
    email = parse_email(forward_as_attachment(carrier))
    assert "[HTML attachment: Invoice.htm]" in email.body and "Sign in to view" in email.body
    hrefs = {link.href for link in email.links}
    assert {"https://collect.evil.example/p", "https://redirect.evil.example"} <= hrefs


def test_list_and_bounce_traffic_is_automated():
    for header, value in [("List-Id", "<x.example.org>"), ("Precedence", "bulk"), ("Return-Path", "<>")]:
        m = EmailMessage()
        m["From"] = "someone@example.org"
        m[header] = value
        m.set_content("x")
        assert parse_email(m.as_bytes(policy=SMTP)).auto_submitted, header


@pytest.mark.parametrize(
    ("maintype", "subtype", "filename"),
    [("application", "octet-stream", "invoice.html"), ("image", "svg+xml", "doc.svg"), ("text", "html", "a.htm")],
)
def test_html_like_attachments_are_read_whatever_their_type(maintype, subtype, filename):
    carrier = phish(html=False)
    carrier.add_attachment(
        b'<html><a href="https://steal.evil.example/x">Open</a><meta http-equiv="refresh" content="0; URL=https://r.evil.example"></html>',
        maintype=maintype,
        subtype=subtype,
        filename=filename,
    )
    email = parse_email(forward_as_attachment(carrier))
    hrefs = {link.href for link in email.links}
    assert {"https://steal.evil.example/x", "https://r.evil.example"} <= hrefs


def test_outlook_header_block_inline_forward():
    outer = EmailMessage()
    outer["From"] = "alice@example.org"
    outer["Subject"] = "FW: Payroll"
    outer.set_content(
        "Thoughts?\n\nFrom: HR <hr@payro1l.example>\nSent: Monday\nTo: Alice\nSubject: Payroll update\n\nConfirm your bank details."
    )
    email = parse_email(outer.as_bytes(policy=SMTP))
    assert email.forward_kind == "inline" and email.body.startswith("From: HR") and email.subject == "Payroll update"


def test_eml_attachment_as_octet_stream():
    inner = phish(html=False)
    outer = EmailMessage()
    outer["From"] = "alice@example.org"
    outer.set_content("see attached")
    outer.add_attachment(
        inner.as_bytes(policy=SMTP), maintype="application", subtype="octet-stream", filename="msg.eml"
    )
    email = parse_email(outer.as_bytes(policy=SMTP))
    assert email.forward_kind == "attachment" and email.subject == "Your account is suspended"
