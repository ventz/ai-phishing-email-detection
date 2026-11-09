"""Regression tests for the 2026-11-09 security review findings."""

import time
from email.message import EmailMessage

from conftest import forward_as_attachment, phish
from phishing_detector import parsing, render, urls


def test_unmatched_end_tags_parse_in_linear_time():
    n = 140_000  # just under 1 MB of HTML; the old stack scan took minutes
    msg = phish(html=False)
    msg.add_alternative("<html><body>" + "<b>" * n + "</i>" * n + "</body></html>", subtype="html")
    start = time.monotonic()
    parsing.parse_email(forward_as_attachment(msg))
    assert time.monotonic() - start < 5


def test_proofpoint_v3_unwrap_is_linear():
    start = time.monotonic()
    urls.unwrap("https://urldefense.com/v3/__" + "__;a" * 200_000)
    assert time.monotonic() - start < 1


def test_tlp_marking_after_body_cut_is_still_detected():
    msg = EmailMessage()
    msg["From"] = "someone@partner.example"
    msg["Subject"] = "Incident details"
    msg.set_content("x " * 40_000 + "\nTLP:RED\n")
    email = parsing.parse_email(forward_as_attachment(msg), max_body_chars=1_000)
    assert email.tlp == "RED" and email.tlp_restricted


def test_email_nested_inside_the_original_is_uninspectable():
    lure = phish()
    cover = EmailMessage()
    cover["From"] = "colleague@example.org"
    cover["Subject"] = "see attached"
    cover.set_content("FYI")
    cover.add_attachment(lure)
    email = parsing.parse_email(forward_as_attachment(cover))
    assert any("an email inside the reported email" in u for u in email.uninspectable)


def test_ftp_and_ip_literal_links_are_defanged():
    out = render.defang("ftp://203.0.113.10/payload https://198.51.100.7/x")
    assert "ftp://" not in out and "203.0.113.10" not in out and "198.51.100.7" not in out
