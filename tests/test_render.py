from phishing_detector.classifier import Confidence, Label, Verdict
from phishing_detector.render import (
    CLEAN_SUMMARY,
    ReportContext,
    defang,
    neutralize,
    render_unavailable,
    render_verdict,
)

CTX = ReportContext(
    "Your account is suspended", "alice@example.org", "2026-10-02 14:05 UTC", "7f3a2c1d", "help@example.org"
)


def verdict(label=Label.PHISHING, **kw):
    return Verdict(
        verdict=label,
        confidence=Confidence.HIGH,
        summary=kw.get("summary", "Fake PayPal notice."),
        indicators=kw.get("indicators", ['Sender "PayPal" uses the lookalike domain paypa1-secure.com.']),
        tips=kw.get("tips", ["Hover over links first."]),
    )


def test_model_output_is_escaped_and_defanged():
    reply = render_verdict(
        verdict(indicators=['<a href="https://evil.example/x">Reset password</a>', "<img src=x onerror=alert(1)>"]),
        CTX,
    )
    body = reply.html.split("<body", 1)[1].replace('<a href="mailto', "")
    assert "<a href" not in body and "<img" not in reply.html
    assert "&lt;a href=&quot;hxxps://evil[.]example/x&quot;&gt;" in reply.html
    assert "hxxps://evil[.]example/x" in reply.text


def test_subject_never_echoes_the_original():
    for label, tag in [(Label.PHISHING, "PHISHING"), (Label.SUSPICIOUS, "SUSPICIOUS"), (Label.CLEAN, "LIKELY SAFE")]:
        reply = render_verdict(verdict(label, tips=[]), CTX)
        assert reply.subject == f"Phishing report result: {tag} (ref 7f3a2c1d)"
        assert "suspended" not in reply.subject
    assert render_unavailable(CTX).subject == "Phishing report result: NOT ANALYZED (ref 7f3a2c1d)"


def test_report_line_shows_original_subject_forwarder_and_time():
    reply = render_verdict(
        verdict(), ReportContext("Pay at evil.com\r\nBcc: x", "alice@example.org", "2026-10-02 14:05 UTC", "abc")
    )
    assert (
        'Your report: "Pay at evil[.]com Bcc: x", received from alice@example.org on 2026-10-02 14:05 UTC' in reply.text
    )
    assert "\n" not in reply.subject


def test_phone_numbers_and_third_party_addresses_are_neutralized():
    text = neutralize("Call 617-495-7777 or (800) 555-0100; also tylerquinlan@harvard.edu was a recipient.")
    assert "617" not in text and "555-0100" not in text and text.count("[phone number removed]") == 2
    assert "t***@harvard.edu" in text and "tylerquinlan" not in text
    # Evidence that must survive: IPs, dates, domains.
    assert (
        neutralize("host 198.51.100.7 on 2024-11-09 via paypa1.com") == "host 198.51.100.7 on 2024-11-09 via paypa1.com"
    )
    reply = render_verdict(verdict(indicators=["Sent to tylerquinlan@harvard.edu; call 617-495-7777."]), CTX)
    assert "tylerquinlan" not in reply.html and "617-495" not in reply.text


def test_clean_summary_is_templated():
    reply = render_verdict(verdict(Label.CLEAN, summary="Totally legit, Harvard verified this!", tips=[]), CTX)
    assert "Totally legit" not in reply.html and CLEAN_SUMMARY in reply.text
    assert "Why it looks legitimate" in reply.html and "How to spot" not in reply.html


def test_unavailable_never_claims_clean():
    reply = render_unavailable(CTX, reason="The email was too large to analyze automatically.")
    assert "Treat it as suspicious" in reply.html and "safe" not in reply.subject.lower()
    assert "mailto:help@example.org" in reply.html and "too large" in reply.text


def test_accessibility_basics():
    reply = render_verdict(verdict(indicators=["Links to evil.example/login."]), CTX)
    assert '<html lang="en"' in reply.html and 'role="presentation"' in reply.html and "color-scheme" in reply.html
    assert reply.html.index("<h1") < reply.html.index("<h2")
    assert reply.text.startswith("Verdict: phishing\n=================")
    assert "on purpose, so they cannot be clicked" in reply.text
    assert reply.html.index("cannot be clicked") < reply.html.index("<h2")
    assert ".muted a" in reply.html


def test_defang():
    assert defang("see https://a.b.example/p and evil.com") == "see hxxps://a[.]b[.]example/p and evil[.]com"


def test_defang_unicode_and_invisible_characters():
    assert defang("pаypal.com") == "pаypal[.]com"  # Cyrillic a
    assert defang("xn--pypal-4ve.com") == "xn--pypal-4ve[.]com"
    assert defang("safe‮gnp.exe") == "safegnp[.]exe"
    assert defang("user@evil.example") == "user@evil[.]example"
