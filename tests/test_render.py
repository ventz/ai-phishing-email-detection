from phishing_detector.classifier import Confidence, Label, Verdict
from phishing_detector.render import defang, render_unavailable, render_verdict


def verdict(label=Label.PHISHING, **kw):
    return Verdict(
        verdict=label,
        confidence=Confidence.HIGH,
        summary=kw.get("summary", "Fake PayPal notice."),
        indicators=kw.get("indicators", ['Sender "PayPal" <service@paypa1-secure.com> is a lookalike.']),
        tips=kw.get("tips", ["Hover over links first."]),
    )


def test_model_output_is_escaped_and_defanged():
    reply = render_verdict(
        verdict(indicators=['<a href="https://evil.example/x">Reset password</a>', "<img src=x onerror=alert(1)>"]),
        "Hello",
    )
    assert "<a href" not in reply.html.split("<body", 1)[1].replace('<a href="mailto', "")
    assert "<img" not in reply.html
    assert "&lt;a href=&quot;hxxps://evil[.]example/x&quot;&gt;" in reply.html
    assert "hxxps://evil[.]example/x" in reply.text


def test_sender_address_survives_escaping():
    reply = render_verdict(verdict(), "Hello")
    assert "&lt;service@paypa1-secure[.]com&gt;" in reply.html


def test_subjects_and_headings_per_verdict():
    assert render_verdict(verdict(), "Hi").subject == "[PHISHING] Hi"
    assert render_verdict(verdict(Label.SUSPICIOUS), "Hi").subject == "[SUSPICIOUS] Hi"
    clean = render_verdict(verdict(Label.CLEAN, tips=[]), "Hi")
    assert clean.subject == "[LIKELY SAFE] Hi"
    assert "Why it looks legitimate" in clean.html and "How to spot" not in clean.html


def test_unavailable_never_claims_clean():
    reply = render_unavailable("Hi", "help@example.org")
    assert reply.subject == "[NOT ANALYZED] Hi"
    assert "Treat it as suspicious" in reply.html and "safe" not in reply.subject.lower()
    assert "mailto:help@example.org" in reply.html


def test_accessibility_basics():
    reply = render_verdict(verdict(), "Hi")
    assert '<html lang="en"' in reply.html
    assert 'role="presentation"' in reply.html
    assert "color-scheme" in reply.html
    assert reply.html.index("<h1") < reply.html.index("<h2")
    assert reply.text.startswith("Verdict: phishing\n=================")
    assert "on purpose, so they cannot be clicked" in reply.text  # explained before the defanged items
    assert reply.html.index("cannot be clicked") < reply.html.index("<h2")
    assert ".muted a" in reply.html  # dark-mode link color
    assert "- Hover over links first." in reply.text


def test_subject_header_injection_is_flattened():
    assert "\n" not in render_verdict(verdict(), "Hi\r\nBcc: x@y.z").subject


def test_defang():
    assert defang("see https://a.b.example/p and evil.com") == "see hxxps://a[.]b[.]example/p and evil[.]com"


def test_defang_unicode_and_invisible_characters():
    assert defang("pаypal.com") == "pаypal[.]com"  # Cyrillic a
    assert defang("xn--pypal-4ve.com") == "xn--pypal-4ve[.]com"
    assert defang("safe\u202egnp.exe") == "safegnp[.]exe"
    assert defang("user@evil.example") == "user@evil[.]example"
