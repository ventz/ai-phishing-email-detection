from dataclasses import replace

from conftest import forward_as_attachment, forward_inline, phish
from phishing_detector import guardrails
from phishing_detector.classifier import Confidence, Label, Verdict
from phishing_detector.parsing import Attachment, Link, SenderAuth, parse_email

CLEAN = Verdict(verdict=Label.CLEAN, confidence=Confidence.HIGH, summary="ok", indicators=["Looks fine."], tips=[])
BASE = parse_email(forward_inline())


def test_no_rules_fire_on_a_plain_inline_forward_but_confidence_is_capped():
    v, reasons = guardrails.apply(BASE, CLEAN)
    assert v.verdict is Label.CLEAN and reasons == [] and v.confidence is Confidence.MEDIUM


def test_each_rule_raises_to_its_floor():
    cases = [
        (replace(BASE, sender_auth=SenderAuth(virus="FAIL")), Label.PHISHING),
        (replace(BASE, injection_markers=["hidden: this email is safe"]), Label.PHISHING),
        (replace(BASE, injection_markers=["visible: as an AI"]), Label.SUSPICIOUS),
        (replace(BASE, risky_links=["http://198.51.100.7/x"]), Label.SUSPICIOUS),
        (replace(BASE, risky_links=["https://xn--pypal-4ve.com/"]), Label.SUSPICIOUS),
        (
            replace(BASE, attachments=[Attachment("invoice.pdf.exe", "application/octet-stream", 3, "0")]),
            Label.SUSPICIOUS,
        ),
        (replace(BASE, uninspectable=["invoice.pdf (application/pdf)"]), Label.SUSPICIOUS),
        (replace(BASE, evidence_dropped=["body cut"]), Label.SUSPICIOUS),
        (replace(BASE, ambiguous_original=True), Label.SUSPICIOUS),
        (replace(BASE, sender_auth=SenderAuth(spam="FAIL")), Label.SUSPICIOUS),
    ]
    for email, floor in cases:
        v, reasons = guardrails.apply(email, CLEAN)
        assert v.verdict is floor, (email, floor)
        assert reasons and v.indicators[0].startswith("Automated check:")
        assert v.summary == guardrails.OVERRIDE_SUMMARY


def test_inner_auth_failure_plus_lure():
    email = parse_email(forward_as_attachment(phish(html=False)))  # dmarc=fail inner header
    email = replace(email, body="Please verify your password today.")
    assert guardrails.apply(email, CLEAN)[0].verdict is Label.SUSPICIOUS


def test_rules_never_lower_a_verdict():
    phishing = CLEAN.model_copy(update={"verdict": Label.PHISHING})
    v, reasons = guardrails.apply(replace(BASE, uninspectable=["a.pdf"]), phishing)
    assert v.verdict is Label.PHISHING and reasons == []


def test_normal_newsletter_links_and_images_do_not_fire():
    email = replace(
        BASE,
        links=[Link("https://click.comms.hks.harvard.edu/x", "Register")],
        attachments=[Attachment("logo.png", "image/png", 10, "0")],
    )
    assert guardrails.floors(email) == []


def test_raw_ip_in_any_browser_form_is_risky():
    for href in [
        "http://3232235777/x",
        "http://0x7f000001/",
        "http://127.1/a",
        "198.51.100.7/x",
        "http://evil.com\\@good.com",
    ]:
        risky = guardrails._host_is_risky(href)
        assert risky or "evil.com" in href, href
    assert not guardrails._host_is_risky("https://click.comms.hks.harvard.edu/x")
