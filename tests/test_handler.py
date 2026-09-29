from dataclasses import replace

import pytest

from conftest import forward_as_attachment, forward_inline, phish
from phishing_detector import handler, services
from phishing_detector.classifier import ClassificationError, Confidence, Label, Verdict
from phishing_detector.parsing import parse_email


def test_route_authenticated_forwarder(cfg):
    route = handler.route_reply(parse_email(forward_inline()), cfg)
    assert route.to == "alice@example.org" and not route.catch_all


def test_route_spoofed_forwarder_is_dropped_or_sent_to_catch_all(cfg):
    spoofed = parse_email(forward_inline(auth=None))
    assert handler.route_reply(spoofed, cfg).to is None
    route = handler.route_reply(spoofed, replace(cfg, catch_all="soc@example.org"))
    assert route.to == "soc@example.org" and route.catch_all


def test_route_auth_can_be_disabled(cfg):
    spoofed = parse_email(forward_inline(auth=None))
    assert handler.route_reply(spoofed, replace(cfg, require_sender_auth=False)).to == "alice@example.org"


def test_route_domain_allowlist(cfg):
    email = parse_email(forward_inline())
    assert handler.route_reply(email, replace(cfg, allowed_sender_domains=frozenset({"other.org"}))).to is None
    assert handler.route_reply(email, replace(cfg, allowed_sender_domains=frozenset({"example.org"}))).to


def test_route_external_domains_never_reach_catch_all(cfg):
    email = parse_email(forward_inline(auth=None))
    c = replace(cfg, catch_all="soc@example.org", allowed_sender_domains=frozenset({"other.org"}))
    assert handler.route_reply(email, c).to is None


def test_route_spam_fail_unauthenticated_is_dropped(cfg):
    raw = forward_inline(auth=None).replace(b"From: alice", b"X-SES-Spam-Verdict: FAIL\r\nFrom: alice", 1)
    assert handler.route_reply(parse_email(raw), replace(cfg, catch_all="soc@example.org")).to is None


def test_route_virus_still_answers_authenticated_reporter_and_tells_model(cfg):
    raw = forward_inline().replace(b"From: alice", b"X-SES-Virus-Verdict: FAIL\r\nFrom: alice", 1)
    email = parse_email(raw)
    assert handler.route_reply(email, cfg).to == "alice@example.org"
    assert "virus=FAIL" in email.to_prompt()


def test_too_large_email_gets_not_analyzed_reply(monkeypatch, cfg, fakes):
    monkeypatch.setattr(handler, "_settings", cfg)
    head = forward_inline()

    def too_big(b, k, m):
        raise services.EmailTooLarge("big", head)

    monkeypatch.setattr(services, "fetch_email", too_big)
    assert "too_large" in handler.lambda_handler(event(), None)["body"]
    [(reply, kw)] = fakes
    assert kw["to"] == "alice@example.org" and reply.subject.startswith("[NOT ANALYZED]")
    assert "too large" in reply.text


def test_route_never_replies_to_itself(cfg):
    raw = forward_as_attachment(phish(), sender="phishing@example.org")
    assert handler.route_reply(parse_email(raw), replace(cfg, require_sender_auth=False)).to is None


@pytest.fixture
def fakes(monkeypatch):
    sent = []
    monkeypatch.setattr(services, "fetch_email", lambda b, k, m: forward_as_attachment(phish()))
    monkeypatch.setattr(services, "send_reply", lambda reply, **kw: sent.append((reply, kw)) or "msg-1")
    return sent


def event(key="abc123"):
    return {"Records": [{"s3": {"bucket": {"name": "bucket"}, "object": {"key": key}}}]}


def test_handler_end_to_end(monkeypatch, cfg, fakes):
    monkeypatch.setattr(handler, "_settings", cfg)
    monkeypatch.setattr(
        handler,
        "classify",
        lambda email, c, **kw: Verdict(
            verdict=Label.PHISHING, confidence=Confidence.HIGH, summary="Fake.", indicators=["Lookalike."], tips=[]
        ),
    )
    result = handler.lambda_handler(event(), None)
    assert '"outcome": "phishing"' in result["body"]
    [(reply, kw)] = fakes
    assert kw["to"] == "alice@example.org" and reply.subject.startswith("[PHISHING]")


def test_handler_classification_failure_sends_not_analyzed(monkeypatch, cfg, fakes):
    monkeypatch.setattr(handler, "_settings", cfg)

    def boom(email, c, **kw):
        raise ClassificationError("throttled")

    monkeypatch.setattr(handler, "classify", boom)
    handler.lambda_handler(event(), None)
    assert fakes[0][0].subject.startswith("[NOT ANALYZED]")


def test_handler_skips_ses_setup_notification(monkeypatch, cfg, fakes):
    monkeypatch.setattr(handler, "_settings", cfg)
    assert handler.lambda_handler(event("AMAZON_SES_SETUP_NOTIFICATION"), None)["body"] == "[]"
    assert fakes == []


def test_handler_duplicate_event_is_skipped(monkeypatch, cfg, fakes):
    monkeypatch.setattr(handler, "_settings", cfg)
    monkeypatch.setattr(services.Idempotency, "claim", lambda self, key: None)
    assert "duplicate" in handler.lambda_handler(event(), None)["body"]
    assert fakes == []


def test_handler_releases_claim_on_send_failure(monkeypatch, cfg):
    released = []
    monkeypatch.setattr(handler, "_settings", cfg)
    monkeypatch.setattr(services, "fetch_email", lambda b, k, m: forward_inline())
    monkeypatch.setattr(
        handler,
        "classify",
        lambda e, c, **kw: Verdict(
            verdict=Label.CLEAN, confidence=Confidence.LOW, summary="ok", indicators=["ok"], tips=[]
        ),
    )
    monkeypatch.setattr(services, "send_reply", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ses down")))
    monkeypatch.setattr(services.Idempotency, "release", lambda self, key, token: released.append(key))
    with pytest.raises(RuntimeError):
        handler.lambda_handler(event(), None)
    assert released == ["bucket/abc123"]


def test_in_flight_claim_raises_so_lambda_retries(monkeypatch, cfg):
    monkeypatch.setattr(handler, "_settings", cfg)

    def busy(self, key):
        raise services.InFlight(key)

    monkeypatch.setattr(services.Idempotency, "claim", busy)
    with pytest.raises(services.InFlight):
        handler.lambda_handler(event(), None)


def test_issue_body_has_no_email_text(cfg):
    email = parse_email(forward_as_attachment(phish()))
    body = handler._issue_body("k1", email, None, handler.Route("soc@example.org", "why", True))
    assert "Verify within 24 hours" not in body and "198.51.100.7" in body and "`k1`" in body
