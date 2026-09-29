"""Lambda entry point: S3 "object created" events written by the SES receipt rule."""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

from . import services
from .classifier import ClassificationError, Verdict, classify
from .config import Settings
from .parsing import ParsedEmail, parse_email
from .render import Reply, defang, render_unavailable, render_verdict

logger = logging.getLogger("phishing_detector")
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SKIP_KEYS = {"AMAZON_SES_SETUP_NOTIFICATION"}
_NO_REPLY_LOCALPARTS = {"mailer-daemon", "postmaster", "noreply", "no-reply", "donotreply", "bounce", "bounces"}

_settings: Settings | None = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings


@dataclass(frozen=True)
class Route:
    to: str | None
    reason: str
    catch_all: bool = False


def _domain_allowed(address: str, allowed: frozenset[str]) -> bool:
    domain = address.rpartition("@")[2]
    return any(domain == d or domain.endswith("." + d) for d in allowed)


def route_reply(email: ParsedEmail, cfg: Settings) -> Route:
    """Decide who, if anyone, gets the report. Pure, so every branch is unit-tested.

    The catch-all only receives reports that plausibly came from inside the organization (allowed
    domain, or no allowlist) but failed authentication, never arbitrary internet traffic.
    """
    fwd = email.forwarder
    auth = email.sender_auth
    if email.auto_submitted:
        return Route(None, "automated message (loop protection)")
    if fwd and (fwd in {cfg.receiver, cfg.sender} or fwd.partition("@")[0] in _NO_REPLY_LOCALPARTS):
        return Route(None, "From is a service or no-reply address")
    if fwd and cfg.allowed_sender_domains and not _domain_allowed(fwd, cfg.allowed_sender_domains):
        return Route(None, "forwarder domain not in ALLOWED_SENDER_DOMAINS")

    authenticated = bool(fwd) and (not cfg.require_sender_auth or auth.dmarc_pass_for(fwd))
    if authenticated:
        # A virus verdict is shown to the model as evidence; the reporter still gets the answer.
        return Route(fwd, "authenticated forwarder")

    problem = "no single valid From address" if not fwd else f"forwarder failed DMARC (dmarc={auth.dmarc})"
    if auth.spam == "FAIL" and not authenticated:
        return Route(None, f"{problem}; SES spam verdict FAIL")
    if cfg.catch_all:
        return Route(cfg.catch_all, problem, catch_all=True)
    return Route(None, problem)


def _issue_body(key: str, email: ParsedEmail, verdict: Verdict | None, route: Route) -> str:
    """Metadata only: no body text, which can hold personal data a regex can't reliably redact."""
    from_domain = email.headers.get("From", "").rpartition("@")[2].strip(">").lower() or "unknown"
    link_domains = sorted({urllib.parse.urlsplit(link.href).hostname or "" for link in email.links} - {""})[:20]
    lines = [
        f"**Verdict:** {verdict.verdict.value if verdict else 'not analyzed'}",
        f"**Why it went to the catch-all:** {route.reason}",
        f"**Forward type:** {email.forward_kind}",
        f"**Original sender domain:** `{defang(from_domain)}`",
        f"**Stored email:** `{key}`",
        "",
        "**Link domains:** " + (", ".join(f"`{defang(d)}`" for d in link_domains) or "none"),
        "",
        "**Attachments:**",
        *[
            f"- `{services.redact(a.filename)}` ({a.content_type}, {a.size} bytes, sha256 `{a.sha256}`)"
            for a in email.attachments
        ],
    ]
    if verdict:
        lines += ["", "**Indicators:**", *[f"- {services.redact(defang(i))}" for i in verdict.indicators]]
    return "\n".join(lines)


def process(bucket: str, key: str, cfg: Settings, deadline: float | None = None) -> str:
    idem = services.Idempotency(cfg.idempotency_table, stale_after=cfg.idempotency_stale_seconds)
    idem_key = f"{bucket}/{key}"
    token = idem.claim(idem_key)  # raises InFlight -> Lambda retries -> failure queue
    if token is None:
        logger.info("duplicate event skipped", extra={"key": key})
        return "duplicate"

    try:
        raw = services.fetch_email(bucket, key, cfg.max_email_bytes)
        email = parse_email(raw, max_body_chars=cfg.max_body_chars)
        route = route_reply(email, cfg)
        if route.to is None:
            logger.warning("no reply sent", extra={"key": key, "reason": route.reason})
            idem.complete(idem_key, token, "dropped")
            return "dropped"

        verdict: Verdict | None
        try:
            verdict = classify(email, cfg, deadline=deadline)
            reply: Reply = render_verdict(verdict, email.subject, cfg.help_contact)
        except ClassificationError as exc:
            logger.error("classification failed", extra={"key": key, "error": str(exc)})
            verdict = None
            reply = render_unavailable(email.subject, cfg.help_contact)

        message_id = services.send_reply(
            reply, sender=cfg.sender, to=route.to, configuration_set=cfg.ses_configuration_set
        )
    except services.EmailTooLarge as exc:
        return _too_large(exc, key, cfg, idem, idem_key, token)
    except Exception:
        idem.release(idem_key, token)  # let the Lambda retry (and then the failure queue) handle it
        raise

    outcome = verdict.verdict.value if verdict else "unavailable"
    idem.complete(idem_key, token, outcome)
    logger.info(
        "reply sent", extra={"key": key, "verdict": outcome, "catch_all": route.catch_all, "ses_message_id": message_id}
    )

    if route.catch_all and cfg.github_repo and cfg.github_token_secret_arn:
        services.open_github_issue(
            repo=cfg.github_repo,
            token_secret_arn=cfg.github_token_secret_arn,
            title=f"[{outcome}] {email.subject}",
            body=_issue_body(key, email, verdict, route),
        )
    return outcome


def _too_large(exc: services.EmailTooLarge, key: str, cfg: Settings, idem, idem_key: str, token: str) -> str:
    """Route on the headers alone and tell the reporter it could not be analyzed."""
    logger.warning("email too large to analyze", extra={"key": key, "error": str(exc)})
    try:
        email = parse_email(exc.head, max_body_chars=1)
        route = route_reply(email, cfg)
        if route.to:
            reply = render_unavailable(
                email.subject, cfg.help_contact, reason="The email was too large to analyze automatically."
            )
            services.send_reply(reply, sender=cfg.sender, to=route.to, configuration_set=cfg.ses_configuration_set)
    except Exception:
        idem.release(idem_key, token)
        raise
    idem.complete(idem_key, token, "too_large")
    return "too_large"


def _deadline(context: Any) -> float | None:
    """Monotonic time by which the model call must finish, leaving room to send the reply."""
    remaining_ms = getattr(context, "get_remaining_time_in_millis", None)
    return time.monotonic() + remaining_ms() / 1000 - 15 if remaining_ms else None


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    cfg = settings()
    results = []
    for record in event.get("Records", []):
        s3 = record.get("s3") or {}
        bucket = s3.get("bucket", {}).get("name")
        key = urllib.parse.unquote_plus(s3.get("object", {}).get("key", ""))
        if not bucket or not key or key.rsplit("/", 1)[-1] in SKIP_KEYS:
            continue
        results.append({"key": key, "outcome": process(bucket, key, cfg, _deadline(context))})
    return {"statusCode": 200, "body": json.dumps(results)}
