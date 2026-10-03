"""Lambda entry point: S3 "object created" events written by the SES receipt rule."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from . import guardrails, services
from .classifier import ClassificationError, Verdict, classify
from .config import Settings
from .parsing import RESTRICTED_TLP, ParsedEmail, parse_email, parse_headers, tlp_from_raw
from .render import Reply, ReportContext, defang, render_restricted_notice, render_unavailable, render_verdict

logger = logging.getLogger("phishing_detector")
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SKIP_KEYS = {"AMAZON_SES_SETUP_NOTIFICATION"}
_NO_REPLY_LOCALPARTS = {"mailer-daemon", "postmaster", "noreply", "no-reply", "donotreply", "bounce", "bounces"}

_settings: Settings | None = None


class _NotSent(ClassificationError):
    """A deliberate skip (policy), not a failure: same NOT ANALYZED reply, logged at INFO."""


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
    # The catch-all is for our own people whose forward failed authentication, not internet mail.
    if cfg.catch_all and fwd and _domain_allowed(fwd, cfg.catch_all_domains):
        return Route(cfg.catch_all, problem, catch_all=True)
    return Route(None, problem)


def _issue_body(key: str, email: ParsedEmail, verdict: Verdict | None, route: Route) -> str:
    """Metadata only: no body text, which can hold personal data a regex can't reliably redact."""
    from_domain = email.headers.get("From", "").rpartition("@")[2].strip(">").lower() or "unknown"

    def _host(href: str) -> str:
        try:
            return urllib.parse.urlsplit(href).hostname or ""
        except ValueError:
            return ""

    link_domains = sorted({_host(link.href) for link in email.links} - {""})[:20]
    lines = [
        f"**Verdict:** {verdict.verdict.value if verdict else 'not analyzed'}",
        f"**Why it went to the catch-all:** {route.reason}",
        f"**Forward type:** {email.forward_kind}",
        f"**Original sender domain:** `{services.redact(defang(from_domain)).replace('`', '')}`",
        f"**Stored email:** `{key}`",
        "",
        "**Link domains:** "
        + (", ".join(f"`{services.redact(defang(d)).replace('`', '')}`" for d in link_domains) or "none"),
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


def _context(key: str, email: ParsedEmail | None, cfg: Settings, subject: str | None = None) -> ReportContext:
    return ReportContext(
        original_subject=subject or (email.subject if email else "(unknown)"),
        forwarder=email.forwarder if email else None,
        received_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        ref=hashlib.sha256(key.encode()).hexdigest()[:8],
        help_contact=cfg.help_contact,
    )


def _send(
    idem: services.Idempotency, idem_key: str, token: str, reply: Reply, to: str, cfg: Settings, in_reply_to: str | None
) -> str:
    """Send at most once. After the request leaves, an error means "maybe sent": never retry it."""
    idem.mark_sending(idem_key, token)
    try:
        return services.send_reply(
            reply, sender=cfg.sender, to=to, configuration_set=cfg.ses_configuration_set, in_reply_to=in_reply_to
        )
    except services.SendRejected:
        raise  # SES refused before sending: safe to retry
    except Exception as exc:
        idem.complete(idem_key, token, "send_unknown")
        logger.error("reply may or may not have been sent; not retrying", extra={"key": idem_key, "error": repr(exc)})
        raise services.SendUnknown(str(exc)) from exc


def process(bucket: str, key: str, cfg: Settings, deadline: float | None = None) -> str:
    idem = services.Idempotency(cfg.idempotency_table, stale_after=cfg.idempotency_stale_seconds)
    idem_key = f"{bucket}/{key}"
    token = idem.claim(idem_key)  # raises InFlight -> Lambda retries -> failure queue
    if token is None:
        logger.info("duplicate event skipped", extra={"key": key})
        return "duplicate"

    try:
        raw = services.fetch_email(bucket, key, cfg.max_email_bytes)
    except services.EmailGone:
        idem.complete(idem_key, token, "gone")
        return "gone"
    except services.EmailTooLarge as exc:
        return _not_analyzed(
            exc.head, key, cfg, idem, idem_key, token, "too_large", "The email was too large to analyze automatically."
        )
    except Exception:
        idem.release(idem_key, token)  # transient S3 problem: let Lambda retry
        raise

    # Route on headers first: nobody we wouldn't answer gets to make us open their attachments.
    try:
        early = route_reply(parse_headers(raw), cfg)
    except Exception:
        early = None
    if early is not None and early.to is None:
        logger.warning("no reply sent", extra={"key": key, "reason": early.reason})
        idem.complete(idem_key, token, "dropped")
        _mark_if_restricted(bucket, key, tlp_from_raw(raw))
        return "dropped"

    try:
        email = parse_email(raw, max_body_chars=cfg.max_body_chars)
    except Exception as exc:  # malformed or hostile MIME: retrying won't help
        logger.warning("email could not be parsed", extra={"key": key, "error": type(exc).__name__})
        return _not_analyzed(
            raw[: 256 * 1024],
            key,
            cfg,
            idem,
            idem_key,
            token,
            "unparseable",
            "The email could not be read automatically.",
        )

    try:
        route = route_reply(email, cfg)
        _mark_if_restricted(bucket, key, email.tlp)  # before any send: cleanup can't depend on finishing
        if route.to is None:
            logger.warning("no reply sent", extra={"key": key, "reason": route.reason})
            idem.complete(idem_key, token, "dropped")
            return "dropped"

        ctx = _context(key, email, cfg)
        verdict: Verdict | None
        try:
            if email.tlp_restricted and not cfg.analyze_tlp_restricted:
                # A third-party provider would process it outside the operator's AWS account.
                raise _NotSent(f"{email.tlp} report not sent to the model (ANALYZE_TLP_RESTRICTED is off)")
            verdict = classify(email, cfg, deadline=deadline)
            verdict, raised = guardrails.apply(email, verdict)
            if raised:
                logger.info(
                    "guardrails raised verdict", extra={"key": key, "verdict": verdict.verdict.value, "reasons": raised}
                )
            reply: Reply = render_verdict(verdict, ctx)
            if route.catch_all and email.tlp_restricted:
                # TLP:AMBER/RED may not be shared further: the catch-all learns only that it arrived.
                reply = render_restricted_notice(ctx, email.tlp, reply.subject.split(": ", 1)[1].split(" (")[0])
        except ClassificationError as exc:
            if isinstance(exc, _NotSent):
                logger.info("not analyzed by policy", extra={"key": key, "reason": str(exc)})
            else:
                logger.error("classification failed", extra={"key": key, "error": str(exc)})
            verdict = None
            reply = render_unavailable(ctx)
            if route.catch_all and email.tlp_restricted:
                reply = render_restricted_notice(ctx, email.tlp, "NOT ANALYZED")

        message_id = _send(idem, idem_key, token, reply, route.to, cfg, email.outer_message_id)
    except services.SendUnknown:
        return "send_unknown"
    except Exception:
        idem.release(idem_key, token)  # let the Lambda retry (and then the failure queue) handle it
        raise

    outcome = verdict.verdict.value if verdict else "unavailable"
    idem.complete(idem_key, token, f"{outcome};tlp={email.tlp}" if email.tlp_restricted else outcome)
    logger.info(
        "reply sent", extra={"key": key, "verdict": outcome, "catch_all": route.catch_all, "ses_message_id": message_id}
    )

    if route.catch_all and cfg.github_repo and cfg.github_token_secret_arn and not email.tlp_restricted:
        services.open_github_issue(
            repo=cfg.github_repo,
            token_secret_arn=cfg.github_token_secret_arn,
            title=f"[{outcome}] report {_context(key, email, cfg).ref}",
            body=_issue_body(key, email, verdict, route),
        )
    return outcome


def _mark_if_restricted(bucket: str, key: str, tlp: str | None) -> None:
    """TLP:AMBER/RED: tag for expiry (the lifecycle rule removes it within ~1-2 days). The bucket
    otherwise keeps emails forever and is readable more widely than the original recipients."""
    if tlp not in RESTRICTED_TLP:
        return
    try:
        services.mark_restricted(bucket, key, tlp)
        logger.info("TLP-restricted email tagged for expiry", extra={"key": key, "tlp": tlp})
    except Exception:
        logger.error("could not tag TLP-restricted email", extra={"key": key, "tlp": tlp}, exc_info=True)


def _not_analyzed(
    head: bytes, key: str, cfg: Settings, idem, idem_key: str, token: str, outcome: str, reason: str
) -> str:
    """Route on the headers alone and tell the reporter the email could not be analyzed. Final:
    retrying the same bytes would fail the same way."""
    try:
        try:
            email = parse_headers(head)
        except Exception:
            email = None
        route = route_reply(email, cfg) if email else Route(None, "unparseable headers")
        tlp = tlp_from_raw(head)
        _mark_if_restricted(idem_key.split("/", 1)[0], key, tlp)
        if route.to:
            ctx = _context(key, email, cfg)
            reply = render_unavailable(ctx, reason=reason)
            if route.catch_all and tlp in RESTRICTED_TLP:
                reply = render_restricted_notice(ctx, tlp, "NOT ANALYZED")
            _send(idem, idem_key, token, reply, route.to, cfg, email.outer_message_id if email else None)
        else:
            logger.warning("no reply sent", extra={"key": key, "reason": route.reason})
    except services.SendUnknown:
        return "send_unknown"
    except Exception:
        idem.release(idem_key, token)
        raise
    idem.complete(idem_key, token, outcome)
    return outcome


def _deadline(context: Any) -> float | None:
    """Monotonic time by which the model call must finish, leaving room to send the reply."""
    remaining_ms = getattr(context, "get_remaining_time_in_millis", None)
    # Leave 30 s to render and send the reply (SES client: 10 s read timeout, 2 attempts).
    return time.monotonic() + remaining_ms() / 1000 - 30 if remaining_ms else None


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
