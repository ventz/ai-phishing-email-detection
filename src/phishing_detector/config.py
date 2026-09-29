"""Runtime configuration, read once from environment variables and validated up front."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

DEFAULT_MODEL_ID = "anthropic.claude-opus-5-5"
RETIRED_ENV_VARS = (
    "AI_AWS_ACCESS_KEY_ID",
    "AI_AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "GITHUB_REPO_OWNER",
    "GITHUB_REPO_NAME",
)

logger = logging.getLogger(__name__)


class ConfigError(RuntimeError):
    """A required setting is missing or invalid."""


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, raw: str | None, default: int) -> int:
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be positive, got {value}")
    return value


def _csv(value: str | None) -> frozenset[str]:
    return frozenset(v.strip().lower() for v in (value or "").split(",") if v.strip())


@dataclass(frozen=True)
class Settings:
    sender: str
    """Verified SES identity replies are sent from (e.g. noreply@example.org)."""

    receiver: str
    """The analysis mailbox users forward to (e.g. phishing@example.org). Replies are never sent to it."""

    model_id: str = DEFAULT_MODEL_ID
    effort: str = "low"
    fallback_model_id: str | None = None
    """Optional model to retry on if the primary model declines (refusal stop reason)."""
    bedrock_region: str | None = None
    bedrock_role_arn: str | None = None
    """Optional role to assume for Bedrock, when model access lives in another account."""

    ses_configuration_set: str | None = None
    help_contact: str | None = None
    """Optional help-desk address shown in the reply footer."""

    allowed_sender_domains: frozenset[str] = field(default_factory=frozenset)
    """If set, only forwarders from these domains (or their subdomains) get a reply."""

    require_sender_auth: bool = True
    """Only reply when SES recorded a DMARC pass for the forwarder (blocks spoofed-From backscatter)."""

    catch_all: str | None = None
    """Internal mailbox that gets the report when the forwarder can't be trusted or determined."""

    idempotency_table: str | None = None
    idempotency_stale_seconds: int = 300
    """Just above the Lambda timeout: an older in-progress claim belonged to a killed attempt."""

    max_email_bytes: int = 10 * 1024 * 1024
    max_body_chars: int = 60_000

    github_token_secret_arn: str | None = None
    github_repo: str | None = None
    """owner/name of the repo that receives issues for undeliverable reports."""

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None, *, require_ses: bool = True) -> Settings:
        """``require_ses=False`` is for local CLI analysis, where no reply is sent."""
        e = os.environ if env is None else env

        def get(name: str) -> str | None:
            value = e.get(name, "").strip()
            return value or None

        domain = get("SES_DOMAIN_NAME")
        sender = get("SES_EMAIL_SENDER") or (f"noreply@{domain}" if domain else None)
        # SES_EMAIL_PHISHING_RECEIVER is the name used by earlier hand-built deployments.
        receiver = (
            get("SES_PHISHING_EMAIL_RECEIVER")
            or get("SES_EMAIL_PHISHING_RECEIVER")
            or (f"phishing@{domain}" if domain else None)
        )
        if not require_ses:
            sender = sender or "noreply@example.invalid"
            receiver = receiver or "phishing@example.invalid"
        if not sender:
            raise ConfigError("Set SES_EMAIL_SENDER (or SES_DOMAIN_NAME)")
        if not receiver:
            raise ConfigError("Set SES_PHISHING_EMAIL_RECEIVER (or SES_DOMAIN_NAME)")

        effort = (get("MODEL_EFFORT") or "low").lower()
        if effort not in {"low", "medium", "high", "xhigh", "max"}:
            raise ConfigError(f"MODEL_EFFORT must be low|medium|high|xhigh|max, got {effort!r}")

        github_repo = get("GITHUB_REPO")
        if github_repo and github_repo.count("/") != 1:
            raise ConfigError("GITHUB_REPO must look like owner/name")

        retired = [n for n in RETIRED_ENV_VARS if get(n)]
        if retired:
            logger.warning(
                "Ignoring retired settings %s: Bedrock uses the Lambda role (or BEDROCK_ROLE_ARN) "
                "and GitHub uses GITHUB_TOKEN_SECRET_ARN + GITHUB_REPO. Remove them from the function.",
                ", ".join(retired),
            )

        return cls(
            sender=sender.lower(),
            receiver=receiver.lower(),
            model_id=get("MODEL_ID") or get("MODEL") or DEFAULT_MODEL_ID,
            effort=effort,
            fallback_model_id=get("FALLBACK_MODEL_ID"),
            bedrock_region=get("BEDROCK_REGION") or get("AWS_REGION"),
            bedrock_role_arn=get("BEDROCK_ROLE_ARN"),
            ses_configuration_set=get("SES_CONFIG_SET_NAME"),
            help_contact=get("HELP_CONTACT"),
            allowed_sender_domains=_csv(get("ALLOWED_SENDER_DOMAINS")),
            require_sender_auth=_bool(get("REQUIRE_SENDER_AUTH"), True),
            catch_all=(get("DEFAULT_FORWARDER_CATCH_ALL") or "").lower() or None,
            idempotency_table=get("IDEMPOTENCY_TABLE"),
            idempotency_stale_seconds=_int("IDEMPOTENCY_STALE_SECONDS", get("IDEMPOTENCY_STALE_SECONDS"), 300),
            max_email_bytes=_int("MAX_EMAIL_BYTES", get("MAX_EMAIL_BYTES"), 10 * 1024 * 1024),
            max_body_chars=_int("MAX_BODY_CHARS", get("MAX_BODY_CHARS"), 60_000),
            github_token_secret_arn=get("GITHUB_TOKEN_SECRET_ARN"),
            github_repo=github_repo,
        )
