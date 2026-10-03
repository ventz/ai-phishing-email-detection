"""Runtime configuration, read once from environment variables and validated up front."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_MODEL_ID = "anthropic.claude-opus-5-5"
RETIRED_ENV_VARS = (
    "AI_AWS_ACCESS_KEY_ID",
    "AI_AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "GITHUB_REPO_OWNER",
    "GITHUB_REPO_NAME",
)

logger = logging.getLogger(__name__)


# Read by the anthropic/openai SDKs whenever an argument is left unset (and *_LOG=debug logs
# request bodies, i.e. email content). The client is configured only through LLM_* settings.
SDK_ENV_VARS = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_CUSTOM_HEADERS",
    "ANTHROPIC_PROFILE",
    "ANTHROPIC_LOG",
    "ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
    "OPENAI_BASE_URL",
    "OPENAI_CUSTOM_HEADERS",
    "OPENAI_ORG_ID",
    "OPENAI_PROJECT_ID",
    "OPENAI_LOG",
)
# The Bedrock client uses these instead of the IAM role when no key is passed.
BEDROCK_KEY_ENV_VARS = ("AWS_BEARER_TOKEN_BEDROCK", "ANTHROPIC_AWS_API_KEY")
_CUSTOM_ONLY = ("LLM_API_STYLE", "LLM_AUTH_HEADER", "LLM_AUTH_SCHEME")
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
_AUTH_SCHEME = re.compile(r"[A-Za-z0-9._~+/-]+")
_RESERVED_HEADERS = {"host", "content-length", "content-type", "transfer-encoding", "connection"}


def _check_base_url(url: str) -> None:
    """https://host[/path], or http only for a local proxy; no credentials, query or fragment."""
    try:
        u = urlsplit(url)
        hostname = u.hostname
    except ValueError as exc:
        raise ConfigError(f"LLM_BASE_URL is not a valid URL: {exc}") from exc
    local = u.scheme == "http" and hostname in {"localhost", "127.0.0.1", "::1"}
    if not (u.scheme == "https" or local) or not hostname:
        raise ConfigError("LLM_BASE_URL must use https:// (http only for localhost)")
    if u.username or u.password or u.query or u.fragment:
        raise ConfigError("LLM_BASE_URL must not contain credentials, a query or a fragment")


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
    """Claude effort level, or "none" to omit it (endpoints/models that don't support it)."""

    llm_provider: str = "bedrock"
    """bedrock | anthropic | openai | custom (see providers.py)."""

    llm_api_key_secret_arn: str | None = None
    """Secrets Manager secret holding the provider API key (not needed for bedrock with a role)."""

    llm_base_url: str | None = None
    llm_api_style: str = "anthropic"
    """For custom endpoints: "anthropic" (Messages API) or "openai" (chat completions)."""

    llm_auth_header: str | None = None
    """For custom endpoints: header that carries the key (default: the SDK's own auth header)."""

    llm_auth_scheme: str | None = None
    """Optional prefix for that header's value, e.g. "Bearer"."""

    analyze_tlp_restricted: bool = True
    """Send TLP:AMBER/RED reports to the model. Defaults to true only for bedrock (the email stays in
    your AWS account); with a third-party provider such reports get a NOT ANALYZED reply instead."""

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

    catch_all_domains: frozenset[str] = field(default_factory=frozenset)
    """Forwarder domains whose failed reports may go to the catch-all. Defaults to the allowlist,
    or to the receiver's base domain (example.org for phishing@mail.example.org)."""

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
        if effort not in {"low", "medium", "high", "xhigh", "max", "none"}:
            raise ConfigError(f"MODEL_EFFORT must be low|medium|high|xhigh|max|none, got {effort!r}")

        provider = (get("LLM_PROVIDER") or "bedrock").lower()
        if provider not in {"bedrock", "anthropic", "openai", "custom"}:
            raise ConfigError(f"LLM_PROVIDER must be bedrock|anthropic|openai|custom, got {provider!r}")
        if sdk_env := [n for n in SDK_ENV_VARS if get(n)]:
            raise ConfigError(
                f"Unset {', '.join(sdk_env)}: the model client is configured only through LLM_* settings "
                "(SDK debug logging would also write email content to the logs)"
            )
        # Presence, not value: the SDK switches to key auth even for an empty variable.
        bedrock_env = [n for n in BEDROCK_KEY_ENV_VARS if n in e]
        if provider == "bedrock" and bedrock_env and not get("LLM_API_KEY_SECRET_ARN"):
            raise ConfigError(
                f"Unset {', '.join(bedrock_env)}: it would replace the IAM role for Bedrock. "
                "For a Bedrock API key, store it in Secrets Manager and set LLM_API_KEY_SECRET_ARN"
            )
        if get("LLM_API_KEY"):
            raise ConfigError("Put the API key in Secrets Manager and set LLM_API_KEY_SECRET_ARN, not LLM_API_KEY")
        style = (get("LLM_API_STYLE") or "anthropic").lower()
        if style not in {"anthropic", "openai"}:
            raise ConfigError(f"LLM_API_STYLE must be anthropic|openai, got {style!r}")
        base_url = get("LLM_BASE_URL")
        auth_header, auth_scheme = get("LLM_AUTH_HEADER"), get("LLM_AUTH_SCHEME")
        key_secret = get("LLM_API_KEY_SECRET_ARN")
        role_arn = get("BEDROCK_ROLE_ARN")
        if provider != "custom" and (unused := [n for n in _CUSTOM_ONLY if get(n)]):
            raise ConfigError(f"{', '.join(unused)} only apply to LLM_PROVIDER=custom")
        if provider == "bedrock" and base_url:
            raise ConfigError("LLM_BASE_URL does not apply to LLM_PROVIDER=bedrock")
        if provider != "bedrock" and role_arn:
            raise ConfigError("BEDROCK_ROLE_ARN only applies to LLM_PROVIDER=bedrock")
        if role_arn and key_secret:
            raise ConfigError("Set BEDROCK_ROLE_ARN or LLM_API_KEY_SECRET_ARN for Bedrock, not both")
        if provider == "custom" and not base_url:
            raise ConfigError("LLM_PROVIDER=custom needs LLM_BASE_URL")
        if base_url:
            _check_base_url(base_url)
        if provider != "bedrock" and not key_secret:
            raise ConfigError(f"LLM_PROVIDER={provider} needs LLM_API_KEY_SECRET_ARN (the key, in Secrets Manager)")
        if auth_header and (not _HEADER_NAME.fullmatch(auth_header) or auth_header.lower() in _RESERVED_HEADERS):
            raise ConfigError(f"LLM_AUTH_HEADER is not a usable header name: {auth_header!r}")
        if auth_scheme and not _AUTH_SCHEME.fullmatch(auth_scheme):
            raise ConfigError(f"LLM_AUTH_SCHEME must be a single token such as Bearer, got {auth_scheme!r}")
        if auth_scheme and not auth_header:
            raise ConfigError("LLM_AUTH_SCHEME needs LLM_AUTH_HEADER")

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

        allowed = _csv(get("ALLOWED_SENDER_DOMAINS"))
        catch_all_domains = (
            _csv(get("CATCH_ALL_DOMAINS"))
            or allowed
            or frozenset({".".join(receiver.lower().rpartition("@")[2].split(".")[-2:])})
        )
        return cls(
            sender=sender.lower(),
            receiver=receiver.lower(),
            model_id=get("LLM_MODEL") or get("MODEL_ID") or get("MODEL") or DEFAULT_MODEL_ID,
            llm_provider=provider,
            llm_api_key_secret_arn=key_secret,
            llm_base_url=base_url,
            llm_api_style=style,
            llm_auth_header=auth_header,
            llm_auth_scheme=auth_scheme,
            # Third-party providers process the email outside your AWS account: TLP:AMBER/RED
            # reports are only sent there when the operator opts in.
            analyze_tlp_restricted=_bool(get("ANALYZE_TLP_RESTRICTED"), provider == "bedrock"),
            effort=effort,
            fallback_model_id=get("FALLBACK_MODEL_ID"),
            bedrock_region=get("BEDROCK_REGION") or get("AWS_REGION"),
            bedrock_role_arn=role_arn,
            ses_configuration_set=get("SES_CONFIG_SET_NAME"),
            help_contact=get("HELP_CONTACT"),
            allowed_sender_domains=allowed,
            catch_all_domains=catch_all_domains,
            require_sender_auth=_bool(get("REQUIRE_SENDER_AUTH"), True),
            catch_all=(get("DEFAULT_FORWARDER_CATCH_ALL") or "").lower() or None,
            idempotency_table=get("IDEMPOTENCY_TABLE"),
            idempotency_stale_seconds=_int("IDEMPOTENCY_STALE_SECONDS", get("IDEMPOTENCY_STALE_SECONDS"), 300),
            max_email_bytes=_int("MAX_EMAIL_BYTES", get("MAX_EMAIL_BYTES"), 10 * 1024 * 1024),
            max_body_chars=_int("MAX_BODY_CHARS", get("MAX_BODY_CHARS"), 60_000),
            github_token_secret_arn=get("GITHUB_TOKEN_SECRET_ARN"),
            github_repo=github_repo,
        )
