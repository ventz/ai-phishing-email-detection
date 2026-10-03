"""Model clients for each supported provider. API keys are read from Secrets Manager (never from
environment variables or Terraform state) and, like the clients, cached per warm container for up
to an hour (sooner after an auth failure, so a rotated key is picked up).

Every SDK argument is passed explicitly: left unset, the SDKs fall back to ANTHROPIC_*/OPENAI_*
environment variables, which could send a developer's own key to a custom endpoint.

| LLM_PROVIDER | API style  | Auth                                                  |
|--------------|------------|-------------------------------------------------------|
| bedrock      | anthropic  | Lambda IAM role (default), assumed role, or API key   |
| anthropic    | anthropic  | Claude API key                                        |
| openai       | openai     | OpenAI API key                                        |
| custom       | either     | API key, optionally in a header of your choice        |
"""

from __future__ import annotations

import json
import time
from typing import Any

import anthropic
import openai
from anthropic import AnthropicBedrockMantle, BetaRefusalFallbackMiddleware

from .config import Settings

_ASSUMED_ROLE_SECONDS = 3600
_CACHE_SECONDS = 3600
_DEFAULT_URLS = {"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com/v1"}
_cached: tuple[Settings, float, Any] | None = None
_secret_cache: dict[str, tuple[float, str]] = {}


def api_style(settings: Settings) -> str:
    """ "anthropic" (Messages API + tool call) or "openai" (chat completions + structured output)."""
    if settings.llm_provider in {"bedrock", "anthropic"}:
        return "anthropic"
    if settings.llm_provider == "openai":
        return "openai"
    return settings.llm_api_style


def api_key(settings: Settings) -> str | None:
    """The provider key from Secrets Manager: a plain string, or JSON with an "api_key" field."""
    arn = settings.llm_api_key_secret_arn
    if not arn:
        return None
    cached = _secret_cache.get(arn)
    if cached and time.monotonic() < cached[0]:
        return cached[1]
    import boto3

    raw = boto3.client("secretsmanager").get_secret_value(SecretId=arn).get("SecretString")
    if not isinstance(raw, str):
        raise ValueError("the LLM API key secret must be a text secret")
    value = raw.strip()
    if value.startswith(("{", "[")):
        parsed = json.loads(value)
        value = str(parsed.get("api_key", "") if isinstance(parsed, dict) else "").strip()
    if not value:
        raise ValueError('the LLM API key secret is empty (or JSON without an "api_key" field)')
    if not value.isascii() or any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        raise ValueError("the LLM API key secret contains whitespace, control or non-ASCII characters")
    _secret_cache[arn] = (time.monotonic() + _CACHE_SECONDS, value)
    return value


def forget_credentials() -> None:
    """After a 401/403: the key may have been rotated, so the next email re-reads it."""
    global _cached
    _secret_cache.clear()
    _cached = None


def _assumed_role_credentials(settings: Settings) -> dict[str, str]:
    import boto3

    creds = boto3.client("sts").assume_role(
        RoleArn=settings.bedrock_role_arn, RoleSessionName="phishing-detector", DurationSeconds=_ASSUMED_ROLE_SECONDS
    )["Credentials"]
    return {
        "aws_access_key": creds["AccessKeyId"],
        "aws_secret_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }


def _auth_headers(settings: Settings, key: str) -> dict[str, str]:
    """For custom endpoints whose gateway expects the key in its own header (e.g. "apikey")."""
    if not settings.llm_auth_header:
        return {}
    scheme = f"{settings.llm_auth_scheme} " if settings.llm_auth_scheme else ""
    return {settings.llm_auth_header: f"{scheme}{key}"}


def request_headers(settings: Settings) -> dict[str, Any]:
    """Per-request headers: with a custom auth header, drop the SDK's own one so the gateway never
    sees a second credential. (The OpenAI SDK honors an omitted header only per request.)"""
    header = settings.llm_auth_header
    sdk_header = "X-Api-Key" if api_style(settings) == "anthropic" else "Authorization"
    if settings.llm_provider != "custom" or not header or header.lower() == sdk_header.lower():
        return {}
    return {sdk_header: anthropic.Omit() if sdk_header == "X-Api-Key" else openai.Omit()}


def _build(settings: Settings) -> Any:
    key = api_key(settings)
    timeout = 60.0  # per call; narrowed to the Lambda deadline by the caller
    provider = settings.llm_provider
    middleware = []
    if settings.fallback_model_id:
        middleware.append(BetaRefusalFallbackMiddleware([{"model": settings.fallback_model_id}]))

    if provider == "bedrock":
        if key:
            auth: dict[str, Any] = {"api_key": key}  # Bedrock API key (for running outside AWS)
        elif settings.bedrock_role_arn:
            auth = _assumed_role_credentials(settings)
        else:
            auth = {}  # Lambda execution role via the default AWS credential chain
        import boto3

        region = settings.bedrock_region or boto3.session.Session().region_name
        if not region:
            raise ValueError("Bedrock needs BEDROCK_REGION or AWS_REGION")
        return AnthropicBedrockMantle(
            aws_region=region,
            base_url=f"https://bedrock-mantle.{region}.api.aws/anthropic",  # never from the environment
            timeout=anthropic.Timeout(timeout, connect=5.0),
            max_retries=0,
            middleware=middleware,
            **auth,
        )
    if not key:  # config validation requires the secret; never let the SDK find one itself
        raise ValueError(f"LLM_PROVIDER={provider} has no API key")
    style = api_style(settings)
    base_url = settings.llm_base_url or _DEFAULT_URLS[style]
    if style == "anthropic":
        headers = _auth_headers(settings, key)
        return anthropic.Anthropic(
            api_key=key,
            base_url=base_url,
            default_headers=headers or None,
            timeout=anthropic.Timeout(timeout, connect=5.0),
            max_retries=0,
            middleware=middleware,
        )
    headers = _auth_headers(settings, key)
    return openai.OpenAI(
        api_key=key,
        base_url=base_url,
        default_headers=headers or None,
        timeout=timeout,
        max_retries=0,
    )


def client(settings: Settings) -> Any:
    """One client per warm container; rebuilt hourly (key rotation) and before assumed-role
    credentials expire."""
    global _cached
    now = time.monotonic()
    if _cached and _cached[0] == settings and now < _cached[1]:
        return _cached[2]
    built = _build(settings)
    assumed = settings.llm_provider == "bedrock" and settings.bedrock_role_arn and not settings.llm_api_key_secret_arn
    ttl = _ASSUMED_ROLE_SECONDS - 600 if assumed else _CACHE_SECONDS
    _cached = (settings, now + ttl, built)
    return built
