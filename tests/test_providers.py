from dataclasses import replace
from types import SimpleNamespace

import anthropic
import httpx2
import openai
import pytest

from conftest import forward_as_attachment, phish
from phishing_detector import handler, providers
from phishing_detector.classifier import _OPENAI_SYSTEM_PROMPT, ClassificationError, Verdict, _LooseVerdict, classify
from phishing_detector.config import ConfigError, Settings
from phishing_detector.parsing import parse_email

BASE = {"SES_DOMAIN_NAME": "example.org"}
CUSTOM = {"LLM_PROVIDER": "custom", "LLM_BASE_URL": "https://gw.example/v1", "LLM_API_KEY_SECRET_ARN": "arn:x"}
GOOD = {"verdict": "phishing", "confidence": "high", "summary": "s", "indicators": ["i"], "tips": []}


@pytest.fixture(autouse=True)
def _fresh_caches(monkeypatch):
    monkeypatch.setattr(providers, "_cached", None)
    monkeypatch.setattr(providers, "_secret_cache", {})


def secret(monkeypatch, value="sk-test"):
    monkeypatch.setattr(providers, "api_key", lambda s: value if s.llm_api_key_secret_arn else None)


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"LLM_PROVIDER": "gemini"}, "LLM_PROVIDER"),
        ({"LLM_PROVIDER": "anthropic"}, "LLM_API_KEY_SECRET_ARN"),
        ({"LLM_PROVIDER": "openai"}, "LLM_API_KEY_SECRET_ARN"),
        ({"LLM_PROVIDER": "custom"}, "LLM_BASE_URL"),
        ({**CUSTOM, "LLM_API_KEY_SECRET_ARN": ""}, "LLM_API_KEY_SECRET_ARN"),  # never keyless
        ({**CUSTOM, "LLM_BASE_URL": "http://gw.example/v1"}, "https"),
        ({**CUSTOM, "LLM_BASE_URL": "http://localhost.evil.example/v1"}, "https"),
        ({**CUSTOM, "LLM_BASE_URL": "http://localhost@evil.example/v1"}, "https"),
        ({**CUSTOM, "LLM_BASE_URL": "https://user:pw@gw.example/v1"}, "credentials"),
        ({**CUSTOM, "LLM_BASE_URL": "https://gw.example/v1?key=x"}, "query"),
        ({**CUSTOM, "LLM_API_STYLE": "soap"}, "LLM_API_STYLE"),
        ({**CUSTOM, "LLM_AUTH_HEADER": "api key"}, "LLM_AUTH_HEADER"),
        ({**CUSTOM, "LLM_AUTH_HEADER": "Host"}, "LLM_AUTH_HEADER"),
        ({**CUSTOM, "LLM_AUTH_HEADER": "apikey", "LLM_AUTH_SCHEME": "Bearer x"}, "LLM_AUTH_SCHEME"),
        ({**CUSTOM, "LLM_AUTH_SCHEME": "Bearer"}, "needs LLM_AUTH_HEADER"),
        ({"LLM_API_STYLE": "openai"}, "only apply to LLM_PROVIDER=custom"),
        ({"LLM_PROVIDER": "openai", "LLM_API_KEY_SECRET_ARN": "arn:x", "LLM_AUTH_HEADER": "apikey"}, "only apply"),
        ({"LLM_BASE_URL": "https://gw.example"}, "does not apply"),
        ({"LLM_PROVIDER": "openai", "LLM_API_KEY_SECRET_ARN": "arn:x", "BEDROCK_ROLE_ARN": "arn:r"}, "only applies"),
        ({"BEDROCK_ROLE_ARN": "arn:r", "LLM_API_KEY_SECRET_ARN": "arn:x"}, "not both"),
        ({"LLM_API_KEY": "sk-plain"}, "Secrets Manager"),
        ({"MODEL_EFFORT": "turbo"}, "MODEL_EFFORT"),
        ({"ANTHROPIC_BASE_URL": "https://elsewhere.example"}, "ANTHROPIC_BASE_URL"),
        ({"OPENAI_LOG": "debug"}, "OPENAI_LOG"),
    ],
)
def test_invalid_provider_config_is_rejected(env, message):
    with pytest.raises(ConfigError, match=message):
        Settings.from_env({**BASE, **env})


@pytest.mark.parametrize("url", ["https://gw.example/v1", "http://localhost:4000", "http://127.0.0.1:8080/v1"])
def test_valid_base_urls(url):
    assert Settings.from_env({**BASE, **CUSTOM, "LLM_BASE_URL": url}).llm_base_url == url


def test_tlp_restricted_analysis_defaults_on_only_for_bedrock():
    assert Settings.from_env(BASE).analyze_tlp_restricted
    assert not Settings.from_env({**BASE, **CUSTOM}).analyze_tlp_restricted
    assert Settings.from_env({**BASE, **CUSTOM, "ANALYZE_TLP_RESTRICTED": "true"}).analyze_tlp_restricted


def test_provider_defaults_and_model_precedence():
    s = Settings.from_env({**BASE, "LLM_MODEL": "claude-opus-5-5", "MODEL_ID": "ignored"})
    assert s.llm_provider == "bedrock" and s.model_id == "claude-opus-5-5"
    assert providers.api_style(s) == "anthropic"


def test_bedrock_default_uses_the_role_not_a_key():
    s = Settings(sender="a@b.c", receiver="d@b.c", bedrock_region="us-east-1")
    c = providers.client(s)
    assert type(c).__name__ == "AnthropicBedrockMantle"


def test_anthropic_direct_client(monkeypatch):
    secret(monkeypatch)
    s = Settings(
        sender="a@b.c",
        receiver="d@b.c",
        llm_provider="anthropic",
        llm_api_key_secret_arn="arn:x",
        model_id="claude-opus-5-5",
    )
    c = providers.client(s)
    assert isinstance(c, anthropic.Anthropic) and c.api_key == "sk-test"


def test_openai_client(monkeypatch):
    secret(monkeypatch)
    s = Settings(sender="a@b.c", receiver="d@b.c", llm_provider="openai", llm_api_key_secret_arn="arn:x")
    c = providers.client(s)
    assert isinstance(c, openai.OpenAI) and c.api_key == "sk-test"


def _wire(client, monkeypatch, call):
    """Send one request through the real SDK and return the headers and URL that went out."""
    seen = {}

    def capture(request):
        seen.update(headers=dict(request.headers), url=str(request.url))
        return httpx2.Response(500, json={})

    monkeypatch.setattr(client, "_client", httpx2.Client(transport=httpx2.MockTransport(capture)))
    with pytest.raises((anthropic.APIStatusError, openai.APIStatusError)):
        call(client)
    return seen


def _anthropic_call(settings):
    def call(c):
        c.messages.create(
            model="m",
            max_tokens=1,
            messages=[{"role": "user", "content": "x"}],
            extra_headers=providers.request_headers(settings) or None,
        )

    return call


def _openai_call(settings):
    def call(c):
        c.chat.completions.create(
            model="m", messages=[{"role": "user", "content": "x"}], extra_headers=providers.request_headers(settings)
        )

    return call


def custom(style, **kw):
    return Settings(
        sender="a@b.c",
        receiver="d@b.c",
        llm_provider="custom",
        llm_api_style=style,
        llm_base_url="https://gateway.example/llm",
        llm_api_key_secret_arn="arn:x",
        **kw,
    )


def test_custom_anthropic_gateway_header_replaces_the_sdk_one(monkeypatch):
    secret(monkeypatch, "gw-key")
    s = custom("anthropic", llm_auth_header="apikey")
    sent = _wire(providers.client(s), monkeypatch, _anthropic_call(s))
    assert sent["url"].startswith("https://gateway.example/llm/")
    assert sent["headers"]["apikey"] == "gw-key" and "x-api-key" not in sent["headers"]


def test_custom_openai_gateway_header_replaces_the_sdk_one(monkeypatch):
    secret(monkeypatch, "gw-key")
    s = custom("openai", llm_auth_header="apikey")
    sent = _wire(providers.client(s), monkeypatch, _openai_call(s))
    assert sent["headers"]["apikey"] == "gw-key" and "authorization" not in sent["headers"]


def test_custom_openai_style_with_bearer_scheme(monkeypatch):
    secret(monkeypatch, "tok")
    s = custom("openai", llm_auth_header="Authorization", llm_auth_scheme="Bearer")
    sent = _wire(providers.client(s), monkeypatch, _openai_call(s))
    assert sent["headers"]["authorization"] == "Bearer tok"


def test_environment_keys_and_urls_never_reach_a_custom_endpoint(monkeypatch):
    """A developer's own keys in the shell must not be sent to a third-party gateway."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-REAL")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "tok-REAL")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-REAL")
    secret(monkeypatch, "gw-key")
    for style, call in (("anthropic", _anthropic_call), ("openai", _openai_call)):
        providers.forget_credentials()
        s = custom(style)
        sent = _wire(providers.client(s), monkeypatch, call(s))
        assert "REAL" not in str(sent["headers"]) and sent["url"].startswith("https://gateway.example/")


def test_default_urls_are_explicit(monkeypatch):
    secret(monkeypatch)
    a = providers.client(
        Settings(sender="a@b.c", receiver="d@b.c", llm_provider="anthropic", llm_api_key_secret_arn="x")
    )
    assert str(a.base_url).startswith("https://api.anthropic.com")
    providers.forget_credentials()
    o = providers.client(Settings(sender="a@b.c", receiver="d@b.c", llm_provider="openai", llm_api_key_secret_arn="x"))
    assert str(o.base_url).startswith("https://api.openai.com/v1")


def test_keyless_non_bedrock_client_is_refused(monkeypatch):
    s = replace(custom("openai"), llm_api_key_secret_arn=None)
    with pytest.raises(ValueError, match="no API key"):
        providers.client(s)


def test_client_and_key_are_cached_for_an_hour(monkeypatch):
    calls = []
    monkeypatch.setattr(providers, "_build", lambda s: calls.append(s) or object())
    clock = [1000.0]
    monkeypatch.setattr(providers.time, "monotonic", lambda: clock[0])
    s = Settings(sender="a@b.c", receiver="d@b.c")
    first = providers.client(s)
    clock[0] += 3000
    assert providers.client(s) is first
    clock[0] += 700
    assert providers.client(s) is not first and len(calls) == 2


def test_api_key_from_secrets_manager_plain_and_json(monkeypatch):
    import boto3

    values = {
        "plain": {"SecretString": "sk-1"},
        "json": {"SecretString": '{"api_key": "sk-2"}'},
        "empty": {"SecretString": "  "},
        "list": {"SecretString": '["sk-3"]'},
        "binary": {"SecretBinary": b"sk-4"},
        "spaces": {"SecretString": "sk 5"},
    }

    class SM:
        def get_secret_value(self, SecretId):
            return values[SecretId]

    monkeypatch.setattr(boto3, "client", lambda name: SM())
    base = Settings(sender="a@b.c", receiver="d@b.c")
    assert providers.api_key(replace(base, llm_api_key_secret_arn="plain")) == "sk-1"
    assert providers.api_key(replace(base, llm_api_key_secret_arn="json")) == "sk-2"
    for bad in ("empty", "list", "binary", "spaces"):
        with pytest.raises(ValueError):
            providers.api_key(replace(base, llm_api_key_secret_arn=bad))


class FakeOpenAI:
    def __init__(self, parsed=None, finish="stop", refusal=None, error=None):
        self.error = error
        msg = SimpleNamespace(parsed=parsed, refusal=refusal)
        self.response = SimpleNamespace(
            choices=[SimpleNamespace(message=msg, finish_reason=finish)],
            usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
            model="gpt-x",
        )
        self.kwargs = None
        self.chat = SimpleNamespace(completions=SimpleNamespace(parse=self._parse))

    def with_options(self, **kw):
        return self

    def _parse(self, **kwargs):
        self.kwargs = kwargs
        self.calls = getattr(self, "calls", 0) + 1
        if self.error:
            raise self.error
        return self.response


OPENAI_CFG = Settings(
    sender="a@b.c", receiver="d@b.c", llm_provider="openai", llm_api_key_secret_arn="arn:x", model_id="gpt-test"
)


def test_openai_structured_output_path():
    email = parse_email(forward_as_attachment(phish()))
    fake = FakeOpenAI(parsed=_LooseVerdict.model_validate(GOOD))
    verdict = classify(email, OPENAI_CFG, client=fake)
    assert isinstance(verdict, Verdict) and verdict.verdict == "phishing"
    assert fake.kwargs["response_format"] is _LooseVerdict and fake.kwargs["model"] == "gpt-test"
    assert fake.kwargs["max_completion_tokens"] == 16_000
    system, user = fake.kwargs["messages"]
    assert system["content"] == _OPENAI_SYSTEM_PROMPT and "record_verdict" not in system["content"] + user["content"]


def test_openai_schema_has_no_length_limits_and_long_points_are_trimmed():
    assert "maxLength" not in str(_LooseVerdict.model_json_schema())
    loose = _LooseVerdict.model_validate({**GOOD, "indicators": ["x" * 900, "  ", "ok"], "summary": "s" * 401})
    v = loose.to_verdict()
    assert len(v.summary) == 400 and [len(p) for p in v.indicators] == [400, 2]


def _completion():
    from openai.types.chat import ChatCompletion

    return ChatCompletion.model_validate(
        {
            "id": "c",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-test",
            "choices": [{"index": 0, "finish_reason": "length", "message": {"role": "assistant", "content": "{"}}],
        }
    )


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (lambda: openai.LengthFinishReasonError(completion=_completion()), "output limit"),
        (lambda: openai.ContentFilterFinishReasonError(), "content filter"),
        (lambda: openai.OpenAIError("odd"), "Model call failed"),
    ],
)
def test_openai_sdk_errors_become_not_analyzed_without_retries(error, message):
    email = parse_email(forward_as_attachment(phish()))
    fake = FakeOpenAI(error=error())
    with pytest.raises(ClassificationError, match=message):
        classify(email, OPENAI_CFG, client=fake)
    assert fake.calls == 1


def test_auth_failure_forgets_the_cached_key(monkeypatch):
    forgot = []
    monkeypatch.setattr(providers, "forget_credentials", lambda: forgot.append(1))
    request = httpx2.Request("POST", "https://api.openai.com/v1/chat/completions")
    err = openai.AuthenticationError("bad key", response=httpx2.Response(401, request=request), body=None)
    with pytest.raises(ClassificationError, match="401"):
        classify(parse_email(forward_as_attachment(phish())), OPENAI_CFG, client=FakeOpenAI(error=err))
    assert forgot == [1]


@pytest.mark.parametrize(("finish", "refusal"), [("length", None), ("stop", "I can't help with that")])
def test_openai_unusable_responses_raise(finish, refusal):
    email = parse_email(forward_as_attachment(phish()))
    with pytest.raises(ClassificationError):
        classify(email, OPENAI_CFG, client=FakeOpenAI(parsed=None, finish=finish, refusal=refusal))


def test_effort_none_is_omitted_for_anthropic_style():
    from test_classifier_config import FakeClient, response, tool_use

    email = parse_email(forward_as_attachment(phish()))
    fake = FakeClient(response(content=[tool_use(GOOD)]))
    classify(email, Settings(sender="a@b.c", receiver="d@b.c", effort="none"), client=fake)
    assert "output_config" not in fake.calls[0]


@pytest.mark.parametrize(
    "error", [ValueError("empty"), KeyError("SecretString"), TypeError("auth"), openai.OpenAIError("no key")]
)
def test_client_setup_failures_become_not_analyzed(monkeypatch, error):
    def boom(settings):
        raise error

    monkeypatch.setattr(providers, "client", boom)
    with pytest.raises(ClassificationError, match="model client"):
        classify(parse_email(forward_as_attachment(phish())), OPENAI_CFG)


def test_restricted_tlp_is_not_sent_to_a_third_party_provider(monkeypatch):
    from phishing_detector import services
    from test_handler import _tlp_email, event

    sent, classified = [], []
    cfg = Settings(
        sender="noreply@example.org",
        receiver="phishing@example.org",
        **{"llm_provider": "openai", "llm_api_key_secret_arn": "arn:x", "analyze_tlp_restricted": False},
    )
    monkeypatch.setattr(handler, "_settings", cfg)
    monkeypatch.setattr(services, "fetch_email", lambda b, k, m: _tlp_email("AMBER"))
    monkeypatch.setattr(services, "mark_restricted", lambda b, k, t: None)
    monkeypatch.setattr(services, "send_reply", lambda reply, **kw: sent.append(reply) or "msg-1")
    monkeypatch.setattr(handler, "classify", lambda *a, **kw: classified.append(1))
    handler.lambda_handler(event(), None)
    assert classified == [] and sent[0].subject.startswith("Phishing report result: NOT ANALYZED")


@pytest.mark.parametrize("name", ["AWS_BEARER_TOKEN_BEDROCK", "ANTHROPIC_AWS_API_KEY"])
@pytest.mark.parametrize("value", ["sk-bedrock", ""])  # the SDK switches auth even when it is empty
def test_bedrock_key_env_vars_cannot_replace_the_iam_role(name, value):
    with pytest.raises(ConfigError, match=name):
        Settings.from_env({**BASE, name: value})
    # A Bedrock key from Secrets Manager is passed explicitly, so the variable is moot then.
    assert Settings.from_env({**BASE, name: value, "LLM_API_KEY_SECRET_ARN": "arn:x"}).llm_api_key_secret_arn


def test_bedrock_mantle_base_url_env_is_refused_and_url_is_explicit(monkeypatch):
    with pytest.raises(ConfigError, match="ANTHROPIC_BEDROCK_MANTLE_BASE_URL"):
        Settings.from_env({**BASE, "ANTHROPIC_BEDROCK_MANTLE_BASE_URL": "https://evil.example"})
    monkeypatch.setenv("ANTHROPIC_BEDROCK_MANTLE_BASE_URL", "https://evil.example")
    c = providers.client(Settings(sender="a@b.c", receiver="d@b.c", bedrock_region="us-west-2"))
    assert str(c.base_url).startswith("https://bedrock-mantle.us-west-2.api.aws/anthropic")


def test_non_ascii_secret_is_refused(monkeypatch):
    import boto3

    class SM:
        def get_secret_value(self, SecretId):
            return {"SecretString": "sk-tést"}

    monkeypatch.setattr(boto3, "client", lambda name: SM())
    with pytest.raises(ValueError, match="non-ASCII"):
        providers.api_key(Settings(sender="a@b.c", receiver="d@b.c", llm_api_key_secret_arn="arn:x"))


def test_anthropic_style_auth_failure_forgets_the_cached_key(monkeypatch):
    forgot = []
    monkeypatch.setattr(providers, "forget_credentials", lambda: forgot.append(1))
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    err = anthropic.AuthenticationError("bad key", response=httpx2.Response(401, request=request), body=None)

    class Failing:
        beta = SimpleNamespace(messages=SimpleNamespace(create=lambda **kw: (_ for _ in ()).throw(err)))

        def with_options(self, **kw):
            return self

    cfg = Settings(sender="a@b.c", receiver="d@b.c", llm_provider="anthropic", llm_api_key_secret_arn="arn:x")
    with pytest.raises(ClassificationError, match="401"):
        classify(parse_email(forward_as_attachment(phish())), cfg, client=Failing())
    assert forgot == [1]


def test_signing_failure_becomes_not_analyzed():
    from botocore.exceptions import NoCredentialsError

    class Failing:
        beta = SimpleNamespace(
            messages=SimpleNamespace(create=lambda **kw: (_ for _ in ()).throw(NoCredentialsError()))
        )

        def with_options(self, **kw):
            return self

    with pytest.raises(ClassificationError, match="NoCredentialsError"):
        classify(
            parse_email(forward_as_attachment(phish())), Settings(sender="a@b.c", receiver="d@b.c"), client=Failing()
        )


def test_cli_does_not_send_restricted_tlp_to_a_third_party_provider(monkeypatch, capsys):
    from phishing_detector import cli
    from test_handler import _tlp_email

    classified = []
    cfg = Settings(
        sender="a@b.c",
        receiver="d@b.c",
        llm_provider="openai",
        llm_api_key_secret_arn="x",
        analyze_tlp_restricted=False,
    )
    monkeypatch.setattr(cli, "_raw", lambda b, k: _tlp_email("RED"))
    monkeypatch.setattr(cli, "_settings", lambda args: cfg)
    monkeypatch.setattr(cli, "classify", lambda *a, **kw: classified.append(1))
    cli.cmd_analyze(SimpleNamespace(bucket="b", key="k", html=None))
    assert classified == [] and "NOT ANALYZED" in capsys.readouterr().out
