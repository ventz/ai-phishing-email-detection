# Configuration

Terraform variables map one-to-one onto the Lambda environment variables. You only need the
environment variables yourself if you deploy without Terraform or run the CLI locally.

## Terraform variables

| Variable | Default | Description |
|----------|---------|-------------|
| `s3_bucket_name` | required | Bucket SES writes incoming emails to |
| `ses_email_sender` | required | Verified identity replies come from |
| `ses_phishing_email_receiver` | required | Address users forward to |
| `allowed_sender_domains` | required* | Only these domains (and subdomains) get replies. *Or set `allow_any_sender_domain = true` |
| `allow_any_sender_domain` | `false` | Explicit opt-in to answer DMARC-authenticated senders from any domain on the internet |
| `require_sender_auth` | `true` | Reply only when SES recorded DMARC pass for the forwarder's domain |
| `default_forwarder_catch_all` | `null` | Internal mailbox for reports from `catch_all_domains` whose forwarder failed DMARC. Null drops them. Never used for other domains, unauthenticated spam, or emails with no usable From |
| `catch_all_domains` | `[]` | Forwarder domains whose unauthenticated reports may go to the catch-all. Empty means `allowed_sender_domains`, or else the receiver's base domain |
| `help_contact` | `null` | Help-desk address in the reply footer |
| `llm_provider` | `bedrock` | `bedrock`, `anthropic`, `openai` or `custom`. See [Choosing a model provider](#choosing-a-model-provider) |
| `model_id` | `anthropic.claude-opus-5-5` | Model ID for the provider |
| `llm_api_key_secret_arn` | `null` | Full ARN of the Secrets Manager secret with the provider key. Required for every provider except `bedrock` |
| `llm_base_url` | `null` | Endpoint, `https://host[/path]`. Required for `custom`; optional for `anthropic`/`openai` (e.g. a regional endpoint) |
| `llm_api_style` | `anthropic` | `custom` only: `anthropic` (Messages API) or `openai` (chat completions) |
| `llm_auth_header`, `llm_auth_scheme` | `null` | `custom` only: header that carries the key, and an optional prefix such as `Bearer` |
| `analyze_tlp_restricted` | `null` | Send TLP:AMBER/RED reports to the model. Null means `true` for `bedrock`, `false` otherwise. See [Data handling](#data-handling) |
| `model_effort` | `low` | `low` / `medium` / `high` / `xhigh` / `max`, or `none` to omit it (models or endpoints that reject it) |
| `fallback_model_id` | `null` | Model to retry on if the primary declines a request |
| `bedrock_role_arn` | `null` | Role to assume when Bedrock access is in another account |
| `ses_configuration_set` | `null` | Existing SES configuration set for replies |
| `receipt_rule_set_name` | `RECEIVE` | Existing receipt rule set to add the rule to |
| `receipt_rule_name` | `phishing` | Name of the rule this stack owns |
| `create_receipt_rule_set` | `false` | Create and activate the rule set (fresh accounts only) |
| `email_retention_days` | `90` | S3 expiry for raw emails. `0` keeps them forever. A new expiry also applies to existing objects |
| `lambda_memory_mb` | `1024` | Also doubles CPU. Attachment parsing (PDFs, images) assumes at least this much |
| `lambda_timeout_seconds` | `180` | 90–900. The model call is fitted inside it |
| `lambda_reserved_concurrency` | `5` | Caps parallel analyses and Bedrock spend. `-1` means unlimited |
| `log_retention_days` | `30` | |
| `alarm_sns_topic_arn` | `null` | SNS topic the failure alarm notifies |
| `github_repo` | `null` | `owner/name`. Opens an issue for each catch-all report |
| `github_token_secret_arn` | `null` | Secrets Manager secret holding a fine-grained token with Issues: write |
| `aws_region`, `project_name`, `tags` | `us-east-1`, `phishing-email-detection`, `{}` | |

## Environment variables

| Variable | Required | Notes |
|----------|----------|-------|
| `SES_EMAIL_SENDER` | yes* | *Or `SES_DOMAIN_NAME`, which implies `noreply@<domain>` |
| `SES_PHISHING_EMAIL_RECEIVER` | yes* | *Or `SES_DOMAIN_NAME` (implies `phishing@<domain>`). `SES_EMAIL_PHISHING_RECEIVER` is also accepted |
| `LLM_PROVIDER` | no | `bedrock` (default), `anthropic`, `openai`, `custom` |
| `LLM_MODEL` / `MODEL_ID` | no | Model for the provider (`MODEL` is also accepted) |
| `LLM_API_KEY_SECRET_ARN` | per provider | Secrets Manager ARN of the key. A plain `LLM_API_KEY` is refused on purpose |
| `LLM_BASE_URL`, `LLM_API_STYLE`, `LLM_AUTH_HEADER`, `LLM_AUTH_SCHEME` | per provider | As the Terraform variables above. Settings that don't apply to the chosen provider are refused, not ignored |
| `ANALYZE_TLP_RESTRICTED` | no | `true` / `false`. Defaults to `true` for `bedrock` only |
| `MODEL_EFFORT`, `FALLBACK_MODEL_ID`, `BEDROCK_REGION`, `BEDROCK_ROLE_ARN` | no | `MODEL_EFFORT=none` omits the Claude effort setting. `BEDROCK_REGION` defaults to `AWS_REGION` |
| `ALLOWED_SENDER_DOMAINS` | no | Comma-separated |
| `REQUIRE_SENDER_AUTH` | no | `true` (default) / `false` |
| `DEFAULT_FORWARDER_CATCH_ALL`, `CATCH_ALL_DOMAINS`, `HELP_CONTACT`, `SES_CONFIG_SET_NAME` | no | |
| `IDEMPOTENCY_TABLE` | no | DynamoDB table (`pk` string key, `expires_at` TTL). Without it, retries can send duplicate replies |
| `IDEMPOTENCY_STALE_SECONDS` | no | Default 300. Terraform sets it to the Lambda timeout + 60. An in-progress claim older than this is taken over |
| `MAX_EMAIL_BYTES`, `MAX_BODY_CHARS` | no | Defaults are 10 MiB and 60,000 characters |
| `GITHUB_REPO`, `GITHUB_TOKEN_SECRET_ARN` | no | Both are needed to enable issues |
| `LOG_LEVEL` | no | Default `INFO` |

The function refuses to start while `ANTHROPIC_BASE_URL`, `ANTHROPIC_CUSTOM_HEADERS`,
`ANTHROPIC_PROFILE`, `ANTHROPIC_LOG`, `OPENAI_BASE_URL`, `OPENAI_CUSTOM_HEADERS`, `OPENAI_ORG_ID`,
`OPENAI_PROJECT_ID`, `OPENAI_LOG` or `ANTHROPIC_BEDROCK_MANTLE_BASE_URL` is set, and, for
`bedrock` without a key secret, while `AWS_BEARER_TOKEN_BEDROCK` or `ANTHROPIC_AWS_API_KEY` is set
(either would replace the IAM role). The SDKs would otherwise read them behind the `LLM_*`
settings, and their debug logging writes email content to the logs. `ANTHROPIC_API_KEY` and
`OPENAI_API_KEY` in your shell are harmless: the key is always passed explicitly.

The function ignores the retired variables `AI_AWS_ACCESS_KEY_ID`, `AI_AWS_SECRET_ACCESS_KEY`,
`GITHUB_TOKEN`, `GITHUB_REPO_OWNER` and `GITHUB_REPO_NAME`, and logs a warning while they are set.

## Choosing a model provider

The analysis, guardrails and replies are the same for every provider; only the client changes.
Keys always live in Secrets Manager (create the secret yourself, so it never enters Terraform
state), as a plain string or `{"api_key": "..."}`. Use the secret's full ARN, including the
6-character suffix, so the IAM grant matches. A secret encrypted with a customer-managed KMS key
also needs `kms:Decrypt` on the Lambda role. Keys and clients are cached for up to an hour per warm
container, and re-read after a 401 or 403, so a rotated key takes effect without a redeploy.

```bash
aws secretsmanager create-secret --name phishing-detector/llm-key --secret-string 'sk-...'
```

| Provider | Typical settings | Auth |
|---|---|---|
| `bedrock` (default) | `model_id = "anthropic.claude-opus-5-5"` | The Lambda's IAM role. Optionally `bedrock_role_arn` for another account, or a Bedrock API key in `llm_api_key_secret_arn` when running outside AWS |
| `anthropic` | `model_id = "claude-opus-5-5"` | Claude API key |
| `openai` | `model_id = "<an OpenAI model>"` | OpenAI API key |
| `custom` | `llm_base_url`, `llm_api_style = "anthropic"` or `"openai"`, `model_id` | API key in the SDK's default header, or in `llm_auth_header` (with optional `llm_auth_scheme`), e.g. an API gateway that expects `apikey: <key>`. The SDK's own auth header is then not sent |

For example, an OpenAI-compatible gateway:

```hcl
llm_provider           = "custom"
llm_api_style          = "openai"
llm_base_url           = "https://llm-gateway.example.org/v1"
llm_api_key_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:phishing-detector/llm-key-AbCdEf"
llm_auth_header        = "apikey"
model_id               = "<model name on the gateway>"
```

Claude providers (Bedrock, Anthropic, Anthropic-style custom) use a validated `record_verdict`
tool call. OpenAI-style providers use structured output against the same schema (without length
limits, which many servers reject; long points are trimmed). For a non-Claude model behind an
Anthropic-style endpoint, set `model_effort = "none"`. Whatever you pick, compare results on your
own stored reports with `phishing-tools analyze` before switching, and make one live test call:
the structured-output support of OpenAI-compatible servers varies.

### Data handling

Each analysis sends the forwarded email (headers, body, link targets, and text extracted from
attachments) to the model provider. With `bedrock` it stays in your AWS account under the Amazon
Bedrock data terms. With `anthropic`, `openai` or a `custom` endpoint, the email, including
personal data of staff and third parties, is processed by that third party under its own
retention and usage terms, and a gateway may log prompts. Before switching, check the provider's
current API data-retention and training policy, and sign a data-processing or zero-retention
agreement where your policies require one.

TLP:AMBER and TLP:RED reports are not sent to a third-party provider unless you set
`analyze_tlp_restricted = true`; they get a NOT ANALYZED reply instead. With `bedrock` they are
analyzed by default.

## Choosing a model

Opus 5.5 at `low` effort is the default. It takes about 10–15 seconds and roughly 2–3K input
tokens per email, and caches the 1.5K-token static prompt. For higher volume, `anthropic.claude-sonnet-5-5`
costs half as much. Compare the two on a sample of your own stored emails with
`phishing-tools analyze` before you switch.
