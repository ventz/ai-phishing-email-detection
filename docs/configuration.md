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
| `model_id` | `anthropic.claude-opus-5-5` | Bedrock model ID (Messages API) |
| `model_effort` | `low` | `low` / `medium` / `high` / `xhigh` / `max` |
| `fallback_model_id` | `null` | Model to retry on if the primary declines a request |
| `bedrock_role_arn` | `null` | Role to assume when Bedrock access is in another account |
| `ses_configuration_set` | `null` | Existing SES configuration set for replies |
| `receipt_rule_set_name` | `RECEIVE` | Existing receipt rule set to add the rule to |
| `receipt_rule_name` | `phishing` | Name of the rule this stack owns |
| `create_receipt_rule_set` | `false` | Create and activate the rule set (fresh accounts only) |
| `email_retention_days` | `90` | S3 expiry for raw emails. `0` keeps them forever. A new expiry also applies to existing objects |
| `lambda_memory_mb` | `512` | |
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
| `MODEL_ID` | no | `MODEL` is also accepted |
| `MODEL_EFFORT`, `FALLBACK_MODEL_ID`, `BEDROCK_REGION`, `BEDROCK_ROLE_ARN` | no | `BEDROCK_REGION` defaults to `AWS_REGION` |
| `ALLOWED_SENDER_DOMAINS` | no | Comma-separated |
| `REQUIRE_SENDER_AUTH` | no | `true` (default) / `false` |
| `DEFAULT_FORWARDER_CATCH_ALL`, `CATCH_ALL_DOMAINS`, `HELP_CONTACT`, `SES_CONFIG_SET_NAME` | no | |
| `IDEMPOTENCY_TABLE` | no | DynamoDB table (`pk` string key, `expires_at` TTL). Without it, retries can send duplicate replies |
| `IDEMPOTENCY_STALE_SECONDS` | no | Default 300. Terraform sets it to the Lambda timeout + 60. An in-progress claim older than this is taken over |
| `MAX_EMAIL_BYTES`, `MAX_BODY_CHARS` | no | Defaults are 10 MiB and 60,000 characters |
| `GITHUB_REPO`, `GITHUB_TOKEN_SECRET_ARN` | no | Both are needed to enable issues |
| `LOG_LEVEL` | no | Default `INFO` |

The function ignores the retired variables `AI_AWS_ACCESS_KEY_ID`, `AI_AWS_SECRET_ACCESS_KEY`,
`GITHUB_TOKEN`, `GITHUB_REPO_OWNER` and `GITHUB_REPO_NAME`, and logs a warning while they are set.

## Choosing a model

Opus 5.5 at `low` effort is the default. It takes about 10–15 seconds and roughly 2–3K input
tokens per email, and caches the 1.5K-token static prompt. For higher volume, `anthropic.claude-sonnet-5-5`
costs half as much. Compare the two on a sample of your own stored emails with
`phishing-tools analyze` before you switch.
