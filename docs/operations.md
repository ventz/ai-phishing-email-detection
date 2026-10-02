# Operations

## CLI

```bash
export AWS_PROFILE=my-profile AWS_REGION=us-east-1
export PHISHING_BUCKET=example-org-phishing-emails PHISHING_FUNCTION=phishing-email-detection

uv run phishing-tools list [--limit 50] [--prefix p]
uv run phishing-tools show    --key <key>              # parsed evidence, exactly as the model sees it
uv run phishing-tools analyze --key <key> [--html out.html]   # classify locally, send nothing
uv run phishing-tools replay  --key <key> --yes        # run the deployed function (sends a real reply)
```

`show` and `list` strip terminal control characters, because stored emails are
attacker-controlled. `replay` on a key that was already processed is skipped as a duplicate.
Delete the `bucket/key` item from the idempotency table first if you really want a second reply.

## Logs

The function writes JSON logs to `/aws/lambda/<project_name>`. Useful messages:

| Message | Meaning |
|---------|---------|
| `reply sent` | Includes `verdict`, `catch_all` and `ses_message_id` |
| `no reply sent` | `reason` says why (DMARC failure, domain not allowed, auto-submitted, ...) |
| `classified` | Model, stop reason, token usage, and cache reads and writes |
| `classification failed` | The user got the NOT ANALYZED reply |
| `TLP-restricted email tagged for expiry` | A TLP:AMBER/RED report was detected; its raw email is removed by lifecycle within ~1-2 days |
| `guardrails raised verdict` | A deterministic rule raised the model's verdict; `reasons` lists which |
| `email could not be parsed` / `email too large to analyze` | The reporter got a NOT ANALYZED reply |
| `duplicate event skipped` | The email was already handled (retry or redelivery) |
| `InFlight` error | Another attempt holds a fresh claim; Lambda retries later |

```bash
aws logs tail /aws/lambda/phishing-email-detection --follow --format short
```

## Failure queue

An email whose processing still fails after two Lambda retries (for example, SES or S3 errors)
goes to the `<project_name>-failures` SQS queue, and the `<project_name>-failed-emails` alarm
fires. Subscribe the alarm to an SNS topic to get notified. Each message holds the original S3
event: fix the cause, then `replay` the key.

## Cost

Per email at the default Opus 5.5 at `low` effort: about 1.5K cached prompt tokens, 1–4K fresh
input tokens, and 0.5–1K output tokens. Lambda time is 10–20 seconds at 512 MB. Reserved
concurrency (5 by default) is the ceiling on spend during a flood.

## Testing attachments end to end

Mail clients often drop attachments when forwarding inline (Superhuman does), so a forward is a
poor test of PDF or QR handling. Instead, build a test `.eml` that forwards a sample *as an
attachment*, from your own address, and put it straight into the bucket under a `synthetic-test-`
key. The S3 notification triggers the function exactly as for real mail, and the reply comes to
you. Afterwards delete the object and its `bucket/key` item in the idempotency table.

Never replay other people's stored reports to test: the reply goes to the original reporter.
