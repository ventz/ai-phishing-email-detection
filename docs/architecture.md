# Architecture

## Request flow

1. **SES receives** mail for the phishing address. The receipt rule requires TLS, runs spam and
   virus scanning, and writes the raw message to S3. SES adds its own `Authentication-Results`
   (SPF/DKIM/DMARC for the *forwarder*) and `X-SES-*-Verdict` headers at the top.
2. **S3 triggers Lambda** asynchronously. The Lambda service retries twice, and anything that still
   fails lands in the SQS failure queue, which has an alarm.
3. **Idempotency.** The function claims `bucket/key` in DynamoDB, with a per-attempt token,
   before any side effect. S3 redeliveries and Lambda retries therefore never send a second reply.
   A retry that finds a *fresh* claim raises an error, so it backs off and eventually reaches the
   failure queue instead of being dropped silently. A claim older than the Lambda timeout is
   taken over.
4. **Parse** (`parsing.py`, pure). This step finds the forwarded original. An inline forward
   below a Gmail or Outlook marker or header block wins; otherwise it uses the first attached
   message. It extracts:
   - identity headers: From, Reply-To, Return-Path, DKIM signing domain, and the original's
     Authentication-Results;
   - links as (anchor text, real href) pairs, including form actions and meta refreshes;
   - attachments with their SHA-256 hashes, plus the text of any HTML attachments;
   - the visible text from **every** inline HTML and plain part.

   Size is capped, and truncation is flagged to the model.
5. **Route** (`handler.route_reply`, pure). A reply goes to the forwarder only if:
   - there is exactly one From header, with one address;
   - it isn't a service or no-reply address;
   - its domain is in `allowed_sender_domains`;
   - SES recorded DMARC pass for that domain.

   SES's verdict is read only from the **first** `Authentication-Results` header, and only from a
   clause that *starts* with `dmarc=`. Comments and quoted strings are removed first, so an
   envelope sender like `dmarc=pass@attacker` cannot fake a pass.

   Allowed-domain failures (and virus hits) go to the catch-all. Other domains, unauthenticated
   spam, bounces, auto-replies and mailing-list mail are dropped.
6. **Classify** (`classifier.py`). This step calls the Bedrock Messages API with a static system
   prompt (cached) and a `record_verdict` tool. The tool's input is validated against a Pydantic
   schema, and the model gets one re-prompt if it doesn't call the tool.
7. **Render** (`render.py`, pure). The HTML and plain-text replies are built from the verdict.
   Everything is escaped, and every URL and domain is defanged.
8. **Send** with SES v2, with the header `Auto-Submitted: auto-replied`.

## Security model

| Threat | Control |
|--------|---------|
| Spoofed `From:` turns the service into a relay or backscatter source | DMARC-pass gate on SES's own verdict (the topmost header only), domain allowlist, and an IAM `ses:FromAddress` condition |
| A phish talks the model into "clean" | Evidence is fenced as untrusted data, and steering text counts as a phishing signal. A decoy text/plain part is surfaced next to the HTML. The verdict comes from a schema, not keyword matching |
| Failures reported as "clean" | Any classification failure sends **NOT ANALYZED — treat as suspicious** |
| Model output injects links or HTML into the reply | Everything is HTML-escaped. URLs and domains, including internationalized (IDN) domains, are defanged, and bidirectional and zero-width characters are stripped |
| Catch-all GitHub issues leak personal data | Issues carry metadata only: verdict, reason, S3 key, sender and link domains, attachment hashes |
| Long-lived credentials | No static keys: the Lambda role, or an optional assumed role. The GitHub token lives in Secrets Manager and never enters Terraform state |
| Stored emails contain personal data and live payloads | Bucket is private, owner-enforced, SSE, and TLS-only; the SES write is scoped by `SourceArn`; lifecycle expiry. Logs record keys and verdicts, never content |
| Floods and cost | A domain allowlist is required by default. Reserved concurrency, a 10 MiB size cap, body truncation, prompt caching, and model timeouts that respect the Lambda deadline |
| Supply chain | Locked dependencies installed with `--require-hashes`; providers pinned with a lock file |
| Mail loops | `Auto-Submitted` in both directions, and the service never replies to itself |

## Design decisions

- **Bedrock Messages API via the Anthropic SDK (`AnthropicBedrockMantle`)** rather than
  `InvokeModel` or Converse. It is the same request surface as the Claude API, SigV4-signed with the
  Lambda role. On Bedrock, `strict` tools and `output_config.format` currently return 400, and
  Opus/Sonnet 5.5 reject forced `tool_choice`. That is why the verdict uses `tool_choice: auto`
  plus validation and a re-prompt.
- **No `temperature`.** Sampling parameters return 400 on the current models, so variance is
  controlled by the schema and by effort.
- **S3 trigger kept** (rather than a direct SES Lambda action). SES's verdict headers in the stored
  message carry the same authentication information, and the existing deployment keeps working
  unchanged.
- **Handler shim.** `lambda_function.lambda_handler` re-exports `phishing_detector.handler`, so
  existing function configurations keep working.
