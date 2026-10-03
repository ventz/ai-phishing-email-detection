variable "aws_region" {
  description = "Region for every resource. SES email receiving must be available here."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for resource names."
  type        = string
  default     = "phishing-email-detection"
}

variable "tags" {
  description = "Extra tags applied to every resource."
  type        = map(string)
  default     = {}
}

# --- Email ---------------------------------------------------------------------------------------

variable "s3_bucket_name" {
  description = "Globally unique bucket that SES writes incoming emails to."
  type        = string
}

variable "ses_email_sender" {
  description = "Verified SES identity replies come from, e.g. noreply@example.org."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.ses_email_sender))
    error_message = "ses_email_sender must be a single email address."
  }
}

variable "ses_phishing_email_receiver" {
  description = "Address users forward suspicious emails to, e.g. phishing@example.org. Its domain must be verified in SES with an MX record pointing at SES."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.ses_phishing_email_receiver))
    error_message = "ses_phishing_email_receiver must be a single email address."
  }
}

variable "ses_configuration_set" {
  description = "Optional existing SES configuration set for replies (event publishing, reputation metrics)."
  type        = string
  default     = null
}

variable "receipt_rule_set_name" {
  description = "Existing SES receipt rule set to add the rule to. Usually the account's active set, which other services may share."
  type        = string
  default     = "RECEIVE"
}

variable "receipt_rule_name" {
  description = "Name of the receipt rule this stack owns."
  type        = string
  default     = "phishing"
}

variable "create_receipt_rule_set" {
  description = "Create (and activate) receipt_rule_set_name. Only for a fresh account: an account has one active set."
  type        = bool
  default     = false
}

variable "email_retention_days" {
  description = "Days to keep raw emails in S3 (they contain personal data and live phishing payloads). 0 keeps them forever: use it when adopting a bucket whose history you want to keep, since a new expiry applies to existing objects immediately."
  type        = number
  default     = 90

  validation {
    condition     = var.email_retention_days >= 0
    error_message = "email_retention_days must be 0 (keep forever) or a positive number of days."
  }
}

# --- Who gets a reply ----------------------------------------------------------------------------

variable "allowed_sender_domains" {
  description = "Only forwarders in these domains (and subdomains) get a reply."
  type        = list(string)
  default     = []
}

variable "allow_any_sender_domain" {
  description = "Explicit opt-in to reply to DMARC-authenticated senders from any domain."
  type        = bool
  default     = false
}

variable "require_sender_auth" {
  description = "Require the forwarder's DMARC to pass (per SES) before replying. Prevents spoofed-From backscatter."
  type        = bool
  default     = true
}

variable "default_forwarder_catch_all" {
  description = "Internal mailbox that gets the report when the forwarder is unauthenticated or unknown. Null drops those emails."
  type        = string
  default     = null
}

variable "catch_all_domains" {
  description = "Forwarder domains whose unauthenticated reports may go to the catch-all. Empty uses allowed_sender_domains, or else the receiver's base domain."
  type        = list(string)
  default     = []
}

variable "help_contact" {
  description = "Help-desk address shown in the reply footer."
  type        = string
  default     = null
}

# --- Model ---------------------------------------------------------------------------------------

variable "llm_provider" {
  description = "Model provider: bedrock (IAM role, default), anthropic (Claude API), openai, or custom (any Anthropic- or OpenAI-compatible endpoint)."
  type        = string
  default     = "bedrock"

  validation {
    condition     = contains(["bedrock", "anthropic", "openai", "custom"], var.llm_provider)
    error_message = "llm_provider must be bedrock, anthropic, openai or custom."
  }
}

variable "model_id" {
  description = "Model ID for the chosen provider, e.g. anthropic.claude-opus-5-5 (Bedrock), claude-opus-5-5 (Claude API), or an OpenAI model."
  type        = string
  default     = "anthropic.claude-opus-5-5"
}

variable "llm_api_key_secret_arn" {
  description = "Secrets Manager secret holding the provider API key (plain string or {\"api_key\": \"...\"}). Required for anthropic, openai and custom; optional for bedrock (a Bedrock API key, instead of the IAM role). Use the full ARN including its 6-character suffix. Created outside Terraform so the key never enters state; a secret encrypted with a customer-managed KMS key also needs kms:Decrypt on the Lambda role."
  type        = string
  default     = null
}

variable "llm_base_url" {
  description = "custom (required) or anthropic/openai (optional, e.g. a regional endpoint): the base URL, https://host[/path] with no credentials or query."
  type        = string
  default     = null

  validation {
    condition     = var.llm_base_url == null || can(regex("^https://[^/@?#\\s]+(/[^@?#\\s]*)?$", var.llm_base_url))
    error_message = "llm_base_url must be https://host[/path], with no credentials, query or fragment."
  }
}

variable "llm_api_style" {
  description = "custom only: anthropic (Messages API) or openai (chat completions)."
  type        = string
  default     = "anthropic"

  validation {
    condition     = contains(["anthropic", "openai"], var.llm_api_style)
    error_message = "llm_api_style must be anthropic or openai."
  }
}

variable "llm_auth_header" {
  description = "custom only: header that carries the key when the gateway doesn't use the SDK default (e.g. apikey)."
  type        = string
  default     = null

  validation {
    condition = var.llm_auth_header == null || (
      can(regex("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$", var.llm_auth_header)) &&
      !contains(["host", "content-length", "content-type", "transfer-encoding", "connection"], lower(coalesce(var.llm_auth_header, "x")))
    )
    error_message = "llm_auth_header must be a valid HTTP header name, not Host, Content-Length, Content-Type, Transfer-Encoding or Connection."
  }
}

variable "llm_auth_scheme" {
  description = "custom only: optional prefix for that header, e.g. Bearer. Needs llm_auth_header."
  type        = string
  default     = null

  validation {
    condition     = var.llm_auth_scheme == null || can(regex("^[A-Za-z0-9._~+/-]+$", var.llm_auth_scheme))
    error_message = "llm_auth_scheme must be a single token, e.g. Bearer."
  }
}

variable "analyze_tlp_restricted" {
  description = "Send TLP:AMBER/RED reports to the model. Null means true for bedrock (the email stays in your AWS account) and false for third-party providers, where such reports get a NOT ANALYZED reply."
  type        = bool
  default     = null
}

variable "model_effort" {
  description = "Claude effort level: low | medium | high | xhigh | max, or none to omit it (non-Claude models or endpoints that reject it)."
  type        = string
  default     = "low"

  validation {
    condition     = contains(["low", "medium", "high", "xhigh", "max", "none"], var.model_effort)
    error_message = "model_effort must be one of low, medium, high, xhigh, max, none."
  }
}

variable "fallback_model_id" {
  description = "Optional Bedrock model ID to retry on when the primary model declines a request."
  type        = string
  default     = null
}

variable "bedrock_role_arn" {
  description = "Optional role to assume for Bedrock when model access lives in another account. Null uses the Lambda role."
  type        = string
  default     = null
}

# --- Lambda --------------------------------------------------------------------------------------

variable "lambda_memory_mb" {
  description = "1024 MB also doubles CPU; attachment parsing (PDF, images) assumes at least this much."
  type        = number
  default     = 1024
}

variable "lambda_timeout_seconds" {
  description = "Covers a slow model call plus SDK retries; the model call is fitted inside it."
  type        = number
  default     = 180

  validation {
    condition     = var.lambda_timeout_seconds >= 90 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be 90-900 (a single Opus call takes 10-20 s, with up to 3 attempts)."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Caps parallel analyses (and Bedrock spend) if the address is flooded. -1 for no limit."
  type        = number
  default     = 5
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic notified when an email lands in the failure queue. Null leaves the alarm without an action."
  type        = string
  default     = null
}

variable "log_retention_days" {
  type    = number
  default = 30
}

# --- Optional GitHub issues for catch-all reports ------------------------------------------------

variable "github_repo" {
  description = "owner/name of a repo to open an issue in for each catch-all report. Null disables."
  type        = string
  default     = null
}

variable "github_token_secret_arn" {
  description = "Secrets Manager secret holding a fine-grained GitHub token (Issues: write on github_repo only). Created outside Terraform so the token never enters state."
  type        = string
  default     = null
}
