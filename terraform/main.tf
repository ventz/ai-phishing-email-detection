data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  rule_name     = var.receipt_rule_name
  sender        = lower(var.ses_email_sender) # the code lowercases too; ses:FromAddress is case-sensitive
  sender_domain = split("@", local.sender)[1]
  rule_arn      = "arn:${local.partition}:ses:${var.aws_region}:${local.account_id}:receipt-rule-set/${var.receipt_rule_set_name}:receipt-rule/${local.rule_name}"
}

# --- Email storage -------------------------------------------------------------------------------

resource "aws_s3_bucket" "emails" {
  bucket = var.s3_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "emails" {
  bucket = aws_s3_bucket.emails.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "emails" {
  bucket                  = aws_s3_bucket.emails.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "emails" {
  bucket = aws_s3_bucket.emails.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "emails" {
  bucket = aws_s3_bucket.emails.id
  rule {
    id     = "expire-emails"
    status = "Enabled"
    filter {}
    expiration {
      days = var.email_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "emails" {
  bucket     = aws_s3_bucket.emails.id
  depends_on = [aws_s3_bucket_public_access_block.emails]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSESReceiptRuleWrites"
        Effect    = "Allow"
        Principal = { Service = "ses.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.emails.arn}/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
          ArnLike      = { "aws:SourceArn" = local.rule_arn }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.emails.arn, "${aws_s3_bucket.emails.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

# --- SES receipt rule ----------------------------------------------------------------------------

resource "aws_ses_receipt_rule_set" "this" {
  count         = var.create_receipt_rule_set ? 1 : 0
  rule_set_name = var.receipt_rule_set_name
}

resource "aws_ses_active_receipt_rule_set" "this" {
  count         = var.create_receipt_rule_set ? 1 : 0
  rule_set_name = aws_ses_receipt_rule_set.this[0].rule_set_name
}

resource "aws_ses_receipt_rule" "phishing" {
  name          = local.rule_name
  rule_set_name = var.receipt_rule_set_name
  recipients    = [var.ses_phishing_email_receiver]
  enabled       = true
  tls_policy    = "Require"
  scan_enabled  = true # adds X-SES-Spam-Verdict / X-SES-Virus-Verdict headers

  s3_action {
    bucket_name = aws_s3_bucket.emails.bucket
    position    = 1
  }

  depends_on = [aws_s3_bucket_policy.emails, aws_ses_receipt_rule_set.this]
}

# --- Idempotency and failure handling ------------------------------------------------------------

resource "aws_dynamodb_table" "idempotency" {
  name         = "${var.project_name}-idempotency"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_sqs_queue" "failures" {
  name                      = "${var.project_name}-failures"
  message_retention_seconds = 1209600 # 14 days
  sqs_managed_sse_enabled   = true
}

# --- Lambda --------------------------------------------------------------------------------------

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../build/lambda"
  output_path = "${path.module}/../build/function.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "ReadEmails"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.emails.arn}/*"]
  }

  statement {
    sid     = "SendReplies"
    actions = ["ses:SendEmail"]
    resources = concat(
      [
        "arn:${local.partition}:ses:${var.aws_region}:${local.account_id}:identity/${local.sender}",
        "arn:${local.partition}:ses:${var.aws_region}:${local.account_id}:identity/${local.sender_domain}",
      ],
      var.ses_configuration_set == null ? [] : [
        "arn:${local.partition}:ses:${var.aws_region}:${local.account_id}:configuration-set/${var.ses_configuration_set}",
      ],
    )
    condition {
      test     = "StringEquals"
      variable = "ses:FromAddress"
      values   = [local.sender]
    }
  }

  statement {
    sid       = "Idempotency"
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.idempotency.arn]
  }

  statement {
    sid       = "FailureDestination"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.failures.arn]
  }

  dynamic "statement" {
    for_each = var.bedrock_role_arn == null ? [1] : []
    content {
      # Claude Messages API on Bedrock. bedrock-mantle has no per-model resource type yet.
      sid       = "BedrockMessages"
      actions   = ["bedrock-mantle:CreateInference", "bedrock-mantle:GetProject", "bedrock-mantle:ListProjects"]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "aws:RequestedRegion"
        values   = [var.aws_region]
      }
    }
  }

  dynamic "statement" {
    for_each = var.bedrock_role_arn == null ? [] : [1]
    content {
      sid       = "AssumeBedrockRole"
      actions   = ["sts:AssumeRole"]
      resources = [var.bedrock_role_arn]
    }
  }

  dynamic "statement" {
    for_each = var.github_token_secret_arn == null ? [] : [1]
    content {
      sid       = "GitHubToken"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.github_token_secret_arn]
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${var.project_name}-lambda"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "this" {
  function_name    = var.project_name
  role             = aws_iam_role.lambda.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.13"
  architectures    = ["arm64"]
  memory_size      = var.lambda_memory_mb
  timeout          = var.lambda_timeout_seconds
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.lambda.name
  }

  environment {
    variables = { for k, v in {
      SES_EMAIL_SENDER            = local.sender
      SES_PHISHING_EMAIL_RECEIVER = var.ses_phishing_email_receiver
      SES_CONFIG_SET_NAME         = var.ses_configuration_set
      DEFAULT_FORWARDER_CATCH_ALL = var.default_forwarder_catch_all
      ALLOWED_SENDER_DOMAINS      = join(",", var.allowed_sender_domains)
      REQUIRE_SENDER_AUTH         = tostring(var.require_sender_auth)
      HELP_CONTACT                = var.help_contact
      MODEL_ID                    = var.model_id
      MODEL_EFFORT                = var.model_effort
      FALLBACK_MODEL_ID           = var.fallback_model_id
      BEDROCK_ROLE_ARN            = var.bedrock_role_arn
      IDEMPOTENCY_TABLE           = aws_dynamodb_table.idempotency.name
      IDEMPOTENCY_STALE_SECONDS   = tostring(var.lambda_timeout_seconds + 60)
      GITHUB_REPO                 = var.github_repo
      GITHUB_TOKEN_SECRET_ARN     = var.github_token_secret_arn
    } : k => v if v != null && v != "" }
  }

  lifecycle {
    precondition {
      condition     = length(var.allowed_sender_domains) > 0 || var.allow_any_sender_domain
      error_message = "Set allowed_sender_domains (recommended), or allow_any_sender_domain = true to answer any DMARC-authenticated sender on the internet (every analysis costs a model call)."
    }
  }

  depends_on = [aws_iam_role_policy.lambda]
}

resource "aws_lambda_function_event_invoke_config" "this" {
  function_name                = aws_lambda_function.this.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 21600

  destination_config {
    on_failure {
      destination = aws_sqs_queue.failures.arn
    }
  }
}

resource "aws_lambda_permission" "s3" {
  statement_id   = "AllowS3Invoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.this.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.emails.arn
  source_account = local.account_id
}

resource "aws_s3_bucket_notification" "emails" {
  bucket = aws_s3_bucket.emails.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.this.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.s3]
}

# --- Alerting hook -------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "failures" {
  alarm_name          = "${var.project_name}-failed-emails"
  alarm_description   = "An email exhausted its retries and landed in the failure queue."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.failures.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = compact([var.alarm_sns_topic_arn])
}
