# AWS Phishing Email Detection Infrastructure
# This Terraform configuration sets up the necessary AWS resources for the phishing email detection service.

# Provider Configuration
provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  aws_account_id = data.aws_caller_identity.current.account_id
  aws_region     = data.aws_region.current.region
}

# Variables
variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "phishing-email-detection"
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for storing emails"
  type        = string
  default     = "phishing-emails"
}

variable "ses_domain_name" {
  description = "Domain name for SES"
  type        = string
  default     = "domain.tld"
}

variable "ses_email_sender" {
  description = "Email address to use as the sender for response emails"
  type        = string
  default     = "noreply@domain.tld"
}

variable "ses_phishing_email_receiver" {
  description = "Email address to receive forwarded emails for analysis"
  type        = string
  default     = "phishing@domain.tld"
}

variable "default_forwarder_catch_all" {
  description = "Required catch-all email address when forwarder can't be determined"
  type        = string
}

variable "github_token" {
  description = "Optional GitHub token for creating issues when emails are sent to catch-all"
  type        = string
  default     = ""
  sensitive   = true
}

variable "github_repo_owner" {
  description = "Optional GitHub repository owner for issue creation"
  type        = string
  default     = ""
}

variable "github_repo_name" {
  description = "Optional GitHub repository name for issue creation"
  type        = string
  default     = ""
}

variable "ses_configuration_set" {
  description = "SES Configuration Set Name"
  type        = string
  default     = "AWS-SES-Send-Email"
}

# S3 Bucket for storing emails
resource "aws_s3_bucket" "phishing_emails" {
  bucket = "${var.s3_bucket_name}-${local.aws_account_id}"

  tags = {
    Name        = "${var.s3_bucket_name}-${local.aws_account_id}"
    Environment = "production"
    Project     = var.project_name
  }
}

# S3 Bucket Ownership Controls
resource "aws_s3_bucket_ownership_controls" "phishing_emails" {
  bucket = aws_s3_bucket.phishing_emails.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket ACL
resource "aws_s3_bucket_acl" "phishing_emails_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.phishing_emails]
  bucket     = aws_s3_bucket.phishing_emails.id
  acl        = "private"
}

# S3 Bucket Policy to Allow SES to Write
resource "aws_s3_bucket_policy" "phishing_emails_policy" {
  bucket = aws_s3_bucket.phishing_emails.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "ses.amazonaws.com" },
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.phishing_emails.arn}/*",
        Condition = {
          StringEquals = {
            "aws:Referer" = local.aws_account_id
          }
        }
      }
    ]
  })
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = 30

  tags = {
    Name        = "${var.project_name}-logs"
    Environment = "production"
    Project     = var.project_name
  }
}

# IAM Role for Lambda Execution
resource "aws_iam_role" "lambda_execution_role" {
  name = "${var.project_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-role"
    Environment = "production"
    Project     = var.project_name
  }
}

# IAM Policies for Lambda Role

# S3 GetObject Policy
resource "aws_iam_policy" "lambda_s3_get_object_policy" {
  name        = "Allow-Lambda-to-S3-Retrieve-Object"
  description = "Allows Lambda to retrieve objects from the S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "s3:GetObject",
        Resource = "${aws_s3_bucket.phishing_emails.arn}/*"
      }
    ]
  })
}

# SES SendEmail Policy
resource "aws_iam_policy" "lambda_ses_send_email_policy" {
  name        = "Allow-Lambda-to-SES-Send-Email"
  description = "Allows Lambda to send emails via SES"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "ses:SendEmail",
        Resource = [
          "arn:aws:ses:${local.aws_region}:${local.aws_account_id}:identity/${var.ses_domain_name}",
          "arn:aws:ses:${local.aws_region}:${local.aws_account_id}:configuration-set/${var.ses_configuration_set}"
        ]
      }
    ]
  })
}

# CloudWatch Logs Policy
resource "aws_iam_policy" "lambda_cloudwatch_logs_policy" {
  name        = "Allow-Lambda-to-CloudWatch-Logs"
  description = "Allows Lambda to write logs to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
      }
    ]
  })
}

# Bedrock Policy
resource "aws_iam_policy" "lambda_bedrock_policy" {
  name        = "Allow-Lambda-to-Bedrock"
  description = "Allows Lambda to invoke Bedrock models"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "bedrock:InvokeModel"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach policies to Lambda Role
resource "aws_iam_role_policy_attachment" "attach_s3_policy" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_s3_get_object_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_ses_policy" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_ses_send_email_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_cloudwatch_logs_policy" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_cloudwatch_logs_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_bedrock_policy" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_bedrock_policy.arn
}

# IAM Role Policy for S3 to Invoke Lambda
resource "aws_lambda_permission" "allow_s3_invoke" {
  statement_id  = "AllowS3ToInvokeLambda"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.phishing_email_detection.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.phishing_emails.arn
}

# Create lambda package directory with dependencies
resource "null_resource" "install_dependencies" {
  triggers = {
    requirements = filemd5("${path.module}/requirements.txt")
    lambda_code  = filemd5("${path.module}/lambda_function.py")
  }

  provisioner "local-exec" {
    command = <<-EOT
      # Create a temporary directory for packaging
      rm -rf ${path.module}/lambda_package
      mkdir -p ${path.module}/lambda_package

      # Install dependencies to the package directory
      pip install -r ${path.module}/requirements.txt -t ${path.module}/lambda_package/

      # Copy the lambda function code
      cp ${path.module}/lambda_function.py ${path.module}/lambda_package/

      # Create the zip file
      cd ${path.module}/lambda_package && zip -r ../function.zip .

      # Clean up temporary directory
      rm -rf ${path.module}/lambda_package
    EOT
  }
}

# Create the zip file using Terraform's archive_file
data "archive_file" "lambda_zip" {
  depends_on = [null_resource.install_dependencies]

  type        = "zip"
  source_dir  = "${path.module}/lambda_package"
  output_path = "${path.module}/function.zip"
}

# Lambda Function
resource "aws_lambda_function" "phishing_email_detection" {
  function_name = var.project_name
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"
  timeout       = 60  # 60 seconds timeout
  memory_size   = 256 # 256 MB memory

  # Path to your deployment package
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SES_DOMAIN_NAME             = var.ses_domain_name
      SES_EMAIL_SENDER            = var.ses_email_sender
      SES_PHISHING_EMAIL_RECEIVER = var.ses_phishing_email_receiver
      SES_CONFIG_SET_NAME         = var.ses_configuration_set
      DEFAULT_FORWARDER_CATCH_ALL = var.default_forwarder_catch_all
      GITHUB_TOKEN                = var.github_token
      GITHUB_REPO_OWNER           = var.github_repo_owner
      GITHUB_REPO_NAME            = var.github_repo_name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    data.archive_file.lambda_zip
  ]

  tags = {
    Name        = var.project_name
    Environment = "production"
    Project     = var.project_name
  }
}

# S3 Bucket Notification to Trigger Lambda on Object Creation
resource "aws_s3_bucket_notification" "s3_to_lambda_trigger" {
  bucket = aws_s3_bucket.phishing_emails.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.phishing_email_detection.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke]
}

# SES Receipt Rule Set (ensure it's active)
resource "aws_ses_receipt_rule_set" "receive_rule_set" {
  rule_set_name = "RECEIVE"
}

# SES Receipt Rule for Phishing Emails
resource "aws_ses_receipt_rule" "phishing_rule" {
  rule_set_name = aws_ses_receipt_rule_set.receive_rule_set.rule_set_name
  name          = "phishing"
  enabled       = true
  recipients    = [var.ses_phishing_email_receiver]
  tls_policy    = "Optional"
  scan_enabled  = false # Disable spam and virus scanning

  s3_action {
    bucket_name       = aws_s3_bucket.phishing_emails.bucket
    object_key_prefix = ""
    position          = 1
  }

  depends_on = [aws_s3_bucket.phishing_emails]
}

# Outputs
output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.phishing_email_detection.function_name
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for storing emails"
  value       = aws_s3_bucket.phishing_emails.bucket
}

output "ses_phishing_email_receiver" {
  description = "Email address to receive forwarded emails for analysis"
  value       = var.ses_phishing_email_receiver
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group for Lambda logs"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}
