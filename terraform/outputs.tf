output "lambda_function_name" {
  value = aws_lambda_function.this.function_name
}

output "s3_bucket_name" {
  value = aws_s3_bucket.emails.bucket
}

output "phishing_address" {
  description = "Tell users to forward suspicious emails here."
  value       = var.ses_phishing_email_receiver
}

output "log_group" {
  value = aws_cloudwatch_log_group.lambda.name
}

output "failure_queue_url" {
  description = "Emails that exhausted their retries. Inspect, then replay with phishing-tools."
  value       = aws_sqs_queue.failures.url
}
