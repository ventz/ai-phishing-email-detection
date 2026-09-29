# Getting Started

This guide takes you from an empty AWS account (or an existing hand-built deployment) to a working
phishing address.

- [Prerequisites](#prerequisites)
- [1. Build the package](#1-build-the-package)
- [2. Configure](#2-configure)
- [3. Deploy](#3-deploy)
- [4. Test with one email](#4-test-with-one-email)
- [Adopting an existing deployment](#adopting-an-existing-deployment)

## Prerequisites

- **Tools:** Python 3.13, [uv](https://docs.astral.sh/uv/), Terraform 1.5+, AWS CLI v2.
- **SES sending:** a verified domain (or at least the sender address). The account must be out of
  the SES sandbox, or replies only reach verified addresses.
- **SES receiving:** the receiving domain must have an MX record pointing at
  `inbound-smtp.<region>.amazonaws.com`, in a region that supports email receiving. An account has
  one *active* receipt rule set. This stack adds its rule to the existing set (`RECEIVE` by
  default) and does not take it over. Set `create_receipt_rule_set = true` only in a fresh account.
- **Bedrock:** the function calls Claude through the Bedrock Messages API
  (`bedrock-mantle.<region>.api.aws`), with model ID `anthropic.claude-opus-5-5` by default. The
  account must have access to that model. If model access lives in a different account, set
  `bedrock_role_arn` to a role there that the function can assume. That role needs
  `bedrock-mantle:CreateInference`, and a trust policy that allows the Lambda role. The function
  never uses static keys.

## 1. Build the package

```bash
uv sync
uv run pytest
./scripts/build.sh     # writes build/lambda (Linux arm64 wheels); Terraform zips it
```

## 2. Configure

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

At a minimum, set `s3_bucket_name`, `ses_email_sender`, `ses_phishing_email_receiver`, and
`allowed_sender_domains`. The plan fails without it unless you set `allow_any_sender_domain`.
Every option is described in [Configuration](configuration.md).

State contains resource IDs and the full configuration. Configure the S3 backend in
`terraform/versions.tf` before the first apply, rather than keeping state on a laptop.

## 3. Deploy

```bash
cd terraform
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

## 4. Test with one email

1. From an address in `allowed_sender_domains`, forward a known phishing sample *as an
   attachment* to the phishing address.
2. Watch the logs: `aws logs tail /aws/lambda/<project_name> --follow`.
3. A `reply sent` log line with the verdict should appear, followed by the email. If you see
   `no reply sent`, the log entry gives the reason. The usual one is a DMARC failure for the
   forwarder's domain.

## Adopting an existing deployment

If you built the stack by hand (or with the original single-file Terraform), import what exists
before you apply, so Terraform takes over resources instead of trying to recreate them. Add a
temporary `terraform/imports.tf`:

```hcl
import {
  to = aws_s3_bucket.emails
  id = "my-existing-bucket"
}
import {
  to = aws_lambda_function.this
  id = "phishing-email-detection"
}
import {
  to = aws_cloudwatch_log_group.lambda
  id = "/aws/lambda/phishing-email-detection"
}
import {
  to = aws_ses_receipt_rule.phishing
  id = "RECEIVE:phishing"   # rule-set-name:rule-name
}
```

Then:

1. **Plan and read it.** `terraform plan` should show *updates* to the bucket, function and rule,
   plus *creates* for the new pieces: role, table, queue, lifecycle and policies. It must not
   show any `destroy` of those resources.
2. **Check the environment variables.** The function no longer reads `AI_AWS_ACCESS_KEY_ID` or
   `AI_AWS_SECRET_ACCESS_KEY`. It logs a warning if they are still present, and applying this
   stack removes them. Grant Bedrock access to the new Lambda role (the default), or set
   `bedrock_role_arn`.
3. **Keep what you relied on.** The old default `ses_configuration_set = "AWS-SES-Send-Email"` is
   no longer implied. Set it explicitly if replies should keep using it.
4. **Revoke the old keys.** After the first successful reply, delete the IAM access key that used
   to be in the environment variables. It sat in plaintext in the function configuration.
5. **Clean up.** Remove `imports.tf`. Then delete what the old stack or console created and nothing
   uses any more: the old execution role and its `Allow-Lambda-to-*` policies, and the old
   `AllowS3ToInvokeLambda` permission if its statement ID differs.

The handler path (`lambda_function.lambda_handler`) is unchanged, so an old function can also
run the new package directly while you migrate.
