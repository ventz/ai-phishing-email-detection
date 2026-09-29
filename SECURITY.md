# Security Policy

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/ventz/ai-phishing-email-detection/security/advisories/new)
rather than in a public issue. Include steps to reproduce, and expect an acknowledgment within a few
days.

Examples of things in scope: bypassing the forwarder-authentication gate, getting the service to
send mail to arbitrary recipients, injecting content into replies, manipulating verdicts through
crafted emails, and privilege problems in the Terraform IAM policies.

For how the service defends against these, see the security model in
[docs/architecture.md](docs/architecture.md#security-model).
