# Contributing

```bash
uv sync                  # Python 3.13 + dev tools
uv run pytest            # unit tests (no AWS needed)
uv run ruff check . && uv run ruff format --check .
terraform -chdir=terraform fmt -check && terraform -chdir=terraform validate
```

- CI (`.github/workflows/ci.yml`) runs the same checks on every push and pull request.
- Parsing, routing and rendering are pure functions. Add a test for every behavior change. Build
  fixtures in `tests/conftest.py` from `email.message.EmailMessage` instead of committing real
  emails, which contain personal data.
- Anything that reaches the reply must go through `render._safe` (escape + defang).
- Keep the system prompt static. Per-email data goes in the user turn so the prompt cache keeps
  working.
- Pull requests: one logical change, with tests, and the docs in `docs/` updated when behavior or
  configuration changes.
