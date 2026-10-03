"""Operator CLI: list stored emails, show what the model sees, analyze locally, replay through Lambda.

    uv run phishing-tools list    --bucket BUCKET [--limit 20]
    uv run phishing-tools show    --bucket BUCKET --key KEY
    uv run phishing-tools analyze --bucket BUCKET --key KEY [--html out.html]
    uv run phishing-tools replay  --bucket BUCKET --key KEY --function NAME --yes

Bucket and function default to $PHISHING_BUCKET and $PHISHING_FUNCTION. AWS credentials and region
come from the usual AWS_PROFILE / AWS_REGION environment.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime

import boto3

from . import guardrails
from .classifier import ClassificationError, classify
from .config import Settings
from .parsing import parse_email
from .render import ReportContext, render_unavailable, render_verdict

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(text: str) -> str:
    """Strip terminal control characters: stored emails are attacker-controlled."""
    return _CONTROL.sub("", text)


def _raw(bucket: str, key: str) -> bytes:
    return boto3.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()


def cmd_list(args: argparse.Namespace) -> None:
    pages = boto3.client("s3").get_paginator("list_objects_v2").paginate(Bucket=args.bucket, Prefix=args.prefix)
    objects = [o for page in pages for o in page.get("Contents", [])]
    objects.sort(key=lambda o: o["LastModified"], reverse=True)
    for o in objects[: args.limit]:
        print(f"{o['LastModified']:%Y-%m-%d %H:%M}  {o['Size']:>9,}  {_safe(o['Key'])}")
    print(f"\n{min(args.limit, len(objects))} of {len(objects)} objects (newest first)")


def cmd_show(args: argparse.Namespace) -> None:
    email = parse_email(_raw(args.bucket, args.key))
    auth = email.sender_auth
    print(f"Forwarder: {_safe(email.forwarder or '(none)')}  (SES: spf={auth.spf} dkim={auth.dkim} dmarc={auth.dmarc})")
    print(f"Subject:   {_safe(email.subject)}\n")
    print(_safe(email.to_prompt()))


def _settings(args: argparse.Namespace) -> Settings:
    # Local analysis sends nothing, so SES settings are optional; model settings are still validated.
    return Settings.from_env(require_ses=False)


def cmd_analyze(args: argparse.Namespace) -> None:
    email = parse_email(_raw(args.bucket, args.key))
    try:
        settings = _settings(args)
        if email.tlp_restricted and not settings.analyze_tlp_restricted:
            raise ClassificationError(f"{email.tlp} report not sent to the model (ANALYZE_TLP_RESTRICTED is off)")
        verdict = classify(email, settings)
        verdict, _ = guardrails.apply(email, verdict)
        reply = render_verdict(verdict, ReportContext(email.subject, email.forwarder, ref="local"))
    except ClassificationError as exc:
        print(f"Classification failed: {exc}", file=sys.stderr)
        reply = render_unavailable(ReportContext(email.subject, email.forwarder, ref="local"))
    print(f"Subject: {_safe(reply.subject)}\n\n{_safe(reply.text)}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(reply.html)
        print(f"\nHTML preview written to {args.html}")


def cmd_replay(args: argparse.Namespace) -> None:
    if not args.yes:
        sys.exit("replay sends a REAL reply email to the original forwarder. Re-run with --yes to confirm.")
    event = {
        "Records": [
            {
                "eventSource": "aws:s3",
                "eventName": "ObjectCreated:Put",
                "eventTime": datetime.now(UTC).isoformat(),
                "s3": {"bucket": {"name": args.bucket}, "object": {"key": args.key}},
            }
        ]
    }
    response = boto3.client("lambda").invoke(FunctionName=args.function, Payload=json.dumps(event).encode())
    print(response["Payload"].read().decode())
    if response.get("FunctionError"):
        sys.exit(1)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="phishing-tools", description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def with_bucket(p: argparse.ArgumentParser, key: bool = True) -> argparse.ArgumentParser:
        bucket = os.environ.get("PHISHING_BUCKET")
        p.add_argument("--bucket", default=bucket, required=bucket is None, help="S3 bucket (or $PHISHING_BUCKET)")
        if key:
            p.add_argument("--key", required=True, help="S3 object key of the stored email")
        return p

    p = with_bucket(sub.add_parser("list", help="list stored emails, newest first"), key=False)
    p.add_argument("--prefix", default="")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_list)

    with_bucket(sub.add_parser("show", help="print the evidence exactly as the model sees it")).set_defaults(
        func=cmd_show
    )

    p = with_bucket(sub.add_parser("analyze", help="classify locally and print the reply (sends nothing)"))
    p.add_argument("--html", help="also write the HTML reply to this file")
    p.set_defaults(func=cmd_analyze)

    p = with_bucket(sub.add_parser("replay", help="re-run the deployed Lambda on a stored email"))
    function = os.environ.get("PHISHING_FUNCTION")
    p.add_argument("--function", default=function, required=function is None, help="Lambda name ($PHISHING_FUNCTION)")
    p.add_argument("--yes", action="store_true", help="confirm that a real reply will be sent")
    p.set_defaults(func=cmd_replay)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
