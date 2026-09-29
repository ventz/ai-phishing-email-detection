"""Thin wrappers around the AWS and GitHub side effects, kept apart so the core stays pure."""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from .render import Reply

logger = logging.getLogger(__name__)

_BOTO = Config(retries={"mode": "standard", "max_attempts": 4}, connect_timeout=5, read_timeout=20)
_clients: dict[str, Any] = {}


def client(name: str) -> Any:
    if name not in _clients:
        _clients[name] = boto3.client(name, config=_BOTO)
    return _clients[name]


class EmailTooLarge(ValueError):
    """Carries the first bytes of the message so the headers can still be routed and answered."""

    def __init__(self, message: str, head: bytes) -> None:
        super().__init__(message)
        self.head = head


def fetch_email(bucket: str, key: str, max_bytes: int, head_bytes: int = 256 * 1024) -> bytes:
    s3 = client("s3")
    size = s3.head_object(Bucket=bucket, Key=key)["ContentLength"]
    if size > max_bytes:
        head = s3.get_object(Bucket=bucket, Key=key, Range=f"bytes=0-{head_bytes - 1}")["Body"].read()
        raise EmailTooLarge(f"{size} bytes exceeds the {max_bytes}-byte limit", head)
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def send_reply(reply: Reply, *, sender: str, to: str, configuration_set: str | None) -> str:
    params: dict[str, Any] = {
        "FromEmailAddress": sender,
        "Destination": {"ToAddresses": [to]},
        "Content": {
            "Simple": {
                "Subject": {"Data": reply.subject, "Charset": "UTF-8"},
                "Body": {
                    "Text": {"Data": reply.text, "Charset": "UTF-8"},
                    "Html": {"Data": reply.html, "Charset": "UTF-8"},
                },
                # Mark as an automated reply so well-behaved systems never answer it (no mail loops).
                "Headers": [{"Name": "Auto-Submitted", "Value": "auto-replied"}],
            }
        },
    }
    if configuration_set:
        params["ConfigurationSetName"] = configuration_set
    return client("sesv2").send_email(**params)["MessageId"]


class InFlight(RuntimeError):
    """Another attempt holds a fresh claim. Raised so Lambda retries later, then the failure queue."""


class Idempotency:
    """At-most-once replies across Lambda retries and duplicate S3 events.

    ``claim`` writes an ``in_progress`` record with a unique token before any side effect;
    ``complete``/``release`` only touch the record while it still carries that token. A claim older
    than ``stale_after`` (set just above the Lambda timeout) belonged to a killed attempt and can be
    taken over. A fresh claim held by someone else raises ``InFlight``.
    """

    def __init__(self, table: str | None, *, stale_after: int = 300, ttl_days: int = 14) -> None:
        self.table = table
        self.stale_after = stale_after
        self.ttl_days = ttl_days

    def claim(self, key: str) -> str | None:
        """Token when claimed, None when the email was already handled."""
        token = str(time.time_ns())
        if not self.table:
            return token
        now = int(time.time())
        try:
            client("dynamodb").put_item(
                TableName=self.table,
                Item={
                    "pk": {"S": key},
                    "status": {"S": "in_progress"},
                    "token": {"S": token},
                    "claimed_at": {"N": str(now)},
                    "expires_at": {"N": str(now + self.ttl_days * 86400)},
                },
                ConditionExpression="attribute_not_exists(pk) OR (#s = :p AND claimed_at < :stale)",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":p": {"S": "in_progress"}, ":stale": {"N": str(now - self.stale_after)}},
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
            )
            return token
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            status = exc.response.get("Item", {}).get("status", {}).get("S")
            if status == "in_progress":
                raise InFlight(f"{key} is being processed by another attempt") from exc
            return None

    def _owned(self, token: str) -> dict[str, Any]:
        return {
            "ConditionExpression": "#t = :t",
            "ExpressionAttributeNames": {"#t": "token"},
            "ExpressionAttributeValues": {":t": {"S": token}},
        }

    def complete(self, key: str, token: str, outcome: str) -> None:
        if not self.table:
            return
        cond = self._owned(token)
        cond["ExpressionAttributeNames"]["#s"] = "status"
        cond["ExpressionAttributeValues"].update({":d": {"S": "done"}, ":o": {"S": outcome}})
        try:
            client("dynamodb").update_item(
                TableName=self.table, Key={"pk": {"S": key}}, UpdateExpression="SET #s = :d, outcome = :o", **cond
            )
        except ClientError:
            logger.warning("could not mark idempotency record done", exc_info=True)

    def release(self, key: str, token: str) -> None:
        if not self.table:
            return
        try:
            client("dynamodb").delete_item(TableName=self.table, Key={"pk": {"S": key}}, **self._owned(token))
        except ClientError:
            logger.warning("could not release idempotency claim", exc_info=True)


_PII = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE), "[URL]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[CARD]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\+?\d[\d ().-]{7,}\d"), "[PHONE]"),
]


def redact(text: str) -> str:
    for pattern, token in _PII:
        text = pattern.sub(token, text)
    # Neutralize GitHub markdown side effects: @mentions, #refs, images, HTML.
    text = text.replace("@", "@​").replace("#", "#​").replace("![", "!​[")
    return text.replace("<", "&lt;").replace(">", "&gt;")


_github_token: str | None = None


def open_github_issue(*, repo: str, token_secret_arn: str, title: str, body: str) -> None:
    """Best effort: failures are logged, never raised."""
    global _github_token
    try:
        if _github_token is None:
            _github_token = client("secretsmanager").get_secret_value(SecretId=token_secret_arn)["SecretString"]
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/issues",
            data=json.dumps(
                {"title": redact(title)[:200], "body": body, "labels": ["phishing-report", "catch-all"]}
            ).encode(),
            headers={
                "Authorization": f"Bearer {_github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "phishing-detector",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - fixed https URL
            number = json.load(response).get("number")
        logger.info("github issue created", extra={"issue": number})
    except Exception:
        logger.warning("github issue creation failed", exc_info=True)
