"""Turn a raw forwarded email into the evidence the model analyzes.

Everything here is pure (bytes in, dataclasses out) so it can be unit-tested without AWS.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses
from html.parser import HTMLParser
from typing import ClassVar

MAX_PARTS = 200
MAX_LINKS = 60
MAX_ATTACHMENTS = 20
MAX_HEADER_CHARS = 1_000
DEFAULT_SUBJECT = "(no subject)"

# Inline-forward separators written by Gmail, Outlook, Apple Mail and Thunderbird.
_FORWARD_MARKER = re.compile(
    r"^[ \t>]*(?:-{2,}\s*(?:Forwarded message|Original Message)\s*-{2,}"
    r"|Begin forwarded message:"
    r"|-{5,}\s*Forwarded Message\s*-{5,})[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
# Outlook-style forwards have no marker, just a quoted header block: From: ... Subject: ...
_HEADER_BLOCK = re.compile(
    r"^[ \t>*]*From:[^\n]*\n(?:[^\n]*\n){0,12}?[ \t>*]*Subject:",
    re.IGNORECASE | re.MULTILINE,
)
_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\"\s>]+)", re.IGNORECASE)
_WORD = re.compile(r"[a-z0-9]{3,}")
_URL = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.IGNORECASE)
# RFC 8601 resinfo clause, anchored at the start of a ";"-separated clause.
_RESINFO = re.compile(r"^\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b(.*)$", re.IGNORECASE | re.DOTALL)
_HEADER_FROM = re.compile(r"\bheader\.from\s*=\s*([^\s;]+)", re.IGNORECASE)
_COMMENT = re.compile(r"\([^()]*\)")
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


@dataclass(frozen=True)
class Link:
    href: str
    text: str


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass(frozen=True)
class SenderAuth:
    """What SES recorded about the *forwarder's* message when it arrived."""

    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    dmarc_domain: str | None = None
    spam: str | None = None
    virus: str | None = None

    def dmarc_pass_for(self, address: str) -> bool:
        domain = address.rpartition("@")[2].lower()
        return self.dmarc == "pass" and bool(domain) and self.dmarc_domain == domain


@dataclass(frozen=True)
class ParsedEmail:
    forwarder: str | None
    """Single, well-formed address of the person who forwarded the email, else None."""

    sender_auth: SenderAuth
    subject: str
    forward_kind: str
    """How the original was found: "attachment", "inline", or "none" (the email itself is analyzed)."""

    headers: dict[str, str]
    received: list[str]
    body: str
    links: list[Link]
    attachments: list[Attachment]
    truncated: bool
    auto_submitted: bool = False
    """The outer message is an auto-reply/bounce (RFC 3834); never answer it."""

    notes: list[str] = field(default_factory=list)

    def to_prompt(self) -> str:
        """Deterministic plain-text rendering of the evidence for the model."""
        lines = [f"Forward type: {self.forward_kind}"]
        if self.sender_auth.virus == "FAIL" or self.sender_auth.spam == "FAIL":
            lines.append(
                f"SES scan of the forwarded message: virus={self.sender_auth.virus}, spam={self.sender_auth.spam}"
            )
        if self.forward_kind == "inline":
            lines.append("Note: inline forward, so the original's transport headers were not preserved.")
        lines.append("")
        lines.append("## Headers")
        for name, value in self.headers.items():
            lines.append(f"{name}: {value}")
        for hop in self.received:
            lines.append(f"Received: {hop}")
        lines.append("")
        lines.append(f"## Links ({len(self.links)})")
        for link in self.links:
            shown = link.text if link.text and link.text != link.href else "(same as URL)"
            lines.append(f"- text: {shown} | href: {link.href}")
        lines.append("")
        lines.append(f"## Attachments ({len(self.attachments)})")
        for a in self.attachments:
            lines.append(f"- {a.filename} | {a.content_type} | {a.size} bytes | sha256 {a.sha256}")
        lines.append("")
        lines.append("## Body" + (" (truncated)" if self.truncated else ""))
        lines.append(self.body)
        for note in self.notes:
            lines.append(f"\nParser note: {note}")
        return "\n".join(lines)


class _HTMLText(HTMLParser):
    """Visible text plus (href, anchor text) pairs; ignores script/style."""

    _BLOCK: ClassVar[frozenset[str]] = frozenset(
        {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote"}
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[Link] = []
        self._skip = 0
        self._href: str | None = None
        self._anchor: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "head", "title"}:
            self._skip += 1
        elif tag == "a":
            self._href = (dict(attrs).get("href") or "").strip() or None
            self._anchor = []
        elif tag == "img":
            alt = dict(attrs).get("alt")
            if alt:
                self.handle_data(f"[image: {alt}]")
        else:
            a = dict(attrs)
            target = {"form": a.get("action"), "area": a.get("href"), "base": a.get("href")}.get(tag)
            if tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh":
                m = _REFRESH_URL.search(a.get("content") or "")
                target = m.group(1) if m else a.get("content")
            if target and target.strip():
                self.links.append(Link(target.strip(), f"[{tag} {'action' if tag == 'form' else 'target'}]"))
        if tag in self._BLOCK:
            self.text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "head", "title"}:
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._href is not None:
            self.links.append(Link(self._href, _squash(" ".join(self._anchor))))
            self._href = None
        if tag in self._BLOCK:
            self.text.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _clean_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t ]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    return text.strip()


def _header(msg: EmailMessage, name: str) -> str | None:
    try:
        value = msg.get(name)
    except Exception:  # malformed header: fall back to the raw value
        value = msg.get_all(name, failobj=[None])[0]
    if value is None:
        return None
    return _squash(str(value))[:MAX_HEADER_CHARS]


def _single_address(value: str | None) -> str | None:
    if not value:
        return None
    addresses = [a for _, a in getaddresses([value]) if a]
    if len(addresses) != 1:
        return None
    address = addresses[0].strip().lower()
    return address if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", address) else None


def _resinfo_clauses(value: str) -> list[str]:
    """Split an Authentication-Results value into clauses, after removing comments and quoted
    strings, so text inside e.g. ``envelope-from=`` can never be read as a verdict."""
    value = _QUOTED.sub('""', value)
    while _COMMENT.search(value):
        value = _COMMENT.sub(" ", value)
    return value.split(";")


def parse_sender_auth(msg: EmailMessage) -> SenderAuth:
    """Read the verdicts SES added on arrival.

    SES prepends its own ``Authentication-Results: amazonses.com; ...`` header, so only the very
    first Authentication-Results header is trusted, and only if SES wrote it. Each verdict is taken
    from a clause that *starts* with ``spf=``/``dkim=``/``dmarc=``; the DMARC domain comes from the
    same clause as the DMARC verdict.
    """
    headers = msg.get_all("Authentication-Results", [])
    results: dict[str, str] = {}
    dmarc_domain = None
    if headers:
        clauses = _resinfo_clauses(str(headers[0]))
        if clauses[0].strip().lower() == "amazonses.com":
            for clause in clauses[1:]:
                m = _RESINFO.match(clause)
                if not m or m.group(1).lower() in results:
                    continue
                method, verdict, props = m.group(1).lower(), m.group(2).lower(), m.group(3)
                results[method] = verdict
                if method == "dmarc" and (hf := _HEADER_FROM.search(props)):
                    dmarc_domain = hf.group(1).strip().lower()
    return SenderAuth(
        spf=results.get("spf", "none"),
        dkim=results.get("dkim", "none"),
        dmarc=results.get("dmarc", "none"),
        dmarc_domain=dmarc_domain,
        spam=(_header(msg, "X-SES-Spam-Verdict") or "").upper() or None,
        virus=(_header(msg, "X-SES-Virus-Verdict") or "").upper() or None,
    )


def _attached_message(part: EmailMessage) -> EmailMessage | None:
    ctype = part.get_content_type()
    filename = (part.get_filename() or "").lower()
    try:
        if ctype == "message/rfc822":
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else None
            return inner if isinstance(inner, EmailMessage) else None
        if filename.endswith(".eml") or ctype == "application/eml":
            data = part.get_payload(decode=True)
            if data:
                return message_from_bytes(data, policy=policy.default)  # type: ignore[return-value]
    except Exception:
        return None
    return None


def find_forwarded_original(msg: EmailMessage) -> EmailMessage | None:
    """First attached message in walk order: the one the user forwarded, not something nested
    inside it (a phish can carry a harmless .eml to be analyzed in its place)."""
    for i, part in enumerate(msg.walk()):
        if i > MAX_PARTS:
            break
        if part is not msg and (inner := _attached_message(part)):
            return inner
    return None


def _decode(part: EmailMessage) -> str:
    try:
        content = part.get_content()
    except Exception:
        data = part.get_payload(decode=True) or b""
        content = data.decode(part.get_content_charset() or "utf-8", errors="replace")
    if isinstance(content, bytes):  # application/octet-stream, image/svg+xml, ...
        content = content.decode(part.get_content_charset() or "utf-8", errors="replace")
    return content if isinstance(content, str) else ""


def _adds_content(plain: str, html_text: str) -> bool:
    """True when the text/plain part says something the HTML part doesn't (a decoy alternative),
    not merely the same words laid out differently."""
    # URLs are compared separately (links); in the plain part they are mostly tracking noise.
    plain_words = set(_WORD.findall(_URL.sub(" ", plain).lower()))
    if not plain_words:
        return False
    missing = plain_words - set(_WORD.findall(_URL.sub(" ", html_text).lower()))
    return len(missing) >= 3 and len(missing) > len(plain_words) // 5


def _inline_parts(msg: EmailMessage):
    """Non-attachment leaf parts in order, without descending into attached messages."""
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_maintype() == "message":
                continue
            yield from _inline_parts(part)
    elif not msg.is_attachment():
        yield msg


_HTML_ATTACHMENT = re.compile(r"\.(?:s?html?|svg|xhtml)$", re.IGNORECASE)


def _html_text(content: str) -> tuple[str, list[Link]]:
    parser = _HTMLText()
    try:
        parser.feed(content)
        parser.close()
    except Exception:  # noqa: S110 - keep whatever text was parsed before the error
        pass
    return _clean_text("".join(parser.text)), parser.links


def extract_body(msg: EmailMessage) -> tuple[str, list[Link]]:
    """Visible text and links from every inline part, plus HTML attachments (a common credential
    phishing payload). Reads both HTML and plain parts: a phisher can ship a harmless text/plain
    alternative next to a malicious HTML part."""
    html_texts: list[str] = []
    plain_texts: list[str] = []
    links: list[Link] = []
    for i, part in enumerate(_inline_parts(msg)):
        if i >= MAX_PARTS:
            break
        ctype = part.get_content_type()
        if ctype == "text/html":
            text, found = _html_text(_decode(part))
            html_texts.append(text)
            links.extend(found)
        elif ctype == "text/plain":
            plain_texts.append(_clean_text(_decode(part)))

    text = "\n\n".join(t for t in html_texts if t)
    plain = "\n\n".join(t for t in plain_texts if t)
    if not text:
        text = plain
    elif plain and _adds_content(plain, text):
        text = f"{text}\n\n[text/plain alternative differs from the HTML part]\n{plain}"

    for part in list(msg.iter_attachments())[:MAX_ATTACHMENTS]:
        name = part.get_filename() or ""
        if part.get_content_type() in {"text/html", "image/svg+xml"} or _HTML_ATTACHMENT.search(name):
            att_text, found = _html_text(_decode(part))
            text += f"\n\n[HTML attachment: {_squash(name)[:200] or '(unnamed)'}]\n{att_text[:10_000]}"
            links.extend(found)

    seen = {link.href for link in links}
    for url in _URL.findall(text):
        if url not in seen:
            links.append(Link(url, url))
            seen.add(url)
    return text, links[:MAX_LINKS]


def extract_attachments(msg: EmailMessage) -> list[Attachment]:
    found: list[Attachment] = []
    for part in msg.iter_attachments():
        if len(found) >= MAX_ATTACHMENTS:
            break
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        found.append(
            Attachment(
                filename=_squash(part.get_filename() or "(unnamed)")[:200],
                content_type=part.get_content_type(),
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )
    return found


_ORIGINAL_HEADERS = (
    "From",
    "Reply-To",
    "Return-Path",
    "Sender",
    "To",
    "Cc",
    "Date",
    "Subject",
    "Message-ID",
    "Authentication-Results",
    "Received-SPF",
    "DKIM-Signature",
    "List-Unsubscribe",
)


def parse_email(raw: bytes, *, max_body_chars: int = 60_000) -> ParsedEmail:
    outer: EmailMessage = message_from_bytes(raw, policy=policy.default)  # type: ignore[assignment]
    # Exactly one From header with exactly one address; SES's DMARC header.from must match it.
    forwarder = _single_address(_header(outer, "From")) if len(outer.get_all("From", [])) == 1 else None
    sender_auth = parse_sender_auth(outer)
    notes: list[str] = []

    outer_body, outer_links = extract_body(outer)
    marker = _FORWARD_MARKER.search(outer_body)
    block = None if marker else _HEADER_BLOCK.search(outer_body)
    # An inline forward wins over attachments: the phish's own attachments (possibly a decoy .eml)
    # are re-attached by the mail client.
    original = None if (marker or block) else find_forwarded_original(outer)
    if marker or block:
        kind = "inline"
        body = outer_body[marker.end() :].strip() if marker else outer_body[block.start() :].strip()
        # Links above the marker belong to the forwarder's own note, not the original.
        links = [link for link in outer_links if link.href in body or (link.text and link.text in body)] or outer_links
        attachments = extract_attachments(outer)
        source = outer
    elif original is not None:
        kind = "attachment"
        body, links = extract_body(original)
        attachments = extract_attachments(original)
        source = original
    else:
        kind = "none"
        body, links = outer_body, outer_links
        attachments = extract_attachments(outer)
        source = outer
        notes.append("No forwarded message found; analyzing the email exactly as received.")

    headers: dict[str, str] = {}
    if kind != "inline":
        for name in _ORIGINAL_HEADERS:
            if name == "DKIM-Signature":
                value = _header(source, name)
                if value and (d := re.search(r"\bd=([^;\s]+)", value)):
                    headers["DKIM-Signature domain"] = d.group(1)
                continue
            if value := _header(source, name):
                headers[name] = value
    received = [] if kind == "inline" else [_squash(str(v))[:300] for v in source.get_all("Received", [])[:6]]

    subject = (
        (_header(source, "Subject") if kind != "inline" else None)
        or _inline_subject(body)
        or _header(outer, "Subject")
        or DEFAULT_SUBJECT
    )
    subject = re.sub(r"^\s*((fwd?|fw)\s*:\s*)+", "", subject, flags=re.IGNORECASE) or DEFAULT_SUBJECT

    truncated = len(body) > max_body_chars
    if truncated:
        body = body[:max_body_chars]

    return ParsedEmail(
        forwarder=forwarder,
        sender_auth=sender_auth,
        subject=subject[:250],
        forward_kind=kind,
        headers=headers,
        received=received,
        body=body,
        links=links,
        attachments=attachments,
        truncated=truncated,
        auto_submitted=_is_automated(outer),
        notes=notes,
    )


def _is_automated(msg: EmailMessage) -> bool:
    """Bounces, auto-replies and list traffic (RFC 3834 and common conventions): never answer."""
    return (
        (_header(msg, "Auto-Submitted") or "no").lower() != "no"
        or (_header(msg, "Precedence") or "").lower() in {"bulk", "junk", "list", "auto_reply"}
        or msg.get("List-Id") is not None
        or (_header(msg, "Return-Path") or "").strip() == "<>"
        or msg.get("X-Autoreply") is not None
    )


def _inline_subject(body: str) -> str | None:
    m = re.search(r"^\s*Subject:\s*(.+)$", body[:2_000], re.IGNORECASE | re.MULTILINE)
    return _squash(m.group(1)) if m else None
