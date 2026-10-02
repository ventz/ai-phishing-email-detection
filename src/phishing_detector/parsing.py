"""Turn a raw forwarded email into the evidence the model analyzes.

Everything here is pure (bytes in, dataclasses out) so it can be unit-tested without AWS.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses
from html.parser import HTMLParser
from typing import ClassVar
from urllib.parse import unquote, urlsplit

from . import extractors, urls

MAX_PARTS = 200
MAX_DEPTH = 20
MAX_LINKS = 150
MAX_HREF_CHARS = 2_000
MAX_ATTACHMENTS = 20
MAX_HTML_ATTACHMENT_CHARS = 30_000
MAX_HIDDEN_CHARS = 5_000
MAX_SECONDARY_CHARS = 15_000
MAX_HEADER_CHARS = 1_000
MAX_FROM_CHARS = 2_000
DEFAULT_SUBJECT = "(no subject)"

# Attachment types we cannot open; their presence means the email can't be called safe.
_UNINSPECTABLE_EXT = re.compile(
    r"\.(?:pdf|zip|7z|rar|gz|tgz|tar|bz2|xz|cab|docx?|xlsx?|pptx?|docm|xlsm|pptm|odt|ods|odp|rtf|"
    r"iso|img|vhdx?|lnk|one|msg|eml\.zip)$",
    re.IGNORECASE,
)
_UNINSPECTABLE_TYPES = (
    "application/pdf",
    "application/zip",
    "application/x-7z",
    "application/x-rar",
    "application/vnd.ms-",
    "application/vnd.openxmlformats",
    "application/msword",
    "application/x-iso9660",
)
# Inline styles that hide text from the reader (hidden "preheader" text and anti-AI-scanner tricks).
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|!|$)"
    r"|opacity\s*:\s*0(?:\.0+)?\s*(?:;|!|$)|max-height\s*:\s*0(?:px)?\s*(?:;|!|$)",
    re.IGNORECASE,
)
# Phrases aimed at an AI reader rather than a person.
INJECTION_PHRASES = re.compile(
    r"ignore (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions|prompts?|rules)"
    r"|(?:classify|mark|treat|label|consider|report) (?:this|it|the (?:e-?mail|message)) as "
    r"(?:safe|clean|legitimate|benign|harmless|not (?:phishing|spam|malicious))"
    r"|this (?:e-?mail|message) is (?:safe|legitimate|benign|not (?:phishing|spam|malicious))"
    r"|do(?: not|n'?t) (?:flag|report|block) (?:this|it)"
    r"|(?:you are|you're) an? (?:ai|automated) (?:assistant|scanner|classifier|filter|model)",
    re.IGNORECASE,
)
INVISIBLE_CHARS = re.compile("[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]")

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
    via: str = ""
    """Security gateways peeled off to reach href (e.g. "Proofpoint URL Defense")."""


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
    hidden_text: str = ""
    """Text in the original that the reader cannot see (display:none, zero size, ...)."""

    injection_markers: list[str] = field(default_factory=list)
    """Phrases aimed at an AI reader, prefixed "hidden:" or "visible:"."""

    evidence_dropped: list[str] = field(default_factory=list)
    """Every cap that discarded evidence. Non-empty means the analysis saw only part of the email."""

    uninspectable: list[str] = field(default_factory=list)
    """Attachments of types we cannot open (PDF, archives, office documents, ...)."""

    ambiguous_original: bool = False
    """Both an attached and an inline original were found and they disagree."""

    secondary_text: str = ""
    """Other candidate text (inline text next to an attached original, or a long note above a marker)."""

    attachment_text: str = ""
    """Text read out of attachments (PDFs), labeled per file."""

    upstream_verdict: str | None = None
    """What the recipient's own mail filter (Microsoft 365) flagged: "malware", "high-confidence
    phishing", "phishing", "impersonation", "spoof" or "spam". None when it flagged nothing."""

    lookalikes: list[tuple[str, str, str]] = field(default_factory=list)
    """(host, brand, how) for link or sender hosts imitating a brand; see urls.lookalike_brand."""

    risky_links: list[str] = field(default_factory=list)
    """Every link (before the display cap) to a raw IP or internationalized host."""

    tlp: str | None = None
    """Most restrictive Traffic Light Protocol marking found (RED, AMBER+STRICT, AMBER, GREEN, CLEAR)."""

    @property
    def tlp_restricted(self) -> bool:
        """AMBER or RED: may not be shared beyond its recipients' organization, so we don't keep it."""
        return self.tlp in {"RED", "AMBER+STRICT", "AMBER"}

    outer_message_id: str | None = None
    """Message-ID of the forward itself, used to thread the reply."""

    def to_prompt(self) -> str:
        """Deterministic plain-text rendering of the evidence for the model."""
        lines = [f"Forward type: {self.forward_kind}"]
        if self.sender_auth.virus == "FAIL" or self.sender_auth.spam == "FAIL":
            lines.append(
                f"SES scan of the forwarded message: virus={self.sender_auth.virus}, spam={self.sender_auth.spam}"
            )
        if self.forward_kind == "inline":
            lines.append("Note: inline forward, so the original's transport headers were not preserved.")
        if self.upstream_verdict:
            lines.append(f"Recipient's mail filter (Microsoft 365) flagged the original as: {self.upstream_verdict}")
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
            via = f" | unwrapped from {link.via}" if link.via else ""
            lines.append(f"- text: {shown} | href: {link.href}{via}")
        lines.append("")
        lines.append(f"## Attachments ({len(self.attachments)})")
        for a in self.attachments:
            lines.append(f"- {a.filename} | {a.content_type} | {a.size} bytes | sha256 {a.sha256}")
        lines.append("")
        lines.append("## Body" + (" (truncated)" if self.truncated else ""))
        lines.append(self.body)
        if self.secondary_text:
            lines.append("")
            lines.append("## Other text in the forward (secondary evidence)")
            lines.append(self.secondary_text)
        if self.attachment_text:
            lines.append("")
            lines.append("## Text extracted from attachments")
            lines.append(self.attachment_text)
        if self.hidden_text:
            lines.append("")
            lines.append("## Hidden text (present in the email but not visible to the reader)")
            lines.append(self.hidden_text)
        if self.uninspectable:
            lines.append("")
            lines.append("## Attachments that could not be inspected")
            lines.extend(f"- {name}" for name in self.uninspectable)
        for item in self.evidence_dropped:
            lines.append(f"\nParser note: evidence omitted: {item}")
        for note in self.notes:
            lines.append(f"\nParser note: {note}")
        return "\n".join(lines)


class _HTMLText(HTMLParser):
    """Visible text, hidden text and (href, anchor text) pairs.

    Only script/style/template suppress text. ``<head>``/``<title>`` are not counted: ``</head>``
    is optional in HTML, and counting it once blanked every following character. Text inside
    elements hidden by inline style or the ``hidden`` attribute is collected separately, so the
    model can see it as a finding instead of it being silently dropped. Hiding is tracked with a
    stack of open elements (with HTML's implicit closes), so an unclosed hidden element can't
    swallow the visible text that follows it.
    """

    _BLOCK: ClassVar[frozenset[str]] = frozenset(
        {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote"}
    )
    _VOID: ClassVar[frozenset[str]] = frozenset(
        {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
    )
    _SKIP: ClassVar[frozenset[str]] = frozenset({"script", "style", "template"})
    # Elements whose start implicitly closes an open sibling of the same kind.
    _SELF_CLOSING_SIBLINGS: ClassVar[frozenset[str]] = frozenset({"p", "li", "td", "th", "tr", "option", "dt", "dd"})
    # Elements whose start implicitly closes an open <p>.
    _CLOSES_P: ClassVar[frozenset[str]] = frozenset(
        {
            "div",
            "p",
            "table",
            "ul",
            "ol",
            "dl",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "blockquote",
            "section",
            "article",
            "header",
            "footer",
            "form",
            "hr",
            "pre",
            "nav",
            "aside",
        }
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.hidden: list[str] = []
        self.links: list[Link] = []
        self.data_images: list[str] = []
        self._skip = 0
        self._in_title = False
        self._stack: list[str] = []
        self._hidden_at: int | None = None  # stack depth of the element that started hiding
        self._href: str | None = None
        self._anchor: list[str] = []

    def _pop_to(self, tag: str) -> None:
        if tag in self._stack:
            while self._stack and self._stack.pop() != tag:
                pass
        self._check_unhide()

    def _check_unhide(self) -> None:
        if self._hidden_at is not None and len(self._stack) < self._hidden_at:
            self._hidden_at = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "body":
            self._skip, self._in_title = 0, False
        elif tag in self._SKIP:
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        if tag in self._SELF_CLOSING_SIBLINGS and self._stack and self._stack[-1] == tag:
            self._pop_to(tag)
        if tag in self._CLOSES_P and self._stack and self._stack[-1] == "p":
            self._pop_to("p")
        if tag not in self._VOID:
            self._stack.append(tag)
            if self._hidden_at is None and ("hidden" in a or _HIDDEN_STYLE.search(a.get("style") or "")):
                self._hidden_at = len(self._stack)
        if tag == "a":
            href = (a.get("href") or "").strip()
            self._href = href or None
            self._anchor = []
        elif tag == "img":
            if a.get("alt"):
                self.handle_data(f"[image: {a['alt']}]")
            src = (a.get("src") or "").strip()
            if src[:5].lower() == "data:" and len(self.data_images) < extractors.MAX_DATA_URI_IMAGES:
                self.data_images.append(src)
        else:
            target = {"form": a.get("action"), "area": a.get("href"), "base": a.get("href")}.get(tag)
            if tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh":
                m = _REFRESH_URL.search(a.get("content") or "")
                target = m.group(1) if m else a.get("content")
            if target and target.strip():
                self.links.append(Link(target.strip(), f"[{tag} {'action' if tag == 'form' else 'target'}]"))
        if tag in self._BLOCK:
            self._out().append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP:
            self._skip = max(0, self._skip - 1)
        elif tag == "title":
            self._in_title = False
        elif tag == "a" and self._href is not None:
            self.links.append(Link(self._href, _squash(" ".join(self._anchor))))
            self._href = None
        if tag in self._BLOCK:
            self._out().append("\n")
        self._pop_to(tag)

    def _out(self) -> list[str]:
        return self.hidden if self._hidden_at is not None else self.text

    def handle_data(self, data: str) -> None:
        if self._skip or self._in_title:
            return
        self._out().append(data)
        if self._href is not None:
            self._anchor.append(data)


def normalize_for_matching(text: str) -> str:
    """NFKC, invisible characters removed, whitespace collapsed: defeats trivial regex evasion."""
    return re.sub(r"\s+", " ", INVISIBLE_CHARS.sub("", unicodedata.normalize("NFKC", text)))


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
                if not m:
                    continue
                method, verdict, props = m.group(1).lower(), m.group(2).lower(), m.group(3)
                if method in results:
                    # SES never repeats a method; a repeat means attacker text became a clause.
                    return SenderAuth(
                        spam=(_header(msg, "X-SES-Spam-Verdict") or "").upper() or None,
                        virus=(_header(msg, "X-SES-Virus-Verdict") or "").upper() or None,
                    )
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


def _inline_parts(msg: EmailMessage, depth: int = 0):
    """Non-attachment leaf parts in order, without descending into attached messages."""
    if depth > MAX_DEPTH:
        raise ValueError(f"MIME nesting deeper than {MAX_DEPTH}")
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_maintype() == "message":
                continue
            yield from _inline_parts(part, depth + 1)
    elif not msg.is_attachment():
        yield msg


_HTML_ATTACHMENT = re.compile(r"\.(?:s?html?|svg|xhtml)$", re.IGNORECASE)


@dataclass
class _Body:
    text: str = ""
    hidden: str = ""
    links: list[Link] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    """Material omissions (body or attachment content): forbid a "safe" verdict."""
    notes: list[str] = field(default_factory=list)
    """Minor omissions (link list, URL length): shown to the model only."""
    qr: list[Link] = field(default_factory=list)
    """Links decoded from QR codes (highest priority: the reader can't hover over them)."""
    pdf_links: list[Link] = field(default_factory=list)
    data_images: list[str] = field(default_factory=list)
    seen_files: set[str] = field(default_factory=set)
    budget: extractors.Budget | None = None


def _html_text(content: str, sink: _Body | None = None) -> tuple[str, str, list[Link]]:
    parser = _HTMLText()
    try:
        parser.feed(content)
        parser.close()
    except Exception:  # noqa: S110 - keep whatever text was parsed before the error
        pass
    if sink is not None:
        sink.data_images += parser.data_images
    visible, hidden = _clean_text("".join(parser.text)), _clean_text("".join(parser.hidden))
    if not visible and hidden:
        # Everything "hidden" means our heuristic misread the markup; never lose the content.
        return f"[note: all text in this part was styled hidden]\n{hidden}", "", parser.links
    return visible, hidden, parser.links


def extract_body(msg: EmailMessage) -> _Body:
    """Visible text, hidden text and links from every inline part, plus HTML attachments (a common
    credential phishing payload). Reads both HTML and plain parts: a phisher can ship a harmless
    text/plain alternative next to a malicious HTML part. Every cap that drops evidence is recorded."""
    out = _Body()
    html_texts: list[str] = []
    hidden_texts: list[str] = []
    plain_texts: list[str] = []
    for i, part in enumerate(_inline_parts(msg)):
        if i >= MAX_PARTS:
            out.dropped.append(f"more than {MAX_PARTS} MIME parts; the rest were not read")
            break
        ctype = part.get_content_type()
        if ctype == "text/html":
            text, hidden, found = _html_text(_decode(part), out)
            html_texts.append(text)
            hidden_texts.append(hidden)
            out.links.extend(found)
        elif ctype == "text/plain":
            plain_texts.append(_clean_text(_decode(part)))

    text = "\n\n".join(t for t in html_texts if t)
    plain = "\n\n".join(t for t in plain_texts if t)
    if not text:
        text = plain
    elif plain and _adds_content(plain, text):
        text = f"{text}\n\n[text/plain alternative differs from the HTML part]\n{plain}"
    # URLs in the plain part count even when its words match the HTML part.
    for url in _URL.findall(plain):
        out.links.append(Link(url, url))

    attachments = [p for p in _attachment_parts(msg) if p.get_content_maintype() != "message"]
    for part in attachments[:MAX_ATTACHMENTS]:
        name = part.get_filename() or ""
        if part.get_content_type() in {"text/html", "image/svg+xml"} or _HTML_ATTACHMENT.search(name):
            att_text, att_hidden, found = _html_text(_decode(part))
            label = _squash(name)[:200] or "(unnamed)"
            if len(att_text) > MAX_HTML_ATTACHMENT_CHARS:
                message = f"HTML attachment {label} cut to {MAX_HTML_ATTACHMENT_CHARS} characters"
                # Mail clients attach their own rendering of a forward as an unnamed ("noname") HTML
                # part; cutting that is not losing evidence. A named HTML file is a real payload.
                unnamed = label.lower() in {"(unnamed)", "noname", "noname.html", "noname.htm"}
                (out.notes if unnamed else out.dropped).append(message)
            text += f"\n\n[HTML attachment: {label}]\n{att_text[:MAX_HTML_ATTACHMENT_CHARS]}"
            hidden_texts.append(att_hidden)
            out.links.extend(found)

    out.text = text
    out.hidden = "\n".join(h for h in hidden_texts if h)
    for url in _URL.findall(text):
        out.links.append(Link(url, url))
    out.links = _dedupe_links(out.links, out.notes)
    return out


def _dedupe(links: list[Link]) -> list[Link]:
    """Dedupe by href in first-seen order, keeping the most informative anchor text and gateway."""
    by_href: dict[str, Link] = {}
    for link in links:
        href = urls.clean_href(link.href)
        if len(href) > MAX_HREF_CHARS:
            href = href[:MAX_HREF_CHARS] + "..."
        text = re.sub(r"[\x00-\x1f\x7f\u2028\u2029]+", " ", link.text)[:300]
        kept = by_href.get(href)
        if kept is None:
            by_href[href] = Link(href, text, link.via)
        elif kept.text in ("", href) and text not in ("", href):
            by_href[href] = Link(href, text, kept.via or link.via)
    return list(by_href.values())


def _dedupe_links(links: list[Link], notes: list[str]) -> list[Link]:
    """Dedupe, then cap the count (used for the per-part link lists)."""
    unique = _dedupe(links)
    long_urls = sum(link.href.endswith("...") for link in unique)
    if long_urls:
        notes.append(f"{long_urls} URL(s) longer than {MAX_HREF_CHARS} characters were cut")
    return unique


def _attachment_parts(msg: EmailMessage, depth: int = 0):
    """Every attachment leaf at any depth, without looking inside attached emails. (iter_attachments
    only sees one level, so a file nested inside an inner multipart/mixed was invisible.)"""
    if depth > MAX_DEPTH:
        raise ValueError(f"MIME nesting deeper than {MAX_DEPTH}")
    for part in msg.iter_parts() if msg.is_multipart() else []:
        if part.get_content_maintype() == "message":
            yield part
        elif part.is_multipart():
            yield from _attachment_parts(part, depth + 1)
        elif part.is_attachment() or (part.get_filename() and part.get_content_maintype() != "text"):
            yield part


_SAFE_OPAQUE_EXT = re.compile(r"\.(?:png|jpe?g|gif|bmp|webp|heic|tiff?|txt|csv|vcf|ics|json|xml|log)$", re.IGNORECASE)


def _image_parts(msg: EmailMessage, depth: int = 0):
    """Image leaves (inline or attached), without looking inside attached emails."""
    if depth > MAX_DEPTH:
        return
    for part in msg.iter_parts() if msg.is_multipart() else []:
        if part.get_content_maintype() == "message":
            continue
        if part.is_multipart():
            yield from _image_parts(part, depth + 1)
        elif part.get_content_maintype() == "image":
            yield part


def extract_attachments(
    msg: EmailMessage, dropped: list[str], content: _Body | None = None
) -> tuple[list[Attachment], list[str]]:
    """List attachments with hashes. When ``content`` is given, also read what we can out of them:
    PDF text, links and embedded images, and QR codes in any image (attached or inline)."""
    found: list[Attachment] = []
    uninspectable: list[str] = []
    attachments = list(_attachment_parts(msg))
    if len(attachments) > MAX_ATTACHMENTS:
        dropped.append(f"{len(attachments) - MAX_ATTACHMENTS} of {len(attachments)} attachments not listed")
    for part in attachments[:MAX_ATTACHMENTS]:
        if part.get_content_maintype() == "message":
            continue  # attached emails are analyzed (or listed as secondary), not opened as files
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        name = _squash(part.get_filename() or "(unnamed)")[:200]
        ctype = part.get_content_type()
        found.append(
            Attachment(filename=name, content_type=ctype, size=len(data), sha256=hashlib.sha256(data).hexdigest())
        )
        # Readers accept leading junk before the header, so look in the first KB, not just byte 0.
        is_pdf = ctype == "application/pdf" or name.lower().endswith(".pdf") or b"%PDF-" in data[:1024]
        if is_pdf and content is not None:
            digest = found[-1].sha256
            if digest in content.seen_files:
                continue  # same PDF on the forward and the attached original: read once
            content.seen_files.add(digest)
            pdf = extractors.pdf_evidence(data, content.budget)
            content.notes += [f"PDF {name}: {note}" for note in pdf.notes]
            dropped += [f"PDF {name}: {item}" for item in pdf.dropped]
            if pdf.active:
                # JavaScript, embedded files, launch/submit actions: we read the text, not these.
                uninspectable.append(f"{name} ({ctype}; contains {', '.join(pdf.active[:3])})")
            if pdf.inspected:
                content.text += f"\n\n[PDF attachment: {name}]\n{pdf.text}"
                content.pdf_links += [Link(u, f"[link in PDF {name}]") for u in pdf.links]
                content.qr += [Link(q, f"[QR code in PDF {name}]") for q in pdf.qr_payloads]
                continue  # read (any active content was already listed as uninspectable)
            uninspectable.append(f"{name} ({ctype})")  # a PDF we could not read, whatever its name
            continue
        opaque = ctype == "application/octet-stream" and not _SAFE_OPAQUE_EXT.search(name)
        unreadable = _UNINSPECTABLE_EXT.search(name) or ctype.startswith(_UNINSPECTABLE_TYPES) or opaque
        if unreadable and not _HTML_ATTACHMENT.search(name):  # HTML/SVG attachments are read as text
            uninspectable.append(f"{name} ({ctype})")

    if content is not None:
        for i, part in enumerate(_image_parts(msg)):
            if i >= extractors.MAX_QR_IMAGES:
                content.notes.append(f"only the first {extractors.MAX_QR_IMAGES} images were checked for QR codes")
                break
            try:
                data = part.get_payload(decode=True) or b""
            except Exception:  # noqa: S112 - undecodable image: nothing to scan
                continue
            label = _squash(part.get_filename() or part.get("Content-ID") or "inline image")[:120]
            content.qr += [Link(q, f"[QR code in image {label}]") for q in extractors.decode_qr(data, content.budget)]
    return found, uninspectable


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


def _forward_split(body: str) -> tuple[str, str] | None:
    """(text above, original below) for an inline forward found in *visible* text, else None."""
    if marker := _FORWARD_MARKER.search(body):
        return body[: marker.start()].strip(), body[marker.end() :].strip()
    if block := _HEADER_BLOCK.search(body):
        return body[: block.start()].strip(), body[block.start() :].strip()
    return None


def _inline_identity(text: str) -> tuple[str | None, str | None]:
    head = text[:2_000]
    frm = re.search(r"^\s*From:\s*(.+)$", head, re.IGNORECASE | re.MULTILINE)
    addr = _single_address(frm.group(1)) if frm else None
    return addr, _inline_subject(head)


def parse_email(raw: bytes, *, max_body_chars: int = 60_000, attachment_seconds: float = 30.0) -> ParsedEmail:
    outer: EmailMessage = message_from_bytes(raw, policy=policy.default)  # type: ignore[assignment]
    # Exactly one From header holding exactly one address, validated at full length (not truncated).
    from_headers = outer.get_all("From", [])
    raw_from = str(from_headers[0]) if len(from_headers) == 1 else ""
    forwarder = _single_address(raw_from) if 0 < len(raw_from) <= MAX_FROM_CHARS else None
    sender_auth = parse_sender_auth(outer)
    notes: list[str] = []

    outer_extract = extract_body(outer)
    dropped = list(outer_extract.dropped)
    notes.extend(outer_extract.notes)
    split = _forward_split(outer_extract.text)  # visible text only: hidden markers can't steer this
    original = find_forwarded_original(outer)
    secondary = ""
    ambiguous = False
    content = _Body(budget=extractors.new_budget(attachment_seconds))  # PDF text/links, QR codes

    if original is not None:
        # An attached original carries real headers, so it is the primary evidence. Inline text in
        # the forward (if any) is kept as secondary evidence rather than thrown away.
        kind = "attachment"
        extracted = extract_body(original)
        dropped += extracted.dropped
        notes.extend(extracted.notes)
        body, links, hidden = extracted.text, extracted.links, extracted.hidden
        attachments, uninspectable = extract_attachments(original, dropped, content)
        source = original
        if split:
            # Both an inline forward and an attached email. Mail clients re-attach a phish's own
            # attachments, so the attached email may be a decoy carried by the real lure. Keep
            # both, include the inline links and the forward's other attachments, and never allow
            # a "safe" verdict.
            inline = split[1]
            secondary = f"[inline text in the forward]\n{inline}"
            ambiguous = True
            notes.append("The forward contains both inline forwarded text and an attached email; both are shown.")
            links = _dedupe_links(links + outer_extract.links, notes)
            outer_files, outer_unins = extract_attachments(outer, dropped, content)
            attachments += [a for a in outer_files if a not in attachments]
            uninspectable += [u for u in outer_unins if u not in uninspectable]
    elif split:
        kind = "inline"
        above, body = split
        # Links above the marker belong to the forwarder's own note, not the original. Links with no
        # visible text (image buttons) can't be matched to text, so keep them unless they point to
        # the forwarder's own domain.
        own = (forwarder or "@").rpartition("@")[2]

        def _belongs(link: Link) -> bool:
            if link.href in body or (link.text and link.text in body):
                return True
            host = (urlsplit(link.href).hostname or "") if link.href.startswith(("http:", "https:")) else ""
            return not link.text and bool(host) and not (own and host.endswith(own))

        links = [link for link in outer_extract.links if _belongs(link)] or outer_extract.links
        hidden = outer_extract.hidden
        attachments, uninspectable = extract_attachments(outer, dropped, content)
        source = outer
        if len(above) > 300:
            secondary = f"[text above the forward marker, usually the forwarder's own note]\n{above}"
    else:
        kind = "none"
        body, links, hidden = outer_extract.text, outer_extract.links, outer_extract.hidden
        attachments, uninspectable = extract_attachments(outer, dropped, content)
        source = outer
        notes.append("No forwarded message found; analyzing the email exactly as received.")

    # QR codes in inline data: images (a trick to dodge attachment-based QR scanning).
    for i, src in enumerate(outer_extract.data_images + (extracted.data_images if original is not None else [])):
        if i >= extractors.MAX_DATA_URI_IMAGES:
            break
        if data := extractors.data_uri_image(src):
            content.qr += [Link(q, "[QR code in embedded image]") for q in extractors.decode_qr(data, content.budget)]

    if content.budget and content.budget.exhausted:
        dropped.append("some attachments were not fully read (" + "; ".join(content.budget.exhausted) + ")")
    notes.extend(content.notes)
    attachment_text = content.text.strip()
    if len(attachment_text) > MAX_SECONDARY_CHARS:
        attachment_text = attachment_text[:MAX_SECONDARY_CHARS]
        dropped.append(f"attachment text cut to {MAX_SECONDARY_CHARS} characters")

    # Priority order: QR codes, the email's own links, then links inside PDFs. Unwrap gateways,
    # dedupe, and run the host checks on the FULL list before capping what the model is shown.
    all_links = _dedupe([_unwrapped(link) for link in content.qr + links + content.pdf_links])
    risky_links = [link.href for link in all_links if urls.host_is_risky(link.href)]
    lookalikes: list[tuple[str, str, str]] = []
    for link in all_links:
        try:
            host = urlsplit(link.href).hostname or ""
        except ValueError:
            continue
        hit = urls.lookalike_brand(host)
        if hit and (host, *hit) not in lookalikes:
            lookalikes.append((host, *hit))
    if len(all_links) > MAX_LINKS:
        cut = all_links[MAX_LINKS:]
        message = f"{len(cut)} of {len(all_links)} distinct links not shown"
        (notes if all(link.text.startswith("[link in PDF") for link in cut) else dropped).append(message)
    links = all_links[:MAX_LINKS]
    upstream = _microsoft_verdict(source) if kind == "attachment" else None

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
        if "Authentication-Results" in headers and kind == "attachment":
            headers["Authentication-Results"] = (
                "(as written in the forwarded email, unverified) " + headers["Authentication-Results"]
            )
    received = [] if kind == "inline" else [_squash(str(v))[:300] for v in source.get_all("Received", [])[:6]]

    # The sender's own domains are the most common place for a lookalike.
    for name in ("From", "Reply-To", "Return-Path", "Sender"):
        address = _single_address(headers.get(name)) if kind != "inline" else None
        if name == "From" and kind == "inline":
            address = _inline_identity(body)[0]
        host = (address or "").rpartition("@")[2]
        hit = urls.lookalike_brand(host) if host else None
        if hit and (host, *hit) not in lookalikes:
            lookalikes.append((host, *hit))
    if lookalikes:
        notes.append(
            "Domains resembling a brand: "
            + "; ".join(
                f"{h} ({'imitates' if how == 'lookalike' else 'contains the name'} "
                f"{urls.DISPLAY_NAMES.get(brand, brand)})"
                for h, brand, how in lookalikes[:8]
            )
        )

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
        dropped.append(f"body cut to {max_body_chars} characters")
    if len(secondary) > MAX_SECONDARY_CHARS:
        secondary = secondary[:MAX_SECONDARY_CHARS]
        dropped.append(f"secondary text cut to {MAX_SECONDARY_CHARS} characters")
    if len(hidden) > MAX_HIDDEN_CHARS:
        hidden = hidden[:MAX_HIDDEN_CHARS]
        notes.append(f"hidden text cut to {MAX_HIDDEN_CHARS} characters")

    # Only the original's own text: the forwarder's note ("should I mark this as safe?") is not evidence.
    markers = [f"hidden: {m.group(0)}" for m in INJECTION_PHRASES.finditer(normalize_for_matching(hidden))]
    if kind != "none":
        markers += [f"visible: {m.group(0)}" for m in INJECTION_PHRASES.finditer(normalize_for_matching(body))]
    markers += [
        f"attachment: {m.group(0)}" for m in INJECTION_PHRASES.finditer(normalize_for_matching(attachment_text))
    ]
    link_text = "\n".join(f"{link.text} {unquote(link.href)}" for link in links)  # incl. QR payloads
    markers += [f"link: {m.group(0)}" for m in INJECTION_PHRASES.finditer(normalize_for_matching(link_text))]
    mismatches = link_text_mismatches(links)
    if mismatches:
        notes.append("Links whose visible text names a different domain than they go to: " + "; ".join(mismatches))
    invisible = len(INVISIBLE_CHARS.findall(body))
    if invisible:
        notes.append(f"{invisible} invisible formatting characters (zero-width or direction marks) in the body.")

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
        hidden_text=hidden,
        injection_markers=markers[:10],
        evidence_dropped=dropped,
        uninspectable=uninspectable,
        ambiguous_original=ambiguous,
        secondary_text=secondary,
        attachment_text=attachment_text,
        upstream_verdict=upstream,
        lookalikes=lookalikes,
        risky_links=risky_links,
        # Hidden text is ignored on purpose: a real sender never hides a TLP label, an attacker might
        # (to get a phish dropped from the catch-all or expired from the evidence bucket).
        tlp=tlp_marking(subject, _header(outer, "Subject") or "", outer_extract.text, body, secondary, attachment_text),
        outer_message_id=_header(outer, "Message-ID"),
    )


_HOSTLIKE = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#]\S*)?$", re.IGNORECASE)


def _base_domain(host: str) -> str:
    """Rough registrable domain: last two labels, or three for two-letter country second levels."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "ac", "gov", "org", "net", "edu"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def link_text_mismatches(links: list[Link], limit: int = 5) -> list[str]:
    """Anchor text that is itself a hostname/URL whose domain differs from the real destination."""
    found = []
    for link in links:
        m = _HOSTLIKE.match(link.text.strip())
        if not m:
            continue
        try:
            dest = urlsplit(link.href).hostname or ""
        except ValueError:
            continue
        if dest and _base_domain(m.group(1)) != _base_domain(dest):
            found.append(f"text {m.group(1)} -> goes to {dest}")
        if len(found) >= limit:
            break
    return found


def _unwrapped(link: Link) -> Link:
    """Replace a security-gateway wrapper with the real destination, saying what was peeled off."""
    dest, wrappers = urls.unwrap(link.href)
    if not wrappers:
        return link
    return Link(urls.clean_href(dest)[:MAX_HREF_CHARS], link.text, ", ".join(dict.fromkeys(wrappers)))


_FOREFRONT_CAT = re.compile(r"\bCAT:([A-Z]+)")
_FOREFRONT_SFV = re.compile(r"\bSFV:([A-Z]+)")


def _microsoft_verdict(msg: EmailMessage) -> str | None:
    """Microsoft 365's verdict stamped on the original when it was delivered to the reporter.

    Only read when exactly one header of each kind exists (an attacker could add their own). Even
    then it is only used to raise our verdict, so a forged "clean" changes nothing.
    """
    reports = msg.get_all("X-Forefront-Antispam-Report", [])
    scls = msg.get_all("X-MS-Exchange-Organization-SCL", [])
    if len(reports) > 1 or len(scls) > 1 or not (reports or scls):
        return None
    report = str(reports[0]) if reports else ""
    cat = (m.group(1) if (m := _FOREFRONT_CAT.search(report)) else "").upper()
    sfv = (m.group(1) if (m := _FOREFRONT_SFV.search(report)) else "").upper()
    try:
        scl = int(str(scls[0]).strip()) if scls else None
    except ValueError:
        scl = None
    if cat in {"MALW", "AMP", "SAP"}:
        return "malware"
    if cat == "HPHSH":
        return "high-confidence phishing"
    if cat in {"PHSH", "INTOS"}:
        return "phishing"
    if cat in {"GIMP", "UIMP", "DIMP"}:
        return "impersonation"
    if cat == "SPOOF":
        return "spoof"
    if cat in {"HSPM", "SPM", "BULK"} or sfv in {"SPM", "SKS", "SKB"} or (scl is not None and scl >= 5):
        return "spam"
    # "Not flagged" is NOT reported: nearly every reported phish got past the filter, so a clean
    # verdict carries no information and would only bias the model toward "safe".
    return None


_TLP = re.compile(r"\bTLP\s*[:：\-_ ]\s*(RED|AMBER\s*\+\s*STRICT|AMBER|GREEN|CLEAR|WHITE)\b", re.IGNORECASE)
_TLP_RANK = {"RED": 4, "AMBER+STRICT": 3, "AMBER": 2, "GREEN": 1, "CLEAR": 0}


def tlp_marking(*texts: str) -> str | None:
    """Most restrictive TLP label in the texts (TLP 1.0's WHITE is today's CLEAR)."""
    found = None
    for text in texts:
        for m in _TLP.finditer(normalize_for_matching(text or "")):
            label = re.sub(r"\s+", "", m.group(1).upper()).replace("WHITE", "CLEAR")
            if found is None or _TLP_RANK[label] > _TLP_RANK[found]:
                found = label
    return found


RESTRICTED_TLP = frozenset({"RED", "AMBER+STRICT", "AMBER"})
MAX_TLP_SCAN_BYTES = 1024 * 1024


def tlp_from_raw(raw: bytes) -> str | None:
    """TLP marking without analyzing the email: decoded subjects plus the decoded text of text/*
    parts (base64 and quoted-printable included), descending into attached emails. Never opens PDFs,
    images or other attachments, so it is safe to run for senders we won't answer."""
    try:
        msg = message_from_bytes(raw, policy=policy.default)
    except Exception:
        return tlp_marking(raw[:MAX_TLP_SCAN_BYTES].decode("latin-1"))
    texts, budget = [], MAX_TLP_SCAN_BYTES
    for i, part in enumerate(msg.walk()):
        if i > MAX_PARTS or budget <= 0:
            break
        if part.get_content_maintype() == "message":
            inner = _attached_message(part)
            if inner is not None:
                texts.append(_header(inner, "Subject") or "")
            continue
        if part.get_content_maintype() == "text" and not part.is_multipart():
            text = _decode(part)[:budget]
            budget -= len(text)
            texts.append(_html_text(text)[0] if part.get_content_subtype() == "html" else text)
    return tlp_marking(_header(msg, "Subject") or "", *texts)


def route_headers(raw: bytes) -> ParsedEmail:
    """Headers-only view used to decide routing before any attachment is opened."""
    return parse_headers(raw)


def parse_headers(raw: bytes) -> ParsedEmail:
    """Headers only, never the body: used to answer emails whose body could not be parsed."""
    from email.parser import BytesHeaderParser

    outer = BytesHeaderParser(policy=policy.default).parsebytes(raw)
    from_headers = outer.get_all("From", [])
    raw_from = str(from_headers[0]) if len(from_headers) == 1 else ""
    subject = re.sub(r"^\s*((fwd?|fw)\s*:\s*)+", "", _header(outer, "Subject") or "", flags=re.IGNORECASE)
    return ParsedEmail(
        forwarder=_single_address(raw_from) if 0 < len(raw_from) <= MAX_FROM_CHARS else None,
        sender_auth=parse_sender_auth(outer),
        subject=(subject or DEFAULT_SUBJECT)[:250],
        forward_kind="none",
        headers={},
        received=[],
        body="",
        links=[],
        attachments=[],
        truncated=False,
        auto_submitted=_is_automated(outer),
        outer_message_id=_header(outer, "Message-ID"),
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
