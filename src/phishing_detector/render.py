"""Render the reply email (HTML + plain text) from a verdict.

Everything that came from the email or the model is HTML-escaped, and URLs/domains are
defanged so nothing in the reply is clickable. Colors meet WCAG 2.2 AA contrast.
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass

from .classifier import Label, Verdict


@dataclass(frozen=True)
class Reply:
    subject: str
    html: str
    text: str


@dataclass(frozen=True)
class ReportContext:
    """Facts about the report itself, shown in the reply so it can't be passed off out of context."""

    original_subject: str
    forwarder: str | None = None
    received_at: str | None = None
    """e.g. "2026-10-02 14:05 UTC"."""
    ref: str | None = None
    """Short reference derived from the stored email's key, for support lookups."""
    help_contact: str | None = None


@dataclass(frozen=True)
class _Theme:
    tag: str
    heading: str
    action: str
    color: str  # header background; white text on it is >= 7:1


_THEMES = {
    Label.PHISHING: _Theme(
        "PHISHING", "Verdict: phishing", "Do not click links, open attachments, or reply. Delete the email.", "#a31515"
    ),
    Label.SUSPICIOUS: _Theme(
        "SUSPICIOUS",
        "Verdict: suspicious",
        "Treat it with caution. Verify with the sender through a channel you already trust before you act on it.",
        "#7a4100",
    ),
    Label.CLEAN: _Theme(
        "LIKELY SAFE",
        "Verdict: likely safe",
        "No phishing indicators were found. Stay alert: automated analysis can be wrong.",
        "#1b5e20",
    ),
}
_UNAVAILABLE = _Theme(
    "NOT ANALYZED",
    "We could not analyze this email",
    "Treat it as suspicious: do not click links, open attachments, or reply. You can try forwarding it again later.",
    "#3d3d3d",
)

_URL = re.compile(r"\b(?:https?|ftp)://\S+", re.IGNORECASE)
# Unicode-aware so IDN lookalikes (xn-- or raw Unicode) are defanged too.
_DOMAIN = re.compile(r"(?<![\w-])((?:[^\W_][\w-]*\.)+)([^\W\d_]{2,24}|xn--[\w-]+)\b")
_INVISIBLE = re.compile(r"[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]")


def defang(text: str) -> str:
    """hxxps://evil[.]example/login - readable, never auto-linked by mail clients. Also strips
    invisible/bidi control characters that can disguise text."""
    text = _INVISIBLE.sub("", text)
    text = _URL.sub(lambda m: re.sub(r"^(?i:http)", "hxxp", m.group(0)), text)
    return _DOMAIN.sub(lambda m: m.group(1).replace(".", "[.]") + m.group(2), text)


DEFANG_NOTE = "Links and domains below are written as hxxp:// and [.] on purpose, so they cannot be clicked."


_PHONE = re.compile(r"(?<![\w.])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\) ?|\d{2,4}[ .\-–])\d{3,4}[ .-]\d{3,4}(?!\w|\.\d)")
_TEL = re.compile(r"\btel:\S+", re.IGNORECASE)
_PHONE_DIGITS = re.compile(r"(?<![\w.])\+?\d{10,15}(?![\w]|\.\d)")
_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
CLEAN_SUMMARY = (
    "No phishing indicators were found in this email. That is not a guarantee: if anything about it "
    "feels off, verify it with the sender through a channel you already trust."
)


def neutralize(text: str) -> str:
    """Remove phone numbers (callback-scam bait) and hide the local part of email addresses (privacy),
    keeping the domain, which is the useful teaching signal. Normalizes first so zero-width or
    fullwidth characters can't hide a number from the patterns."""
    text = _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    text = _TEL.sub("[phone number removed]", text)
    text = _PHONE.sub("[phone number removed]", text)
    text = _PHONE_DIGITS.sub("[phone number removed]", text)
    return _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)


def _has_defanged(summary: str | None, sections: list[tuple[str, list[str]]]) -> bool:
    texts = [summary or ""] + [item for _, items in sections for item in items]
    return any(defang(t) != t for t in texts)


def _safe(text: str) -> str:
    """For any text derived from the email or the model."""
    return html.escape(defang(neutralize(text)), quote=True)


def _plain(text: str) -> str:
    return defang(neutralize(text))


def _subject(tag: str, ctx: ReportContext) -> str:
    # Never echo the phish's own subject: it trips content filters and turns our reply into a lure.
    return f"Phishing report result: {tag}" + (f" (ref {ctx.ref})" if ctx.ref else "")


def _report_line(ctx: ReportContext) -> str:
    subject = re.sub(r"[\r\n\t]+", " ", ctx.original_subject).strip()
    subject = defang(neutralize(subject[:120] + ("..." if len(subject) > 120 else "")))
    parts = [f'Your report: "{subject}"']
    if ctx.forwarder or ctx.received_at:
        who = f"from {ctx.forwarder}" if ctx.forwarder else ""
        when = f"on {ctx.received_at}" if ctx.received_at else ""
        parts.append(f"received {who} {when}".replace("  ", " ").strip())
    if ctx.ref:
        parts.append(f"reference {ctx.ref}")
    return ", ".join(parts) + "."


def _page(
    theme: _Theme, title: str, sections: list[tuple[str, list[str]]], summary: str | None, ctx: ReportContext
) -> str:
    help_contact = ctx.help_contact
    # The forwarder's address is shown as-is (it's the reader's own); the subject is attacker text.
    report = html.escape(_report_line(ctx), quote=True)
    parts = [f'<p class="muted" style="margin:0 0 16px;font-size:14px;color:#555555;">{report}</p>']
    if summary:
        parts.append(f'<p style="margin:0 0 16px;font-size:16px;">{_safe(summary)}</p>')
    if _has_defanged(summary, sections):
        parts.append(f'<p style="margin:0 0 16px;font-size:16px;">{DEFANG_NOTE}</p>')
    for heading, items in sections:
        if not items:
            continue
        lis = "".join(f'<li style="margin:0 0 6px;">{_safe(item)}</li>' for item in items)
        parts.append(
            f'<h2 style="margin:20px 0 8px;font-size:18px;">{html.escape(heading)}</h2>'
            f'<ul style="margin:0;padding-left:22px;">{lis}</ul>'
        )
    contact = ""
    if help_contact:
        c = html.escape(help_contact, quote=True)
        contact = f' Questions? <a href="mailto:{c}" style="color:#0b57d0;">Email the help desk ({c})</a>.'
    footer = "This result was produced automatically by an AI model and can be wrong." + contact
    return f"""<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{html.escape(title)}</title>
<style>
  @media (prefers-color-scheme: dark) {{
    .bg {{ background:#121212 !important; color:#e8e8e8 !important; }}
    .muted {{ color:#bdbdbd !important; }}
    .muted a {{ color:#8ab4f8 !important; }}
  }}
</style>
</head>
<body class="bg" style="margin:0;padding:0;background:#ffffff;color:#1f1f1f;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="bg"
 style="background:#ffffff;">
<tr><td align="center" style="padding:16px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:640px;">
<tr><td style="background:{theme.color};color:#ffffff;padding:18px 20px;font-family:Arial,Helvetica,sans-serif;">
<h1 style="margin:0;font-size:24px;line-height:1.3;color:#ffffff;">{html.escape(theme.heading)}</h1>
<p style="margin:8px 0 0;font-size:16px;line-height:1.5;color:#ffffff;">{html.escape(theme.action)}</p>
</td></tr>
<tr><td class="bg" style="padding:18px 20px;font-family:Arial,Helvetica,sans-serif;font-size:16px;
 line-height:1.5;background:#ffffff;color:#1f1f1f;">
{"".join(parts)}
<p class="muted" style="margin:28px 0 0;font-size:14px;line-height:1.5;color:#555555;">{footer}</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"""


def _text(theme: _Theme, sections: list[tuple[str, list[str]]], summary: str | None, ctx: ReportContext) -> str:
    help_contact = ctx.help_contact
    out = [theme.heading, "=" * len(theme.heading), theme.action, "", _report_line(ctx), ""]
    if summary:
        out += [_plain(summary), ""]
    if _has_defanged(summary, sections):
        out += [DEFANG_NOTE, ""]
    for heading, items in sections:
        if items:
            out.append(f"{heading}:")
            out += [f"- {_plain(item)}" for item in items]
            out.append("")
    out.append("This result was produced automatically by an AI model and can be wrong.")
    if help_contact:
        out.append(f"Questions? Email the help desk: {help_contact}")
    return "\n".join(out)


def render_verdict(verdict: Verdict, ctx: ReportContext) -> Reply:
    theme = _THEMES[verdict.verdict]
    first = "Red flags" if verdict.verdict is not Label.CLEAN else "Why it looks legitimate"
    noted = "AI review noted: "
    flags = [i for i in verdict.indicators if not i.startswith(noted)]
    ai_points = [i.removeprefix(noted) for i in verdict.indicators if i.startswith(noted)]
    sections = [(first, flags)]
    if ai_points:
        sections.append(("What the AI review saw (before the automated checks)", ai_points))
    if verdict.verdict is not Label.CLEAN:
        sections.append(("How to spot similar emails", verdict.tips))
    # A "safe" verdict gets a fixed summary: the model's wording is derived from attacker text and
    # must never read as an endorsement someone could screenshot.
    summary_text = CLEAN_SUMMARY if verdict.verdict is Label.CLEAN else verdict.summary
    summary = f"{summary_text} (Confidence: {verdict.confidence.value}.)"
    return Reply(
        subject=_subject(theme.tag, ctx),
        html=_page(theme, theme.heading, sections, summary, ctx),
        text=_text(theme, sections, summary, ctx),
    )


def render_unavailable(ctx: ReportContext, reason: str | None = None) -> Reply:
    sections = [
        (
            "What to do",
            [
                "Do not click links or open attachments in the original email.",
                "If it claims to be from someone you know, contact them through a channel you already trust.",
            ],
        )
    ]
    return Reply(
        subject=_subject(_UNAVAILABLE.tag, ctx),
        html=_page(_UNAVAILABLE, _UNAVAILABLE.heading, sections, reason, ctx),
        text=_text(_UNAVAILABLE, sections, reason, ctx),
    )
