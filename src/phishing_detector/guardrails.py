"""Deterministic checks applied after the model. They can only raise severity, never lower it.

The model is the analyst, but it reads attacker-controlled text. These rules make sure hard signals
(a virus verdict, instructions aimed at an AI, evidence we could not see) can never end in "safe".
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .classifier import Confidence, Label, Verdict
from .parsing import ParsedEmail

_RANK = {Label.CLEAN: 0, Label.SUSPICIOUS: 1, Label.PHISHING: 2}
_RISKY_EXT = re.compile(
    r"\.(?:exe|scr|bat|cmd|com|pif|ps1|js|jse|vbs|vbe|wsf|wsh|hta|lnk|iso|img|vhdx?|docm|xlsm|pptm|jar|msi|reg|cpl"
    r"|mht|mhtml|dmg|apk|url|xll|chm|appx|msix|scf)$",
    re.IGNORECASE,
)
_LURE = re.compile(
    r"password|verify your|sign[ -]?in|log[ -]?in|payroll|direct deposit|gift ?cards?|wire transfer|invoice"
    r"|\bw-?2\b|\bmfa\b|one[- ]time (?:code|password)|bank (?:details|account)",
    re.IGNORECASE,
)
OVERRIDE_SUMMARY = (
    "Automated checks found risk signals in this email, listed first below. Treat it with caution "
    "and do not act on it until you have verified it another way."
)


def _host_is_risky(href: str) -> bool:
    """Raw IP (any form browsers accept: dotted, decimal, hex, short) or an internationalized host."""
    href = href.strip().replace("\\", "/")
    if "://" not in href[:12]:
        href = "http://" + href
    try:
        host = (urlsplit(href).hostname or "").strip(".")
    except ValueError:
        return False
    if not host:
        return False
    if host.startswith("xn--") or ".xn--" in host or not host.isascii():
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    parts = host.split(".")
    numeric = all(re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", p) for p in parts)
    return numeric and 1 <= len(parts) <= 4


def floors(email: ParsedEmail) -> list[tuple[Label, str]]:
    """(minimum verdict, reason shown to the user) for every rule that fires."""
    out: list[tuple[Label, str]] = []
    auth = email.sender_auth
    if auth.virus == "FAIL":
        out.append((Label.PHISHING, "Our mail scanner detected malware in this email."))
    hidden_markers = [m for m in email.injection_markers if m.startswith("hidden:")]
    if hidden_markers:
        out.append((Label.PHISHING, "The email contains hidden text addressed to automated scanners."))
    elif email.injection_markers:
        out.append((Label.SUSPICIOUS, "The email contains text that tries to influence automated scanners."))
    risky_links = [link.href for link in email.links if _host_is_risky(link.href)]
    if risky_links:
        out.append(
            (Label.SUSPICIOUS, "A link points to a raw IP address or an internationalized (lookalike-prone) domain.")
        )
    risky_files = [a.filename for a in email.attachments if _RISKY_EXT.search(a.filename)]
    if risky_files:
        out.append((Label.SUSPICIOUS, f'It has a risky attachment type: "{risky_files[0]}".'))
    if email.uninspectable:
        name = email.uninspectable[0].split(" (")[0]
        out.append(
            (Label.SUSPICIOUS, f'The attachment "{name}" could not be inspected, so the email cannot be called safe.')
        )
    if email.evidence_dropped:
        out.append((Label.SUSPICIOUS, "Part of the email was too large to analyze in full."))
    if email.ambiguous_original:
        out.append((Label.SUSPICIOUS, "The forward contained two different emails, so the analysis may be incomplete."))
    inner_auth = email.headers.get("Authentication-Results", "").lower()
    all_text = f"{email.body}\n{email.hidden_text}\n{email.secondary_text}"
    if ("dmarc=fail" in inner_auth or ("spf=fail" in inner_auth and "dkim=fail" in inner_auth)) and _LURE.search(
        all_text
    ):
        out.append(
            (Label.SUSPICIOUS, "The sender failed email authentication and the message asks for sensitive action.")
        )
    if auth.spam == "FAIL":
        out.append((Label.SUSPICIOUS, "Our mail scanner classified this email as spam."))
    return out


def apply(email: ParsedEmail, verdict: Verdict) -> tuple[Verdict, list[str]]:
    """Return the verdict raised to the strongest floor that fired, and the reasons for any raise."""
    fired = floors(email)
    floor = max((label for label, _ in fired), key=_RANK.__getitem__, default=Label.CLEAN)
    confidence = verdict.confidence
    if email.forward_kind == "inline" and confidence is Confidence.HIGH and verdict.verdict is Label.CLEAN:
        confidence = Confidence.MEDIUM  # no transport headers to back a confident "safe"
    if _RANK[floor] <= _RANK[verdict.verdict]:
        return verdict.model_copy(update={"confidence": confidence}), []
    reasons = [f"Automated check: {reason}" for _, reason in fired]
    # A model "clean" listed reasons the email looks legitimate; keep them, but say whose they are.
    model_points = [
        f"AI review noted: {point}" if verdict.verdict is Label.CLEAN else point for point in verdict.indicators
    ]
    raised = verdict.model_copy(
        update={
            "verdict": floor,
            "confidence": Confidence.MEDIUM,
            "summary": OVERRIDE_SUMMARY,
            "indicators": reasons + model_points,
        }
    )
    return raised, reasons
