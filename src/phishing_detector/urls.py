"""Offline URL analysis: unwrap security-gateway rewrites to the real destination, and spot
lookalike domains. No network calls: fetching attacker URLs would tip them off and burn one-time links.
"""

from __future__ import annotations

import base64
import re
import string
import unicodedata
from urllib.parse import parse_qs, unquote, urlsplit

_V3 = re.compile(r"v3/__(?P<url>.+?)__;(?P<enc>.*?)!")
_V3_TOKEN = re.compile(r"(\*\*.)|(\*)")
_RUN_LENGTH = {c: i + 2 for i, c in enumerate(string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_")}


def _proofpoint_v3(url: str) -> str | None:
    m = _V3.search(url)
    if not m:
        return None
    try:
        replacements = base64.urlsafe_b64decode(m.group("enc") + "==").decode("utf-8")
    except Exception:
        replacements = ""
    out, pos, used = [], 0, 0
    text = unquote(m.group("url"))
    for token in _V3_TOKEN.finditer(text):
        out.append(text[pos : token.start()])
        if token.group(1):  # "**X": a run of N replacement characters
            n = _RUN_LENGTH.get(token.group(1)[-1], 0)
            out.append(replacements[used : used + n])
            used += n
        else:
            out.append(replacements[used : used + 1])
            used += 1
        pos = token.end()
    out.append(text[pos:])
    return "".join(out)


def _query(url: str, *names: str) -> str | None:
    """The single value of the first present parameter. Repeated or competing parameters are
    refused: the gateway might follow a different one than we'd show (parser differential)."""
    try:
        params = parse_qs(urlsplit(url).query)
    except ValueError:
        return None
    present = [n for n in names if params.get(n)]
    if len(present) != 1 or len(params[present[0]]) != 1:
        return None
    return params[present[0]][0]


def unwrap_once(url: str) -> tuple[str, str] | None:
    """(destination, wrapper name) when the URL is a known security/redirect wrapper."""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return None
    if host in {"urldefense.com", "urldefense.proofpoint.com", "urldefense.us"}:
        if "/v3/" in url:
            dest = _proofpoint_v3(url)
            return (dest, "Proofpoint URL Defense") if dest else None
        if "/v2/" in url:
            u = _query(url, "u")
            return (unquote(u.replace("-", "%").replace("_", "/")), "Proofpoint URL Defense") if u else None
        if "/v1/" in url:
            u = _query(url, "u")
            return (u, "Proofpoint URL Defense") if u else None
    if host.endswith(("safelinks.protection.outlook.com", "safelinks.protection.office365.us")):
        u = _query(url, "url")
        return (u, "Microsoft Safe Links") if u else None
    if host in {"www.google.com", "google.com"} and urlsplit(url).path == "/url":
        u = _query(url, "q", "url")
        return (u, "Google redirect") if u else None
    return None


def unwrap(url: str, max_hops: int = 4) -> tuple[str, list[str]]:
    """Follow nested wrappers offline. Returns the destination and the wrappers peeled off."""
    wrappers: list[str] = []
    for _ in range(max_hops):
        step = unwrap_once(url)
        if not step or not step[0].lower().startswith(("http://", "https://")):
            break
        url, name = step
        wrappers.append(name)
    return url, wrappers


# Brands most impersonated in phishing (APWG/vendor reports) plus this deployment's own context.
BRANDS = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com"},
    "outlook": {"outlook.com", "office.com", "microsoft.com"},
    "sharepoint": {"sharepoint.com", "microsoft.com"},
    "onedrive": {"onedrive.com", "live.com", "microsoft.com"},
    "google": {"google.com", "gmail.com", "googleusercontent.com"},
    "gmail": {"gmail.com", "google.com"},
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazonaws.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "linkedin": {"linkedin.com"},
    "netflix": {"netflix.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "okta": {"okta.com"},
    "duosecurity": {"duosecurity.com", "duo.com"},
    "workday": {"workday.com", "myworkday.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "dhl": {"dhl.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com"},
    "bankofamerica": {"bankofamerica.com"},
    "harvard": {"harvard.edu"},
}
_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "|": "l", "!": "i"})


def _skeleton(label: str) -> str:
    label = unicodedata.normalize("NFKD", label).encode("ascii", "ignore").decode().lower()
    label = label.translate(_CONFUSABLE).replace("rn", "m").replace("vv", "w").replace("cl", "d")
    return re.sub(r"[^a-z]", "", label)


def _one_substitution(a: str, b: str) -> bool:
    """Same length, exactly one character different (amazom, goggle, harward)."""
    return len(a) == len(b) and sum(x != y for x, y in zip(a, b, strict=True)) == 1


def _one_insert_or_delete(a: str, b: str) -> bool:
    """One character added or missing (welsfargo, micosoft). Only used for long brand names:
    for short ones it hits real words (workday -> workdays)."""
    if abs(len(a) - len(b)) != 1:
        return False
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))


# Real companies whose names sit one character from a brand.
_NOT_LOOKALIKES = {"paypay", "goodle", "googlе"}
DISPLAY_NAMES = {
    "microsoft": "Microsoft",
    "outlook": "Outlook",
    "sharepoint": "SharePoint",
    "onedrive": "OneDrive",
    "google": "Google",
    "gmail": "Gmail",
    "paypal": "PayPal",
    "apple": "Apple",
    "icloud": "iCloud",
    "amazon": "Amazon",
    "docusign": "DocuSign",
    "dropbox": "Dropbox",
    "adobe": "Adobe",
    "linkedin": "LinkedIn",
    "netflix": "Netflix",
    "zoom": "Zoom",
    "okta": "Okta",
    "duosecurity": "Duo",
    "workday": "Workday",
    "fedex": "FedEx",
    "usps": "USPS",
    "dhl": "DHL",
    "wellsfargo": "Wells Fargo",
    "chase": "Chase",
    "bankofamerica": "Bank of America",
    "harvard": "Harvard",
}


# Anyone can host content under these, so a subdomain is not the brand: still check its labels.
SHARED_HOSTING = {
    "amazonaws.com",
    "googleusercontent.com",
    "sharepoint.com",
    "onedrive.com",
    "live.com",
    "outlook.com",
    "googleapis.com",
    "dropbox.com",
    "docusign.net",
}


def _is_official(host: str) -> bool:
    for official in BRANDS.values():
        for d in official:
            if host == d or (host.endswith("." + d) and d not in SHARED_HOSTING):
                return True
            # Country editions: amazon.com.au, google.com.br, apple.com.cn
            if re.fullmatch(rf"(?:.+\.)?{re.escape(d)}\.[a-z]{{2}}", host):
                return True
    return False


def lookalike_brand(host: str) -> tuple[str, str] | None:
    """(brand, how) when a host imitates a brand, else None. Official domains are never flagged.

    how = "lookalike": a character swap or typo of the brand name (paypa1, rnicrosoft, goggle), or a
          real brand domain embedded in another (chase.com-onlinebanking.com).
          Strong signal; legitimate companies don't register misspellings of other brands.
    how = "contains": the brand name used inside another domain (paypal-secure.com). Weaker:
          brands own many such domains (googleadservices.com), so this is evidence, not a verdict.
    """
    host = host.lower().strip(".")
    if not host or "." not in host or _is_official(host):
        return None
    # A real brand domain embedded in a different one: chase.com-onlinebanking.com,
    # paypal.com.account-verify.net. Classic trick; strong signal. (Microsoft Defender for Cloud
    # Apps legitimately rewrites links as <domain>.mcas.ms.)
    if host.endswith((".mcas.ms", ".mcas-gov.us")):
        return None
    for brand, official in BRANDS.items():
        for d in official:
            for m in re.finditer(re.escape(d), host):  # every occurrence, not just the first
                i, end = m.start(), m.end()
                if (i == 0 or host[i - 1] in ".-") and host[end : end + 1] in {"-", "."}:
                    return brand, "lookalike"
    found: tuple[str, str] | None = None
    labels = host.split(".")
    shared = next((d for d in SHARED_HOSTING if host.endswith("." + d)), None)
    if shared:  # only the tenant-controlled part counts: micros0ft-support.sharepoint.com
        labels = [*host[: -len(shared) - 1].split("."), "x"]
    for label in labels[:-1]:  # skip the TLD
        for part in dict.fromkeys([label, *label.split("-")]):
            plain = re.sub(r"[^a-z]", "", part)
            sk = _skeleton(part)
            if len(sk) < 4 or plain in _NOT_LOOKALIKES:
                continue
            for brand in BRANDS:
                bsk = _skeleton(brand)  # compare like with like (icloud's "cl" maps to "d" too)
                if sk == bsk and plain != brand:
                    return brand, "lookalike"  # character substitution: paypa1, rnicrosoft, icl0ud
                if len(brand) >= 6 and sk != bsk and _one_substitution(sk, bsk):
                    return brand, "lookalike"  # one-character typo: goggle, amazom, harward
                if len(bsk) >= 8 and _one_insert_or_delete(sk, bsk):
                    return brand, "lookalike"  # welsfargo, micosoft
                if found is None and (sk == bsk or (len(brand) >= 6 and bsk in sk)):
                    found = (brand, "contains")
    return found


def host_is_risky(href: str) -> bool:
    """Raw IP (any form browsers accept: dotted, decimal, hex, short) or an internationalized host."""
    import ipaddress

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
    return all(re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", p) for p in parts) and 1 <= len(parts) <= 4


def clean_href(href: str) -> str:
    """No control characters or whitespace: a decoded URL must not be able to inject prompt lines."""
    return re.sub(r"[\x00-\x20\x7f\u2028\u2029]+", "%20", href.strip())
