"""Read evidence out of attachments the HTML/text parser can't: PDF text, links and images, and QR
codes in images. Every function is bounded (bytes, pages, pixels, count) because the input is
attacker-controlled, and none ever raises: failures come back as "not inspected".
"""

from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
logging.getLogger("pypdf").setLevel(logging.ERROR)  # malformed attacker PDFs are expected; keep logs clean

MAX_PDF_BYTES = 10 * 1024 * 1024
MAX_PDF_PAGES = 20
MAX_PDF_TEXT_CHARS = 20_000
MAX_PDF_IMAGES = 20
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000  # ~100 MB decoded RGBA: safe in a 512 MB Lambda
MAX_QR_IMAGES = 15
MAX_PDF_LINKS = 200  # all are risk-checked; the display cap ranks PDF links last

try:  # set at import so every decode is bounded, not only those after decode_qr ran once
    from PIL import Image as _Image

    _Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
except Exception:  # noqa: S110 - Pillow missing: QR decoding simply finds nothing
    pass

_URL = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.IGNORECASE)


@dataclass
class Budget:
    """Per-email limits across ALL attachments, plus a wall-clock deadline: per-item limits alone
    multiply out (20 attachments x 20 pages x 20 images) to more than a Lambda can do in time."""

    deadline: float
    pdfs: int = 5
    pages: int = 40
    images: int = 25
    exhausted: list[str] = field(default_factory=list)

    def time_ok(self) -> bool:
        import time

        if time.monotonic() < self.deadline:
            return True
        self._note("time budget for reading attachments ran out")
        return False

    def take(self, kind: str) -> bool:
        if not self.time_ok():
            return False
        left = getattr(self, kind)
        if left <= 0:
            self._note(f"per-email limit on {kind} reached")
            return False
        setattr(self, kind, left - 1)
        return True

    def _note(self, message: str) -> None:
        if message not in self.exhausted:
            self.exhausted.append(message)


def new_budget(seconds: float = 30.0) -> Budget:
    import time

    return Budget(deadline=time.monotonic() + seconds)


# pypdf's defaults allow 75 MB per decompressed stream; far more than a phishing PDF needs.
_PYPDF_LIMITS = {
    "maximum_declared_stream_length": 10_000_000,
    "array_based_stream_maximum_output_length": 8_000_000,
    "lzw_maximum_output_length": 8_000_000,
    "run_length_maximum_output_length": 8_000_000,
    "zlib_maximum_output_length": 8_000_000,
    "image_maximum_buffer_size": 16_000_000,
    "page_tree_maximum_entries": 500,
    "xform_maximum_invocations_per_extraction": 200,
}
_ACTIVE_ACTIONS = {"/Launch", "/JavaScript", "/SubmitForm", "/GoToR", "/ImportData", "/GoToE"}
_IMAGE_FORMATS = ["PNG", "JPEG", "GIF", "BMP", "WEBP"]  # no TIFF/JPEG2000/PSD/... decoders
_MAX_DECODE_SIDE = 4000


@dataclass
class PdfEvidence:
    inspected: bool = False
    """True when we could read the document (text, links or images)."""

    text: str = ""
    links: list[str] = field(default_factory=list)
    qr_payloads: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    """Parts of the document that were not read; forbids a "safe" verdict."""
    active: list[str] = field(default_factory=list)
    """Active content we don't analyze (JavaScript, embedded files, launch/submit actions, XFA)."""


def decode_qr(image_bytes: bytes, budget: Budget | None = None) -> list[str]:
    """Payloads of every QR code in the image (several can be stacked to hide a malicious one)."""
    if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
        return []
    if budget is not None and not budget.take("images"):
        return []
    try:
        import warnings

        import zxingcpp
        from PIL import Image

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(image_bytes), formats=_IMAGE_FORMATS) as img:
                width, height = img.size
                if width * height > MAX_IMAGE_PIXELS:
                    return []
                img.draft("L", (_MAX_DECODE_SIDE, _MAX_DECODE_SIDE))  # JPEG: decode smaller
                frame = img.convert("L")
            if max(frame.size) > _MAX_DECODE_SIDE:
                frame.thumbnail((_MAX_DECODE_SIDE, _MAX_DECODE_SIDE))
        return [r.text for r in zxingcpp.read_barcodes(frame, formats=zxingcpp.BarcodeFormat.QRCode) if r.text][:10]
    except Exception as exc:  # unsupported format, decompression bomb, corrupt data
        logger.info("image not decoded", extra={"error": type(exc).__name__})
        return []


def pdf_evidence(data: bytes, budget: Budget | None = None) -> PdfEvidence:
    out = PdfEvidence()
    budget = budget or new_budget()
    if len(data) > MAX_PDF_BYTES:
        out.notes.append(f"larger than {MAX_PDF_BYTES // (1024 * 1024)} MB, not opened")
        return out
    if not budget.take("pdfs"):
        out.notes.append("not opened: " + "; ".join(budget.exhausted))
        return out
    try:
        from pypdf import PdfReader, apply_configuration

        with apply_configuration(**_PYPDF_LIMITS):
            _read_pdf(PdfReader(io.BytesIO(data)), out, budget)
    except Exception as exc:
        out.notes.append(f"could not be parsed ({type(exc).__name__})")
        out.inspected = False
    out.dropped = list(dict.fromkeys(out.dropped))
    out.active = list(dict.fromkeys(out.active))
    return out


def _read_pdf(reader, out: PdfEvidence, budget: Budget) -> None:
    if reader.is_encrypted:
        try:
            if not reader.decrypt(""):  # many "encrypted" PDFs only have an owner password
                out.notes.append("password-protected, could not be opened")
                return
        except Exception:
            out.notes.append("password-protected, could not be opened")
            return
    _find_active_content(reader, out)
    total = len(reader.pages)
    if total > MAX_PDF_PAGES:
        out.dropped.append(f"{total} pages; only the first {MAX_PDF_PAGES} were read")
    texts: list[str] = []
    images = 0
    for index in range(min(total, MAX_PDF_PAGES)):  # by index: never materialize every page
        if not budget.take("pages"):
            out.dropped.append("not every page was read (" + "; ".join(budget.exhausted) + ")")
            break
        page = reader.pages[index]
        try:
            texts.append(page.extract_text() or "")
        except Exception:
            out.dropped.append("text on some pages could not be read")
        for annot in _annotations(page):
            action = annot.get("/A") if hasattr(annot, "get") else None
            if not hasattr(action, "get"):
                continue
            if action.get("/S") in _ACTIVE_ACTIONS:
                out.active.append(f"link action {action.get('/S')}")
            uri = action.get("/URI")
            if isinstance(uri, bytes):
                uri = uri.decode("latin-1", errors="replace")
            if isinstance(uri, str) and uri.strip():
                out.links.append(uri.strip())
        try:
            for image in page.images:
                if images >= MAX_PDF_IMAGES:
                    out.dropped.append(f"only the first {MAX_PDF_IMAGES} images were checked for QR codes")
                    break
                images += 1
                out.qr_payloads += decode_qr(image.data, budget)
        except Exception:
            out.dropped.append("images on some pages could not be read")
    text = "\n".join(t.strip() for t in texts if t.strip())
    if len(text) > MAX_PDF_TEXT_CHARS:
        out.dropped.append(f"text cut to {MAX_PDF_TEXT_CHARS} characters")
        text = text[:MAX_PDF_TEXT_CHARS]
    out.text = text
    out.links += [u for u in _URL.findall(text) if u not in out.links]
    if len(out.links) > MAX_PDF_LINKS:
        out.dropped.append(f"{len(out.links) - MAX_PDF_LINKS} of {len(out.links)} links not checked")
        out.links = out.links[:MAX_PDF_LINKS]
    # A PDF with no text, no links and no decodable images is effectively an image we can't read.
    out.inspected = bool(text or out.links or out.qr_payloads)
    if not out.inspected:
        out.notes.append("no readable text (likely scanned or image-only)")


def _find_active_content(reader, out: PdfEvidence) -> None:
    try:
        root = reader.trailer["/Root"]
        if "/OpenAction" in root or "/AA" in root:
            out.active.append("automatic open action")
        names = root.get("/Names") or {}
        if hasattr(names, "get"):
            if names.get("/EmbeddedFiles") is not None:
                out.active.append("embedded files")
            if names.get("/JavaScript") is not None:
                out.active.append("JavaScript")
        form = root.get("/AcroForm") or {}
        if hasattr(form, "get") and form.get("/XFA") is not None:
            out.active.append("XFA form")
    except Exception:  # noqa: S110 - malformed catalog: the page loop will report what it can
        pass


def _annotations(page) -> list:
    try:
        annots = page.get("/Annots") or []
        return [a.get_object() for a in annots][:200]
    except Exception:
        return []


MAX_DATA_URI_IMAGES = 10
MAX_DATA_URI_BYTES = 2 * 1024 * 1024


def data_uri_image(src: str) -> bytes | None:
    """Bytes of a ``data:image/...;base64,`` image (used to dodge attachment-based QR scanning)."""
    import base64

    m = re.match(r"data:image/[a-z0-9.+-]+;base64,", src[:64], re.IGNORECASE)
    if not m or len(src) > MAX_DATA_URI_BYTES * 4 // 3 + 64:
        return None
    try:
        return base64.b64decode(src[m.end() :], validate=False)
    except Exception:
        return None
