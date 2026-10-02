import io

import zxingcpp
from PIL import Image

from conftest import forward_as_attachment, phish
from phishing_detector import extractors, guardrails
from phishing_detector.parsing import parse_email


def qr_png(text: str) -> bytes:
    barcode = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode)
    img = zxingcpp.write_barcode_to_image(barcode, scale=4)
    height, width = memoryview(img).shape
    buf = io.BytesIO()
    Image.frombytes("L", (width, height), bytes(memoryview(img))).save(buf, "PNG")
    return buf.getvalue()


def make_pdf(text: str, uri: str | None = None, encrypt: bool = False) -> bytes:
    """Minimal one-page PDF with a text line and an optional URI link annotation."""
    from pypdf import PdfWriter
    from pypdf.annotations import Link
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})}
    )
    stream = DecodedStreamObject()
    stream.set_data(f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode())
    page[NameObject("/Contents")] = writer._add_object(stream)
    if uri:
        writer.add_annotation(0, Link(rect=(70, 700, 300, 730), url=uri))
    if encrypt:
        writer.encrypt(user_password="secret", owner_password="owner")
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def test_decode_qr_reads_payload():
    assert extractors.decode_qr(qr_png("https://evil.example/login")) == ["https://evil.example/login"]


def test_decode_qr_never_raises_on_garbage_or_huge_input():
    assert extractors.decode_qr(b"not an image") == []
    assert extractors.decode_qr(b"\x00" * (extractors.MAX_IMAGE_BYTES + 1)) == []


def test_pdf_text_and_links_are_read():
    pdf = extractors.pdf_evidence(make_pdf("Your payroll account needs verification", "https://pay.evil.example/x"))
    assert pdf.inspected and "payroll account" in pdf.text
    assert "https://pay.evil.example/x" in pdf.links


def test_password_protected_pdf_is_not_inspected():
    pdf = extractors.pdf_evidence(make_pdf("secret", encrypt=True))
    assert not pdf.inspected and any("password" in n for n in pdf.notes)


def test_readable_pdf_is_evidence_not_uninspectable():
    carrier = phish(html=False)
    carrier.add_attachment(
        make_pdf("Invoice overdue, pay now", "https://pay.evil.example/i"),
        maintype="application",
        subtype="pdf",
        filename="invoice.pdf",
    )
    email = parse_email(forward_as_attachment(carrier))
    assert email.uninspectable == []
    assert "[PDF attachment: invoice.pdf]" in email.attachment_text and "Invoice overdue" in email.attachment_text
    assert any(link.href == "https://pay.evil.example/i" and "PDF" in link.text for link in email.links)
    assert "## Text extracted from attachments" in email.to_prompt()


def test_encrypted_pdf_stays_uninspectable():
    carrier = phish(html=False)
    carrier.add_attachment(make_pdf("x", encrypt=True), maintype="application", subtype="pdf", filename="locked.pdf")
    email = parse_email(forward_as_attachment(carrier))
    assert email.uninspectable == ["locked.pdf (application/pdf)"]


def test_qr_code_image_becomes_a_labeled_link_and_feeds_guardrails():
    carrier = phish(html=False)
    carrier.add_attachment(qr_png("http://198.51.100.7/mfa"), maintype="image", subtype="png", filename="scan.png")
    email = parse_email(forward_as_attachment(carrier))
    [qr] = [link for link in email.links if link.text.startswith("[QR code")]
    assert qr.href == "http://198.51.100.7/mfa" and "scan.png" in qr.text
    assert any("raw IP" in reason for _, reason in guardrails.floors(email))


def test_pdf_links_cannot_push_out_body_links():
    many = " ".join(f"https://filler{i}.example/x" for i in range(200))
    carrier = phish()  # body has the raw-IP lure link
    carrier.add_attachment(make_pdf(many[:3000]), maintype="application", subtype="pdf", filename="f.pdf")
    email = parse_email(forward_as_attachment(carrier))
    assert any(link.href == "http://198.51.100.7/login" for link in email.links)
    assert "http://198.51.100.7/login" in email.risky_links


def test_misnamed_unreadable_pdf_is_uninspectable():
    carrier = phish(html=False)
    carrier.add_attachment(make_pdf("x", encrypt=True), maintype="image", subtype="png", filename="scan.png")
    assert parse_email(forward_as_attachment(carrier)).uninspectable == ["scan.png (image/png)"]


def test_pdf_with_leading_junk_is_read():
    carrier = phish(html=False)
    carrier.add_attachment(
        b"junk\n" + make_pdf("Wire the funds today"), maintype="application", subtype="octet-stream", filename="doc.dat"
    )
    email = parse_email(forward_as_attachment(carrier))
    assert "Wire the funds today" in email.attachment_text and email.uninspectable == []


def test_qr_in_inline_data_uri_image_is_decoded():
    import base64
    from email.message import EmailMessage
    from email.policy import SMTP

    src = "data:image/png;base64," + base64.b64encode(qr_png("https://evil.example/qr")).decode()
    m = EmailMessage()
    m["From"] = "alice@example.org"
    m.set_content("x")
    m.add_alternative(f"<p>Scan:</p><img src='{src}'>", subtype="html")
    email = parse_email(m.as_bytes(policy=SMTP))
    assert any(link.href == "https://evil.example/qr" and "QR" in link.text for link in email.links)


def test_truncated_pdf_counts_as_dropped_evidence():
    long_text = "word " * 6000
    pdf = extractors.pdf_evidence(make_pdf(long_text[:30000]))
    assert pdf.inspected


def test_same_pdf_on_forward_and_original_is_read_once():
    pdf = make_pdf("Invoice overdue")
    original = phish(html=False)
    original.add_attachment(pdf, maintype="application", subtype="pdf", filename="a.pdf")
    from email.message import EmailMessage
    from email.policy import SMTP

    outer = EmailMessage()
    outer["From"] = "alice@example.org"
    outer.set_content("---------- Forwarded message ---------\nFrom: x@evil.example\nSubject: s\n\nhi")
    outer.add_attachment(original)
    outer.add_attachment(pdf, maintype="application", subtype="pdf", filename="a.pdf")
    email = parse_email(outer.as_bytes(policy=SMTP))
    assert email.attachment_text.count("[PDF attachment: a.pdf]") == 1


def make_active_pdf() -> bytes:
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer._root_object[NameObject("/OpenAction")] = DictionaryObject(
        {NameObject("/S"): NameObject("/JavaScript"), NameObject("/JS"): TextStringObject("app.alert('x');")}
    )
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def test_pdf_with_javascript_is_listed_as_uninspectable():
    pdf = extractors.pdf_evidence(make_active_pdf())
    assert "automatic open action" in pdf.active
    carrier = phish(html=False)
    carrier.add_attachment(make_active_pdf(), maintype="application", subtype="pdf", filename="form.pdf")
    email = parse_email(forward_as_attachment(carrier))
    assert any("form.pdf" in u and "open action" in u for u in email.uninspectable)


def test_per_email_budget_limits_pdfs_and_records_it():
    budget = extractors.new_budget()
    budget.pdfs = 1
    assert extractors.pdf_evidence(make_pdf("one"), budget).inspected
    second = extractors.pdf_evidence(make_pdf("two"), budget)
    assert not second.inspected and budget.exhausted


def test_time_budget_exhaustion_counts_as_dropped_evidence():
    carrier = phish(html=False)
    carrier.add_attachment(make_pdf("x"), maintype="application", subtype="pdf", filename="a.pdf")
    email = parse_email(forward_as_attachment(carrier), attachment_seconds=0)
    assert any("not fully read" in d for d in email.evidence_dropped)


def test_image_bomb_dimensions_are_refused():
    big = Image.new("L", (6000, 5000))
    buf = io.BytesIO()
    big.save(buf, "PNG")
    assert extractors.decode_qr(buf.getvalue()) == []


def test_unsupported_image_formats_are_not_decoded():
    buf = io.BytesIO()
    Image.new("L", (50, 50)).save(buf, "TIFF")
    assert extractors.decode_qr(buf.getvalue()) == []
