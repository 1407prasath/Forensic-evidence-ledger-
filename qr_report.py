import io
import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def make_qr_png(verify_url):
    """Return PNG bytes of a QR code that points to the verification page."""
    img = qrcode.make(verify_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def build_evidence_report(path, case, evidence, events, result):
    st = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4)
    story = [
        Paragraph("Forensic Evidence & Chain-of-Custody Report", st["Title"]),
        Spacer(1, 8),
        Paragraph(f"<b>Case ID:</b> {case['case_id']} | <b>FIR Number:</b> {case['fir_number']}", st["Normal"]),
        Paragraph(f"<b>Crime Type:</b> {case['crime_type']} | <b>Police Station:</b> {case['police_station']}", st["Normal"]),
        Paragraph(f"<b>Investigating Officer:</b> {case['officer']}", st["Normal"]),
        Spacer(1, 10),
        Paragraph(f"Evidence ID: {evidence['evidence_id']}", st["Heading3"]),
        Paragraph(f"<b>Evidence Type:</b> {evidence['evidence_type']} | <b>File Name:</b> {evidence['file_name']}", st["Normal"]),
        Paragraph(f"<b>Serial No:</b> {evidence['serial_no'] or '-'} | <b>Seal No:</b> {evidence['seal_no'] or '-'}", st["Normal"]),
        Paragraph(f"<b>Condition:</b> {evidence['condition'] or '-'} | <b>Storage Location:</b> {evidence['location'] or '-'}", st["Normal"]),
        Spacer(1, 6),
        Paragraph(f"<b>Registered SHA-256:</b><br/>{evidence['sha256']}", st["Normal"]),
        Paragraph(f"<b>Current SHA-256:</b><br/>{result.get('current_hash', 'N/A')}", st["Normal"]),
        Paragraph(f"<b>Verification Status:</b> {result['status']} (Checked at {result.get('checked_at', '-')})", st["Normal"]),
        Spacer(1, 12),
        Paragraph("Chronological Chain of Custody", st["Heading3"]),
    ]

    rows = [["Time (UTC)", "Action", "From", "To", "Location", "Condition"]]
    for e in events:
        rows.append([
            e["event_time"],
            e["action"],
            e["from_user"] or "-",
            e["to_user"] or "-",
            e["location"] or "-",
            e["condition"] or "-",
        ])

    tbl = Table(rows, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(tbl)
    doc.build(story)
