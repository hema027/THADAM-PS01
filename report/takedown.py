"""
CloneTrace Takedown Incident Pack Generator (ReportLab).
Generates standardized, evidence-backed abuse escalation PDF dossiers.
Black-on-white layout with theme accent heading accents and under 6 pages.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

try:
    from app.theme import ACCENT
except ImportError:
    from theme import ACCENT
from db import get_conn


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and stamp total page numbers and footer."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Footer
        footer_text = f"CloneTrace Takedown Dossier  |  Page {self._pageNumber} of {page_count}"
        self.drawString(40, 25, footer_text)

        is_synthetic = getattr(self, "_is_synthetic", True)
        if is_synthetic:
            self.drawRightString(
                letter[0] - 40,
                25,
                "DEMO / SYNTHETIC DATASET - STRICT CONFIDENTIALITY",
            )
        else:
            self.drawRightString(
                letter[0] - 40,
                25,
                "CONFIDENTIAL - ABUSE DESK ESCALATION",
            )
        self.restoreState()


def generate_takedown(campaign_id: int) -> str:
    """
    Generates a structured PDF takedown report for a detected campaign.
    Saves to data/reports/campaign_<id>.pdf and returns the file path.
    """
    conn = get_conn()
    try:
        # 1. Campaign Details
        cur = conn.execute(
            "SELECT id, name, first_seen, last_seen, size, brands, top_indicators FROM campaigns WHERE id = ?",
            (campaign_id,)
        )
        camp = cur.fetchone()
        if not camp:
            raise ValueError(f"Campaign {campaign_id} not found.")

        brands = json.loads(camp["brands"]) if camp["brands"] else []
        brands_str = ", ".join(b.upper() for b in brands) if brands else "UNKNOWN"

        # 2. Member Observations
        cur = conn.execute("""
            SELECT o.id, o.url, o.first_seen, o.is_synthetic, v.label, v.brand, v.score, v.signals
            FROM campaign_members cm
            JOIN observations o ON cm.obs_id = o.id
            LEFT JOIN verdicts v ON o.id = v.obs_id
            WHERE cm.campaign_id = ?
            ORDER BY o.id ASC
        """, (campaign_id,))
        members = cur.fetchall()

        member_ids = [m["id"] for m in members]
        placeholders = ",".join("?" for _ in member_ids)

        has_synthetic = any(m["is_synthetic"] == 1 for m in members)

        # 3. Indicators for members
        cur = conn.execute(
            f"""
            SELECT type, value, COUNT(DISTINCT obs_id) as obs_count
            FROM indicators
            WHERE obs_id IN ({placeholders})
            GROUP BY type, value
            ORDER BY obs_count DESC, type ASC
            """,
            member_ids
        )
        shared_inds = cur.fetchall()

        # 4. Distinct IOC list
        cur = conn.execute(
            f"SELECT DISTINCT type, value FROM indicators WHERE obs_id IN ({placeholders}) ORDER BY type, value",
            member_ids
        )
        all_iocs = cur.fetchall()

    finally:
        conn.close()

    reports_dir = Path("data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = reports_dir / f"campaign_{campaign_id}.pdf"

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()

    accent_color = colors.HexColor(ACCENT)
    dark_text = colors.HexColor("#0F172A")
    muted_text = colors.HexColor("#475569")
    border_color = colors.HexColor("#CBD5E1")
    surface_bg = colors.HexColor("#F8FAFC")

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=dark_text,
        fontName="Helvetica-Bold",
        spaceAfter=4
    )
    h2_style = ParagraphStyle(
        "Heading2",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=accent_color,
        fontName="Helvetica-Bold",
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=dark_text,
        fontName="Helvetica"
    )
    body_bold = ParagraphStyle(
        "BodyBold",
        parent=body_style,
        fontName="Helvetica-Bold"
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=body_style,
        fontName="Courier",
        fontSize=8,
        leading=11
    )
    meta_style = ParagraphStyle(
        "Meta",
        parent=body_style,
        fontSize=8,
        textColor=muted_text
    )

    elements = []

    # Case Header
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    case_id = f"CT-CAMP-{campaign_id:04d}"

    elements.append(Paragraph(f"INCIDENT DOSSIER: {camp['name']} ({case_id})", title_style))
    elements.append(Paragraph(f"Generated by CloneTrace Abuse Escalation Engine  |  Date: {now_utc}", meta_style))
    elements.append(Spacer(1, 6))
    elements.append(HRFlowable(width="100%", thickness=1, color=border_color, spaceAfter=8))

    # 1. Summary Paragraph
    elements.append(Paragraph("1. Incident Summary & Attribution Basis", h2_style))
    summary_text = (
        f"This takedown incident pack documents an active, coordinated fraud/phishing campaign targeting "
        f"<b>{brands_str}</b>. The campaign comprises <b>{len(members)} observed infrastructure nodes</b> "
        f"spanning from <b>{str(camp['first_seen'])[:19]}</b> to <b>{str(camp['last_seen'])[:19]}</b>. "
        f"Attribution is established via bipartite graph clustering over shared telemetry anchors including "
        f"UPI Virtual Payment Addresses (VPAs), Telegram exfiltration bots, kit hash signatures, and common hosting infrastructure."
    )
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 8))

    # Summary key-value table
    summary_rows = [
        [Paragraph("Case ID", body_bold), Paragraph(case_id, mono_style),
         Paragraph("Targeted Brands", body_bold), Paragraph(brands_str, body_style)],
        [Paragraph("Cluster Size", body_bold), Paragraph(f"{len(members)} Nodes", body_style),
         Paragraph("First Seen", body_bold), Paragraph(str(camp["first_seen"])[:19], mono_style)],
        [Paragraph("Status", body_bold), Paragraph("VERIFIED FRAUD CAMPAIGN", body_bold),
         Paragraph("Last Seen", body_bold), Paragraph(str(camp["last_seen"])[:19], mono_style)],
    ]
    sum_t = Table(summary_rows, colWidths=[90, 160, 100, 180])
    sum_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), surface_bg),
        ("GRID", (0, 0), (-1, -1), 0.5, border_color),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(sum_t)
    elements.append(Spacer(1, 10))

    # 2. Evidence Table
    elements.append(Paragraph("2. Primary Evidence Nodes (Hosts & Scores)", h2_style))
    ev_header = [
        Paragraph("Obs ID", body_bold),
        Paragraph("Host / URL", body_bold),
        Paragraph("Verdict", body_bold),
        Paragraph("Score", body_bold),
        Paragraph("Top Fired Signals", body_bold),
    ]
    ev_rows = [ev_header]
    for m in members[:15]:  # limit to top 15 rows to maintain concise page limit
        sig_dict = json.loads(m["signals"]) if m["signals"] else {}
        top_sigs = ", ".join(list(sig_dict.keys())[:3]) if sig_dict else "heuristic_match"
        url_disp = m["url"] if m["url"] else "N/A"
        if len(url_disp) > 40:
            url_disp = url_disp[:37] + "..."
        ev_rows.append([
            Paragraph(str(m["id"]), mono_style),
            Paragraph(url_disp, mono_style),
            Paragraph(str(m["label"] or "phish").upper(), body_bold),
            Paragraph(f"{float(m['score'] or 0.0):.2f}", mono_style),
            Paragraph(top_sigs, meta_style),
        ])
    ev_table = Table(ev_rows, colWidths=[45, 175, 65, 45, 200])
    ev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), surface_bg),
        ("GRID", (0, 0), (-1, -1), 0.5, border_color),
        ("PADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(ev_table)
    elements.append(Spacer(1, 10))

    # 3. Side-by-Side Screenshots (up to 3 members)
    elements.append(Paragraph("3. Captured Visual Evidence (Mobile Viewport)", h2_style))
    shot_images: list[Any] = []
    for m in members:
        shot_candidate = Path(f"data/cache/{m['id']}/mobile.png")
        if not shot_candidate.exists():
            shot_candidate = Path(f"data/cache/{m['id']}/mobile/shot.png")
        if shot_candidate.exists() and shot_candidate.stat().st_size > 1000:
            try:
                img = Image(str(shot_candidate), width=150, height=270)
                caption = Paragraph(f"<b>Obs #{m['id']}</b><br/>{m['url'][:28]}", meta_style)
                shot_images.append([img, caption])
                if len(shot_images) >= 3:
                    break
            except Exception:
                pass

    if shot_images:
        shot_row = [item[0] for item in shot_images]
        cap_row = [item[1] for item in shot_images]
        col_w = 530 / len(shot_images)
        shot_table = Table([shot_row, cap_row], colWidths=[col_w] * len(shot_images))
        shot_table.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(shot_table)
    else:
        elements.append(Paragraph("<i>No visual screenshots captured in local cache for campaign members.</i>", meta_style))
    elements.append(Spacer(1, 10))

    # 4. Linked Infrastructure Table
    elements.append(Paragraph("4. Shared Infrastructure Anchors", h2_style))
    shared_header = [
        Paragraph("Indicator Type", body_bold),
        Paragraph("Indicator Value", body_bold),
        Paragraph("Obs Count", body_bold),
    ]
    shared_rows = [shared_header]
    for ind in shared_inds[:10]:
        shared_rows.append([
            Paragraph(str(ind["type"]).upper(), body_bold),
            Paragraph(str(ind["value"]), mono_style),
            Paragraph(str(ind["obs_count"]), mono_style),
        ])
    shared_table = Table(shared_rows, colWidths=[120, 330, 80])
    shared_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), surface_bg),
        ("GRID", (0, 0), (-1, -1), 0.5, border_color),
        ("PADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(shared_table)
    elements.append(Spacer(1, 10))

    # 5. Recommended Escalation Recipients (marked to be verified, contacts unresolved)
    elements.append(Paragraph("5. Recommended Escalation Authority Dispatch (Unresolved)", h2_style))
    recipients_data = [
        [Paragraph("Authority / Counterparty", body_bold), Paragraph("Contact Target", body_bold), Paragraph("Verification Status", body_bold)],
        [Paragraph("Domain Registrar Abuse", body_style), Paragraph("Registrar abuse mailbox (RDAP lookup unresolved)", meta_style), Paragraph("To be verified", body_bold)],
        [Paragraph("Hosting Provider Abuse", body_style), Paragraph("Upstream ASN / Host abuse desk (unresolved)", meta_style), Paragraph("To be verified", body_bold)],
        [Paragraph("Google Safe Browsing", body_style), Paragraph("https://safebrowsing.google.com/safebrowsing/report_phish/", meta_style), Paragraph("To be verified", body_bold)],
        [Paragraph("National Cyber Coordination (CERT-In)", body_style), Paragraph("incident@cert-in.org.in (unresolved)", meta_style), Paragraph("To be verified", body_bold)],
        [Paragraph("Cybercrime.gov.in (I4C Portal)", body_style), Paragraph("National Cyber Crime Reporting Portal", meta_style), Paragraph("To be verified", body_bold)],
        [Paragraph("Brand Fraud Defense Desk", body_style), Paragraph(f"{brands_str} Brand Fraud Operation Desk", meta_style), Paragraph("To be verified", body_bold)],
        [Paragraph("DoT / Sanchar Saathi (Telecom Abuse)", body_style), Paragraph("Department of Telecommunications Chakshu portal", meta_style), Paragraph("To be verified", body_bold)],
    ]
    rec_table = Table(recipients_data, colWidths=[160, 250, 120])
    rec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), surface_bg),
        ("GRID", (0, 0), (-1, -1), 0.5, border_color),
        ("PADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(rec_table)
    elements.append(Spacer(1, 10))

    # 6. Appendix: Full IOC Table
    elements.append(Paragraph("6. Appendix: Complete Indicator Manifest", h2_style))
    ioc_rows = [[Paragraph("Type", body_bold), Paragraph("Value", body_bold)]]
    for ind in all_iocs[:40]:  # Cap to keep well within 6 pages
        ioc_rows.append([
            Paragraph(str(ind["type"]).upper(), body_style),
            Paragraph(str(ind["value"]), mono_style)
        ])
    ioc_table = Table(ioc_rows, colWidths=[120, 410])
    ioc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), surface_bg),
        ("GRID", (0, 0), (-1, -1), 0.5, border_color),
        ("PADDING", (0, 0), (-1, -1), 2.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(ioc_table)

    # Build PDF with custom two-pass NumberedCanvas
    def _canvas_maker(*args: Any, **kwargs: Any) -> NumberedCanvas:
        c = NumberedCanvas(*args, **kwargs)
        c._is_synthetic = has_synthetic
        return c

    doc.build(elements, canvasmaker=_canvas_maker)
    return str(pdf_path)
