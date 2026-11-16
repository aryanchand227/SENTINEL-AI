"""
SENTINEL AI — Reporting Service (PDF, JSON, CSV).

Generates evidence-backed report artifacts from immutable investigation snapshots.
Applies 'SYNTHETIC DATA' watermark/designation as required by Section 13.
Defends against CSV formula injection.
Computes SHA-256 artifact checksums for integrity verification.
"""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.app.core.config import get_settings


def escape_csv_field(val: Any) -> str:
    """
    Defend CSV exports against formula injection.
    Prepends a single quote if the string begins with =, +, -, @, or tab.
    """
    if val is None:
        return ""
    s = str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


class ReportService:
    """Generates immutable report artifacts."""

    def __init__(self, storage_dir: Path | None = None) -> None:
        settings = get_settings()
        self.storage_dir = storage_dir or settings.report_storage_path
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def generate_json_report(
        self,
        report_id: str,
        investigation_id: str,
        title: str,
        data_mode: str,
        provider: str,
        summary: str,
        findings: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
    ) -> tuple[Path, str]:
        """Generate JSON report artifact and return (path, sha256)."""
        payload = {
            "report_id": report_id,
            "investigation_id": investigation_id,
            "title": title,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "data_mode": data_mode.upper(),
            "is_synthetic": data_mode.lower() == "synthetic",
            "provider": provider,
            "executive_summary": summary,
            "key_findings": findings,
            "evidence_table": evidence,
        }

        path = self.storage_dir / f"{report_id}.json"
        content = json.dumps(payload, indent=2).encode("utf-8")
        path.write_bytes(content)

        sha256 = hashlib.sha256(content).hexdigest()
        return path, sha256

    def generate_csv_report(
        self,
        report_id: str,
        evidence: list[dict[str, Any]],
    ) -> tuple[Path, str]:
        """Generate CSV export with formula-injection defense."""
        path = self.storage_dir / f"{report_id}.csv"
        fieldnames = [
            "event_id",
            "timestamp",
            "provider",
            "action",
            "outcome",
            "user",
            "source_ip",
            "severity",
        ]

        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(fieldnames)
            for ev in evidence:
                writer.writerow(
                    [
                        escape_csv_field(ev.get("event_id")),
                        escape_csv_field(ev.get("timestamp")),
                        escape_csv_field(ev.get("provider")),
                        escape_csv_field(ev.get("action")),
                        escape_csv_field(ev.get("outcome")),
                        escape_csv_field(ev.get("user")),
                        escape_csv_field(ev.get("source_ip")),
                        escape_csv_field(ev.get("severity")),
                    ]
                )

        content = path.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()
        return path, sha256

    def generate_pdf_report(
        self,
        report_id: str,
        investigation_id: str,
        title: str,
        data_mode: str,
        provider: str,
        summary: str,
        findings: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
    ) -> tuple[Path, str]:
        """Generate formal executive incident report in PDF using ReportLab."""
        path = self.storage_dir / f"{report_id}.pdf"
        doc = SimpleDocTemplate(
            str(path),
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Title"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            alignment=0,
        )
        subtitle_style = ParagraphStyle(
            "SubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
        )
        badge_style = ParagraphStyle(
            "Badge",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#b91c1c")
            if data_mode.lower() == "synthetic"
            else colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
        )
        h2_style = ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1e3a8a"),
            spaceBefore=10,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1e293b"),
        )

        story: list[Any] = []

        # Header Title
        story.append(Paragraph(f"SENTINEL AI — {title}", title_style))
        story.append(Spacer(1, 4))

        # Metadata banner
        gen_time = datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')
        banner_text = (
            f"<b>Report ID:</b> {report_id} &nbsp;|&nbsp; "
            f"<b>Investigation:</b> {investigation_id} &nbsp;|&nbsp; "
            f"<b>Generated (UTC):</b> {gen_time} &nbsp;|&nbsp; "
            f"<b>Provider:</b> {provider}"
        )
        story.append(Paragraph(banner_text, subtitle_style))
        story.append(Spacer(1, 6))

        # Data Mode Warning Banner (Mandatory Section 13)
        watermark_text = (
            "*** SYNTHETIC DATA ADVISORY: THIS REPORT WAS GENERATED FROM SYNTHETIC "
            "LABORATORY TELEMETRY FOR SIMULATION AND VERIFICATION PURPOSES ***"
            if data_mode.lower() == "synthetic"
            else "OFFICIAL INCIDENT REPORT — LIVE SECURITY TELEMETRY"
        )
        story.append(Paragraph(watermark_text, badge_style))
        story.append(Spacer(1, 10))

        # Executive Summary
        story.append(Paragraph("1. Executive Summary", h2_style))
        story.append(Paragraph(summary or "No summary provided.", body_style))
        story.append(Spacer(1, 10))

        # Key Findings
        story.append(Paragraph("2. Key Investigation Findings", h2_style))
        if findings:
            finding_data = [["Finding Title", "Classification", "Severity", "Confidence"]]
            for f in findings:
                finding_data.append(
                    [
                        f.get("title", ""),
                        f.get("classification", "").upper(),
                        f.get("severity", "").upper(),
                        f.get("confidence_label", "").upper(),
                    ]
                )
            t_findings = Table(
                finding_data, colWidths=[3.2 * inch, 1.4 * inch, 1.2 * inch, 1.2 * inch]
            )
            t_findings.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ]
                )
            )
            story.append(t_findings)
        else:
            story.append(Paragraph("No anomalous findings recorded.", body_style))
        story.append(Spacer(1, 10))

        # Evidence Table
        story.append(Paragraph("3. Supporting Forensic Evidence", h2_style))
        if evidence:
            ev_data = [["Event ID", "Timestamp (UTC)", "Action", "Outcome", "Source IP", "User"]]
            for e in evidence[:25]:  # display up to 25 primary events
                ev_data.append(
                    [
                        str(e.get("event_id", ""))[:16],
                        str(e.get("timestamp", ""))[:19],
                        str(e.get("action", ""))[:18],
                        str(e.get("outcome", ""))[:10],
                        str(e.get("source_ip", ""))[:15],
                        str(e.get("user", ""))[:15],
                    ]
                )
            t_ev = Table(
                ev_data,
                colWidths=[1.5 * inch, 1.5 * inch, 1.2 * inch, 0.9 * inch, 1.0 * inch, 0.9 * inch],
            )
            t_ev.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 7),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ]
                )
            )
            story.append(t_ev)
            if len(evidence) > 25:
                story.append(
                    Paragraph(f"<i>... and {len(evidence) - 25} more events.</i>", subtitle_style)
                )
        else:
            story.append(Paragraph("No evidence records attached.", body_style))
        story.append(Spacer(1, 10))

        # Recommendations
        story.append(Paragraph("4. Recommended Security Response", h2_style))
        recs = (
            "• Reset credentials for accounts with successful login post-brute-force.<br/>"
            "• Block confirmed malicious source IPs on external firewall allowlists.<br/>"
            "• Inspect endpoint process activity and host integrity on affected assets."
        )
        story.append(Paragraph(recs, body_style))

        # Build Document
        doc.build(story)

        content = path.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()
        return path, sha256
