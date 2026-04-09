#!/usr/bin/env python3
"""
KaliGuard AI - Reporting Tools Module

Generates professional PDF and HTML security reports using reportlab/fpdf2.
Also provides database operations for saving and retrieving findings.

LEGAL: Reports are for internal authorized security assessment use only.
"""

import os
import sqlite3
import logging
import json
from datetime import datetime
from typing import List, Dict

logger = logging.getLogger("kaliguard.tools.reporting")


def _build_result(success: bool, output: str, error: str = "", **extra) -> dict:
    """Build a standardized result dictionary."""
    result = {
        "success": success,
        "output": output,
        "error": error,
        "timestamp": datetime.now().isoformat()
    }
    result.update(extra)
    return result


def save_finding_to_db(
    db_path: str,
    session_id: str,
    category: str,
    severity: str,
    description: str,
    target: str
) -> dict:
    """
    Save a security finding to the SQLite database.

    Args:
        db_path: Path to the sessions SQLite database
        session_id: Session ID this finding belongs to
        category: Finding category (e.g. 'Open Port', 'SQL Injection')
        severity: Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO
        description: Detailed description of the finding
        target: Target where the finding was discovered

    Returns:
        dict with keys: success, output, error, timestamp
    """
    try:
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Ensure tables exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'active'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        # Ensure session exists
        cursor.execute(
            "INSERT OR IGNORE INTO sessions (id, created_at) VALUES (?, ?)",
            (session_id, datetime.now().isoformat())
        )

        # Insert finding
        cursor.execute(
            """INSERT INTO findings (session_id, category, severity, description, target, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (session_id, category, severity, description, target, datetime.now().isoformat())
        )
        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return _build_result(
            True,
            f"Finding saved (ID: {finding_id}): [{severity}] {category} on {target}",
            finding_id=finding_id
        )
    except Exception as e:
        logger.error(f"Failed to save finding: {e}")
        return _build_result(False, "", str(e))


def get_session_findings(db_path: str, session_id: str) -> list:
    """
    Retrieve all security findings for a session from the database.

    Args:
        db_path: Path to the sessions SQLite database
        session_id: Session ID to retrieve findings for

    Returns:
        List of finding dictionaries
    """
    try:
        if not os.path.exists(db_path):
            return []

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, session_id, category, severity, description, target, timestamp
               FROM findings WHERE session_id = ? ORDER BY
               CASE severity
                 WHEN 'CRITICAL' THEN 1
                 WHEN 'HIGH' THEN 2
                 WHEN 'MEDIUM' THEN 3
                 WHEN 'LOW' THEN 4
                 WHEN 'INFO' THEN 5
                 ELSE 6
               END""",
            (session_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Failed to get findings: {e}")
        return []


def generate_pdf_report(
    session_id: str,
    findings: list,
    output_dir: str = "reports/"
) -> dict:
    """
    Generate a professional PDF security report using FPDF2.

    Includes executive summary, findings table, risk ratings, and remediation.

    Args:
        session_id: Session ID for the report
        findings: List of finding dictionaries from get_session_findings
        output_dir: Directory to save the PDF report

    Returns:
        dict with keys: success, output, error, timestamp, report_path
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = os.path.join(output_dir, f"kaliguard_report_{session_id}_{timestamp}.pdf")

    try:
        from fpdf import FPDF, XPos, YPos

        class KaliGuardPDF(FPDF):
            def header(self):
                self.set_font("Helvetica", "B", 14)
                self.set_fill_color(30, 30, 30)
                self.set_text_color(0, 255, 100)
                self.cell(0, 12, "KaliGuard AI - Security Assessment Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True, align="C")
                self.set_text_color(0, 0, 0)
                self.ln(2)

            def footer(self):
                self.set_y(-15)
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(128, 128, 128)
                self.cell(0, 10, f"KaliGuard AI | Confidential | Page {self.page_no()}/{{nb}} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C")

        pdf = KaliGuardPDF()
        pdf.alias_nb_pages()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Title page info
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 15, "SECURITY ASSESSMENT REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        pdf.ln(5)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, 8, f"Session ID: {session_id}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        pdf.cell(0, 8, f"Report Date: {datetime.now().strftime('%B %d, %Y %H:%M:%S')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        pdf.cell(0, 8, "Classification: CONFIDENTIAL", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        pdf.ln(8)

        # Legal notice box
        pdf.set_fill_color(255, 240, 240)
        pdf.set_draw_color(200, 0, 0)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(180, 0, 0)
        pdf.multi_cell(0, 6, "LEGAL NOTICE: This report is CONFIDENTIAL and contains sensitive security information. "
                             "Distribution is restricted to authorized personnel only. "
                             "All testing was conducted on authorized systems only.",
                       border=1, fill=True, align="C")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(8)

        # Executive Summary
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        pdf.set_font("Helvetica", "B", 14)
        pdf.set_fill_color(30, 30, 30)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 10, "1. EXECUTIVE SUMMARY", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6,
            f"This report presents the findings from an automated security assessment conducted using KaliGuard AI. "
            f"The assessment identified {len(findings)} total finding(s) across {len(set(f.get('target','') for f in findings))} target(s). "
            f"Immediate remediation is recommended for all CRITICAL and HIGH severity findings."
        )
        pdf.ln(5)

        # Risk summary table
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Risk Summary:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        col_w = 37
        colors = {
            "CRITICAL": (220, 53, 69),
            "HIGH": (255, 107, 53),
            "MEDIUM": (255, 193, 7),
            "LOW": (40, 167, 69),
            "INFO": (23, 162, 184),
        }
        headers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        pdf.set_font("Helvetica", "B", 10)
        for h in headers:
            r, g, b = colors[h]
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255) if h in ("CRITICAL", "HIGH") else pdf.set_text_color(30, 30, 30)
            pdf.cell(col_w, 10, h, border=1, align="C", fill=True)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 14)
        for h in headers:
            pdf.set_fill_color(245, 245, 245)
            pdf.cell(col_w, 12, str(severity_counts[h]), border=1, align="C", fill=True)
        pdf.ln(15)

        # Findings Section
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_fill_color(30, 30, 30)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 10, "2. DETAILED FINDINGS", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

        if not findings:
            pdf.set_font("Helvetica", "I", 10)
            pdf.cell(0, 8, "No findings recorded for this session.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, finding in enumerate(findings, 1):
                sev = finding.get("severity", "INFO").upper()
                r, g, b = colors.get(sev, (128, 128, 128))

                # Finding header
                pdf.set_fill_color(r, g, b)
                text_color = (255, 255, 255) if sev in ("CRITICAL", "HIGH") else (30, 30, 30)
                pdf.set_text_color(*text_color)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 8,
                         f"Finding #{i}: [{sev}] {finding.get('category', 'Unknown')}",
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
                pdf.set_text_color(0, 0, 0)

                # Finding details
                pdf.set_font("Helvetica", "", 9)
                pdf.set_fill_color(250, 250, 250)
                pdf.cell(40, 7, "Target:", border="LB")
                pdf.cell(0, 7, finding.get("target", "N/A"), border="RB", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
                pdf.cell(40, 7, "Timestamp:", border="LB")
                pdf.cell(0, 7, finding.get("timestamp", "N/A")[:19], border="RB", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
                pdf.cell(40, 7, "Description:", border="LTB")
                desc = finding.get("description", "No description")
                pdf.multi_cell(0, 7, desc[:500] + "..." if len(desc) > 500 else desc,
                               border="RTB", fill=True)
                pdf.ln(4)

        # Remediation Section
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_fill_color(30, 30, 30)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 10, "3. REMEDIATION RECOMMENDATIONS", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

        remediations = {
            "CRITICAL": [
                "Immediately isolate affected systems from the network",
                "Apply all available security patches",
                "Conduct thorough incident response investigation",
                "Review access logs for signs of exploitation"
            ],
            "HIGH": [
                "Apply patches within 72 hours",
                "Implement compensating controls immediately",
                "Review and update firewall rules",
                "Audit user accounts and access privileges"
            ],
            "MEDIUM": [
                "Schedule patches for next maintenance window",
                "Review security configurations",
                "Implement additional monitoring and alerting",
                "Consider network segmentation improvements"
            ],
            "LOW": [
                "Address in next scheduled maintenance cycle",
                "Review and update security policies",
                "Implement security hardening guidelines",
                "Consider defense-in-depth improvements"
            ],
        }

        for sev, items in remediations.items():
            if severity_counts.get(sev, 0) > 0:
                r, g, b = colors[sev]
                pdf.set_fill_color(r, g, b)
                text_color = (255, 255, 255) if sev in ("CRITICAL", "HIGH") else (30, 30, 30)
                pdf.set_text_color(*text_color)
                pdf.set_font("Helvetica", "B", 11)
                pdf.cell(0, 8, f"{sev} Priority Actions:", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font("Helvetica", "", 10)
                for item in items:
                    pdf.cell(8, 7, "")
                    pdf.cell(0, 7, f"• {item}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.ln(3)

        # Footer disclaimer
        pdf.ln(10)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.multi_cell(0, 5,
            "This report was generated by KaliGuard AI. All assessments were conducted on authorized systems only. "
            "This report contains confidential information and is intended solely for the authorized recipient. "
            "KaliGuard AI provides this report for defensive security purposes only."
        )

        pdf.output(report_path)
        logger.info(f"PDF report generated: {report_path}")
        return _build_result(True, f"PDF report saved to: {report_path}", report_path=report_path)

    except ImportError:
        # Fallback: generate a text-based report
        return _generate_text_report(session_id, findings, output_dir, report_path.replace('.pdf', '.txt'))
    except Exception as e:
        logger.error(f"PDF generation error: {e}", exc_info=True)
        return _generate_text_report(session_id, findings, output_dir, report_path.replace('.pdf', '.txt'))


def _generate_text_report(session_id: str, findings: list, output_dir: str, report_path: str) -> dict:
    """Fallback text report generator when PDF libraries are unavailable."""
    os.makedirs(output_dir, exist_ok=True)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    content = f"""
================================================================================
                    KALIGUARD AI - SECURITY ASSESSMENT REPORT
================================================================================
Session ID  : {session_id}
Report Date : {datetime.now().strftime('%B %d, %Y %H:%M:%S')}
Classification: CONFIDENTIAL

RISK SUMMARY
============
Critical: {severity_counts['CRITICAL']} | High: {severity_counts['HIGH']} | Medium: {severity_counts['MEDIUM']} | Low: {severity_counts['LOW']} | Info: {severity_counts['INFO']}
Total Findings: {len(findings)}

DETAILED FINDINGS
=================
"""
    for i, finding in enumerate(findings, 1):
        content += f"""
Finding #{i}
  Severity   : {finding.get('severity', 'N/A')}
  Category   : {finding.get('category', 'N/A')}
  Target     : {finding.get('target', 'N/A')}
  Timestamp  : {finding.get('timestamp', 'N/A')}
  Description: {finding.get('description', 'N/A')}
{'-' * 60}"""

    content += """

REMEDIATION
===========
1. Immediately address all CRITICAL findings
2. Address HIGH findings within 72 hours
3. Schedule MEDIUM findings for next maintenance window
4. Track LOW findings in your vulnerability management system

================================================================================
Generated by KaliGuard AI | For authorized use only
================================================================================
"""

    with open(report_path, 'w') as f:
        f.write(content)

    return _build_result(True, f"Text report saved to: {report_path} (fpdf2 not installed)", report_path=report_path)


def generate_html_report(
    session_id: str,
    findings: list,
    output_dir: str = "reports/"
) -> dict:
    """
    Generate a professional HTML security report.

    Args:
        session_id: Session ID for the report
        findings: List of finding dictionaries
        output_dir: Directory to save the HTML report

    Returns:
        dict with keys: success, output, error, timestamp, report_path
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = os.path.join(output_dir, f"kaliguard_report_{session_id}_{timestamp}.html")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    severity_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
        "INFO": "#17a2b8",
    }
    severity_text_colors = {
        "CRITICAL": "#fff",
        "HIGH": "#fff",
        "MEDIUM": "#212529",
        "LOW": "#fff",
        "INFO": "#fff",
    }

    findings_html = ""
    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "INFO").upper()
        bg = severity_colors.get(sev, "#6c757d")
        tc = severity_text_colors.get(sev, "#fff")
        desc = finding.get("description", "").replace("<", "&lt;").replace(">", "&gt;")
        findings_html += f"""
        <div class="finding">
            <div class="finding-header" style="background:{bg};color:{tc}">
                Finding #{i}: [{sev}] {finding.get('category', 'Unknown')}
            </div>
            <table class="finding-table">
                <tr><td><strong>Target</strong></td><td>{finding.get('target', 'N/A')}</td></tr>
                <tr><td><strong>Severity</strong></td><td><span class="badge" style="background:{bg};color:{tc}">{sev}</span></td></tr>
                <tr><td><strong>Timestamp</strong></td><td>{finding.get('timestamp', 'N/A')[:19]}</td></tr>
                <tr><td><strong>Description</strong></td><td>{desc}</td></tr>
            </table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KaliGuard AI - Security Report - {session_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 20px; }}
        .container {{ max-width: 1100px; margin: 0 auto; background: #16213e; border-radius: 8px; padding: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
        h1 {{ color: #00ff64; text-align: center; border-bottom: 2px solid #00ff64; padding-bottom: 10px; }}
        h2 {{ color: #00bcd4; border-left: 4px solid #00bcd4; padding-left: 10px; margin-top: 30px; }}
        .meta {{ text-align: center; color: #aaa; margin-bottom: 20px; }}
        .legal {{ background: #2d1b1b; border: 1px solid #dc3545; border-radius: 4px; padding: 15px; margin: 20px 0; color: #ff8a80; font-size: 0.9em; }}
        .risk-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        .risk-table td {{ text-align: center; padding: 15px; font-size: 1.4em; font-weight: bold; border: 2px solid #333; border-radius: 4px; }}
        .finding {{ margin: 15px 0; border-radius: 6px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.3); }}
        .finding-header {{ padding: 10px 15px; font-weight: bold; font-size: 1.05em; }}
        .finding-table {{ width: 100%; border-collapse: collapse; background: #1e2a3a; }}
        .finding-table td {{ padding: 8px 12px; border-bottom: 1px solid #2d3748; vertical-align: top; }}
        .finding-table td:first-child {{ width: 130px; color: #aaa; font-weight: bold; white-space: nowrap; }}
        .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.85em; font-weight: bold; }}
        .footer {{ text-align: center; color: #666; margin-top: 30px; font-size: 0.85em; border-top: 1px solid #333; padding-top: 15px; }}
        .no-findings {{ color: #aaa; font-style: italic; text-align: center; padding: 20px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>KaliGuard AI - Security Assessment Report</h1>
    <div class="meta">
        <strong>Session ID:</strong> {session_id} |
        <strong>Date:</strong> {datetime.now().strftime('%B %d, %Y %H:%M:%S')} |
        <strong>Classification:</strong> CONFIDENTIAL
    </div>
    <div class="legal">
        <strong>LEGAL NOTICE:</strong> This report is CONFIDENTIAL and contains sensitive security information.
        Distribution is restricted to authorized personnel only. All testing was conducted on authorized systems only.
    </div>

    <h2>1. Executive Summary</h2>
    <table class="risk-table">
        <tr>
            <td style="background:#dc3545;color:#fff">CRITICAL<br>{severity_counts['CRITICAL']}</td>
            <td style="background:#fd7e14;color:#fff">HIGH<br>{severity_counts['HIGH']}</td>
            <td style="background:#ffc107;color:#212529">MEDIUM<br>{severity_counts['MEDIUM']}</td>
            <td style="background:#28a745;color:#fff">LOW<br>{severity_counts['LOW']}</td>
            <td style="background:#17a2b8;color:#fff">INFO<br>{severity_counts['INFO']}</td>
        </tr>
    </table>
    <p>This assessment identified <strong>{len(findings)}</strong> total finding(s).
    {"Immediate remediation is required for CRITICAL and HIGH findings." if severity_counts['CRITICAL'] + severity_counts['HIGH'] > 0 else "No critical or high severity findings were identified."}</p>

    <h2>2. Detailed Findings</h2>
    {"".join([findings_html]) if findings else '<p class="no-findings">No findings recorded for this session.</p>'}

    <h2>3. Remediation Recommendations</h2>
    <ul>
        <li><strong style="color:#dc3545">CRITICAL:</strong> Immediately isolate affected systems, apply patches, conduct incident response</li>
        <li><strong style="color:#fd7e14">HIGH:</strong> Apply patches within 72 hours, implement compensating controls</li>
        <li><strong style="color:#ffc107">MEDIUM:</strong> Schedule patches for next maintenance window, review configurations</li>
        <li><strong style="color:#28a745">LOW:</strong> Address in next maintenance cycle, review security policies</li>
    </ul>

    <div class="footer">
        Generated by KaliGuard AI v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
        For authorized use only | All testing on authorized systems only
    </div>
</div>
</body>
</html>"""

    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return _build_result(True, f"HTML report saved to: {report_path}", report_path=report_path)
    except Exception as e:
        return _build_result(False, "", str(e))
