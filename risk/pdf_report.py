"""
risk/pdf_report.py — PDF forensic report using fpdf2.
Generated only for risk_tier "medium", "high", or "critical".
"""
from __future__ import annotations
import os
from datetime import datetime, timezone

from fpdf import FPDF

TIER_COLORS = {
    "low":      (34, 139, 34),
    "medium":   (255, 165, 0),
    "high":     (220, 50, 50),
    "critical": (139, 0, 0),
}


def _safe(text, maxlen: int = 200) -> str:
    """Strip characters not representable in latin-1 so fpdf2 never chokes."""
    s = str(text)[:maxlen]
    return s.encode("latin-1", errors="replace").decode("latin-1")


class ThreatReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_fill_color(30, 30, 60)
        self.set_text_color(255, 255, 255)
        self.cell(0, 12, "ThreatLens - Email Forensic Report", align="C", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |  Page {self.page_no()}", align="C")

    def section_title(self, title: str):
        self.ln(4)
        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(230, 235, 245)
        self.set_text_color(20, 20, 80)
        self.cell(0, 8, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def kv_row(self, key: str, value: str, bold_value: bool = False):
        self.set_font("Helvetica", "B", 9)
        self.cell(50, 6, _safe(key + ":"), new_x="RIGHT", new_y="LAST")
        self.set_font("Helvetica", "B" if bold_value else "", 9)
        self.multi_cell(0, 6, _safe(value, 110), new_x="LMARGIN", new_y="NEXT")

    def bullet(self, text: str):
        self.set_font("Helvetica", "", 9)
        self.set_x(self.get_x() + 8)
        self.cell(5, 6, "-", new_x="RIGHT", new_y="LAST")
        self.multi_cell(0, 6, _safe(text, 160), new_x="LMARGIN", new_y="NEXT")

    def table_row(self, cols: list[str], widths: list[int], header: bool = False):
        self.set_font("Helvetica", "B" if header else "", 9)
        if header:
            self.set_fill_color(200, 210, 230)
        else:
            self.set_fill_color(245, 247, 250)
        for col, w in zip(cols, widths):
            self.cell(w, 7, _safe(col, 40), border=1, fill=header, new_x="RIGHT", new_y="LAST")
        self.ln()


def generate_pdf(
    risk_data: dict,
    forensics: dict | None,
    geo: dict | None,
    classified: dict | None,
    reputation: dict | None,
    email_meta: dict | None,
    output_path: str,
) -> str:
    """Generate PDF and return the saved path."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    pdf = ThreatReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_margins(15, 15, 15)

    message_id = risk_data.get("message_id", "unknown")
    score = risk_data.get("risk_score", 0.0)
    tier = risk_data.get("risk_tier", "low")
    tier_r, tier_g, tier_b = TIER_COLORS.get(tier, (100, 100, 100))

    # ── Risk Score Banner ─────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(tier_r, tier_g, tier_b)
    pdf.cell(0, 14, f"Risk Score: {score:.1f} / 100  [{tier.upper()}]", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)

    # ── Email Metadata ────────────────────────────────────────────────────────
    pdf.section_title("Email Metadata")
    pdf.kv_row("Message ID", message_id)
    if email_meta:
        pdf.kv_row("From", email_meta.get("from", {}).get("email", "-"))
        tos = [r.get("email", "") for r in email_meta.get("to", [])]
        pdf.kv_row("To", ", ".join(tos) or "-")
        pdf.kv_row("Subject", email_meta.get("subject", "-"))
        pdf.kv_row("Date", str(email_meta.get("date", "-")))

    # ── Data Completeness ─────────────────────────────────────────────────────
    pdf.section_title("Data Completeness")
    comp = risk_data.get("data_completeness", {})
    for module, present in comp.items():
        status = "AVAILABLE" if present else "MISSING"
        pdf.kv_row(module.capitalize(), status, bold_value=not present)

    # ── Component Scores ──────────────────────────────────────────────────────
    pdf.section_title("Component Scores")
    cs = risk_data.get("component_scores", {})
    headers = ["Component", "Score (0-100)", "Weight"]
    widths = [70, 50, 50]
    weight_labels = {"auth_score": "20%", "geo_score": "20%", "nlp_score": "30%", "reputation_score": "30%"}
    pdf.table_row(headers, widths, header=True)
    for key, label in [("auth_score", "Auth (SPF/DKIM/DMARC)"),
                        ("geo_score", "Geolocation Anomaly"),
                        ("nlp_score", "NLP Phishing Classifier"),
                        ("reputation_score", "URL/File Reputation")]:
        pdf.table_row([label, f"{cs.get(key, 0):.1f}", weight_labels[key]], widths)

    # ── Contributing Factors ──────────────────────────────────────────────────
    factors = risk_data.get("contributing_factors", [])
    if factors:
        pdf.section_title("Contributing Factors")
        for f in factors:
            pdf.bullet(f)
    else:
        pdf.section_title("Contributing Factors")
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  No significant risk factors detected.", new_x="LMARGIN", new_y="NEXT")

    # ── Auth Results Table ────────────────────────────────────────────────────
    if forensics:
        pdf.section_title("Authentication Results (SPF / DKIM / DMARC)")
        pdf.table_row(["Check", "Result", "Detail"], [50, 40, 80], header=True)
        alignment = forensics.get("alignment", {}) or {}
        pdf.table_row(["SPF", str(forensics.get("spf", "unknown")).upper(),
                        "aligned" if alignment.get("spf_aligned") else "misaligned"], [50, 40, 80])
        pdf.table_row(["DKIM", str(forensics.get("dkim", "unknown")).upper(),
                        "aligned" if alignment.get("dkim_aligned") else "misaligned"], [50, 40, 80])
        policy = forensics.get("dmarc_policy", "—")
        pdf.table_row(["DMARC", str(forensics.get("dmarc", "unknown")).upper(),
                        f"policy: {policy}"], [50, 40, 80])

    # ── Geolocation ───────────────────────────────────────────────────────────
    if geo:
        pdf.section_title("Geolocation")
        gloc = geo.get("geolocation") or {}
        pdf.kv_row("Originating IP", str(geo.get("originating_ip", "—")))
        pdf.kv_row("Country", str(gloc.get("country", "—")))
        pdf.kv_row("City", str(gloc.get("city", "—")))
        lat = gloc.get("lat", "—")
        lon = gloc.get("long", "—")
        pdf.kv_row("Coordinates", f"{lat}, {lon}")
        pdf.kv_row("ISP/ASN", str(gloc.get("isp", "—")))
        anomaly = geo.get("anomaly") or {}
        pdf.kv_row("Anomaly Flagged", "YES" if anomaly.get("flagged") else "No", bold_value=anomaly.get("flagged", False))
        if anomaly.get("reason"):
            pdf.kv_row("Anomaly Reason", anomaly["reason"])

    # ── NLP Classification ────────────────────────────────────────────────────
    if classified:
        pdf.section_title("NLP Phishing Classification")
        prob = classified.get("phishing_probability", 0)
        pdf.kv_row("Phishing Probability", f"{prob*100:.1f}%", bold_value=prob >= 0.5)
        pdf.kv_row("Predicted Label", str(classified.get("predicted_label", "—")).upper())
        terms = classified.get("top_indicative_terms", [])
        if terms:
            pdf.kv_row("Top Indicative Terms", ", ".join(terms))

    # ── URL / Attachment Reputation ───────────────────────────────────────────
    if reputation:
        url_checks = reputation.get("url_checks", []) or []
        if url_checks:
            pdf.section_title("URL Reputation Checks")
            pdf.table_row(["URL", "Safe Browsing", "VT Malicious", "VT Total"], [80, 30, 30, 30], header=True)
            for uc in url_checks[:10]:  # cap at 10 rows
                url_display = uc.get("url", "")[:40]
                sb = "YES" if uc.get("safe_browsing_flagged") else "No"
                vt_mal = str(uc.get("virustotal_malicious_count", "—"))
                vt_tot = str(uc.get("virustotal_total_vendors", "—"))
                pdf.table_row([url_display, sb, vt_mal, vt_tot], [80, 30, 30, 30])

        att_checks = reputation.get("attachment_checks", []) or []
        if att_checks:
            pdf.section_title("Attachment Reputation Checks")
            pdf.table_row(["Filename", "Known to VT", "VT Malicious", "VT Total"], [80, 30, 30, 30], header=True)
            for ac in att_checks:
                pdf.table_row([
                    ac.get("filename", "—")[:40],
                    "Yes" if ac.get("known_to_virustotal") else "No",
                    str(ac.get("virustotal_malicious_count", "—")),
                    str(ac.get("virustotal_total_vendors", "—")),
                ], [80, 30, 30, 30])

    pdf.output(output_path)
    return output_path
