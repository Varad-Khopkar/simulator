# report_generator.py
# Report export utilities for H-SAFE Firewall Simulator

import json
import csv
from typing import Dict

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


# =========================
# JSON EXPORT
# =========================

def export_json(report: Dict, output_path: str) -> None:
    """
    Export analysis report as JSON.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)


# =========================
# CSV EXPORT
# =========================

def export_csv(report: Dict, output_path: str) -> None:
    """
    Export key report sections as CSV.
    """
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Overview
        writer.writerow(["SECTION", "KEY", "VALUE"])
        for key, value in report["overview"].items():
            writer.writerow(["OVERVIEW", key, value])

        # Traffic profile
        for proto, count in report["traffic_profile"]["by_protocol"].items():
            writer.writerow(["PROTOCOL", proto, count])

        for lane, count in report["traffic_profile"]["by_lane"].items():
            writer.writerow(["LANE", lane, count])

        # Rule hits
        for rule_id, hits in report["security_findings"]["rule_hit_count"].items():
            writer.writerow(["RULE_HITS", rule_id, hits])

        # Severity distribution
        for sev, count in report["security_findings"]["severity_distribution"].items():
            writer.writerow(["SEVERITY", sev, count])

        # Top targets
        for asset in report["security_findings"]["top_targeted_assets"]:
            writer.writerow(
                ["TOP_TARGET", asset["ip"], asset["hits"]]
            )


# =========================
# PDF EXPORT
# =========================

def export_pdf(report: Dict, output_path: str) -> None:
    """
    Export analysis report as a human-readable PDF.
    """
    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    y = height - 40

    def draw_line(text):
        nonlocal y
        if y < 50:
            c.showPage()
            y = height - 40
        c.drawString(40, y, text)
        y -= 14

    draw_line("H-SAFE Firewall Simulation Report")
    draw_line("=" * 50)
    draw_line("")

    draw_line("Overview:")
    for k, v in report["overview"].items():
        draw_line(f"  {k}: {v}")

    draw_line("")
    draw_line("Traffic Profile:")
    draw_line("  By Protocol:")
    for proto, count in report["traffic_profile"]["by_protocol"].items():
        draw_line(f"    {proto}: {count}")

    draw_line("  By Lane:")
    for lane, count in report["traffic_profile"]["by_lane"].items():
        draw_line(f"    {lane}: {count}")

    draw_line("")
    draw_line("Security Findings:")
    draw_line("  Rule Hit Count:")
    for rule_id, hits in report["security_findings"]["rule_hit_count"].items():
        draw_line(f"    {rule_id}: {hits}")

    draw_line("  Severity Distribution:")
    for sev, count in report["security_findings"]["severity_distribution"].items():
        draw_line(f"    {sev}: {count}")

    draw_line("")
    draw_line("Top Targeted Assets:")
    for asset in report["security_findings"]["top_targeted_assets"]:
        draw_line(f"  {asset['ip']} -> {asset['hits']} hits")

    draw_line("")
    draw_line("Assessment:")
    draw_line(report["assessment"])

    c.save()
