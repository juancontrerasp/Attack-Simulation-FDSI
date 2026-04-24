#!/usr/bin/env python3
"""
create-standalone-dashboard.py (US-07)
Reads combined-report.json and dashboard.html and produces a self-contained
dashboard-standalone.html with all STRIDE data embedded directly in the HTML.
The standalone file can be opened via file:// without a web server.
"""

import json
import sys
from pathlib import Path


def create_standalone_dashboard():
    repo_root = Path(__file__).resolve().parent

    # ── Load data source ──────────────────────────────────────────────────────
    data_file = repo_root / "combined-report.json"
    if not data_file.exists():
        print("❌ Error: combined-report.json not found")
        print("   Run the STRIDE analysis first to generate combined-report.json")
        sys.exit(1)

    print("📊 Reading combined-report.json…")
    with open(data_file, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    # ── Load dashboard template ───────────────────────────────────────────────
    dashboard_file = repo_root / "dashboard.html"
    if not dashboard_file.exists():
        print("❌ Error: dashboard.html not found")
        sys.exit(1)

    print("📄 Reading dashboard.html…")
    with open(dashboard_file, "r", encoding="utf-8") as f:
        dashboard_content = f.read()

    # ── Embed data ────────────────────────────────────────────────────────────
    data_js = json.dumps(report_data, ensure_ascii=False, separators=(",", ":"))

    # Replace the fetch call with embedded data so the file works via file://
    fetch_pattern = "fetch('combined-report.json?' + Date.now())"
    embedded = (
        "Promise.resolve({"
        "ok: true, "
        "json: function() { return Promise.resolve(" + data_js + "); }"
        "})"
    )

    if fetch_pattern not in dashboard_content:
        print("⚠️  Warning: fetch pattern not found in dashboard.html – the standalone")
        print("   file may not work correctly. Check dashboard.html for fetch() calls.")

    standalone = dashboard_content.replace(fetch_pattern, embedded)

    # ── Write output ──────────────────────────────────────────────────────────
    output_file = repo_root / "dashboard-standalone.html"
    print(f"💾 Writing {output_file.name}…")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(standalone)

    print()
    print("✅ Standalone dashboard created!")
    print()
    print(f"📊 File : {output_file}")
    print()
    print("🌐 Open in browser:")
    print(f"   file://{output_file}")
    print()
    print("💡 The data is embedded – no web server required.")

    # ── Summary ───────────────────────────────────────────────────────────────
    threats = report_data.get("combined_threats", [])
    if threats:
        print()
        print("📈 Threat Summary:")
        alta  = sum(1 for t in threats if t.get("severity") == "Alta")
        media = sum(1 for t in threats if t.get("severity") == "Media")
        baja  = sum(1 for t in threats if t.get("severity") == "Baja")
        conf  = sum(1 for t in threats if t.get("confirmed") is True)
        cats  = len({t.get("category") for t in threats})
        print(f"   Total threats : {len(threats)}")
        print(f"   Alta          : {alta}")
        print(f"   Media         : {media}")
        print(f"   Baja          : {baja}")
        print(f"   Confirmed     : {conf}")
        print(f"   Categories    : {cats}")


if __name__ == "__main__":
    try:
        create_standalone_dashboard()
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
