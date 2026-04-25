#!/usr/bin/env python3
"""
create-standalone-dashboard.py (US-07)
Generates dashboard-standalone.html with:
- combined-report.json embedded inline
- Chart.js embedded inline for full offline support
- hard size limit: < 2MB
"""

import json
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen


MAX_SIZE_BYTES = 2 * 1024 * 1024
CHART_JS_CDN = "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
ACTIONS_API = "https://api.github.com/repos/juancontrerasp/Attack-Simulation-FDSI/actions/runs?per_page=1"


def fetch_chartjs_inline():
    with urlopen(CHART_JS_CDN, timeout=15) as response:
        return response.read().decode("utf-8")


def fetch_latest_pipeline():
    request = Request(
        ACTIONS_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "Attack-Simulation-FDSI-Standalone-Generator"
        }
    )
    with urlopen(request, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))

    runs = payload.get("workflow_runs", [])
    if not runs:
        return None

    run = runs[0]
    return {
        "conclusion": run.get("conclusion") or "unknown",
        "status": run.get("status") or "unknown",
        "html_url": run.get("html_url") or "https://github.com/juancontrerasp/Attack-Simulation-FDSI/actions",
        "run_number": run.get("run_number"),
        "updated_at": run.get("updated_at")
    }


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

    # ── Load baseline for offline CI panel ───────────────────────────────────
    baseline_file = repo_root / "security" / "baseline.json"
    baseline_data = []
    if baseline_file.exists():
        with open(baseline_file, "r", encoding="utf-8") as bf:
            loaded_baseline = json.load(bf)
            if isinstance(loaded_baseline, list):
                baseline_data = loaded_baseline
            elif isinstance(loaded_baseline, dict):
                baseline_data = loaded_baseline.get("approved_threats", [])

    # ── Fetch latest pipeline metadata (best effort) ─────────────────────────
    pipeline_data = None
    try:
        pipeline_data = fetch_latest_pipeline()
    except Exception:
        pipeline_data = None

    # ── Embed report data ─────────────────────────────────────────────────────
    data_js = json.dumps(report_data, ensure_ascii=False, separators=(",", ":"))
    baseline_js = json.dumps(baseline_data, ensure_ascii=False, separators=(",", ":"))
    pipeline_js = json.dumps(pipeline_data, ensure_ascii=False, separators=(",", ":"))

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

    embedded_vars_script = (
        "<script>"
        f"window.__EMBEDDED_BASELINE__={baseline_js};"
        f"window.__EMBEDDED_PIPELINE__={pipeline_js};"
        "</script>"
    )
    standalone = standalone.replace("</head>", embedded_vars_script + "\n</head>", 1)

    # ── Embed Chart.js inline for offline support ─────────────────────────────
    print("📦 Embedding Chart.js inline…")
    chart_js = fetch_chartjs_inline()
    script_tag_pattern = r'<script\s+src="https://cdn\.jsdelivr\.net/npm/chart\.js@4\.4\.0/dist/chart\.umd\.min\.js"></script>'
    inline_script = f"<script>{chart_js}</script>"
    standalone = re.sub(script_tag_pattern, lambda _: inline_script, standalone, count=1)

    # ── Write output ──────────────────────────────────────────────────────────
    output_file = repo_root / "dashboard-standalone.html"
    print(f"💾 Writing {output_file.name}…")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(standalone)

    # ── Enforce size limit (<2MB) ─────────────────────────────────────────────
    size_bytes = output_file.stat().st_size
    size_kb = size_bytes / 1024.0
    if size_bytes >= MAX_SIZE_BYTES:
        print(f"❌ Error: standalone size is {size_kb:.1f} KB and must be < 2048 KB")
        sys.exit(1)

    print()
    print("✅ Standalone dashboard created!")
    print()
    print(f"📊 File : {output_file}")
    print()
    print("🌐 Open in browser:")
    print(f"   file://{output_file}")
    print()
    print("💡 Data + Chart.js are embedded – no web server and no internet required.")
    print(f"📏 Size: {size_kb:.1f} KB (< 2048 KB)")

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
