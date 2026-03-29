#!/usr/bin/env python3
"""
Create a self-contained dashboard with embedded results data.
This solves CORS issues when opening the dashboard directly in a browser.
"""

import json
import sys
from pathlib import Path

def create_standalone_dashboard():
    """Create a standalone version of the dashboard with embedded data."""
    
    # Check if results.json exists
    results_file = Path('results.json')
    if not results_file.exists():
        print("❌ Error: results.json not found")
        print("   Run the attack simulation first to generate results")
        sys.exit(1)
    
    # Check if dashboard.html exists
    dashboard_file = Path('dashboard.html')
    if not dashboard_file.exists():
        print("❌ Error: dashboard.html not found")
        print("   Make sure you're in the Attack-Simulation-FDSI directory")
        sys.exit(1)
    
    # Read the results
    print("📊 Reading results.json...")
    with open('results.json', 'r') as f:
        results_data = json.load(f)
    
    # Read the dashboard template
    print("📄 Reading dashboard.html...")
    with open('dashboard.html', 'r') as f:
        dashboard_content = f.read()
    
    # Convert results to JavaScript object
    results_js = json.dumps(results_data)
    
    # Replace the fetch call with embedded data
    fetch_pattern = "fetch('results.json?' + Date.now())"
    embedded_data = f"Promise.resolve({{ok: true, json: () => Promise.resolve({results_js})}})"
    
    if fetch_pattern not in dashboard_content:
        print("⚠️  Warning: Could not find fetch pattern in dashboard.html")
        print("   The dashboard may have been modified")
    
    dashboard_standalone = dashboard_content.replace(fetch_pattern, embedded_data)
    
    # Write the standalone version
    output_file = Path('dashboard-standalone.html')
    print(f"💾 Writing {output_file}...")
    with open(output_file, 'w') as f:
        f.write(dashboard_standalone)
    
    print()
    print("✅ Created self-contained dashboard!")
    print()
    print(f"📊 File: {output_file.absolute()}")
    print()
    print("🌐 You can now open this file directly in your browser:")
    print(f"   file://{output_file.absolute()}")
    print()
    print("💡 Tip: This version works without a web server")
    print("   The data is embedded directly in the HTML file")
    
    # Show summary
    systems = results_data.get('systems', [])
    if systems:
        print()
        print("📈 Results Summary:")
        for system in systems:
            attacks = system.get('attacks', [])
            vulnerable = sum(1 for a in attacks if a.get('vulnerable', False))
            total = len(attacks)
            status = "❌ VULNERABLE" if vulnerable > 0 else "✅ SECURE"
            print(f"   {system.get('name', 'Unknown')}: {vulnerable}/{total} attacks succeeded {status}")

if __name__ == '__main__':
    try:
        create_standalone_dashboard()
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
