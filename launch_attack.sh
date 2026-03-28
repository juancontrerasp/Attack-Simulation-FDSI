#!/bin/bash

# Attack Simulation Launcher
# Usage: ./launch_attack.sh [target_url]

TARGET=${1:-http://localhost:8080}

echo "🛡️ Attack Simulation Tool"
echo "========================="
echo "Target: $TARGET"
echo ""

# Check if we're in the right directory
if [ ! -d "attack-engine" ]; then
    echo "❌ Error: attack-engine directory not found"
    echo "Please run this script from the Attack-Simulation-FDSI root directory"
    exit 1
fi

# Compile if needed
if [ ! -d "out" ] || [ ! -f "out/AttackEngine.class" ]; then
    echo "🔨 Compiling attack engine..."
    cd attack-engine
    mkdir -p ../out
    javac -d ../out AttackEngine.java attacks/*.java model/*.java util/*.java
    if [ $? -ne 0 ]; then
        echo "❌ Compilation failed"
        exit 1
    fi
    cd ..
    echo "✅ Compilation successful"
    echo ""
fi

# Update target in AttackEngine if custom URL provided
if [ "$TARGET" != "http://localhost:8080" ]; then
    echo "📝 Using custom target: $TARGET"
    # Note: This requires modifying the source or passing as argument
    # For now, remind user to update AttackEngine.java manually
    echo "⚠️  Remember to update the target URL in attack-engine/AttackEngine.java"
    echo ""
fi

# Run attack simulation
echo "🚀 Launching attack simulation..."
echo ""
java -cp out AttackEngine

# Check results
if [ -f "results.json" ]; then
    echo ""
    echo "✅ Attack simulation complete!"
    echo ""
    echo "📊 Results saved to:"
    echo "   - results.json (detailed results)"
    echo "   - dashboard.html (interactive view)"
    echo ""
    echo "To view the dashboard:"
    echo "   ./launch_dashboard.sh"
    echo ""
    
    # Quick summary
    VULN_COUNT=$(grep -c '"vulnerable": *true' results.json 2>/dev/null || echo "0")
    if [ "$VULN_COUNT" -gt 0 ]; then
        echo "⚠️  Warning: $VULN_COUNT vulnerabilities detected!"
    else
        echo "✅ No vulnerabilities detected"
    fi
else
    echo "❌ Error: results.json not found"
    exit 1
fi
