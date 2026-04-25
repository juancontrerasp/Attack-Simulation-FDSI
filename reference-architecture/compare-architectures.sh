#!/bin/bash
# compare-architectures.sh
# Runs the STRIDE agent on both the insecure attack-engine and the secure
# reference architecture, then generates comparison-result.json.
#
# Usage:
#   ./reference-architecture/compare-architectures.sh [--skip-dynamic]
#
# Output:
#   reference-architecture/insecure-threats.json
#   reference-architecture/secure-threats.json
#   reference-architecture/comparison-result.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
AGENT="$PROJECT_ROOT/stride-agent/index.js"

INSECURE_OUT="$SCRIPT_DIR/insecure-threats.json"
SECURE_OUT="$SCRIPT_DIR/secure-threats.json"
RESULT="$SCRIPT_DIR/comparison-result.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"; }
ok()   { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')]${NC} $1"; }
err()  { echo -e "${RED}[$(date '+%H:%M:%S')]${NC} $1"; }

# --- Dependency check ---
if ! command -v node &>/dev/null; then
    err "node is not installed. Install Node.js 18+ and retry."
    exit 1
fi

if [ ! -f "$AGENT" ]; then
    err "STRIDE agent not found at: $AGENT"
    exit 1
fi

echo ""
echo -e "${BOLD}=====================================================${NC}"
echo -e "${BOLD}  Architecture Comparison — STRIDE Agent Analysis    ${NC}"
echo -e "${BOLD}=====================================================${NC}"
echo ""

# --- Phase 1: Analyze insecure architecture ---
log "${BOLD}Phase 1: Analyzing insecure architecture (attack-engine/)${NC}"
node "$AGENT" --repo "$PROJECT_ROOT/attack-engine" --output "$INSECURE_OUT" --no-cache

INSECURE_COUNT=$(node -e "const f=require('$INSECURE_OUT'); console.log(f.counts.total)" 2>/dev/null || echo "?")
ok "Insecure analysis complete — ${INSECURE_COUNT} threats detected"
echo ""

# --- Phase 2: Analyze secure reference architecture ---
log "${BOLD}Phase 2: Analyzing secure reference architecture (reference-architecture/)${NC}"
node "$AGENT" --repo "$SCRIPT_DIR" --output "$SECURE_OUT" --no-cache

SECURE_COUNT=$(node -e "const f=require('$SECURE_OUT'); console.log(f.counts.total)" 2>/dev/null || echo "?")
ok "Secure analysis complete — ${SECURE_COUNT} threats detected"
echo ""

# --- Phase 3: Generate comparison-result.json ---
log "${BOLD}Phase 3: Generating comparison-result.json${NC}"
node "$SCRIPT_DIR/generate-comparison.js" "$INSECURE_OUT" "$SECURE_OUT" "$RESULT"
COMPARE_EXIT=$?

echo ""
echo -e "${BOLD}=====================================================${NC}"
if [ $COMPARE_EXIT -eq 0 ]; then
    ok "${BOLD}PASS: Differentiation ratio >= 2.0 — agent correctly identifies secure vs insecure${NC}"
else
    warn "${BOLD}FAIL: Differentiation ratio < 2.0 — review secure architecture artifacts${NC}"
fi
echo -e "Result saved to: ${BOLD}${RESULT}${NC}"
echo -e "${BOLD}=====================================================${NC}"
echo ""

exit $COMPARE_EXIT
