#!/usr/bin/env bash
# demo.sh - ThreatLens quick demo
# Author: Jude Hilgendorf
#
# Installs ThreatLens in editable mode, runs a scan against
# sample data, and generates HTML report + timeline artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== ThreatLens Demo ==="
echo ""

# ── 1. Install in editable mode ──────────────────────────────────────────────
echo "[1/4] Installing ThreatLens in editable mode ..."
pip install -e "$PROJECT_ROOT" --quiet
echo "      Done."
echo ""

# ── 2. Determine sample data file ────────────────────────────────────────────
SAMPLE_FILE="$PROJECT_ROOT/sample_data/sample_security_log.json"
if [ ! -f "$SAMPLE_FILE" ]; then
    # Fall back to any JSON file in sample_data/
    SAMPLE_FILE="$(find "$PROJECT_ROOT/sample_data" -maxdepth 1 -name '*.json' | head -n1)"
fi

if [ -z "$SAMPLE_FILE" ] || [ ! -f "$SAMPLE_FILE" ]; then
    echo "ERROR: No sample data found in $PROJECT_ROOT/sample_data/"
    exit 1
fi

echo "[2/4] Scanning: $(basename "$SAMPLE_FILE")"
echo "      (verbose output enabled)"
echo ""

# ── 3. Run scan with verbose output ──────────────────────────────────────────
threatlens scan "$SAMPLE_FILE" --verbose

echo ""

# ── 4. Generate HTML report ──────────────────────────────────────────────────
REPORT="$PROJECT_ROOT/demo_report.html"
echo "[3/4] Generating HTML report -> $REPORT"
threatlens scan "$SAMPLE_FILE" \
    --output "$REPORT" \
    --format html \
    --quiet

echo "      Done."
echo ""

# ── 5. Generate timeline ─────────────────────────────────────────────────────
TIMELINE="$PROJECT_ROOT/demo_timeline.html"
echo "[4/4] Generating attack timeline -> $TIMELINE"
threatlens scan "$SAMPLE_FILE" \
    --timeline "$TIMELINE" \
    --quiet

echo "      Done."
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo "=== Demo Complete ==="
echo ""
echo "Artifacts created:"
echo "  Report:   $REPORT"
echo "  Timeline: $TIMELINE"
echo ""
echo "Open them in a browser to explore the results."
