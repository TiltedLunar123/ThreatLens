# demo.ps1 - ThreatLens quick demo
# Author: Jude Hilgendorf
#
# Installs ThreatLens in editable mode, runs a scan against
# sample data, and generates HTML report + timeline artifacts.

$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "=== ThreatLens Demo ===" -ForegroundColor Cyan
Write-Host ""

# -- 1. Install in editable mode ----------------------------------------------
Write-Host "[1/4] Installing ThreatLens in editable mode ..."
pip install -e $ProjectRoot --quiet
Write-Host "      Done."
Write-Host ""

# -- 2. Determine sample data file --------------------------------------------
$SampleFile = Join-Path $ProjectRoot "sample_data\sample_security_log.json"
if (-not (Test-Path $SampleFile)) {
    $SampleFile = Get-ChildItem -Path (Join-Path $ProjectRoot "sample_data") `
        -Filter "*.json" -File | Select-Object -First 1 -ExpandProperty FullName
}

if (-not $SampleFile -or -not (Test-Path $SampleFile)) {
    Write-Error "No sample data found in $ProjectRoot\sample_data\"
    exit 1
}

Write-Host "[2/4] Scanning: $(Split-Path -Leaf $SampleFile)"
Write-Host "      (verbose output enabled)"
Write-Host ""

# -- 3. Run scan with verbose output ------------------------------------------
threatlens scan $SampleFile --verbose

Write-Host ""

# -- 4. Generate HTML report ---------------------------------------------------
$Report = Join-Path $ProjectRoot "demo_report.html"
Write-Host "[3/4] Generating HTML report -> $Report"
threatlens scan $SampleFile `
    --output $Report `
    --format html `
    --quiet

Write-Host "      Done."
Write-Host ""

# -- 5. Generate timeline -----------------------------------------------------
$Timeline = Join-Path $ProjectRoot "demo_timeline.html"
Write-Host "[4/4] Generating attack timeline -> $Timeline"
threatlens scan $SampleFile `
    --timeline $Timeline `
    --quiet

Write-Host "      Done."
Write-Host ""

# -- Summary -------------------------------------------------------------------
Write-Host "=== Demo Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Artifacts created:"
Write-Host "  Report:   $Report"
Write-Host "  Timeline: $Timeline"
Write-Host ""
Write-Host "Open them in a browser to explore the results."
