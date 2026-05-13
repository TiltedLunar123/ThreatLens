"""Run ThreatLens against the EVTX-ATTACK-SAMPLES corpus and emit a markdown report.

Usage:
    python scripts/evaluate_evtx_attack_samples.py \
        --corpus /path/to/EVTX-ATTACK-SAMPLES \
        --output docs/evaluation_results.md

EVTX-ATTACK-SAMPLES is a community corpus of real Windows event logs that
demonstrate adversary techniques. Each .evtx file is named after the MITRE
technique it exercises. This script walks the corpus, runs `threatlens scan`
on every file, and groups the resulting alerts by technique directory so the
output is directly comparable to public detection-rate write-ups for other
tools (Hayabusa, Chainsaw, Zircolite).

The corpus is not vendored in this repo. Clone it locally:

    git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path


def _run_one(evtx_path: Path, sigma_rules: Path | None) -> dict:
    """Run threatlens against a single .evtx file and parse the JSON output."""
    cmd = [
        sys.executable,
        "-m",
        "threatlens.cli",
        "scan",
        str(evtx_path),
        "--quiet",
        "--no-color",
        "--min-severity",
        "low",
        "-o",
        "-",
        "-f",
        "json",
    ]
    if sigma_rules:
        cmd.extend(["--sigma-rules", str(sigma_rules)])

    t0 = time.time()
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    elapsed = time.time() - t0

    if proc.returncode not in (0, 2):
        return {
            "file": str(evtx_path),
            "error": proc.stderr.strip()[:300],
            "elapsed": elapsed,
            "alerts": [],
        }

    report_marker = "  Report saved to -"
    if report_marker in proc.stdout:
        json_part = proc.stdout.split(report_marker, 1)[0]
    else:
        json_part = proc.stdout

    try:
        report = json.loads(json_part.strip())
    except json.JSONDecodeError:
        return {
            "file": str(evtx_path),
            "error": "could not parse threatlens JSON output",
            "elapsed": elapsed,
            "alerts": [],
        }

    return {
        "file": str(evtx_path),
        "elapsed": elapsed,
        "alerts": report.get("alerts", []),
        "events_analyzed": report.get("total_events", 0),
    }


def _technique_from_path(path: Path, corpus_root: Path) -> str:
    """Pull the MITRE technique name from the EVTX-ATTACK-SAMPLES directory layout."""
    rel = path.relative_to(corpus_root)
    parts = rel.parts
    if len(parts) >= 2:
        return parts[0]
    return "uncategorized"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="Path to a checkout of EVTX-ATTACK-SAMPLES",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/evaluation_results.md"),
        help="Output markdown path (default: docs/evaluation_results.md)",
    )
    parser.add_argument(
        "--sigma-rules",
        type=Path,
        default=Path("rules/sigma_starter"),
        help="Sigma rule directory to load (default: bundled starter pack)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit the number of files scanned (0 = scan everything)",
    )
    args = parser.parse_args()

    if not args.corpus.exists():
        print(f"Corpus not found: {args.corpus}", file=sys.stderr)
        return 1

    evtx_files = sorted(args.corpus.rglob("*.evtx"))
    if args.limit:
        evtx_files = evtx_files[: args.limit]

    print(f"Found {len(evtx_files)} EVTX files under {args.corpus}", file=sys.stderr)

    by_technique: dict[str, list[dict]] = defaultdict(list)
    total_alerts = 0
    total_events = 0
    total_elapsed = 0.0
    errored = 0

    for i, evtx in enumerate(evtx_files, 1):
        result = _run_one(evtx, args.sigma_rules)
        technique = _technique_from_path(evtx, args.corpus)
        by_technique[technique].append(result)
        if "error" in result:
            errored += 1
        else:
            total_alerts += len(result["alerts"])
            total_events += result.get("events_analyzed", 0)
        total_elapsed += result["elapsed"]
        if i % 25 == 0:
            print(
                f"  scanned {i}/{len(evtx_files)} files, "
                f"{total_alerts} alerts so far",
                file=sys.stderr,
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("# ThreatLens vs EVTX-ATTACK-SAMPLES\n\n")
        f.write(f"Files scanned: {len(evtx_files)}  \n")
        f.write(f"Files with at least one alert: "
                f"{sum(1 for r in (x for xs in by_technique.values() for x in xs) if r.get('alerts'))}  \n")
        f.write(f"Total alerts: {total_alerts}  \n")
        f.write(f"Total events analyzed: {total_events:,}  \n")
        f.write(f"Errored files: {errored}  \n")
        f.write(f"Total wall time: {total_elapsed:.1f}s\n\n")

        f.write("## Detection rate by technique directory\n\n")
        f.write("| Technique | Files | Files with alerts | Detection rate | Total alerts |\n")
        f.write("|-----------|-------|-------------------|----------------|--------------|\n")
        for technique in sorted(by_technique):
            results = by_technique[technique]
            files = len(results)
            with_alerts = sum(1 for r in results if r.get("alerts"))
            total = sum(len(r.get("alerts", [])) for r in results)
            rate = f"{(with_alerts / files * 100):.0f}%" if files else "n/a"
            f.write(f"| {technique} | {files} | {with_alerts} | {rate} | {total} |\n")

    print(f"Wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
