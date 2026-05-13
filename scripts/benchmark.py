"""Benchmark ThreatLens parse + detection throughput across corpus sizes.

Usage:
    python scripts/benchmark.py [--sizes 10000 100000 1000000] [--out bench.md]

Generates synthetic corpora at the requested sizes, scans each one, and
reports parse time, detection time, and overall events-per-second. The
generated files are written to a temporary directory and cleaned up
afterward unless --keep is passed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _generate(size: int, target: Path) -> None:
    """Invoke the existing sample generator to produce a corpus of the given size."""
    cmd = [
        sys.executable,
        str(Path(__file__).parent / "generate_sample_data.py"),
        "--events",
        str(size),
        "--attack-chains",
        str(max(3, size // 5000)),
        "-o",
        str(target),
    ]
    subprocess.run(cmd, check=True, capture_output=True)


def _scan(target: Path) -> dict:
    """Run threatlens scan with --profile and parse the timing breakdown."""
    cmd = [
        sys.executable,
        "-m",
        "threatlens.cli",
        "scan",
        str(target),
        "--quiet",
        "--no-color",
        "--summary-only",
        "--profile",
    ]
    t0 = time.time()
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    wall = time.time() - t0

    parse_time = detect_time = total_time = 0.0
    alerts = 0
    events = 0
    for line in proc.stdout.splitlines():
        s = line.strip()
        if s.startswith("Parsing:"):
            parse_time = float(s.split(":", 1)[1].strip().rstrip("s"))
        elif s.startswith("Detection:") and "s" in s:
            detect_time = float(s.split(":", 1)[1].strip().rstrip("s"))
        elif s.startswith("Total:") and "s" in s:
            total_time = float(s.split(":", 1)[1].strip().rstrip("s"))
        elif s.startswith("Events analyzed:"):
            events = int(s.split(":", 1)[1].strip().replace(",", ""))
        elif s.startswith("Alerts generated:"):
            alerts = int(s.split(":", 1)[1].strip())

    return {
        "events": events,
        "alerts": alerts,
        "parse_time": parse_time,
        "detect_time": detect_time,
        "total_time": total_time or wall,
        "wall_time": wall,
    }


def _fmt_rate(events: int, seconds: float) -> str:
    if seconds <= 0:
        return "n/a"
    rate = events / seconds
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.2f} M/s"
    if rate >= 1_000:
        return f"{rate / 1_000:.1f} k/s"
    return f"{rate:.0f} /s"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes",
        type=int,
        nargs="+",
        default=[10_000, 100_000, 1_000_000],
        help="Corpus sizes to benchmark (default: 10k, 100k, 1M)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional markdown output file (default: stdout)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Keep generated corpora after the run for inspection",
    )
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="threatlens_bench_"))
    print(f"[bench] working in {work}", file=sys.stderr)

    rows = []
    try:
        for size in args.sizes:
            corpus = work / f"corpus_{size}.json"
            print(f"[bench] generating {size:,} events", file=sys.stderr)
            _generate(size, corpus)

            print(f"[bench] scanning {size:,} events", file=sys.stderr)
            result = _scan(corpus)
            result["size"] = size
            result["file_size_mb"] = corpus.stat().st_size / 1_048_576
            rows.append(result)
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    lines = []
    lines.append("# ThreatLens benchmark\n")
    lines.append(
        "| Events | File size | Parse | Detect | Total | Throughput | Alerts |\n"
        "|--------|-----------|-------|--------|-------|------------|--------|"
    )
    for r in rows:
        lines.append(
            f"| {r['events']:>7,} | {r['file_size_mb']:>5.1f} MB "
            f"| {r['parse_time']:>5.2f}s | {r['detect_time']:>5.2f}s "
            f"| {r['total_time']:>5.2f}s | {_fmt_rate(r['events'], r['total_time'])} "
            f"| {r['alerts']} |"
        )
    report = "\n".join(lines) + "\n"

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"[bench] wrote {args.out}", file=sys.stderr)
    print(report)

    raw_path = (args.out.with_suffix(".json") if args.out
                else None)
    if raw_path:
        raw_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"[bench] wrote raw data to {raw_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
