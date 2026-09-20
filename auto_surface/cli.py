from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import analyze, parse_file
from .report import write


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline, lab-only automotive CAN/UDS log analyzer")
    parser.add_argument("--can-log", action="append", required=True, help="Captured CAN log (repeatable; JSONL, CSV, candump, or text)")
    parser.add_argument("--firmware-info", help="Optional local JSON list of product/version metadata")
    parser.add_argument("--kev-feed", help="Optional local CISA KEV JSON catalog for offline CVE matching")
    parser.add_argument("--out", default="runs-auto", help="Output directory")
    args = parser.parse_args()
    records, errors = [], []
    for path in args.can_log:
        parsed, parse_errors = parse_file(path)
        records.extend(parsed); errors.extend(parse_errors)
    analysis = analyze(records)
    cve_matches = []
    if args.firmware_info and args.kev_feed:
        from bounty_surface.cve import load_kev, match_kev
        metadata = json.loads(Path(args.firmware_info).read_text())
        technologies = [{"product": x["product"], "version": x.get("version"), "evidence": x.get("evidence", "local firmware metadata"), "source_url": x.get("source", "local") } for x in metadata]
        cve_matches = match_kev(technologies, load_kev(args.kev_feed, _NullLogger()))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(args.out) / stamp; run_dir.mkdir(parents=True, exist_ok=True)
    write(run_dir, analysis, errors, cve_matches)
    print(f"Done. Review {run_dir / 'report.md'}")


class _NullLogger:
    def info(self, *_args, **_kwargs):
        pass


if __name__ == "__main__":
    main()
