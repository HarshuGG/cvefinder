from __future__ import annotations

import json
from pathlib import Path


def write(run_dir: Path, analysis: dict, parse_errors: list[str], cve_matches: list[dict]) -> None:
    data = {"analysis": analysis, "parse_errors": parse_errors, "cve_candidates": cve_matches}
    (run_dir / "report.json").write_text(json.dumps(data, indent=2))
    lines = ["# Automotive security analysis", "", "> Offline analysis only. No CAN, UDS, diagnostic, or vehicle-control frames were transmitted.", "", "## Summary", "", f"- Frames parsed: {analysis['frames']}", f"- ECU/arbitration IDs: {len(analysis['ecu_ids'])}", f"- Review candidates: {len(analysis['anomalies'])}", "", "## ECU / message IDs", "", "| ID | Frames | Lengths | Sample |", "|---|---:|---|---|"]
    lines += [f"| `{x['id']}` | {x['frames']} | {', '.join(f'{k} bytes ({v})' for k, v in x['lengths'].items())} | `{x['sample_data']}` |" for x in analysis["message_stats"]]
    lines += ["", "## Review candidates", ""]
    lines += [f"- `{x['id']}` — {x['type']}: {x['detail']} ({x['confidence']})" for x in analysis["anomalies"]] or ["No parser-level anomalies detected."]
    lines += ["", "## UDS service observations", "", "| ID | Service | Name | Flag |", "|---|---|---|---|"]
    lines += [f"| `{x['id']}` | `{x['service']}` | {x['name']} | {'sensitive service observed — review authorization' if x['sensitive'] else 'observed'} |" for x in analysis["uds_services"]] or ["No recognized UDS service bytes observed."]
    lines += ["", "## CVE candidates", "", "> Matches from firmware metadata and a KEV catalog are candidates only; verify component identity, version, exposure, and safety impact manually.", "", "| CVE | Product | Version | Evidence |", "|---|---|---|---|"]
    lines += [f"| {x.get('cve', '')} | {x.get('detected_product', '')} | {x.get('detected_version') or 'not observed'} | {x.get('evidence', '')} |" for x in cve_matches] or ["No CVE candidates."]
    if parse_errors:
        lines += ["", "## Parse warnings", ""] + [f"- {x}" for x in parse_errors]
    (run_dir / "report.md").write_text("\n".join(lines) + "\n")
