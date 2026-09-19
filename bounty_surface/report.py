from __future__ import annotations
import json
from pathlib import Path
from .recon import classify, priority

def write(run_dir: Path, scope, records: list[dict], endpoints: set[str], cve_matches: list[dict] | None = None) -> None:
    cve_matches = cve_matches or []
    rows = [{"url": u, "classification": classify(u), "priority": priority(u)} for u in endpoints]
    rows.sort(key=lambda x: (-x["priority"], x["url"]))
    data = {"program": scope.program, "scope": scope.allowed_domains, "urls_inspected": records,
            "manual_review_candidates": rows, "cve_candidates": cve_matches}
    (run_dir / "report.json").write_text(json.dumps(data, indent=2))
    lines = [f"# Recon report: {scope.program}", "", "## Manual-review candidates", "", "| Priority | Type | URL |", "|---:|---|---|"]
    lines += [f"| {r['priority']} | {r['classification']} | {r['url']} |" for r in rows]
    lines += ["", "## CVE candidates (manual verification required)", "",
              "> These are technology/name matches against CISA KEV, not proof of vulnerability. Confirm the exact version, configuration, exposure, and program policy manually.", "",
              "| CVE | Detected product | Version | Source URL | Confidence |", "|---|---|---|---|---|"]
    lines += [f"| {r.get('cve','')} | {r.get('detected_product','')} | {r.get('detected_version') or 'not observed'} | {r.get('source_url','')} | {r.get('confidence','')} |" for r in cve_matches]
    (run_dir / "report.md").write_text("\n".join(lines) + "\n")
