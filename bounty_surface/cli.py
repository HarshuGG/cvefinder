from __future__ import annotations
import argparse
from datetime import datetime, timezone
from pathlib import Path
from .scope import Scope
from .logging_setup import setup, event
from .http import SafeHttp
from .recon import external_subdomains, external_urls, inspect_url, inspect_js
from .report import write
from .cve import load_kev, match_kev

def main() -> None:
    p = argparse.ArgumentParser(description="Authorized, non-destructive attack-surface assistant")
    p.add_argument("--scope", required=True, help="JSON scope file")
    p.add_argument("--url", action="append", default=[], help="In-scope seed URL; repeatable")
    p.add_argument("--urls-file", help="File containing seed URLs")
    p.add_argument("--out", default="runs", help="Output directory")
    p.add_argument("--passive-subdomains", action="store_true", help="Use optional installed subfinder")
    p.add_argument("--passive-urls", action="store_true", help="Use optional installed gau (passive URL archive)")
    p.add_argument("--cve-check", action="store_true", help="Match detected technologies against CISA's Known Exploited Vulnerabilities catalog")
    p.add_argument("--cve-feed", help="Local CISA KEV JSON file (offline alternative to the remote feed)")
    args = p.parse_args(); scope = Scope.load(args.scope)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(args.out) / stamp; run_dir.mkdir(parents=True)
    logger = setup(run_dir); event(logger, "run_started", program=scope.program)
    seeds = set(args.url)
    if args.urls_file: seeds |= {x.strip() for x in Path(args.urls_file).read_text().splitlines() if x.strip()}
    rejected = [u for u in seeds if not scope.allows_url(u)]
    if rejected: raise SystemExit("Refusing out-of-scope seed(s): " + ", ".join(rejected))
    if args.passive_subdomains:
        for host in external_subdomains(scope, logger): seeds.add("https://" + host)
    if args.passive_urls:
        seeds |= external_urls(scope, logger)
    if not seeds: raise SystemExit("Provide at least one in-scope --url or --urls-file.")
    client = SafeHttp(scope, logger); records=[]; endpoints=set()
    for url in sorted(seeds):
        try:
            record=inspect_url(url, client, scope, logger); records.append(record); endpoints.update(record["endpoints"])
            for js in record["js"]:
                try: endpoints.update(inspect_js(js, client, scope, logger))
                except Exception as exc: event(logger, "javascript_error", url=js, error=str(exc))
        except Exception as exc: event(logger, "url_error", url=url, error=str(exc))
    cve_matches = []
    if args.cve_check:
        technologies = [tech for record in records for tech in record.get("technologies", [])]
        cve_matches = match_kev(technologies, load_kev(args.cve_feed, logger))
        event(logger, "cve_matching_complete", technologies=len(technologies), matches=len(cve_matches))
    write(run_dir, scope, records, endpoints, cve_matches)
    event(logger, "run_finished", candidates=len(endpoints), cve_matches=len(cve_matches))
    print(f"Done. Review {run_dir / 'report.md'}")

if __name__ == "__main__": main()
