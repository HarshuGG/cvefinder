# Bounty Surface

Local, **non-destructive** reconnaissance for authorized bug-bounty targets. It discovers and organizes attack-surface candidates for human review; it does not exploit, authenticate, brute-force, evade controls, or modify targets.

## What it does

- Refuses hosts and URLs outside the explicit JSON scope, including excluded subdomains.
- Optionally reads passive subdomains from a locally installed `subfinder`.
- Optionally reads passive, archived URLs from a locally installed `gau`.
- Fetches only in-scope seed pages and JavaScript, with a configurable delay.
- Extracts in-scope script URLs, API-like paths, embedded URLs, and query parameters.
- Identifies basic web/API/GraphQL/identity candidates and ranks them for manual review.
- Optionally fingerprints exposed technology/version hints and matches product names against CISA's Known Exploited Vulnerabilities (KEV) catalog.
- Emits a human-readable Markdown report, JSON report, and JSONL activity audit log per run.

## Kali setup

The project runs inside a Kali Linux VM with Python 3.10+. Copy this directory into the VM (shared folder, `scp`, or a Git checkout), then run:

```bash
git clone https://github.com/HarshuGG/cvefinder.git
cd cvefinder
chmod +x install.sh bounty-surface
./install.sh
cp config/scope.example.json config/my-program.json
```

The installer creates a local `.venv`; it does not install system-wide packages. The launcher automatically uses that environment, even when called from another directory.

Edit `config/my-program.json` with the exact program scope. Wildcards are supported only as `*.example.com`. Do not include assets that the program has not authorized.

## Run

```bash
./bounty-surface --scope config/my-program.json --url https://app.example.com
./bounty-surface --scope config/my-program.json --urls-file seeds.txt
./bounty-surface --scope config/my-program.json --url https://app.example.com --passive-subdomains
./bounty-surface --scope config/my-program.json --passive-urls
./bounty-surface --scope config/my-program.json --url https://app.example.com --cve-check
```

Reports are placed under `runs/<UTC timestamp>/`. Open `report.md` first; it is a shortlist for manual, program-authorized testing. `activity.jsonl` records each outbound GET and all scope blocks.

For a file of seeds (one URL per line):

```bash
./bounty-surface --scope config/my-program.json --urls-file seeds.txt
```

## Safety model and limits

Every initial URL, discovered JavaScript URL, and extracted endpoint is checked against the scope file before use. Redirects are never followed; an out-of-scope redirect is logged. The tool uses only GET requests and does not crawl arbitrary links or fuzz parameters. It intentionally has no exploitation, credential testing, stealth, persistence, active vulnerability testing, or destructive capability.

`subfinder` and `gau` are optional and must be installed separately if you select their flags; absent tooling is logged and the remaining run continues. Both integrations are filtered through the same scope file before any URL is fetched.

## CVE awareness

`--cve-check` downloads the current CISA KEV catalog over HTTPS and compares it with technology hints visible in response headers, generator tags, and common public markers. Use `--cve-feed path/to/known_exploited_vulnerabilities.json` to work offline with a previously downloaded catalog. Results are deliberately labeled **candidates**: a product-name match is not proof that the target runs the affected version or is exploitable. The report includes the CVE, evidence URL, observed version (when available), date added to KEV, and a manual-verification warning. No CVE payloads or exploit attempts are sent.

## Safe operating checklist

1. Copy the program's written scope into the JSON file; never use a guessed or third-party domain.
2. Start with one or two known in-scope HTTPS URLs.
3. Review `report.md` and manually validate candidates through the program-approved workflow.
4. Keep `activity.jsonl` with the report so every request and scope decision is auditable.

This is an attack-surface mapper, not an automated vulnerability scanner. It performs bounded GET requests only, does not submit forms, and does not attempt credentials, payloads, bypasses, or exploitation.

## Automotive lab analyzer

The companion `auto-surface` command analyzes **captured** CAN/UDS logs and optional local firmware metadata. It is offline and passive: it never opens a CAN interface and never transmits frames or diagnostic commands. Use only simulator, bench, or explicitly authorized lab data.

Supported inputs include candump text, simple `ID [length] bytes` text, CSV, and JSONL. It reports ECU/arbitration IDs, payload-length changes, recognized UDS service observations, parser warnings, and optional candidate matches from a local KEV catalog.

```bash
./auto-surface --can-log captures/session.log
./auto-surface --can-log captures/session.log --firmware-info firmware.json --kev-feed known_exploited_vulnerabilities.json
```

Example `firmware.json`:

```json
[
  {"product": "Example ECU", "version": "1.2.3", "evidence": "bench firmware manifest"}
]
```

The report is written to `runs-auto/<UTC timestamp>/`. A “sensitive service observed” line is only a review cue; it is not proof of an authorization flaw or unsafe vehicle behavior.

## Verify the install

```bash
PYTHONPATH=. python -m unittest discover -s tests -v
./bounty-surface --help
```
