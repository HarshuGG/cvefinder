#!/usr/bin/env bash
set -euo pipefail
command -v python3 >/dev/null || { echo "Python 3 is required (install python3)" >&2; exit 1; }
python3 -m venv --help >/dev/null 2>&1 || { echo "The venv module is required (install python3-venv on Kali)" >&2; exit 1; }
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
echo "Installed. Activate with: source .venv/bin/activate"
