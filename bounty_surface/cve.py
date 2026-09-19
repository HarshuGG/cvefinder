"""Technology fingerprinting and non-exploitative CISA KEV matching."""
from __future__ import annotations

import json
import re
from pathlib import Path

import requests

from .logging_setup import event

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fingerprint_response(url: str, headers, body: str) -> list[dict]:
    """Return evidence-backed product/version hints; never claims a vulnerability."""
    text = f"{headers.get('server', '')} {headers.get('x-powered-by', '')} {body[:500000]}"
    findings: list[dict] = []

    def add(product: str, version: str | None, evidence: str) -> None:
        key = (product.lower(), version or "")
        if any((x["product"].lower(), x.get("version") or "") == key for x in findings):
            return
        findings.append({"product": product, "version": version, "evidence": evidence, "source_url": url})

    rules = [
        (r"(?:Apache(?:/|\s+HTTP\s+Server\s+))([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "Apache HTTP Server"),
        (r"nginx/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "nginx"),
        (r"PHP/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "PHP"),
    ]
    for rule in rules[:3]:
        match = re.search(rule[0], text, re.I)
        if match:
            add(rule[1], match.group(1), f"response/header pattern: {match.group(0)[:120]}")
    if re.search(r"(?:WordPress|/wp-content/|/wp-includes/)", text, re.I):
        add("WordPress", None, "WordPress marker in response")
    if re.search(r"(?:Drupal\.settings|/sites/default/files/)", text, re.I):
        add("Drupal", None, "Drupal marker in response")
    if re.search(r"(?:Joomla!|/media/system/js/)", text, re.I):
        add("Joomla", None, "Joomla marker in response")
    meta = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if meta:
        value = meta.group(1).strip()
        version = re.search(r"(\d+(?:\.\d+){1,3})", value)
        add(value.split()[0], version.group(1) if version else None, f"generator meta tag: {value[:120]}")
    return findings


def load_kev(path: str | None, logger) -> list[dict]:
    try:
        if path:
            payload = json.loads(Path(path).read_text())
        else:
            response = requests.get(CISA_KEV_URL, timeout=20, headers={"User-Agent": "BountySurface/0.1 authorized-recon"})
            response.raise_for_status()
            payload = response.json()
        entries = payload.get("vulnerabilities", [])
        event(logger, "cve_feed_loaded", feed="CISA KEV", count=len(entries), source="local" if path else CISA_KEV_URL)
        return entries
    except Exception as exc:
        event(logger, "cve_feed_error", feed="CISA KEV", error=str(exc))
        return []


def match_kev(technologies: list[dict], entries: list[dict]) -> list[dict]:
    """Match product names conservatively; results are candidates for manual verification."""
    aliases = {
        "apache http server": ("apache", "http server"),
        "nginx": ("nginx",),
        "php": ("php",),
        "wordpress": ("wordpress",),
        "drupal": ("drupal",),
        "joomla": ("joomla",),
    }
    matches: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for tech in technologies:
        product = tech["product"].lower()
        needles = aliases.get(product, (product,))
        for item in entries:
            haystack = f"{item.get('vendorProject', '')} {item.get('product', '')}".lower()
            if not all(token in haystack for token in needles):
                continue
            key = (item.get("cveID", ""), product, tech.get("source_url", ""))
            if key in seen:
                continue
            seen.add(key)
            matches.append({
                "cve": item.get("cveID"),
                "product": item.get("product") or item.get("vendorProject"),
                "vendor": item.get("vendorProject"),
                "detected_product": tech["product"],
                "detected_version": tech.get("version"),
                "evidence": tech.get("evidence"),
                "source_url": tech.get("source_url"),
                "date_added": item.get("dateAdded"),
                "ransomware_use": item.get("knownRansomwareCampaignUse"),
                "description": item.get("shortDescription"),
                "required_action": item.get("requiredAction"),
                "confidence": "candidate — verify exact version and exposure manually",
            })
    return matches
