from __future__ import annotations

import re, shutil, subprocess
from urllib.parse import urljoin, urlparse, parse_qs
from .logging_setup import event
from .cve import fingerprint_response

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")
PATH_RE = re.compile(r"[\"'](/(?:api|v\d|graphql|rest|oauth|auth)[^\"'\s]*)[\"']", re.I)
# Deliberately conservative: these are hints for manual review, not fuzzing input.
PARAM_RE = re.compile(r"(?:[?&]|\b(?:params?|query|searchParams)\s*[:=(])\s*([A-Za-z][A-Za-z0-9_.-]{1,64})")

def external_subdomains(scope, logger) -> set[str]:
    """Uses subfinder if installed; it is an optional passive integration."""
    root = next((x[2:] for x in scope.allowed_domains if x.startswith("*.")), None)
    if not root or not shutil.which("subfinder"):
        event(logger, "integration_skipped", integration="subfinder")
        return set()
    result = subprocess.run(["subfinder", "-d", root, "-silent"], text=True, capture_output=True, timeout=120, check=False)
    hosts = {x.strip().lower() for x in result.stdout.splitlines() if scope.allows_host(x.strip())}
    event(logger, "integration_complete", integration="subfinder", count=len(hosts))
    return hosts

def external_urls(scope, logger) -> set[str]:
    """Optionally import passive URLs from gau, filtering every result by scope."""
    if not shutil.which("gau"):
        event(logger, "integration_skipped", integration="gau")
        return set()
    roots = [x[2:] for x in scope.allowed_domains if x.startswith("*.")]
    roots += [x for x in scope.allowed_domains if not x.startswith("*.")]
    urls: set[str] = set()
    for root in sorted(set(roots)):
        result = subprocess.run(["gau", "--subs", root], text=True, capture_output=True, timeout=120, check=False)
        urls.update(x.strip() for x in result.stdout.splitlines() if scope.allows_url(x.strip()))
    limited = set(sorted(urls)[:500])
    event(logger, "integration_complete", integration="gau", count=len(limited), truncated=len(urls) > len(limited))
    return limited

def inspect_url(url, client, scope, logger) -> dict:
    response = client.get(url)
    item = {"url": url, "status": response.status_code, "content_type": response.headers.get("content-type", ""),
            "server": response.headers.get("server", ""), "title": "", "js": [], "endpoints": [], "parameters": sorted(parse_qs(urlparse(url).query)),
            "technologies": fingerprint_response(url, response.headers, "")}
    if "text" not in item["content_type"] and "json" not in item["content_type"]: return item
    body = response.text[:1_000_000]
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    item["title"] = re.sub(r"\s+", " ", title.group(1)).strip()[:200] if title else ""
    js_urls = {urljoin(url, x) for x in re.findall(r"<script[^>]+src=[\"']([^\"']+)", body, re.I)}
    item["js"] = sorted(x for x in js_urls if scope.allows_url(x))
    found = {x.rstrip(".,;)") for x in URL_RE.findall(body) if scope.allows_url(x.rstrip(".,;)"))}
    found |= {urljoin(url, p) for p in PATH_RE.findall(body)}
    item["endpoints"] = sorted(x for x in found if scope.allows_url(x))[:500]
    item["parameters"] = sorted(set(item["parameters"]) | set(PARAM_RE.findall(body)))[:200]
    item["technologies"] = fingerprint_response(url, response.headers, body)
    event(logger, "url_inspected", url=url, status=response.status_code, endpoints=len(item["endpoints"]))
    return item

def inspect_js(url, client, scope, logger) -> set[str]:
    response = client.get(url)
    if response.status_code >= 400: return set()
    content = response.text[:2_000_000]
    urls = {x.rstrip(".,;)") for x in URL_RE.findall(content)}
    urls |= {urljoin(url, p) for p in PATH_RE.findall(content)}
    output = {x for x in urls if scope.allows_url(x)}
    event(logger, "javascript_inspected", url=url, endpoints=len(output))
    return output

def classify(url: str) -> str:
    path = urlparse(url).path.lower()
    if "graphql" in path: return "graphql"
    if re.search(r"/(api|v\d+|rest)(/|$)", path): return "api"
    if any(x in path for x in ("oauth", "login", "auth", "sso")): return "identity"
    return "web"

def priority(url: str) -> int:
    path, params = urlparse(url).path.lower(), parse_qs(urlparse(url).query)
    score = 0
    if params: score += 3
    if classify(url) in ("api", "graphql", "identity"): score += 4
    if any(x in path for x in ("admin", "upload", "export", "redirect", "callback", "webhook")): score += 3
    return score
