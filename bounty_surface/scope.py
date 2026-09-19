from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class Scope:
    program: str
    allowed_domains: list[str]
    excluded_domains: list[str]
    allowed_schemes: list[str]
    rate_limit_seconds: float = 0.4

    @classmethod
    def load(cls, path: str) -> "Scope":
        data = json.loads(Path(path).read_text())
        required = ("program", "allowed_domains")
        missing = [key for key in required if not data.get(key)]
        if missing:
            raise ValueError("Scope file missing: " + ", ".join(missing))
        return cls(data["program"], [x.lower() for x in data["allowed_domains"]],
                   [x.lower() for x in data.get("excluded_domains", [])],
                   data.get("allowed_schemes", ["https"]), float(data.get("rate_limit_seconds", 0.4)))

    def allows_host(self, host: str | None) -> bool:
        host = (host or "").split(":")[0].lower().rstrip(".")
        return bool(host) and any(fnmatch(host, x) for x in self.allowed_domains) and not any(fnmatch(host, x) for x in self.excluded_domains)

    def allows_url(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme in self.allowed_schemes and self.allows_host(parsed.hostname)

    def assert_url(self, url: str) -> None:
        if not self.allows_url(url):
            raise ValueError(f"OUT OF SCOPE: {url}")
