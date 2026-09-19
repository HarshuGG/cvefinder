from __future__ import annotations

import time
import requests
from .scope import Scope
from .logging_setup import event


class SafeHttp:
    def __init__(self, scope: Scope, logger): self.scope, self.logger = scope, logger
    def get(self, url: str, **kwargs):
        self.scope.assert_url(url)
        event(self.logger, "request", url=url, method="GET")
        time.sleep(self.scope.rate_limit_seconds)
        response = requests.get(url, timeout=12, allow_redirects=False, headers={"User-Agent": "BountySurface/0.1 authorized-recon"}, **kwargs)
        location = response.headers.get("Location")
        if location and location.startswith(("http://", "https://")) and not self.scope.allows_url(location):
            event(self.logger, "out_of_scope_redirect_blocked", source=url, destination=location)
        return response
