from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path


def setup(run_dir: Path) -> logging.Logger:
    logger = logging.getLogger("bounty_surface")
    logger.handlers.clear(); logger.setLevel(logging.INFO)
    handler = logging.FileHandler(run_dir / "activity.jsonl")
    handler.setFormatter(logging.Formatter("%(message)s")); logger.addHandler(handler)
    return logger


def event(logger: logging.Logger, action: str, **details: object) -> None:
    logger.info(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "action": action, **details}, sort_keys=True))
