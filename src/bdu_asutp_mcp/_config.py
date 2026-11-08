"""Runtime configuration — env-var overridable."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


SITE_BASE = "https://bduasutp.fstec.ru"
API_BASE = f"{SITE_BASE}/bdu-service/api/v1/"

MIRROR_REPO = "D-Shapyrin/bdu-asutp-mirror"
DEFAULT_DB_URL = f"https://github.com/{MIRROR_REPO}/raw/main/data/bdu_asutp.sqlite.gz"
DEFAULT_STATS_URL = f"https://raw.githubusercontent.com/{MIRROR_REPO}/main/data/stats.json"

# Card URL patterns (SPA hash routes verified against the UI bundle).
URL_THREAT = SITE_BASE + "/#/threat-view/{uuid}"
URL_VIOLATOR = SITE_BASE + "/#/violators-view/{uuid}"
URL_INFLUENCE_OBJECT = SITE_BASE + "/#/object-influence-view/{uuid}"
URL_COMPONENT = SITE_BASE + "/#/components-view/{uuid}"
URL_METHOD_IMPLEMENT = SITE_BASE + "/#/method-implement-view/{uuid}"
URL_PROTECTION_MEASURE = SITE_BASE + "/#/bdu/protection-measures/{uuid}"


def _default_cache_dir() -> Path:
    explicit = os.environ.get("BDU_ASUTP_CACHE_DIR")
    if explicit:
        return Path(explicit)
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "bdu-asutp-mcp"


@dataclass(frozen=True)
class Config:
    api_base: str
    db_url: str
    stats_url: str
    cache_dir: Path
    request_timeout: float
    staleness_days: int

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            api_base=os.environ.get("BDU_ASUTP_API_URL", API_BASE),
            db_url=os.environ.get("BDU_ASUTP_DB_URL", DEFAULT_DB_URL),
            stats_url=os.environ.get("BDU_ASUTP_STATS_URL", DEFAULT_STATS_URL),
            cache_dir=_default_cache_dir(),
            request_timeout=float(os.environ.get("BDU_ASUTP_REQUEST_TIMEOUT", "60")),
            staleness_days=int(os.environ.get("BDU_ASUTP_STALENESS_DAYS", "30")),
        )
