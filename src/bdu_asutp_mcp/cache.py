"""Cache management: download the SQLite snapshot from the mirror, decompress,
staleness check.

Falls back gracefully: if the mirror is unreachable but a local snapshot
exists, it is reused. Building from the source API directly is the job of
:mod:`bdu_asutp_mcp.fetch` (``bdu-asutp-mcp fetch``).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import json
import logging
import shutil
from pathlib import Path

import httpx

from ._config import Config

logger = logging.getLogger("bdu_asutp_mcp.cache")

DB_FILENAME = "bdu_asutp.sqlite"
DB_GZ_FILENAME = "bdu_asutp.sqlite.gz"
STATS_FILENAME = "stats.json"


class MirrorUnavailableError(RuntimeError):
    """Raised when the mirror cannot be reached and no local cache exists."""


class CacheManager:
    """Download the gzipped snapshot and decompress it on demand.

    Cache layout (``<cache_dir>/``):
        ``bdu_asutp.sqlite``      — opened read-only by the store
        ``bdu_asutp.sqlite.gz``   — raw downloaded blob
        ``stats.json``            — mirror metadata, used for staleness
    """

    def __init__(self, config: Config, http: httpx.AsyncClient | None = None) -> None:
        self._config = config
        self._http = http
        self._owns_http = http is None
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    @property
    def db_path(self) -> Path:
        return self._config.cache_dir / DB_FILENAME

    @property
    def gz_path(self) -> Path:
        return self._config.cache_dir / DB_GZ_FILENAME

    @property
    def stats_path(self) -> Path:
        return self._config.cache_dir / STATS_FILENAME

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=self._config.request_timeout,
                follow_redirects=True,
            )
        return self._http

    async def ensure(self, force: bool = False) -> Path:
        """Return a path to the SQLite snapshot, downloading if needed."""
        async with self._lock:
            self._config.cache_dir.mkdir(parents=True, exist_ok=True)
            if not force and self.db_path.exists() and self.db_path.stat().st_size > 0:
                return self.db_path
            await self._download_and_unpack()
            return self.db_path

    async def _download_and_unpack(self) -> None:
        client = await self._client()
        logger.info("Downloading БДУ АСУ ТП snapshot from %s", self._config.db_url)
        try:
            resp = await client.get(self._config.db_url)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            if self.db_path.exists():
                logger.warning("Mirror unreachable, reusing local cache: %s", exc)
                return
            raise MirrorUnavailableError(
                f"Не удалось скачать снимок с {self._config.db_url}: {exc}. "
                f"Либо повторите позже (`bdu-asutp-mcp refresh`), либо соберите "
                f"снимок напрямую из API ФСТЭК: `bdu-asutp-mcp fetch`."
            ) from exc
        self.gz_path.write_bytes(resp.content)
        tmp_path = self.db_path.with_suffix(".sqlite.tmp")
        with gzip.open(self.gz_path, "rb") as fin, open(tmp_path, "wb") as fout:
            shutil.copyfileobj(fin, fout)
        tmp_path.replace(self.db_path)
        # Stats fetched separately (tiny file).
        try:
            sresp = await client.get(self._config.stats_url)
            sresp.raise_for_status()
            self.stats_path.write_bytes(sresp.content)
        except httpx.HTTPError as exc:  # non-fatal
            logger.warning("Could not refresh stats.json: %s", exc)

    async def staleness_check(self, local_snapshot_date: str) -> tuple[bool, str]:
        """Compare the local snapshot date with the mirror's ``stats.json``.

        Returns ``(is_stale, reason)`` with a human-readable reason.
        """
        remote_date = await self._fetch_remote_snapshot_date()
        today = dt.date.today()

        try:
            local = dt.date.fromisoformat(local_snapshot_date)
        except (ValueError, TypeError):
            return True, "Не удалось разобрать дату локального снимка."

        if remote_date and remote_date > local:
            return (
                True,
                (
                    f"В зеркале есть более свежий снимок "
                    f"({remote_date.isoformat()} > {local.isoformat()}). "
                    f"Выполните `bdu-asutp-mcp refresh`."
                ),
            )

        age = (today - local).days
        if age > self._config.staleness_days:
            return (
                True,
                (
                    f"Локальный снимок старше {self._config.staleness_days} дней "
                    f"(возраст: {age} дн., дата: {local.isoformat()})."
                ),
            )
        return False, ""

    async def _fetch_remote_snapshot_date(self) -> dt.date | None:
        try:
            client = await self._client()
            resp = await client.get(self._config.stats_url, timeout=10.0)
            resp.raise_for_status()
            payload = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            logger.debug("Remote stats fetch failed: %s", exc)
            return None
        raw = payload.get("snapshot_date")
        if not raw:
            return None
        try:
            return dt.date.fromisoformat(str(raw))
        except ValueError:
            return None
