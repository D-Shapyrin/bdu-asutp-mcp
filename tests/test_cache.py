"""CacheManager: mirror download, reuse, staleness; publish_mirror."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from bdu_asutp_mcp._config import Config
from bdu_asutp_mcp.cache import CacheManager, MirrorUnavailableError
from bdu_asutp_mcp.publish import publish_mirror


class _Resp:
    def __init__(self, content: bytes, status: int = 200) -> None:
        self.content = content
        self.status_code = status
        self.headers: dict[str, str] = {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPError(f"HTTP {self.status_code}")


class _FakeClient:
    def __init__(self, db_bytes: bytes, stats_bytes: bytes, fail: bool = False) -> None:
        self.db_bytes = db_bytes
        self.stats_bytes = stats_bytes
        self.fail = fail
        self.calls: list[str] = []

    async def get(self, url: str, **kwargs) -> _Resp:
        self.calls.append(url)
        if self.fail:
            import httpx

            raise httpx.HTTPError("unreachable")
        if url.endswith(".gz"):
            return _Resp(self.db_bytes)
        return _Resp(self.stats_bytes)


def _make_config(tmp_path: Path) -> Config:
    return Config(
        api_base="http://127.0.0.1:0/api/",
        db_url="http://127.0.0.1:0/bdu_asutp.sqlite.gz",
        stats_url="http://127.0.0.1:0/stats.json",
        cache_dir=tmp_path / "cache",
        request_timeout=5.0,
        staleness_days=30,
    )


def _fake_gz() -> bytes:
    return gzip.compress(b"fake sqlite bytes")


@pytest.fixture
def snapshot_db(tmp_path: Path) -> Path:
    from tests.conftest import build_sample_db

    db = tmp_path / "src.sqlite"
    build_sample_db(db)
    return db


async def test_ensure_downloads_and_unpacks(tmp_path: Path):
    cfg = _make_config(tmp_path)
    http = _FakeClient(_fake_gz(), b'{"snapshot_date": "2026-11-08"}')
    cache = CacheManager(cfg, http=http)
    try:
        path = await cache.ensure()
        assert path == cfg.cache_dir / "bdu_asutp.sqlite"
        assert path.read_bytes() == b"fake sqlite bytes"
        assert (cfg.cache_dir / "stats.json").read_text().count("2026-11-08") == 1
    finally:
        await cache.aclose()


async def test_ensure_reuses_existing(tmp_path: Path):
    cfg = _make_config(tmp_path)
    cfg.cache_dir.mkdir(parents=True)
    (cfg.cache_dir / "bdu_asutp.sqlite").write_bytes(b"existing")
    http = _FakeClient(_fake_gz(), b"{}")
    cache = CacheManager(cfg, http=http)
    try:
        path = await cache.ensure()
        assert path.read_bytes() == b"existing"
        assert http.calls == []  # no requests made
    finally:
        await cache.aclose()


async def test_ensure_force_redownloads(tmp_path: Path):
    cfg = _make_config(tmp_path)
    cfg.cache_dir.mkdir(parents=True)
    (cfg.cache_dir / "bdu_asutp.sqlite").write_bytes(b"old")
    http = _FakeClient(_fake_gz(), b"{}")
    cache = CacheManager(cfg, http=http)
    try:
        path = await cache.ensure(force=True)
        assert path.read_bytes() == b"fake sqlite bytes"
    finally:
        await cache.aclose()


async def test_mirror_down_reuses_cache(tmp_path: Path):
    cfg = _make_config(tmp_path)
    cfg.cache_dir.mkdir(parents=True)
    (cfg.cache_dir / "bdu_asutp.sqlite").write_bytes(b"cached")
    http = _FakeClient(_fake_gz(), b"{}", fail=True)
    cache = CacheManager(cfg, http=http)
    try:
        path = await cache.ensure(force=True)
        assert path.read_bytes() == b"cached"
    finally:
        await cache.aclose()


async def test_mirror_down_no_cache_raises(tmp_path: Path):
    cfg = _make_config(tmp_path)
    http = _FakeClient(_fake_gz(), b"{}", fail=True)
    cache = CacheManager(cfg, http=http)
    try:
        with pytest.raises(MirrorUnavailableError):
            await cache.ensure()
    finally:
        await cache.aclose()


async def test_staleness_uses_remote_date(tmp_path: Path):
    cfg = _make_config(tmp_path)
    cache = CacheManager(cfg, http=_FakeClient(_fake_gz(), b"{}"))
    try:
        # Remote is newer → stale.
        async def remote_newer():
            import datetime as dt

            return dt.date(2026, 12, 1)

        cache._fetch_remote_snapshot_date = remote_newer  # type: ignore[method-assign]
        stale, reason = await cache.staleness_check("2026-11-08")
        assert stale and "более свежий" in reason

        # Remote older, local fresh → ok.
        async def remote_older():
            import datetime as dt

            return dt.date(2026, 11, 8)

        cache._fetch_remote_snapshot_date = remote_older  # type: ignore[method-assign]
        stale, reason = await cache.staleness_check("2026-11-08")
        assert not stale
    finally:
        await cache.aclose()


def test_publish_mirror(snapshot_db: Path, tmp_path: Path):
    out = tmp_path / "mirror"
    stats = publish_mirror(snapshot_db, out)
    gz = out / "data" / "bdu_asutp.sqlite.gz"
    assert gz.exists()
    assert gzip.decompress(gz.read_bytes())[:15] == b"SQLite format 3"
    assert stats["snapshot_date"] == "2026-11-08"
    assert stats["schema_version"] == 1
    assert stats["counts"]["threats"] == 2
    on_disk = json.loads((out / "stats.json").read_text(encoding="utf-8"))
    assert on_disk["counts"]["software_vulnerabilities"] == 2
