"""Prepare mirror artifacts: gzip the snapshot + write stats.json.

Run from a machine with access to bduasutp.fstec.ru (geo-blocked outside RU):

    bdu-asutp-mcp fetch            # rebuild the local snapshot
    bdu-asutp-mcp publish --out /path/to/bdu-asutp-mirror
    cd /path/to/bdu-asutp-mirror && git add data stats.json && git commit && git push
"""

from __future__ import annotations

import gzip
import json
import shutil
import sqlite3
from pathlib import Path


def publish_mirror(db_path: Path, mirror_dir: Path) -> dict:
    """Copy ``<db>.gz`` and ``stats.json`` into the mirror repo layout."""
    db_path = Path(db_path)
    if not db_path.exists():
        raise FileNotFoundError(f"snapshot not found: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    meta = dict(conn.execute("SELECT key, value FROM metadata").fetchall())
    # Dates are stored as DD.MM.YYYY strings — take the true max in Python,
    # not lexicographic SQL max.
    latest = ""
    latest_key: tuple[int, int, int] | None = None
    for table in ("software_vulnerabilities", "threats", "protection_measures"):
        for (value,) in conn.execute(
            f"SELECT DISTINCT publication_at FROM {table} WHERE publication_at != ''"
        ):
            try:
                d, m, y = value.split(".")
                key = (int(y), int(m), int(d))
            except (ValueError, AttributeError):
                continue
            if latest_key is None or key > latest_key:
                latest_key, latest = key, value
    conn.close()

    data_dir = Path(mirror_dir) / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    gz_path = data_dir / "bdu_asutp.sqlite.gz"
    with open(db_path, "rb") as fin, gzip.open(gz_path, "wb", compresslevel=9) as fout:
        shutil.copyfileobj(fin, fout)

    stats = {
        "snapshot_date": meta.get("snapshot_date", ""),
        "schema_version": int(meta.get("schema_version", "0") or 0),
        "counts": json.loads(meta.get("counts") or "{}"),
        "source_last_update": latest,
        "artifacts": {
            "sqlite_gz": {
                "path": "data/bdu_asutp.sqlite.gz",
                "size_bytes": gz_path.stat().st_size,
                "format": "gzip(SQLite with FTS5)",
            }
        },
    }
    (Path(mirror_dir) / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return stats
