"""SQLite store over the БДУ АСУ ТП snapshot.

All heavy I/O is delegated to a worker thread (``anyio.to_thread``) so the
stdio event loop stays non-blocking while SQLite queries run.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Iterable

import anyio

from ._config import (
    URL_COMPONENT,
    URL_INFLUENCE_OBJECT,
    URL_METHOD_IMPLEMENT,
    URL_PROTECTION_MEASURE,
    URL_THREAT,
    URL_VIOLATOR,
)
from .models import (
    NegativeConsequence,
    NsiItem,
    ProtectionMeasure,
    SnapshotInfo,
    SoftwareVulnerability,
    Threat,
)

# Same tokenizer contract as bdu-fstec-mcp: unsafe characters are stripped,
# Cyrillic words get a suffix-trimming prefix match.
FTS_SAFE_CHARS = re.compile(r"[^0-9a-zA-Zа-яА-ЯёЁ\s]")
FTS_RESERVED = {"AND", "OR", "NOT", "NEAR"}

SUPPORTED_SCHEMA_VERSION = "1"

_CYRILLIC = re.compile(r"[а-яёА-ЯЁ]")


def _to_prefix(token: str) -> str:
    if _CYRILLIC.search(token) and len(token) >= 6:
        return f"{token[:-2]}*"
    if len(token) >= 3:
        return f"{token}*"
    return token


def _escape_fts_query(query: str) -> str:
    cleaned = FTS_SAFE_CHARS.sub(" ", query)
    tokens = [t for t in cleaned.split() if t]
    if not tokens:
        return ""
    parts: list[str] = []
    for t in tokens:
        if t.upper() in FTS_RESERVED:
            parts.append(f'"{t}"')
        elif t.isalnum() and len(t) >= 2:
            parts.append(_to_prefix(t))
        else:
            parts.append(f'"{t}"')
    return " ".join(parts)


def _like(query: str) -> str:
    """Turn a free-text query into a LIKE pattern over space-separated words.

    Russian words inflect via suffixes, so long Cyrillic words lose their
    last 2 characters (``утечка`` → ``утеч*``) — same tolerance as the FTS
    prefix logic above.
    """
    words = []
    for w in re.sub(r"[^\wа-яёА-ЯЁ]+", " ", query).split():
        if not w:
            continue
        if _CYRILLIC.search(w) and len(w) >= 6:
            w = w[:-2]
        words.append(w)
    return "%" + "%".join(words) + "%"


class Store:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        if self._conn is not None:
            return
        conn = sqlite3.connect(self._db_path, check_same_thread=False, uri=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = 1")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA mmap_size = 134217728")  # 128 MB mmap
        # SQLite's LIKE folds case for ASCII only; register a proper
        # lower() so Cyrillic LIKE comparisons are case-insensitive.
        conn.create_function("ulower", 1, str.lower, deterministic=True)
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        version = row["value"] if row else ""
        if version != SUPPORTED_SCHEMA_VERSION:
            conn.close()
            raise RuntimeError(
                f"SQLite snapshot has schema_version={version!r}, "
                f"this build of bdu-asutp-mcp requires {SUPPORTED_SCHEMA_VERSION!r}. "
                f"Run `python -m bdu_asutp_mcp.fetch` to rebuild the snapshot."
            )
        self._conn = conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ---- thread-safe public API --------------------------------------

    async def search_threats(self, query: str, limit: int = 10) -> list[Threat]:
        return await anyio.to_thread.run_sync(self._search_threats_sync, query, limit)

    async def get_threat(self, key: str) -> Threat | None:
        return await anyio.to_thread.run_sync(self._get_threat_sync, key)

    async def search_negative_consequences(
        self,
        query: str,
        limit: int = 10,
        activity_field: str | None = None,
        object_title: str | None = None,
    ) -> list[NegativeConsequence]:
        return await anyio.to_thread.run_sync(
            self._search_negcon_sync, query, limit, activity_field, object_title
        )

    async def search_protection_measures(
        self, query: str, limit: int = 10, group_code: str | None = None
    ) -> list[ProtectionMeasure]:
        return await anyio.to_thread.run_sync(
            self._search_measures_sync, query, limit, group_code
        )

    async def search_software_vulnerabilities(
        self,
        query: str,
        limit: int = 10,
        min_severity: int | None = None,
        year: int | None = None,
        has_exploit: bool | None = None,
        equipment: str | None = None,
    ) -> list[SoftwareVulnerability]:
        return await anyio.to_thread.run_sync(
            self._search_svul_sync,
            query,
            limit,
            min_severity,
            year,
            has_exploit,
            equipment,
        )

    async def get_software_vulnerability(self, key: str) -> SoftwareVulnerability | None:
        return await anyio.to_thread.run_sync(self._get_svul_sync, key)

    async def get_web_or_config_vulnerability(self, key: str) -> NsiItem | None:
        """Typical web (BDA:W###) and configuration (BDA:C###) vulns live in
        separate tables — resolve by code or uuid."""
        return await anyio.to_thread.run_sync(self._get_other_vuln_sync, key)

    async def search_nsi(
        self, kind: str, query: str, limit: int = 10
    ) -> list[NsiItem]:
        return await anyio.to_thread.run_sync(
            self._search_nsi_sync, kind, query, limit
        )

    async def snapshot_info(
        self, is_stale: bool = False, stale_reason: str = ""
    ) -> SnapshotInfo:
        return await anyio.to_thread.run_sync(
            self._snapshot_info_sync, is_stale, stale_reason
        )

    # ---- sync implementations ----------------------------------------

    def _conn_or_open(self) -> sqlite3.Connection:
        if self._conn is None:
            self.open()
        assert self._conn is not None
        return self._conn

    def _search_threats_sync(self, query: str, limit: int) -> list[Threat]:
        conn = self._conn_or_open()
        limit = max(1, min(limit, 50))
        where, params = self._like_where(["code", "title", "description"], query)
        rows = conn.execute(
            "SELECT * FROM threats WHERE 1=1" + where + " ORDER BY code LIMIT ?",
            [*params, limit],
        ).fetchall()
        return [self._threat_from_row(r) for r in rows]

    def _get_threat_sync(self, key: str) -> Threat | None:
        conn = self._conn_or_open()
        k = (key or "").strip().upper().replace(" ", "")
        row = None
        if re.match(r"^УТП[:.]?\d{1,2}$", k, re.IGNORECASE):
            code = "УТП:" + re.sub(r"^УТП[:.]?", "", k, flags=re.IGNORECASE).zfill(2)
            row = conn.execute(
                "SELECT * FROM threats WHERE upper(code) = ?", (code,)
            ).fetchone()
        elif k:
            row = conn.execute(
                "SELECT * FROM threats WHERE id = ? OR upper(code) = ?",
                (key.strip(), k),
            ).fetchone()
        if row is None:
            return None
        return self._threat_from_row(row, with_details=True)

    @staticmethod
    def _like_where(columns: Iterable[str], query: str, prefix: str = "") -> tuple[str, list[str]]:
        """Build ``AND (ulower(col) LIKE ? OR …)`` plus its parameters."""
        pattern = _like(query).lower()
        cols = [f"{prefix}{c}" for c in columns]
        if not pattern or pattern == "%%" or not cols:
            return "", []
        clause = " OR ".join(f"ulower({c}) LIKE ? ESCAPE '\\'" for c in cols)
        return f" AND ({clause})", [pattern] * len(cols)

    def _threat_from_row(self, row: sqlite3.Row, with_details: bool = False) -> Threat:
        conn = self._conn_or_open()
        methods: list[tuple[str, str, str]] = []
        ios: list[NsiItem] = []
        scenarios: list[str] = []
        if with_details:
            for m in conn.execute(
                "SELECT group_code, mi_code, mi_title FROM threat_methods "
                "WHERE threat_id = ? ORDER BY group_code, mi_code",
                (row["id"],),
            ):
                methods.append(
                    (m["group_code"] or "", m["mi_code"] or "", m["mi_title"] or "")
                )
            for io in conn.execute(
                "SELECT io.* FROM threat_influence_objects tio "
                "JOIN influence_objects io ON io.id = tio.io_id "
                "WHERE tio.threat_id = ? ORDER BY io.code",
                (row["id"],),
            ):
                ios.append(
                    NsiItem(
                        kind="influence_object",
                        id=io["id"],
                        code=io["code"] or "",
                        title=io["title"] or "",
                        description=io["description"] or "",
                        url=URL_INFLUENCE_OBJECT.format(uuid=io["id"]),
                    )
                )
            for sc in conn.execute(
                "SELECT DISTINCT ts.id, ts.title FROM scenario_steps ss "
                "JOIN typical_scenarios ts ON ts.id = ss.scenario_id "
                "WHERE ss.threat_id = ? ORDER BY ts.title",
                (row["id"],),
            ):
                scenarios.append(f"{sc['title']} [{sc['id'][:8]}]")
        return Threat(
            id=row["id"],
            code=row["code"],
            title=row["title"],
            description=row["description"] or "",
            publication_at=row["publication_at"] or "",
            url=URL_THREAT.format(uuid=row["id"]),
            methods=tuple(methods),
            influence_objects=tuple(ios),
            scenarios=tuple(scenarios),
        )

    def _search_negcon_sync(
        self,
        query: str,
        limit: int,
        activity_field: str | None,
        object_title: str | None,
    ) -> list[NegativeConsequence]:
        conn = self._conn_or_open()
        limit = max(1, min(limit, 100))
        where, params = self._like_where(
            ["typical_text", "object_title", "consequence_types", "architectures"],
            query,
        )
        sql = "SELECT * FROM negative_consequences WHERE 1=1" + where
        if activity_field:
            sql += " AND ulower(activity_fields) LIKE ?"
            params.append(f"%{activity_field.lower()}%")
        if object_title:
            sql += " AND (ulower(object_title) LIKE ? OR ulower(afo_title) LIKE ?)"
            params.extend([f"%{object_title.lower()}%"] * 2)
        sql += " ORDER BY object_title, typical_text LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [
            NegativeConsequence(
                id=r["id"],
                object_title=r["object_title"] or "",
                typical_text=r["typical_text"] or "",
                consequence_types=r["consequence_types"] or "",
                architectures=r["architectures"] or "",
                activity_fields=r["activity_fields"] or "",
                afo_title=r["afo_title"] or "",
                publication_at=r["publication_at"] or "",
            )
            for r in rows
        ]

    def _search_measures_sync(
        self, query: str, limit: int, group_code: str | None
    ) -> list[ProtectionMeasure]:
        conn = self._conn_or_open()
        limit = max(1, min(limit, 100))
        where, params = self._like_where(["code", "title", "description"], query)
        sql = "SELECT * FROM protection_measures WHERE 1=1" + where
        if group_code:
            sql += " AND group_code LIKE ?"
            params.append(f"%{group_code.upper()}%")
        sql += " ORDER BY code LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [self._measure_from_row(r) for r in rows]

    @staticmethod
    def _measure_from_row(r: sqlite3.Row) -> ProtectionMeasure:
        return ProtectionMeasure(
            id=r["id"],
            code=r["code"] or "",
            title=r["title"] or "",
            description=r["description"] or "",
            group_code=r["group_code"] or "",
            group_title=r["group_title"] or "",
            measure_type=r["measure_type"] or "",
            asu_tp_levels=r["asu_tp_levels"] or "",
            promising_techs=r["promising_techs"] or "",
            importance_categs=r["importance_categs"] or "",
            publication_at=r["publication_at"] or "",
            url=URL_PROTECTION_MEASURE.format(uuid=r["id"]),
        )

    def _search_svul_sync(
        self,
        query: str,
        limit: int,
        min_severity: int | None,
        year: int | None,
        has_exploit: bool | None,
        equipment: str | None,
    ) -> list[SoftwareVulnerability]:
        conn = self._conn_or_open()
        limit = max(1, min(limit, 100))

        match = _escape_fts_query(query) if query else ""
        params: list[object] = []
        filters: list[str] = []

        if match:
            sql = (
                "SELECT v.rowid AS rowid, snippet(software_vulnerabilities_fts, 1, "
                "'«', '»', '…', 20) AS snippet FROM software_vulnerabilities_fts f "
                "JOIN software_vulnerabilities v ON v.rowid = f.rowid "
                "WHERE software_vulnerabilities_fts MATCH ?"
            )
            params.append(match)
            order = "ORDER BY rank"
        else:
            sql = (
                "SELECT v.rowid AS rowid, '' AS snippet "
                "FROM software_vulnerabilities v WHERE 1=1"
            )
            order = "ORDER BY v.publication_at DESC, v.code"

        if min_severity is not None:
            filters.append("v.severity_level >= ?")
            params.append(int(min_severity))
        if year is not None:
            filters.append("v.year = ?")
            params.append(int(year))
        if has_exploit is True:
            filters.append("ulower(v.exploit_presence) LIKE '%существует%'")
        elif has_exploit is False:
            filters.append(
                "(v.exploit_presence = '' OR ulower(v.exploit_presence) LIKE '%отсутствует%')"
            )
        if equipment:
            filters.append("ulower(v.equipments) LIKE ?")
            params.append(f"%{equipment.lower()}%")

        if filters:
            sql += " AND " + " AND ".join(filters)
        sql += f" {order} LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        if not rows:
            return []
        rowids = [r["rowid"] for r in rows]
        snippets = {r["rowid"]: (r["snippet"] or "") for r in rows}
        placeholders = ",".join("?" * len(rowids))
        full = conn.execute(
            f"SELECT * FROM software_vulnerabilities WHERE rowid IN ({placeholders})",
            rowids,
        ).fetchall()
        by_rowid = {r["rowid"]: r for r in full}
        return [
            self._svul_from_row(by_rowid[rid], snippets.get(rid, ""))
            for rid in rowids
            if rid in by_rowid
        ]

    def _get_svul_sync(self, key: str) -> SoftwareVulnerability | None:
        conn = self._conn_or_open()
        k = (key or "").strip().upper()
        row = conn.execute(
            "SELECT * FROM software_vulnerabilities WHERE upper(code) = ? OR id = ?",
            (k, key.strip()),
        ).fetchone()
        if row is None:
            return None
        return self._svul_from_row(row)

    def _get_other_vuln_sync(self, key: str) -> NsiItem | None:
        conn = self._conn_or_open()
        k = (key or "").strip().upper()
        web = conn.execute(
            "SELECT * FROM typical_web_vulnerabilities WHERE upper(code) = ? OR id = ?",
            (k, key.strip()),
        ).fetchone()
        if web is not None:
            desc = "\n\n".join(
                x for x in (
                    web["description"] or "",
                    "Способы эксплуатации: " + web["operation_methods"] if web["operation_methods"] else "",
                    "Рекомендации по предотвращению: " + web["prevention_recommendations"] if web["prevention_recommendations"] else "",
                    "Сценарии угроз: " + web["threat_scenarios"] if web["threat_scenarios"] else "",
                    "Записи об уязвимостях: " + web["vulnerability_records"] if web["vulnerability_records"] else "",
                ) if x
            )
            return NsiItem(
                kind="typical_web", id=web["id"], code=web["code"] or "",
                title=web["title"] or "", description=desc,
                extra="Типовая веб-уязвимость",
            )
        cfg = conn.execute(
            "SELECT * FROM configuration_vulnerabilities WHERE upper(code) = ? OR id = ?",
            (k, key.strip()),
        ).fetchone()
        if cfg is not None:
            desc = "\n\n".join(
                x for x in (
                    cfg["description"] or "",
                    "Группа: " + cfg["vuln_group"] if cfg["vuln_group"] else "",
                    "Типы оборудования: " + cfg["equipment_types"] if cfg["equipment_types"] else "",
                    "Типы ошибок: " + cfg["error_types"] if cfg["error_types"] else "",
                    "Связанные угрозы: " + cfg["threats_joined"] if cfg["threats_joined"] else "",
                    "Меры защиты: " + cfg["protection_measures"] if cfg["protection_measures"] else "",
                ) if x
            )
            return NsiItem(
                kind="configuration", id=cfg["id"], code=cfg["code"] or "",
                title=cfg["title"] or "", description=desc,
                extra="Уязвимость конфигурации",
            )
        return None

    @staticmethod
    def _svul_from_row(
        r: sqlite3.Row, snippet: str = ""
    ) -> SoftwareVulnerability:
        return SoftwareVulnerability(
            id=r["id"],
            code=r["code"],
            title=r["title"] or "",
            description=r["description"] or "",
            mitigation=r["mitigation"] or "",
            repair_info=r["repair_info"] or "",
            source_links=r["source_links"] or "",
            other_info=r["other_info"] or "",
            cvssv2_vector=r["cvssv2_vector"] or "",
            cvssv3_vector=r["cvssv3_vector"] or "",
            severity=r["severity"] or "",
            severity_level=int(r["severity_level"] or 0),
            vuln_class=r["vuln_class"] or "",
            status=r["status"] or "",
            exploit_presence=r["exploit_presence"] or "",
            eliminate_solution=r["eliminate_solution"] or "",
            year=r["year"],
            discovered_at=r["discovered_at"] or "",
            publication_at=r["publication_at"] or "",
            software_names=r["software_names"] or "",
            manufacturers=r["manufacturers"] or "",
            equipments=r["equipments"] or "",
            equipment_types=r["equipment_types"] or "",
            hardware_platforms=r["hardware_platforms"] or "",
            error_types=r["error_types"] or "",
            external_systems=r["external_systems"] or "",
            match_snippet=snippet,
        )

    def _search_nsi_sync(
        self, kind: str, query: str, limit: int
    ) -> list[NsiItem]:
        conn = self._conn_or_open()
        limit = max(1, min(limit, 100))
        if kind == "influence_object":
            where, params = self._like_where(
                ["code", "title", "description"], query
            )
            rows = conn.execute(
                "SELECT id, code, title, description, '' AS extra FROM influence_objects "
                "WHERE 1=1" + where + " ORDER BY code LIMIT ?",
                [*params, limit],
            ).fetchall()
            return [
                NsiItem(
                    kind=kind, id=r["id"], code=r["code"] or "", title=r["title"] or "",
                    description=r["description"] or "",
                    url=URL_INFLUENCE_OBJECT.format(uuid=r["id"]),
                )
                for r in rows
            ]
        if kind == "component":
            where, params = self._like_where(["code", "title"], query)
            rows = conn.execute(
                "SELECT id, code, title, type_title, subtype_title FROM components "
                "WHERE 1=1" + where + " ORDER BY code LIMIT ?",
                [*params, limit],
            ).fetchall()
            return [
                NsiItem(
                    kind=kind, id=r["id"], code=r["code"] or "", title=r["title"] or "",
                    extra="; ".join(
                        x for x in (r["type_title"], r["subtype_title"]) if x
                    ),
                    url=URL_COMPONENT.format(uuid=r["id"]),
                )
                for r in rows
            ]
        if kind == "violator":
            where, params = self._like_where(
                ["code", "title", "description"], query
            )
            rows = conn.execute(
                "SELECT id, code, title, description, violator_types AS extra "
                "FROM violators WHERE 1=1" + where + " ORDER BY code LIMIT ?",
                [*params, limit],
            ).fetchall()
            return [
                NsiItem(
                    kind=kind, id=r["id"], code=r["code"] or "", title=r["title"] or "",
                    description=r["description"] or "", extra=r["extra"] or "",
                    url=URL_VIOLATOR.format(uuid=r["id"]),
                )
                for r in rows
            ]
        if kind == "method_implement":
            where, params = self._like_where(
                ["mi_code", "mi_title", "group_code", "group_title"], query
            )
            rows = conn.execute(
                "SELECT mi_id AS id, mi_code AS code, mi_title AS title, "
                "group_code || ' ' || group_title AS extra FROM threat_methods "
                "WHERE mi_id IS NOT NULL" + where + " GROUP BY mi_code "
                "ORDER BY mi_code LIMIT ?",
                [*params, limit],
            ).fetchall()
            return [
                NsiItem(
                    kind=kind, id=r["id"], code=r["code"] or "", title=r["title"] or "",
                    extra=r["extra"] or "",
                    url=URL_METHOD_IMPLEMENT.format(uuid=r["id"]),
                )
                for r in rows
            ]
        if kind == "typical_scenario":
            where, params = self._like_where(["title", "type_title"], query)
            rows = conn.execute(
                "SELECT id, title, type_title AS extra FROM typical_scenarios "
                "WHERE 1=1" + where + " ORDER BY title LIMIT ?",
                [*params, limit],
            ).fetchall()
            return [
                NsiItem(kind=kind, id=r["id"], code="", title=r["title"] or "",
                        extra=r["extra"] or "")
                for r in rows
            ]
        raise ValueError(f"unknown reference kind: {kind}")

    def _snapshot_info_sync(
        self, is_stale: bool = False, stale_reason: str = ""
    ) -> SnapshotInfo:
        import json

        conn = self._conn_or_open()
        meta = dict(conn.execute("SELECT key, value FROM metadata").fetchall())
        counts = json.loads(meta.get("counts") or "{}")
        return SnapshotInfo(
            snapshot_date=meta.get("snapshot_date", ""),
            schema_version=meta.get("schema_version", ""),
            counts=counts,
            is_stale=is_stale,
            stale_reason=stale_reason,
        )
