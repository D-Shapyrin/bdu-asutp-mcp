"""Download the whole БДУ АСУ ТП API into a local SQLite snapshot.

The API is the same JSON surface the SPA uses (no official dumps exist):
``https://bduasutp.fstec.ru/bdu-service/api/v1/``. Lists are capped at
``per_page=20`` by the server, so the 3k software vulnerabilities take
~150 pages; details add 3k more small requests.

Usage:
    python -m bdu_asutp_mcp.fetch --db ~/.cache/bdu-asutp-mcp/bdu_asutp.sqlite
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx

API_BASE = "https://bduasutp.fstec.ru/bdu-service/api/v1/"
PAGE_SIZE = 20  # server rejects larger values
DETAIL_WORKERS = 3

SCHEMA_VERSION = "1"

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE threats (
    rowid          INTEGER PRIMARY KEY,
    id             TEXT NOT NULL UNIQUE,
    code           TEXT NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT,
    publication_at TEXT
);

CREATE TABLE threat_methods (
    threat_id      TEXT NOT NULL,
    group_code     TEXT,
    group_title    TEXT,
    mi_id          TEXT,
    mi_code        TEXT,
    mi_title       TEXT
);
CREATE INDEX idx_tm_threat  ON threat_methods(threat_id);
CREATE INDEX idx_tm_mi_code ON threat_methods(mi_code);

CREATE TABLE threat_influence_objects (
    threat_id TEXT NOT NULL,
    io_id     TEXT NOT NULL,
    PRIMARY KEY (threat_id, io_id)
);

CREATE TABLE influence_objects (
    rowid          INTEGER PRIMARY KEY,
    id             TEXT NOT NULL UNIQUE,
    code           TEXT,
    title          TEXT,
    description    TEXT
);

CREATE TABLE components (
    rowid          INTEGER PRIMARY KEY,
    id             TEXT NOT NULL UNIQUE,
    code           TEXT,
    title          TEXT,
    type_code      TEXT,
    type_title     TEXT,
    subtype_code   TEXT,
    subtype_title  TEXT
);

CREATE TABLE object_components (
    object_id    TEXT NOT NULL,
    component_id TEXT NOT NULL,
    PRIMARY KEY (object_id, component_id)
);

CREATE TABLE violators (
    rowid          INTEGER PRIMARY KEY,
    id             TEXT NOT NULL UNIQUE,
    code           TEXT,
    title          TEXT,
    description    TEXT,
    violator_types TEXT
);

CREATE TABLE negative_consequence_objects (
    rowid          INTEGER PRIMARY KEY,
    id             TEXT NOT NULL UNIQUE,
    title          TEXT NOT NULL
);

CREATE TABLE negative_consequences (
    rowid             INTEGER PRIMARY KEY,
    id                TEXT NOT NULL UNIQUE,
    object_id         TEXT,
    object_title      TEXT,
    typical_text      TEXT,
    consequence_types TEXT,
    architectures     TEXT,
    activity_fields   TEXT,
    afo_title         TEXT,
    publication_at    TEXT
);

CREATE TABLE protection_measures (
    rowid               INTEGER PRIMARY KEY,
    id                  TEXT NOT NULL UNIQUE,
    code                TEXT,
    title               TEXT,
    description         TEXT,
    group_code          TEXT,
    group_title         TEXT,
    measure_type        TEXT,
    asu_tp_levels       TEXT,
    promising_techs     TEXT,
    importance_categs   TEXT,
    publication_at      TEXT
);
CREATE INDEX idx_pm_code ON protection_measures(code);

CREATE TABLE typical_scenarios (
    rowid       INTEGER PRIMARY KEY,
    id          TEXT NOT NULL UNIQUE,
    title       TEXT,
    type_title  TEXT
);

CREATE TABLE scenario_steps (
    scenario_id  TEXT NOT NULL,
    step_no      INTEGER,
    description  TEXT,
    threat_id    TEXT
);
CREATE INDEX idx_ss_scenario ON scenario_steps(scenario_id);

CREATE TABLE software_vulnerabilities (
    rowid            INTEGER PRIMARY KEY,
    id               TEXT NOT NULL UNIQUE,
    code             TEXT NOT NULL,
    title            TEXT,
    description      TEXT,
    mitigation       TEXT,
    repair_info      TEXT,
    source_links     TEXT,
    other_info       TEXT,
    cvssv2_vector    TEXT,
    cvssv3_vector    TEXT,
    severity         TEXT,
    severity_level   INTEGER,
    vuln_class       TEXT,
    status           TEXT,
    exploit_presence TEXT,
    eliminate_solution TEXT,
    year             INTEGER,
    discovered_at    TEXT,
    publication_at   TEXT,
    software_names   TEXT,
    manufacturers    TEXT,
    equipments       TEXT,
    equipment_types  TEXT,
    hardware_platforms TEXT,
    error_types      TEXT,
    external_systems TEXT
);
CREATE INDEX idx_sv_code    ON software_vulnerabilities(code);
CREATE INDEX idx_sv_year    ON software_vulnerabilities(year);
CREATE INDEX idx_sv_sev     ON software_vulnerabilities(severity_level);
CREATE INDEX idx_sv_pub     ON software_vulnerabilities(publication_at);

CREATE TABLE configuration_vulnerabilities (
    rowid          INTEGER PRIMARY KEY,
    id             TEXT NOT NULL UNIQUE,
    code           TEXT,
    title          TEXT,
    description    TEXT,
    vuln_group     TEXT,
    equipment_types TEXT,
    error_types    TEXT,
    threats_joined TEXT,
    protection_measures TEXT
);

CREATE TABLE typical_web_vulnerabilities (
    rowid          INTEGER PRIMARY KEY,
    id             TEXT NOT NULL UNIQUE,
    code           TEXT,
    title          TEXT,
    description    TEXT,
    operation_methods TEXT,
    prevention_recommendations TEXT,
    threat_scenarios  TEXT,
    vulnerability_records TEXT,
    source_links      TEXT
);

CREATE VIRTUAL TABLE software_vulnerabilities_fts USING fts5(
    title, description, software_names, manufacturers, equipments,
    content = "software_vulnerabilities",
    content_rowid = "rowid",
    tokenize = "unicode61 remove_diacritics 2"
);

CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

SEVERITY_MAP = {
    "критический": 4,
    "высокий": 3,
    "средний": 2,
    "низкий": 1,
}


def severity_level(title: str) -> int:
    t = (title or "").lower()
    for keyword, level in SEVERITY_MAP.items():
        if keyword in t:
            return level
    return 0


def _join(list_of_dicts: list[dict] | None, *keys: str) -> str:
    parts = []
    for item in list_of_dicts or []:
        if isinstance(item, dict):
            text = " ".join(str(item.get(k) or "") for k in keys).strip()
        else:
            text = str(item)
        if text:
            parts.append(text)
    return "; ".join(parts)


class Fetcher:
    """Gentle HTTP client for the БДУ АСУ ТП API.

    The server rate-limits (HTTP 429) under sustained load, so the client
    throttles itself and backs off adaptively when told to slow down.
    """

    def __init__(self, api_base: str = API_BASE, timeout: float = 60.0) -> None:
        self._base = api_base
        # ФСТЭК serves a certificate from the Russian trusted CA, which
        # stock httpx/openssl bundles do not carry — skip verification.
        self._http = httpx.Client(
            base_url=api_base,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "bdu-asutp-mcp/0.1 (+snapshot fetcher)"},
        )
        self._delay = 0.15

    def close(self) -> None:
        self._http.close()

    def _slow_down(self) -> None:
        self._delay = min(self._delay * 1.5 + 0.05, 2.0)

    def get(self, path: str, **params: Any) -> Any:
        last_exc: Exception | None = None
        for attempt in range(1, 13):
            time.sleep(self._delay)
            try:
                resp = self._http.get(path, params=params or None)
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else 15.0 * attempt
                    self._slow_down()
                    last_exc = RuntimeError(f"429 on {path} (attempt {attempt})")
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, dict) and isinstance(data.get("data"), dict):
                    # {"message": "validation…", "data": {field: [errors]}}
                    raise RuntimeError(f"API rejected {path}: {data}")
                return data
            except httpx.HTTPError as exc:
                last_exc = exc
                time.sleep(2.0 * attempt)
        raise RuntimeError(f"GET {path} failed after retries: {last_exc}")

    def paged(self, path: str, extra: dict[str, Any] | None = None) -> list[dict]:
        items: list[dict] = []
        page = 1
        while True:
            data = self.get(path, per_page=PAGE_SIZE, current_page=page, **(extra or {}))
            batch = data.get("data")
            if not isinstance(batch, list) or not batch:
                break
            items.extend(batch)
            total = int(data.get("total") or len(items))
            if len(items) >= total:
                break
            page += 1
        return items


def _iso_date(value: str | None) -> str:
    if not value:
        return ""
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).strftime(
            "%d.%m.%Y"
        )
    except ValueError:
        return value


def build_snapshot(db_path: Path, api_base: str = API_BASE, log=print) -> dict[str, int]:
    import warnings

    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    f = Fetcher(api_base)
    resume = False
    if db_path.exists():
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            resume = row is not None and row[0] == SCHEMA_VERSION
        except sqlite3.DatabaseError:
            resume = False
        finally:
            conn.close()
        if not resume:
            db_path.unlink()
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    if resume:
        log(f"resuming existing snapshot {db_path}…")

    counts: dict[str, int] = {}

    # ---- threats + embedded NSI ------------------------------------
    log("threats…")
    top = f.get("threats")
    threats = top["threats"]
    for t in threats:
        conn.execute(
            "INSERT OR REPLACE INTO threats (id, code, title, description, publication_at) "
            "VALUES (?,?,?,?,?)",
            (t["id"], t["code"], t["title"], t.get("description") or "", _iso_date(t.get("publication_at"))),
        )
    counts["threats"] = len(threats)

    log("threat details…")
    conn.execute("DELETE FROM threat_methods")
    conn.execute("DELETE FROM scenario_steps")
    conn.execute("DELETE FROM threat_influence_objects")
    for t in threats:
        detail = f.get(f"threats/{t['id']}")
        for group in detail.get("method_implement_threat_groups") or []:
            for mi in group.get("method_implement_threats") or []:
                conn.execute(
                    "INSERT INTO threat_methods (threat_id, group_code, group_title, "
                    "mi_id, mi_code, mi_title) VALUES (?,?,?,?,?,?)",
                    (t["id"], group.get("code"), group.get("title"),
                     mi.get("id"), mi.get("code"), mi.get("title")),
                )
        for io in detail.get("influence_object_groups") or []:
            conn.execute(
                "INSERT OR IGNORE INTO threat_influence_objects (threat_id, io_id) "
                "VALUES (?,?)",
                (t["id"], io["id"]),
            )

    # ---- typical scenarios + attack steps --------------------------
    log("typical scenarios…")
    scenario_count = 0
    for ttype in top.get("typical_scenario_types") or []:
        for sc in ttype.get("typical_scenarios") or []:
            conn.execute(
                "INSERT OR IGNORE INTO typical_scenarios (id, title, type_title) "
                "VALUES (?,?,?)",
                (sc["id"], sc.get("title") or "", ttype.get("title") or ""),
            )
            scenario_count += 1
            for step in sc.get("attack_steps") or []:
                threat = step.get("threat") or {}
                conn.execute(
                    "INSERT INTO scenario_steps (scenario_id, step_no, description, threat_id) "
                    "VALUES (?,?,?,?)",
                    (sc["id"], step.get("attack_step"),
                     step.get("attack_step_description") or "", threat.get("id")),
                )
    counts["typical_scenarios"] = scenario_count

    # ---- components (from component_types tree) --------------------
    log("components…")
    comp_count = 0
    for ctype in top.get("component_types") or []:
        for subtype in ctype.get("component_subtypes") or []:
            for comp in subtype.get("components") or []:
                conn.execute(
                    "INSERT OR IGNORE INTO components (id, code, title, type_code, "
                    "type_title, subtype_code, subtype_title) VALUES (?,?,?,?,?,?,?)",
                    (comp["id"], comp.get("code"), comp.get("title") or "",
                     ctype.get("code"), ctype.get("title"),
                     subtype.get("code"), subtype.get("title")),
                )
                comp_count += 1
    counts["components"] = comp_count

    # ---- influence objects (full list with nested components) ------
    log("influence objects…")
    ios = f.paged("influence-objects")
    for io in ios:
        conn.execute(
            "INSERT OR REPLACE INTO influence_objects (id, code, title, description) "
            "VALUES (?,?,?,?)",
            (io["id"], io.get("code"), io.get("title") or "", io.get("description") or ""),
        )
        for comp in io.get("components") or []:
            conn.execute(
                "INSERT OR IGNORE INTO components (id, code, title) VALUES (?,?,?)",
                (comp["id"], comp.get("code"), comp.get("title") or ""),
            )
            conn.execute(
                "INSERT OR IGNORE INTO object_components (object_id, component_id) "
                "VALUES (?,?)",
                (io["id"], comp["id"]),
            )
    counts["influence_objects"] = len(ios)

    # ---- violators --------------------------------------------------
    log("violators…")
    viols = f.paged("violators")
    for v in viols:
        conn.execute(
            "INSERT OR REPLACE INTO violators (id, code, title, description, violator_types) "
            "VALUES (?,?,?,?,?)",
            (v["id"], v.get("code"), v.get("title") or "", v.get("description") or "",
             _join(v.get("violator_types"), "title")),
        )
    counts["violators"] = len(viols)

    # ---- negative consequences --------------------------------------
    log("negative consequences…")
    ncos = f.paged("negative-consequences")
    ncon_count = 0
    for obj in ncos:
        conn.execute(
            "INSERT OR REPLACE INTO negative_consequence_objects (id, title) VALUES (?,?)",
            (obj["id"], obj.get("title") or ""),
        )
        for nc in obj.get("negative_consequences") or []:
            afo = nc.get("activity_field_objects") or {}
            conn.execute(
                "INSERT OR REPLACE INTO negative_consequences "
                "(id, object_id, object_title, typical_text, consequence_types, "
                " architectures, activity_fields, afo_title, publication_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (nc["id"], obj["id"], obj.get("title") or "",
                 nc.get("typical_negative_consequence") or "",
                 _join(nc.get("negative_consequence_types"), "title"),
                 nc.get("asu_tp_architectures") or "",
                 nc.get("activity_fields") or "",
                 afo.get("title") or "",
                 _iso_date(nc.get("publication_at"))),
            )
            ncon_count += 1
    counts["negative_consequences"] = ncon_count
    counts["negative_consequence_objects"] = len(ncos)

    # ---- protection measures (list + details) ------------------------
    log("protection measures…")
    pm_count = 0
    for group in f.get("protection-measures")["data"]:
        for pm in group.get("protection_measures") or []:
            detail = f.get(f"protection-measures/{pm['id']}")
            mtype = detail.get("measure_types") or {}
            conn.execute(
                "INSERT OR REPLACE INTO protection_measures "
                "(id, code, title, description, group_code, group_title, measure_type, "
                " asu_tp_levels, promising_techs, importance_categs, publication_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (pm["id"], pm.get("code"), pm.get("title") or "",
                 pm.get("description") or "",
                 group.get("group_code"), group.get("title"),
                 mtype.get("title") or "",
                 _join(detail.get("asu_tp_levels"), "title"),
                 _join(detail.get("asu_tp_promising_technologies"), "title"),
                 _join(detail.get("importance_categories"), "importance"),
                 _iso_date(pm.get("publication_at"))),
            )
            pm_count += 1
    counts["protection_measures"] = pm_count
    conn.commit()  # everything before the long detail phase is safe now

    # ---- software vulnerabilities (list + details) --------------------
    log("software vulnerabilities (list)…")
    svulns = f.paged("software-vulnerabilities")
    counts["software_vulnerabilities"] = len(svulns)
    existing = {
        r[0] for r in conn.execute("SELECT id FROM software_vulnerabilities")
    }
    todo = [v for v in svulns if v["id"] not in existing]
    if len(todo) < len(svulns):
        log(f"  {len(existing)} details already present, fetching {len(todo)} more…")
    log(f"  fetching {len(todo)} details with {DETAIL_WORKERS} workers…")

    def _detail(v: dict) -> tuple[dict, dict]:
        return v, f.get(f"software-vulnerabilities/{v['id']}")

    done = 0
    with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
        for v, detail in pool.map(_detail, todo):
            done += 1
            if done % 200 == 0:
                log(f"  software vulnerabilities details {done}/{len(todo)}…")
            sev_title = (
                (detail.get("vulnerability_severity_levels") or {}).get("title") or ""
            )
            years = detail.get("years") or {}
            try:
                year = int(str(years.get("title") or "0"))
            except ValueError:
                year = None
            conn.execute(
                """INSERT OR REPLACE INTO software_vulnerabilities
                   (id, code, title, description, mitigation, repair_info, source_links,
                    other_info, cvssv2_vector, cvssv3_vector, severity, severity_level,
                    vuln_class, status, exploit_presence, eliminate_solution, year,
                    discovered_at, publication_at, software_names, manufacturers,
                    equipments, equipment_types, hardware_platforms, error_types,
                    external_systems)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    v["id"], v["code"], v.get("title") or "", v.get("description") or "",
                    v.get("possible_mitigation_measure") or "",
                    v.get("repair_information") or "",
                    v.get("source_links") or "", v.get("other_information") or "",
                    v.get("cvssv2_vector") or "", v.get("cvssv3_vector") or "",
                    sev_title, severity_level(sev_title),
                    (detail.get("vulnerability_classes") or {}).get("title") or "",
                    (detail.get("vulnerability_statuses") or {}).get("title") or "",
                    (detail.get("exploit_presence_types") or {}).get("title") or "",
                    (detail.get("eliminate_solutions") or {}).get("title") or "",
                    year,
                    _iso_date(v.get("discovered_at")),
                    _iso_date(v.get("publication_at")),
                    _join(v.get("software_versions"), "title"),
                    _join(v.get("software_manufacturers"), "title"),
                    _join(v.get("equipments"), "title"),
                    _join(v.get("equipment_types"), "title"),
                    _join(v.get("hardware_platforms"), "title"),
                    _join(detail.get("error_types"), "code", "title"),
                    _join(detail.get("external_systems"), "title"),
                ),
            )
            if done % 50 == 0:
                conn.commit()  # keep progress recoverable across 429 storms
    conn.commit()

    # ---- configuration + typical web vulnerabilities ------------------
    log("configuration & web vulnerabilities…")
    cvs = f.paged("configuration-vulnerabilities")
    for v in cvs:
        detail = f.get(f"configuration-vulnerabilities/{v['id']}")
        conn.execute(
            """INSERT OR REPLACE INTO configuration_vulnerabilities
               (id, code, title, description, vuln_group, equipment_types,
                error_types, threats_joined, protection_measures)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (v["id"], v.get("code"), v.get("title") or "", v.get("description") or "",
             (detail.get("vulnerability_group") or {}).get("title") or "",
             _join(detail.get("equipment_types"), "title"),
             _join(detail.get("error_types"), "code", "title"),
             _join(detail.get("threats"), "code", "title"),
             _join(detail.get("protection_measures"), "code", "title")),
        )
    counts["configuration_vulnerabilities"] = len(cvs)
    conn.commit()

    twvs = f.paged("typical-web-vulnerabilities")
    for v in twvs:
        conn.execute(
            """INSERT OR REPLACE INTO typical_web_vulnerabilities
               (id, code, title, description, operation_methods,
                prevention_recommendations, threat_scenarios,
                vulnerability_records, source_links)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (v["id"], v.get("code"), v.get("title") or "", v.get("description") or "",
             v.get("operation_methods") or "",
             v.get("prevention_recommendations") or "",
             v.get("threat_scenarios") or "",
             v.get("vulnerability_records") or "",
             v.get("source_links") or ""),
        )
    counts["typical_web_vulnerabilities"] = len(twvs)

    # ---- finalize ------------------------------------------------------
    conn.execute("INSERT INTO software_vulnerabilities_fts(software_vulnerabilities_fts) VALUES('rebuild')")
    conn.execute("INSERT INTO software_vulnerabilities_fts(software_vulnerabilities_fts) VALUES('optimize')")
    today = dt.date.today().isoformat()
    for key, value in (
        ("snapshot_date", today),
        ("schema_version", SCHEMA_VERSION),
        ("counts", json.dumps(counts, ensure_ascii=False)),
    ):
        conn.execute("INSERT INTO metadata(key, value) VALUES (?,?)", (key, value))
    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    f.close()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db",
        type=Path,
        default=Path.home() / ".cache" / "bdu-asutp-mcp" / "bdu_asutp.sqlite",
    )
    parser.add_argument("--api-base", default=API_BASE)
    args = parser.parse_args()
    args.db.parent.mkdir(parents=True, exist_ok=True)
    counts = build_snapshot(args.db, args.api_base)
    size_mb = args.db.stat().st_size / 1e6
    print(f"Built {args.db}: {json.dumps(counts, ensure_ascii=False)}, {size_mb:.1f} MB")


if __name__ == "__main__":
    main()
