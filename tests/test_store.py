"""Store layer: searches, lookups, normalization."""

from __future__ import annotations

from pathlib import Path

from bdu_asutp_mcp.models import SoftwareVulnerability, Threat
from bdu_asutp_mcp.store import Store, _escape_fts_query


async def _make_store(path: Path) -> Store:
    store = Store(path)
    store.open()
    return store


# ---- threats --------------------------------------------------------


async def test_threat_search_by_code_and_title(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        assert [t.code for t in await store.search_threats("утечка")] == ["УТП:01"]
        all_threats = await store.search_threats("")
        assert len(all_threats) == 2
    finally:
        store.close()


async def test_threat_get_normalizes_code(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        for raw in ("УТП:01", "УТП:1", "утп.01", "УТП 1"):
            t = await store.get_threat(raw)
            assert t is not None, f"failed to normalize {raw!r}"
            assert t.code == "УТП:01"
            assert t.url.endswith("/#/threat-view/11111111-1111-1111-1111-111111111111")
    finally:
        store.close()


async def test_threat_full_card_includes_relations(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        t = await store.get_threat("УТП:01")
        assert t is not None
        assert ("СП.1", "СПА.01.001", "Эксплуатация известных уязвимостей") in t.methods
        assert ("СП.2", "СПА.02.003", "Перехват паролей") in t.methods
        assert t.influence_objects[0].code == "ОА.001"
    finally:
        store.close()


async def test_threat_scenarios_backlink(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        t = await store.get_threat("УТП:03")
        assert t is not None
        assert any("С3.19" in s for s in t.scenarios)
    finally:
        store.close()


async def test_threat_get_missing(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        assert await store.get_threat("УТП:99") is None
    finally:
        store.close()


# ---- negative consequences ------------------------------------------


async def test_negcon_search_and_filters(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search_negative_consequences("обессоливан")
        assert len(results) == 1
        assert results[0].object_title == "Нефтеперерабатывающий завод"

        tf = await store.search_negative_consequences(
            "", activity_field="топливно"
        )
        assert len(tf) == 2

        stop = await store.search_negative_consequences("", object_title="завод")
        assert len(stop) == 2
    finally:
        store.close()


# ---- protection measures --------------------------------------------


async def test_measures_search_and_group_filter(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search_protection_measures("аутентифика")
        assert [m.code for m in results] == ["ИАФ.0"]

        all_ = await store.search_protection_measures("")
        assert len(all_) == 2

        upd = await store.search_protection_measures("", group_code="упд")
        assert [m.code for m in upd] == ["УПД.5"]
        assert upd[0].url.endswith("/#/bdu/protection-measures/abababab-0000-0000-0000-000000000002")
    finally:
        store.close()


# ---- software vulnerabilities ----------------------------------------


async def test_svul_fts_search(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        results = await store.search_software_vulnerabilities("WinCC")
        assert len(results) == 1
        assert results[0].code == "BDA:2026-158"
        assert "«" in results[0].match_snippet
    finally:
        store.close()


async def test_svul_filters(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        sev = await store.search_software_vulnerabilities("", min_severity=3)
        assert [v.code for v in sev] == ["BDA:2026-158"]

        year = await store.search_software_vulnerabilities("", year=2024)
        assert [v.code for v in year] == ["BDA:2025-077"]

        expl = await store.search_software_vulnerabilities("", has_exploit=True)
        assert [v.code for v in expl] == ["BDA:2026-158"]

        eq = await store.search_software_vulnerabilities("", equipment="WinCC")
        assert [v.code for v in eq] == ["BDA:2026-158"]
    finally:
        store.close()


async def test_svul_get_normalizes_code(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        v = await store.get_software_vulnerability("bda:2026-158")
        assert v is not None
        assert isinstance(v, SoftwareVulnerability)
        assert v.exploit_presence.startswith("Существует")
    finally:
        store.close()


async def test_svul_get_missing(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        assert await store.get_software_vulnerability("BDA:9999-000") is None
    finally:
        store.close()


# ---- NSI -------------------------------------------------------------


async def test_nsi_kinds(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        ios = await store.search_nsi("influence_object", "контроллер")
        assert [i.code for i in ios] == ["ОА.006"]

        comps = await store.search_nsi("component", "прошивк")
        assert comps[0].extra.startswith("Программное обеспечение")

        viols = await store.search_nsi("violator", "базовыми")
        assert [i.code for i in viols] == ["ВА.001"]
        assert "хакеры" in viols[0].extra

        mis = await store.search_nsi("method_implement", "перехват")
        assert [i.code for i in mis] == ["СПА.02.003"]

        scenarios = await store.search_nsi("typical_scenario", "ПЛК")
        assert len(scenarios) == 1
        assert scenarios[0].title.startswith("С3.19")
    finally:
        store.close()


async def test_nsi_empty_query_lists_all(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        assert len(await store.search_nsi("influence_object", "")) == 2
        assert len(await store.search_nsi("violator", "")) == 1
    finally:
        store.close()


async def test_nsi_unknown_kind_raises(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        try:
            await store.search_nsi("nonsense", "")
            raised = False
        except ValueError:
            raised = True
        assert raised
    finally:
        store.close()


# ---- snapshot info ----------------------------------------------------


async def test_snapshot_info(sample_db: Path):
    store = await _make_store(sample_db)
    try:
        info = await store.snapshot_info()
        assert info.snapshot_date == "2026-11-08"
        assert info.schema_version == "1"
        assert info.counts["threats"] == 2
        assert info.counts["software_vulnerabilities"] == 2
    finally:
        store.close()


# ---- FTS escaping ------------------------------------------------------


def test_fts_escape_handles_injection():
    assert _escape_fts_query('OR "dangerous') == '"OR" dangerous*'
    assert _escape_fts_query("инъекция") == "инъекц*"
    assert _escape_fts_query("") == ""
