"""Formatters produce the text blocks surfaced to the LLM."""

from __future__ import annotations

from bdu_asutp_mcp.formatters import (
    format_measure_short,
    format_negcon_results,
    format_nsi_results,
    format_snapshot,
    format_svul_full,
    format_svul_short,
    format_threat_full,
    format_threat_short,
    strip_html,
)
from bdu_asutp_mcp.models import (
    NegativeConsequence,
    NsiItem,
    ProtectionMeasure,
    SnapshotInfo,
    SoftwareVulnerability,
    Threat,
)


def test_strip_html_removes_tags():
    assert strip_html("<p>Раз.</p>\r\n\r\n<p align='justify'>Два.</p>") == "Раз.\n\nДва."


def test_threat_short_and_full():
    t = Threat(
        id="111", code="УТП:01", title="Угроза утечки информации",
        description="<p>Утечка через сеть.</p>", publication_at="24.10.2023",
        url="https://bduasutp.fstec.ru/#/threat-view/111",
        methods=(("СП.1", "СПА.01.001", "Эксплуатация известных уязвимостей"),),
        influence_objects=(NsiItem(
            kind="influence_object", id="222", code="ОА.001", title="АРМ оператора",
            url="x",
        ),),
        scenarios=("С3.19 Сценарий [cdcdcdcd]",),
    )
    short = format_threat_short(t)
    assert "УТП:01" in short
    assert "Утечка через сеть." in short
    full = format_threat_full(t)
    assert "СПА.01.001" in full
    assert "ОА.001 «АРМ оператора»" in full
    assert "С3.19" in full


def test_negcon_results_header_and_body():
    nc = NegativeConsequence(
        id="333", object_title="Нефтеперерабатывающий завод",
        typical_text="Ухудшение качества", consequence_types="Экономический ущерб",
        architectures="", activity_fields="ТЭК", afo_title="Завод",
        publication_at="04.12.2023",
    )
    text = format_negcon_results([nc], "качество", "вид деятельности: ТЭК")
    assert "Найдено 1 негативных последствий" in text
    assert "вид деятельности: ТЭК" in text
    assert "Экономический ущерб" in text
    assert "Ничего" in format_negcon_results([], "x")


def test_measure_short():
    m = ProtectionMeasure(
        id="444", code="ИАФ.0", title="Идентификация", description="Описание",
        group_code="ИАФ", group_title="Идентификация и аутентификация",
        measure_type="Общая", asu_tp_levels="", promising_techs="",
        importance_categs="", publication_at="16.12.2024",
        url="https://bduasutp.fstec.ru/#/bdu/protection-measures/444",
    )
    text = format_measure_short(m)
    assert "ИАФ.0" in text
    assert "Группа: ИАФ Идентификация и аутентификация" in text
    assert "bduasutp.fstec.ru" in text


def test_svul_short_and_full():
    v = SoftwareVulnerability(
        id="555", code="BDA:2026-158", title="Уязвимость WinCC",
        description="<p>Переполнение буфера.</p>", mitigation="Обновить",
        repair_info="Данные уточняются", source_links="example.com",
        other_info="", cvssv2_vector="", cvssv3_vector="AV:N",
        severity="Высокий уровень опасности", severity_level=3,
        vuln_class="Архитектуры", status="Не подтверждена",
        exploit_presence="Существует в открытом доступе",
        eliminate_solution="", year=2025, discovered_at="03.08.2025",
        publication_at="05.06.2026", software_names="", manufacturers="",
        equipments="WinCC Runtime", equipment_types="", hardware_platforms="",
        error_types="", external_systems="",
    )
    short = format_svul_short(v)
    assert "BDA:2026-158" in short
    assert "Опасность: Высокий" in short
    assert "Эксплойт: Существует" in short
    full = format_svul_full(v)
    assert "Переполнение буфера." in full
    assert "Возможные меры снижения: Обновить" in full
    assert "Класс уязвимости: Архитектуры" in full


def test_nsi_results():
    items = [
        NsiItem(kind="component", id="666", code="К.1.1.1", title="Прошивка",
                extra="Программное обеспечение; Микропрограммное",
                url="https://x/#/components-view/666"),
    ]
    text = format_nsi_results(items, "component", "прошивк")
    assert "Компоненты АСУ ТП — найдено 1" in text
    assert "К.1.1.1" in text
    assert "Микропрограммное" in text


def test_snapshot():
    info = SnapshotInfo(
        snapshot_date="2026-11-08", schema_version="1",
        counts={"threats": 10, "software_vulnerabilities": 2918},
    )
    text = format_snapshot(info)
    assert "2026-11-08" in text
    assert "Угроз (УТП): 10" in text
    assert "Уязвимостей ПО АСУ ТП (BDA): 2918" in text
