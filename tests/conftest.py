"""Shared pytest fixtures — builds a tiny synthetic SQLite snapshot."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from bdu_asutp_mcp.fetch import SCHEMA


SAMPLE_THREATS = [
    ("11111111-1111-1111-1111-111111111111", "УТП:01", "Угроза утечки информации",
     "<p>Угроза утечки конфиденциальной информации через каналы передачи данных.</p>",
     "24.10.2023"),
    ("22222222-2222-2222-2222-222222222222", "УТП:03",
     "Угроза удаленного несанкционированного подключения к компонентам АСУ ТП",
     "<p>Угроза НСД к компонентам АСУ ТП через инженерные интерфейсы.</p>",
     "24.10.2023"),
]

SAMPLE_METHODS = [
    ("11111111-1111-1111-1111-111111111111", "СП.1", "Эксплуатация уязвимостей",
     "aaaaaaaa-0000-0000-0000-000000000001", "СПА.01.001", "Эксплуатация известных уязвимостей"),
    ("11111111-1111-1111-1111-111111111111", "СП.2", "Компрометация учетных данных",
     "aaaaaaaa-0000-0000-0000-000000000002", "СПА.02.003", "Перехват паролей"),
    ("22222222-2222-2222-2222-222222222222", "СП.1", "Эксплуатация уязвимостей",
     "aaaaaaaa-0000-0000-0000-000000000003", "СПА.01.002", "Эксплуатация необнаруженных уязвимостей"),
]

SAMPLE_IOS = [
    ("bbbbbbbb-0000-0000-0000-000000000001", "ОА.001",
     "Автоматизированное рабочее место оператора (диспетчера)", "АРМ диспетчера."),
    ("bbbbbbbb-0000-0000-0000-000000000002", "ОА.006",
     "Программируемый логический контроллер", "ПЛК."),
]

SAMPLE_TIO = [
    ("11111111-1111-1111-1111-111111111111", "bbbbbbbb-0000-0000-0000-000000000001"),
    ("22222222-2222-2222-2222-222222222222", "bbbbbbbb-0000-0000-0000-000000000002"),
]

SAMPLE_COMPONENTS = [
    ("cccccccc-0000-0000-0000-000000000001", "К.1.1.1", "Прошивка (встроенная микропрограмма)",
     "К.1", "Программное обеспечение", "К.1.1", "Микропрограммное обеспечение"),
]

SAMPLE_OBJECT_COMPONENTS = [
    ("bbbbbbbb-0000-0000-0000-000000000001", "cccccccc-0000-0000-0000-000000000001"),
]

SAMPLE_VIOLATORS = [
    ("dddddddd-0000-0000-0000-000000000001", "ВА.001",
     "Нарушитель, обладающий базовыми возможностями", "Описание ВА.001",
     "Отдельные физические лица (хакеры)"),
]

SAMPLE_NCO = [
    ("eeeeeeee-0000-0000-0000-000000000001", "Нефтеперерабатывающий завод"),
]

SAMPLE_NEGCONS = [
    ("ffffffff-0000-0000-0000-000000000001", "eeeeeeee-0000-0000-0000-000000000001",
     "Нефтеперерабатывающий завод",
     "Ухудшение качества обессоливания нефти", "Экономический ущерб",
     "Распределенная система управления", "Топливно-энергетический комплекс",
     "Нефтеперерабатывающий завод", "04.12.2023"),
    ("ffffffff-0000-0000-0000-000000000002", "eeeeeeee-0000-0000-0000-000000000001",
     "Нефтеперерабатывающий завод",
     "Остановка технологического процесса", "Причинение вреда", "",
     "Топливно-энергетический комплекс", "Нефтеперерабатывающий завод", "04.12.2023"),
]

SAMPLE_MEASURES = [
    ("abababab-0000-0000-0000-000000000001", "ИАФ.0",
     "Регламентация правил и процедур идентификации и аутентификации",
     "Описание меры ИАФ.0", "ИАФ", "Идентификация и аутентификация",
     "Общая мера защиты информации", "Первый, Второй, Третий уровень", "", "",
     "16.12.2024"),
    ("abababab-0000-0000-0000-000000000002", "УПД.5",
     "Управление учетными записями", "Описание УПД.5", "УПД",
     "Управление доступом", "", "Третий уровень", "", "", "16.12.2024"),
]

SAMPLE_SCENARIOS = [
    ("cdcdcdcd-0000-0000-0000-000000000001",
     "С3.19 Несанкционированное изменение конфигурации ПЛК внутренним нарушителем",
     "Типовые сценарии для систем диспетчерского контроля (SCADA)"),
]

SAMPLE_STEPS = [
    ("cdcdcdcd-0000-0000-0000-000000000001", 1,
     "Получение НСД к АРМ управления ТП", "22222222-2222-2222-2222-222222222222"),
]

SAMPLE_SVULNS = [
    {
        "rowid": 1,
        "id": "eaeaeaea-0000-0000-0000-000000000001",
        "code": "BDA:2026-158",
        "title": "Уязвимость SCADA-системы Siemens WinCC",
        "description": "Переполнение буфера в модуле обработки тегов WinCC.",
        "mitigation": "Установить обновление",
        "repair_info": "Данные уточняются",
        "source_links": "example.com/advisory",
        "other_info": "",
        "cvssv2_vector": "CVSS 2.0: AV:N/AC:L/Au:N/C:C/I:C/A:N",
        "cvssv3_vector": "CVSS 3.0: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "severity": "Высокий уровень опасности",
        "severity_level": 3,
        "vuln_class": "Уязвимость архитектуры",
        "status": "Не подтверждена",
        "exploit_presence": "Существует в открытом доступе",
        "eliminate_solution": "Данные уточняются",
        "year": 2025,
        "discovered_at": "03.08.2025",
        "publication_at": "05.06.2026",
        "software_names": "от 2020 до 2025 включительно (DELMIA Apriso)",
        "manufacturers": "Dassault Systmes; Siemens",
        "equipments": "DELMIA Apriso; WinCC Runtime",
        "equipment_types": "Средство АСУ ТП",
        "hardware_platforms": "Не указана",
        "error_types": "CWE-120 Переполнение буфера",
        "external_systems": "",
    },
    {
        "rowid": 2,
        "id": "eaeaeaea-0000-0000-0000-000000000002",
        "code": "BDA:2025-077",
        "title": "Уязвимость ПЛК Ogasa",
        "description": "Недостатки аутентификации в веб-интерфейсе ПЛК.",
        "mitigation": "", "repair_info": "", "source_links": "", "other_info": "",
        "cvssv2_vector": "", "cvssv3_vector": "",
        "severity": "Средний уровень опасности",
        "severity_level": 2,
        "vuln_class": "Уязвимость реализации",
        "status": "Подтверждена",
        "exploit_presence": "Отсутствует",
        "eliminate_solution": "Устранена производителем",
        "year": 2024,
        "discovered_at": "01.03.2024",
        "publication_at": "10.05.2025",
        "software_names": "Ogasa firmware 1.2",
        "manufacturers": "Ogasa",
        "equipments": "ПЛК Ogasa",
        "equipment_types": "Средство АСУ ТП",
        "hardware_platforms": "",
        "error_types": "",
        "external_systems": "",
    },
]

SAMPLE_CONFIG_VULNS = [
    ("cbcbcbcb-0000-0000-0000-000000000001", "BDA:C010",
     "Отсутствие ограничений времени неактивности пользователей", "Описание C010",
     "Неавтоматизированные объекты", "АСУ ТП", "CWE-613",
     "УТП:01 Угроза утечки информации", "ИАФ.0 Регламентация правил"),
]

SAMPLE_WEB_VULNS = [
    ("wbwbwbwb-0000-0000-0000-000000000001", "BDA:W005",
     "Уязвимости, связанные с недостатками управления ресурсами", "Описание W005",
     "Способы эксплуатации", "Рекомендации", "Сценарии", "Записи", "ссылки"),
]

SVUL_COLUMNS = [
    "rowid", "id", "code", "title", "description", "mitigation", "repair_info",
    "source_links", "other_info", "cvssv2_vector", "cvssv3_vector", "severity",
    "severity_level", "vuln_class", "status", "exploit_presence",
    "eliminate_solution", "year", "discovered_at", "publication_at",
    "software_names", "manufacturers", "equipments", "equipment_types",
    "hardware_platforms", "error_types", "external_systems",
]


def build_sample_db(path: Path, snapshot_date: str = "2026-11-08") -> None:
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT INTO threats (id, code, title, description, publication_at) VALUES (?,?,?,?,?)",
        SAMPLE_THREATS,
    )
    conn.executemany(
        "INSERT INTO threat_methods (threat_id, group_code, group_title, mi_id, mi_code, mi_title) "
        "VALUES (?,?,?,?,?,?)",
        SAMPLE_METHODS,
    )
    conn.executemany(
        "INSERT INTO influence_objects (id, code, title, description) VALUES (?,?,?,?)",
        SAMPLE_IOS,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO threat_influence_objects (threat_id, io_id) VALUES (?,?)",
        SAMPLE_TIO,
    )
    conn.executemany(
        "INSERT INTO components (id, code, title, type_code, type_title, subtype_code, subtype_title) "
        "VALUES (?,?,?,?,?,?,?)",
        SAMPLE_COMPONENTS,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO object_components (object_id, component_id) VALUES (?,?)",
        SAMPLE_OBJECT_COMPONENTS,
    )
    conn.executemany(
        "INSERT INTO violators (id, code, title, description, violator_types) VALUES (?,?,?,?,?)",
        SAMPLE_VIOLATORS,
    )
    conn.executemany(
        "INSERT INTO negative_consequence_objects (id, title) VALUES (?,?)",
        SAMPLE_NCO,
    )
    conn.executemany(
        "INSERT INTO negative_consequences "
        "(id, object_id, object_title, typical_text, consequence_types, architectures, "
        " activity_fields, afo_title, publication_at) VALUES (?,?,?,?,?,?,?,?,?)",
        SAMPLE_NEGCONS,
    )
    conn.executemany(
        "INSERT INTO protection_measures "
        "(id, code, title, description, group_code, group_title, measure_type, "
        " asu_tp_levels, promising_techs, importance_categs, publication_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        SAMPLE_MEASURES,
    )
    conn.executemany(
        "INSERT INTO typical_scenarios (id, title, type_title) VALUES (?,?,?)",
        SAMPLE_SCENARIOS,
    )
    conn.executemany(
        "INSERT INTO scenario_steps (scenario_id, step_no, description, threat_id) VALUES (?,?,?,?)",
        SAMPLE_STEPS,
    )
    for v in SAMPLE_SVULNS:
        conn.execute(
            f"INSERT INTO software_vulnerabilities ({', '.join(SVUL_COLUMNS)}) "
            f"VALUES ({', '.join('?' * len(SVUL_COLUMNS))})",
            [v[c] for c in SVUL_COLUMNS],
        )
    conn.executemany(
        "INSERT INTO configuration_vulnerabilities "
        "(id, code, title, description, vuln_group, equipment_types, error_types, "
        " threats_joined, protection_measures) VALUES (?,?,?,?,?,?,?,?,?)",
        SAMPLE_CONFIG_VULNS,
    )
    conn.executemany(
        "INSERT INTO typical_web_vulnerabilities "
        "(id, code, title, description, operation_methods, prevention_recommendations, "
        " threat_scenarios, vulnerability_records, source_links) VALUES (?,?,?,?,?,?,?,?,?)",
        SAMPLE_WEB_VULNS,
    )
    conn.execute("INSERT INTO software_vulnerabilities_fts(software_vulnerabilities_fts) VALUES('rebuild')")
    counts = {
        "threats": len(SAMPLE_THREATS),
        "negative_consequences": len(SAMPLE_NEGCONS),
        "protection_measures": len(SAMPLE_MEASURES),
        "software_vulnerabilities": len(SAMPLE_SVULNS),
    }
    for key, value in (
        ("snapshot_date", snapshot_date),
        ("schema_version", "1"),
        ("counts", json.dumps(counts)),
    ):
        conn.execute("INSERT INTO metadata(key, value) VALUES (?,?)", (key, value))
    conn.commit()
    conn.close()


@pytest.fixture
def sample_db(tmp_path: Path) -> Path:
    path = tmp_path / "bdu_asutp.sqlite"
    build_sample_db(path)
    return path
