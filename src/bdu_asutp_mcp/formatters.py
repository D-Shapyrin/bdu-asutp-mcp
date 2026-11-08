"""Pretty-printers that turn domain objects into text blocks for the LLM."""

from __future__ import annotations

import re

from .models import (
    NegativeConsequence,
    NsiItem,
    ProtectionMeasure,
    SnapshotInfo,
    SoftwareVulnerability,
    Threat,
)

_DESC_PREVIEW_LIMIT = 400

_TAG_RE = re.compile(r"<[^>]+>")


def strip_html(text: str, limit: int | None = None) -> str:
    """The API returns descriptions as HTML (<p>…); keep plain text."""
    text = _TAG_RE.sub("", text).replace("&nbsp;", " ").replace("\r\n", "\n").strip()
    text = re.sub(r"\n{3,}", "\n\n", text)
    if limit and len(text) > limit:
        return text[:limit].rstrip() + "…"
    return text


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "…"


def format_threat_short(t: Threat) -> str:
    lines = [f"{t.code} — {t.title}"]
    if t.publication_at:
        lines.append(f"  Опубликовано: {t.publication_at}")
    lines.append(f"  {t.url}")
    if t.description:
        lines.append(f"  {_truncate(strip_html(t.description), _DESC_PREVIEW_LIMIT)}")
    return "\n".join(lines)


def format_threat_full(t: Threat) -> str:
    parts = [format_threat_short(t)]
    extras: list[str] = []
    if t.description:
        extras.append("Описание:\n" + strip_html(t.description))
    if t.methods:
        by_group: dict[str, list[str]] = {}
        for group, code, title in t.methods:
            by_group.setdefault(f"{group}", []).append(
                f"{code} {title}" if code else title
            )
        extras.append("Способы реализации:")
        for group, items in by_group.items():
            extras.append(f"  {group}:")
            extras.extend(f"    - {item}" for item in items)
    if t.influence_objects:
        extras.append("Объекты воздействия: " + ", ".join(
            f"{io.code} «{io.title}»" for io in t.influence_objects
        ))
    if t.scenarios:
        extras.append("Типовые сценарии, где встречается:")
        extras.extend(f"  - {s}" for s in t.scenarios)
    if extras:
        parts.append("")
        parts.extend(extras)
    return "\n".join(parts)


def format_threat_results(results: list[Threat], query: str) -> str:
    if not results:
        return f"Ничего не найдено по запросу «{query}»."
    header = f"Найдено {len(results)} угроз по запросу «{query}»"
    body = "\n\n".join(format_threat_short(t) for t in results)
    return f"{header}:\n\n{body}"


def format_negcon_short(nc: NegativeConsequence) -> str:
    lines = [nc.typical_text or "(без описания)"]
    lines.append(f"  Объект АСУ ТП: {nc.object_title}")
    if nc.consequence_types:
        lines.append(f"  Типы последствий: {nc.consequence_types}")
    if nc.activity_fields:
        lines.append(f"  Виды деятельности: {nc.activity_fields}")
    if nc.afo_title:
        lines.append(f"  Объект воздействия: {nc.afo_title}")
    if nc.architectures:
        lines.append(f"  Архитектура АСУ ТП: {nc.architectures}")
    if nc.publication_at:
        lines.append(f"  Опубликовано: {nc.publication_at}")
    return "\n".join(lines)


def format_negcon_results(results: list[NegativeConsequence], query: str, filters: str = "") -> str:
    if not results:
        tail = f" ({filters})" if filters else ""
        return f"Ничего не найдено по запросу «{query}»{tail}."
    header = f"Найдено {len(results)} негативных последствий по запросу «{query}»"
    if filters:
        header += f" ({filters})"
    body = "\n\n".join(format_negcon_short(nc) for nc in results)
    return f"{header}:\n\n{body}"


def format_measure_short(m: ProtectionMeasure) -> str:
    lines = [f"{m.code} — {m.title}"]
    if m.group_code or m.group_title:
        lines.append(f"  Группа: {m.group_code} {m.group_title}".rstrip())
    if m.measure_type:
        lines.append(f"  Тип меры: {m.measure_type}")
    if m.description:
        lines.append(f"  {_truncate(strip_html(m.description), _DESC_PREVIEW_LIMIT)}")
    lines.append(f"  {m.url}")
    return "\n".join(lines)


def format_measure_full(m: ProtectionMeasure) -> str:
    parts = [format_measure_short(m)]
    extras: list[str] = []
    if m.description:
        extras.append("Описание:\n" + strip_html(m.description))
    if m.asu_tp_levels:
        extras.append(f"Уровни АСУ ТП: {m.asu_tp_levels}")
    if m.importance_categs:
        extras.append(f"Категории значимости: {m.importance_categs}")
    if m.promising_techs:
        extras.append(f"Перспективные технологии: {m.promising_techs}")
    if m.publication_at:
        extras.append(f"Опубликовано: {m.publication_at}")
    if extras:
        parts.append("")
        parts.extend(extras)
    return "\n".join(parts)


def format_measure_results(results: list[ProtectionMeasure], query: str, filters: str = "") -> str:
    if not results:
        tail = f" ({filters})" if filters else ""
        return f"Ничего не найдено по запросу «{query}»{tail}."
    header = f"Найдено {len(results)} мер защиты по запросу «{query}»"
    if filters:
        header += f" ({filters})"
    body = "\n\n".join(format_measure_short(m) for m in results)
    return f"{header}:\n\n{body}"


def format_svul_short(v: SoftwareVulnerability) -> str:
    lines = [f"{v.code} — {v.title}"]
    if v.severity:
        lines.append(f"  Опасность: {v.severity}")
    if v.equipments:
        preview = _truncate(v.equipments, 200)
        lines.append(f"  Оборудование/ПО: {preview}")
    if v.publication_at:
        lines.append(f"  Опубликовано: {v.publication_at}")
    if v.exploit_presence:
        lines.append(f"  Эксплойт: {v.exploit_presence}")
    lines.append(f"  Ссылки: {v.source_links or '—'}")
    body = v.match_snippet or v.description
    if body:
        lines.append(f"  {_truncate(strip_html(body), _DESC_PREVIEW_LIMIT)}")
    return "\n".join(lines)


def format_svul_full(v: SoftwareVulnerability) -> str:
    parts = [format_svul_short(v)]
    extras: list[str] = []
    if v.description:
        extras.append("Описание:\n" + strip_html(v.description))
    if v.mitigation:
        extras.append("Возможные меры снижения: " + strip_html(v.mitigation))
    if v.repair_info:
        extras.append(f"Устранение: {v.repair_info}")
    if v.cvssv3_vector:
        extras.append(f"CVSS 3.0: {v.cvssv3_vector}")
    if v.cvssv2_vector:
        extras.append(f"CVSS 2.0: {v.cvssv2_vector}")
    if v.vuln_class:
        extras.append(f"Класс уязвимости: {v.vuln_class}")
    if v.status:
        extras.append(f"Статус: {v.status}")
    if v.eliminate_solution:
        extras.append(f"Решение: {v.eliminate_solution}")
    if v.software_names:
        extras.append(f"Версии ПО: {v.software_names}")
    if v.manufacturers:
        extras.append(f"Производители: {v.manufacturers}")
    if v.equipment_types:
        extras.append(f"Типы оборудования: {v.equipment_types}")
    if v.hardware_platforms:
        extras.append(f"Аппаратные платформы: {v.hardware_platforms}")
    if v.error_types:
        extras.append(f"Типы ошибок: {v.error_types}")
    if v.discovered_at:
        extras.append(f"Обнаружена: {v.discovered_at}")
    if v.other_info:
        extras.append("Прочее: " + strip_html(v.other_info))
    if extras:
        parts.append("")
        parts.extend(extras)
    return "\n".join(parts)


def format_svul_results(
    results: list[SoftwareVulnerability], query: str, filters: str = ""
) -> str:
    if not results:
        tail = f" ({filters})" if filters else ""
        return f"Ничего не найдено по запросу «{query}»{tail}."
    header = f"Найдено {len(results)} уязвимостей по запросу «{query}»"
    if filters:
        header += f" ({filters})"
    body = "\n\n".join(format_svul_short(v) for v in results)
    return f"{header}:\n\n{body}"


_NSI_KIND_LABELS = {
    "influence_object": "Объекты воздействия",
    "component": "Компоненты АСУ ТП",
    "violator": "Нарушители",
    "method_implement": "Способы реализации угроз",
    "typical_scenario": "Типовые сценарии реализации угроз",
}


def format_nsi_results(items: list[NsiItem], kind: str, query: str) -> str:
    label = _NSI_KIND_LABELS.get(kind, kind)
    if not items:
        return f"Ничего не найдено в разделе «{label}» по запросу «{query}»."
    header = f"{label} — найдено {len(items)} по запросу «{query}»"
    lines = []
    for item in items:
        line = f"  {item.code} «{item.title}»" if item.code else f"  «{item.title}»"
        if item.extra:
            line += f"  [{item.extra}]"
        if item.url:
            line += f"\n    {item.url}"
        if item.description:
            line += f"\n    {_truncate(strip_html(item.description), 300)}"
        lines.append(line)
    return header + ":\n" + "\n".join(lines)


def format_snapshot(info: SnapshotInfo) -> str:
    lines = [
        "БДУ АСУ ТП ФСТЭК — локальный снимок",
        f"  Дата снимка: {info.snapshot_date}",
        f"  Схема: {info.schema_version}",
    ]
    labels = {
        "threats": "Угроз (УТП)",
        "typical_scenarios": "Типовых сценариев",
        "components": "Компонентов (К)",
        "influence_objects": "Объектов воздействия (ОА)",
        "violators": "Нарушителей (ВА)",
        "method_implement_threat_groups": "Групп способов реализации",
        "negative_consequences": "Негативных последствий",
        "negative_consequence_objects": "Объектов с последствиями",
        "protection_measures": "Мер защиты",
        "software_vulnerabilities": "Уязвимостей ПО АСУ ТП (BDA)",
        "configuration_vulnerabilities": "Уязвимостей конфигураций",
        "typical_web_vulnerabilities": "Типовых веб-уязвимостей",
    }
    for key, label in labels.items():
        if key in info.counts:
            lines.append(f"  {label}: {info.counts[key]}")
    if info.is_stale:
        lines.append(f"  ⚠ Снимок устарел: {info.stale_reason}")
    return "\n".join(lines)
