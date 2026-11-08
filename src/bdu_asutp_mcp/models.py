"""Value objects returned by the store."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Threat:
    id: str
    code: str  # УТП:01
    title: str
    description: str
    publication_at: str
    url: str
    methods: tuple[tuple[str, str, str], ...] = field(default_factory=tuple)
    # (group, mi_code, mi_title) — способы реализации угрозы
    influence_objects: tuple["NsiItem", ...] = field(default_factory=tuple)
    scenarios: tuple[str, ...] = field(default_factory=tuple)
    # типовые сценарии, в шагах которых участвует угроза


@dataclass(frozen=True)
class NegativeConsequence:
    id: str
    object_title: str  # объект АСУ ТП (напр., «Нефтеперерабатывающий завод»)
    typical_text: str
    consequence_types: str
    architectures: str
    activity_fields: str
    afo_title: str  # объект воздействия по виду деятельности
    publication_at: str


@dataclass(frozen=True)
class ProtectionMeasure:
    id: str
    code: str  # ИАФ.0
    title: str
    description: str
    group_code: str
    group_title: str
    measure_type: str
    asu_tp_levels: str
    promising_techs: str
    importance_categs: str
    publication_at: str
    url: str


@dataclass(frozen=True)
class SoftwareVulnerability:
    id: str
    code: str  # BDA:2026-158
    title: str
    description: str
    mitigation: str
    repair_info: str
    source_links: str
    other_info: str
    cvssv2_vector: str
    cvssv3_vector: str
    severity: str
    severity_level: int
    vuln_class: str
    status: str
    exploit_presence: str
    eliminate_solution: str
    year: int | None
    discovered_at: str
    publication_at: str
    software_names: str
    manufacturers: str
    equipments: str
    equipment_types: str
    hardware_platforms: str
    error_types: str
    external_systems: str
    match_snippet: str = ""


@dataclass(frozen=True)
class NsiItem:
    """A reference-list entry (объект воздействия, компонент, нарушитель,
    способ реализации угрозы, типовой сценарий)."""

    kind: str  # influence_object | component | violator | method_implement | typical_scenario
    id: str
    code: str
    title: str
    description: str = ""
    extra: str = ""  # kind-specific one-liner (тип компонента, тип нарушителя…)
    url: str = ""


@dataclass(frozen=True)
class SnapshotInfo:
    snapshot_date: str
    schema_version: str
    counts: dict[str, int]
    is_stale: bool = False
    stale_reason: str = ""
