"""MCP stdio server exposing БДУ АСУ ТП ФСТЭК as a small set of tools."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool, ToolAnnotations

from . import __version__
from ._config import Config
from .cache import CacheManager
from .formatters import (
    format_measure_results,
    format_negcon_results,
    format_nsi_results,
    format_snapshot,
    format_svul_full,
    format_svul_results,
    format_threat_full,
    format_threat_results,
    strip_html,
)
from .models import SnapshotInfo
from .store import Store

logger = logging.getLogger("bdu_asutp_mcp")

DEFAULT_DB_NAME = "bdu_asutp.sqlite"


def _default_db_path() -> Path:
    return Config.from_env().cache_dir / DEFAULT_DB_NAME

NSI_KINDS = ["influence_object", "component", "violator", "method_implement", "typical_scenario"]


class AsutpServer:
    """Ties together config, cache, store, and the MCP protocol."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._config = Config.from_env()
        self._cache = CacheManager(self._config)
        self._db_path = db_path
        self._store: Store | None = None
        self._ready = asyncio.Lock()
        self._is_stale = False
        self._stale_reason = ""

    async def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None
        await self._cache.aclose()

    async def _ensure_ready(self) -> Store:
        if self._store is not None:
            return self._store
        async with self._ready:
            if self._store is not None:
                return self._store
            db_path = self._db_path or await self._cache.ensure()
            store = Store(db_path)
            store.open()
            # Staleness check is best-effort (needs network).
            snap = await store.snapshot_info()
            try:
                is_stale, reason = await self._cache.staleness_check(
                    snap.snapshot_date
                )
                self._is_stale = is_stale
                self._stale_reason = reason
            except Exception as exc:  # pragma: no cover — best effort
                logger.debug("staleness check failed: %s", exc)
            self._store = store
            return store

    async def refresh(self) -> None:
        """Force re-download of the snapshot from the mirror, reopen the store."""
        async with self._ready:
            if self._store is not None:
                self._store.close()
                self._store = None
            await self._cache.ensure(force=True)

    # ---- tool implementations --------------------------------------

    async def tool_search_threats(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        query = (args.get("query") or "").strip()
        limit = int(args.get("limit", 10))
        results = await store.search_threats(query, limit=limit)
        return format_threat_results(results, query or "(все угрозы)")

    async def tool_get_threat(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        key = (args.get("threat") or "").strip()
        if not key:
            return "Укажите код угрозы (например, УТП:01) или её идентификатор."
        t = await store.get_threat(key)
        if t is None:
            return f"Угроза {key} не найдена. В БДУ АСУ ТП всего 10 угроз (УТП:01…УТП:10)."
        return format_threat_full(t)

    async def tool_search_negative_consequences(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        query = (args.get("query") or "").strip()
        limit = int(args.get("limit", 10))
        activity_field = args.get("activity_field") or None
        object_title = args.get("object") or None
        filters: list[str] = []
        if activity_field:
            filters.append(f"вид деятельности: {activity_field}")
        if object_title:
            filters.append(f"объект: {object_title}")
        results = await store.search_negative_consequences(
            query,
            limit=limit,
            activity_field=activity_field,
            object_title=object_title,
        )
        return format_negcon_results(
            results, query or "(без текстового запроса)", ", ".join(filters)
        )

    async def tool_search_protection_measures(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        query = (args.get("query") or "").strip()
        limit = int(args.get("limit", 10))
        group_code = args.get("group_code") or None
        filters = f"группа: {group_code}" if group_code else ""
        results = await store.search_protection_measures(
            query, limit=limit, group_code=group_code
        )
        return format_measure_results(
            results, query or "(без текстового запроса)", filters
        )

    async def tool_search_software_vulnerabilities(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        query = (args.get("query") or "").strip()
        limit = int(args.get("limit", 10))
        min_severity = args.get("min_severity")
        if isinstance(min_severity, str):
            min_severity = {
                "низкий": 1, "средний": 2, "высокий": 3, "критический": 4,
            }.get(min_severity.lower())
        year = args.get("year")
        has_exploit = args.get("has_exploit")
        equipment = args.get("equipment") or None

        filters: list[str] = []
        if min_severity is not None:
            filters.append(f"опасность ≥ {min_severity}")
        if year is not None:
            filters.append(f"год: {int(year)}")
        if has_exploit is True:
            filters.append("есть эксплойт")
        if equipment:
            filters.append(f"оборудование: {equipment}")

        results = await store.search_software_vulnerabilities(
            query,
            limit=limit,
            min_severity=int(min_severity) if min_severity is not None else None,
            year=int(year) if year is not None else None,
            has_exploit=has_exploit if isinstance(has_exploit, bool) else None,
            equipment=equipment,
        )
        return format_svul_results(
            results, query or "(без текстового запроса)", ", ".join(filters)
        )

    async def tool_get_software_vulnerability(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        key = (args.get("vuln") or "").strip()
        if not key:
            return "Укажите код уязвимости (например, BDA:2026-158) или её идентификатор."
        v = await store.get_software_vulnerability(key)
        if v is not None:
            return format_svul_full(v)
        other = await store.get_web_or_config_vulnerability(key)
        if other is not None:
            lines = [f"{other.code} — {other.title}", f"  {other.extra}"]
            lines.append("")
            lines.append(strip_html(other.description))
            return "\n".join(lines)
        return f"Уязвимость {key} не найдена в снимке."

    async def tool_search_nsi(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        kind = (args.get("kind") or "").strip()
        if kind not in NSI_KINDS:
            return (
                "Укажите kind из списка: "
                + ", ".join(NSI_KINDS) + "."
            )
        query = (args.get("query") or "").strip()
        limit = int(args.get("limit", 10))
        items = await store.search_nsi(kind, query, limit=limit)
        return format_nsi_results(items, kind, query or "(все)")

    async def tool_stats(self, args: dict[str, Any]) -> str:
        store = await self._ensure_ready()
        info = await store.snapshot_info(
            is_stale=self._is_stale, stale_reason=self._stale_reason
        )
        return format_snapshot(info)


def _build_mcp_server(asutp: AsutpServer) -> Server:
    server: Server = Server("bdu-asutp-mcp", version=__version__)

    READ_ONLY = ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="search_asutp_threats",
                title="Search БДУ АСУ ТП threats",
                description=(
                    "Поиск угроз безопасности информации в АСУ ТП в БДУ АСУ ТП "
                    "ФСТЭК (Банк данных угроз безопасности информации в "
                    "автоматизированных системах управления технологическими "
                    "процессами). Индекс содержит все 10 угроз (УТП:01…УТП:10): "
                    "заголовок, описание, код. Поиск по подстроке в коде, "
                    "названии или описании. Пустой query → все угрозы. "
                    "Примечание: угроз всего 10 — для обзорного поиска "
                    "используйте пустой query. Read-only, локальный снимок."
                ),
                annotations=READ_ONLY,
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": (
                                "Подстрока для поиска по коду, названию и "
                                "описанию угрозы (русский). Примеры: «утечка "
                                "информации», «несанкционированный»."
                            ),
                            "examples": ["утечка", "НСД", "программный"],
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Максимум угроз в выдаче (1–50).",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 50,
                        },
                    },
                },
            ),
            Tool(
                name="get_asutp_threat",
                title="Get one БДУ АСУ ТП threat card",
                description=(
                    "Полная карточка угрозы БДУ АСУ ТП по коду `УТП:N` "
                    "(например, `УТП:01`, `УТП 3`) или UUID. Возвращает "
                    "описание, способы реализации угрозы по группам (СП.x → "
                    "СПА.x с кодами), объекты воздействия (ОА.x) и типовые "
                    "сценарии реализации, в шагах которых участвует угроза. "
                    "Read-only."
                ),
                annotations=READ_ONLY,
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "threat": {
                            "type": "string",
                            "description": (
                                "Код угрозы: `УТП:01`, `УТП:1`, `утп.01` или "
                                "UUID карточки."
                            ),
                            "examples": ["УТП:01", "УТП:03"],
                        }
                    },
                    "required": ["threat"],
                },
            ),
            Tool(
                name="search_asutp_negative_consequences",
                title="Search БДУ АСУ ТП negative consequences",
                description=(
                    "Поиск негативных последствий реализации угроз в БДУ АСУ ТП "
                    "ФСТЭК: типовое негативное последствие для объекта АСУ ТП, "
                    "типы последствий (экономический ущерб, причинение вреда "
                    "жизни и здоровью людей и т.п.), виды деятельности "
                    "(топливно-энергетический комплекс и др.), объект "
                    "воздействия, архитектура АСУ ТП. Полезно для "
                    "категорирования объектов КИИ и оценки ущерба по 187-ФЗ. "
                    "Read-only, локальный снимок."
                ),
                annotations=READ_ONLY,
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": (
                                "Подстрока по тексту последствия, объекту АСУ "
                                "ТП, типам последствий, архитектуре. Примеры: "
                                "«потеря управления», «энергетика», «SCADA»."
                            ),
                        },
                        "activity_field": {
                            "type": "string",
                            "description": (
                                "Фильтр по виду деятельности (подстрока): "
                                "«энергетический», «нефтегазовый», "
                                "«транспортный» и т.п."
                            ),
                        },
                        "object": {
                            "type": "string",
                            "description": (
                                "Фильтр по объекту АСУ ТП или объекту "
                                "воздействия (подстрока): «завод», "
                                "«подстанция», «водоканал»."
                            ),
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Максимум записей в выдаче (1–100).",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 100,
                        },
                    },
                },
            ),
            Tool(
                name="search_asutp_protection_measures",
                title="Search БДУ АСУ ТП protection measures",
                description=(
                    "Поиск мер защиты информации в АСУ ТП из БДУ АСУ ТП ФСТЭК "
                    "(сопоставимы с мерами приказа ФСТЭК №239 для АСУ ТП). "
                    "Возвращает код (ИАФ.0, УПД.5, АВЗ…), название, группу мер, "
                    "тип меры, применимые уровни АСУ ТП, категории значимости. "
                    "Фильтр по группе: ИАФ (идентификация и аутентификация), "
                    "УПД (управление доступом), АВЗ (антивирусная защита), РСБ "
                    "(регистрация событий), ОЦЛ (целостность), ЗИС и др. "
                    "Read-only, локальный снимок."
                ),
                annotations=READ_ONLY,
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": (
                                "Подстрока по коду, названию, описанию меры. "
                                "Примеры: «аутентификация», «пароль», "
                                "«журнал»."
                            ),
                        },
                        "group_code": {
                            "type": "string",
                            "description": (
                                "Фильтр по коду группы мер (подстрока): «ИАФ», "
                                "«УПД», «АВЗ», «РСБ»…"
                            ),
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Максимум мер в выдаче (1–100).",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 100,
                        },
                    },
                },
            ),
            Tool(
                name="search_asutp_software_vulnerabilities",
                title="Search БДУ АСУ ТП software vulnerabilities",
                description=(
                    "Поиск уязвимостей ПО АСУ ТП в БДУ АСУ ТП ФСТЭК "
                    "(идентификаторы BDA:YYYY-NNN, ~2900 записей): "
                    "полнотекстовый FTS5-поиск с BM25-ранжированием по "
                    "названию, описанию, ПО, производителям, оборудованию. "
                    "Фильтры: минимальный уровень опасности, год, наличие "
                    "эксплойта, оборудование (SCADA, ПЛК и т.п.). Отличать от "
                    "обычной БДУ (BDU:…): здесь коды BDA и только ПО АСУ ТП. "
                    "Read-only, локальный снимок."
                ),
                annotations=READ_ONLY,
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": (
                                "Полнотекстовый запрос. Токены автоматически "
                                "получают префиксный поиск с обрезкой "
                                "окончания для кириллицы. Примеры: «Siemens "
                                "S7», «SCADA», «переполнение буфера»."
                            ),
                            "examples": ["Siemens", "SCADA", "uintento"],
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Максимум уязвимостей в выдаче (1–100).",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 100,
                        },
                        "min_severity": {
                            "type": "string",
                            "description": "Минимальный уровень опасности по ФСТЭК.",
                            "enum": ["низкий", "средний", "высокий", "критический"],
                        },
                        "year": {
                            "type": "integer",
                            "description": "Год обнаружения уязвимости.",
                        },
                        "has_exploit": {
                            "type": "boolean",
                            "description": (
                                "true → только уязвимости, для которых "
                                "подтверждено существование эксплойта."
                            ),
                        },
                        "equipment": {
                            "type": "string",
                            "description": (
                                "Фильтр по оборудованию/ПО (подстрока): "
                                "«Siemens», «WinCC», «ПЛК»."
                            ),
                        },
                    },
                },
            ),
            Tool(
                name="get_asutp_software_vulnerability",
                title="Get one БДУ АСУ ТП vulnerability card",
                description=(
                    "Полная карточка уязвимости по коду `BDA:YYYY-NNN` "
                    "(например, `BDA:2026-158`) или UUID: описание, CVSS 2/3 "
                    "векторы, класс уязвимости, статус, присутствие эксплойта, "
                    "меры снижения, информация по устранению, затронутое "
                    "оборудование и версии ПО, производители, типы ошибок, "
                    "ссылки на источники. Также принимает коды типовых "
                    "веб-уязвимостей (`BDA:W###`) и уязвимостей конфигураций "
                    "(`BDA:C###`). Read-only."
                ),
                annotations=READ_ONLY,
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "vuln": {
                            "type": "string",
                            "description": "Код уязвимости (`BDA:2026-158`) или UUID.",
                            "examples": ["BDA:2026-158", "BDA:W005"],
                        }
                    },
                    "required": ["vuln"],
                },
            ),
            Tool(
                name="search_asutp_nsi",
                title="Search БДУ АСУ ТП reference lists (НСИ)",
                description=(
                    "Поиск по справочникам БДУ АСУ ТП ФСТЭК: объекты "
                    "воздействия (ОА.x — АРМ оператора, ПЛК, SCADA-сервер…), "
                    "компоненты (К.x.x.x — ПО, микропрограммы, технические "
                    "средства), нарушители (ВА.x — потенциал и тип), способы "
                    "реализации угроз (СПА.x), типовые сценарии (С3.x). "
                    "Укажите kind и подстроку. Read-only, локальный снимок."
                ),
                annotations=READ_ONLY,
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "kind": {
                            "type": "string",
                            "description": (
                                "Раздел справочника: influence_object (объекты "
                                "воздействия ОА), component (компоненты К), "
                                "violator (нарушители ВА), method_implement "
                                "(способы реализации СПА), typical_scenario "
                                "(типовые сценарии)."
                            ),
                            "enum": NSI_KINDS,
                        },
                        "query": {
                            "type": "string",
                            "description": (
                                "Подстрока для поиска. Пустой query → весь "
                                "раздел (объектов воздействия 14, нарушителей "
                                "4, компонентов ~40)."
                            ),
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Максимум записей в выдаче (1–100).",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 100,
                        },
                    },
                    "required": ["kind"],
                },
            ),
            Tool(
                name="get_asutp_stats",
                title="БДУ АСУ ТП snapshot statistics",
                description=(
                    "Метаданные локального снимка БДУ АСУ ТП: дата сборки, "
                    "число угроз, сценариев, компонентов, объектов воздействия, "
                    "нарушителей, негативных последствий, мер защиты, "
                    "уязвимостей. Нет побочных эффектов."
                ),
                annotations=READ_ONLY,
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        try:
            handlers = {
                "search_asutp_threats": asutp.tool_search_threats,
                "get_asutp_threat": asutp.tool_get_threat,
                "search_asutp_negative_consequences": asutp.tool_search_negative_consequences,
                "search_asutp_protection_measures": asutp.tool_search_protection_measures,
                "search_asutp_software_vulnerabilities": asutp.tool_search_software_vulnerabilities,
                "get_asutp_software_vulnerability": asutp.tool_get_software_vulnerability,
                "search_asutp_nsi": asutp.tool_search_nsi,
                "get_asutp_stats": asutp.tool_stats,
            }
            handler = handlers.get(name)
            if handler is None:
                text = f"Неизвестный инструмент: {name}"
            else:
                text = await handler(arguments)
        except Exception as exc:
            logger.exception("tool %s failed", name)
            text = f"Ошибка при выполнении инструмента {name}: {exc}"
        return [TextContent(type="text", text=text)]

    return server


async def _run() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    asutp = AsutpServer()
    try:
        mcp_server = _build_mcp_server(asutp)
        async with stdio_server() as (read, write):
            await mcp_server.run(read, write, mcp_server.create_initialization_options())
    finally:
        await asutp.close()


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
