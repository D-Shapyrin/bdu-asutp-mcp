"""Entry-point CLI: run (default), stats, refresh, fetch, publish."""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bdu-asutp-mcp",
        description="MCP-сервер для БДУ АСУ ТП ФСТЭК (Russian ICS threat database).",
    )
    parser.add_argument("--version", action="version", version=f"bdu-asutp-mcp {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("run", help="Запустить MCP stdio-сервер (по умолчанию).")
    sub.add_parser("stats", help="Метаданные локального снимка.")
    sub.add_parser(
        "refresh", help="Перекачать снимок с зеркала (GitHub) в локальный кэш."
    )
    fetch = sub.add_parser(
        "fetch", help="Скачать данные напрямую из API ФСТЭК и пересобрать снимок."
    )
    fetch.add_argument(
        "--db",
        type=str,
        default=None,
        help="Путь к SQLite-снимку (по умолчанию ~/.cache/bdu-asutp-mcp/bdu_asutp.sqlite).",
    )
    publish = sub.add_parser(
        "publish",
        help="Подготовить артефакты для зеркала (data/bdu_asutp.sqlite.gz + stats.json).",
    )
    publish.add_argument(
        "--db",
        type=str,
        default=None,
        help="Исходный снимок (по умолчанию ~/.cache/bdu-asutp-mcp/bdu_asutp.sqlite).",
    )
    publish.add_argument(
        "--out",
        type=str,
        required=True,
        help="Каталог зеркала (в него лягут data/… и stats.json).",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    cmd = args.command or "run"
    if cmd == "run":
        from .server import main as run_main

        run_main()
    elif cmd == "stats":
        from .cache import MirrorUnavailableError
        from .formatters import format_snapshot
        from .server import AsutpServer

        bdu = AsutpServer()
        try:
            print(asyncio.run(bdu.tool_stats({})))
        except MirrorUnavailableError as exc:
            print(f"Ошибка: {exc}", file=sys.stderr)
            sys.exit(1)
        finally:
            asyncio.run(bdu.close())
    elif cmd == "refresh":
        from .cache import MirrorUnavailableError
        from ._config import Config
        from .cache import CacheManager

        async def _refresh() -> None:
            cache = CacheManager(Config.from_env())
            try:
                path = await cache.ensure(force=True)
                print(f"Снимок обновлён: {path}")
            finally:
                await cache.aclose()

        try:
            asyncio.run(_refresh())
        except MirrorUnavailableError as exc:
            print(f"Ошибка: {exc}", file=sys.stderr)
            sys.exit(1)
    elif cmd == "fetch":
        import json
        from pathlib import Path

        from .fetch import build_snapshot
        from .server import _default_db_path

        db = Path(args.db) if args.db else _default_db_path()
        db.parent.mkdir(parents=True, exist_ok=True)
        counts = build_snapshot(db)
        print(f"Snapshot rebuilt: {db}")
        print(json.dumps(counts, ensure_ascii=False))
    elif cmd == "publish":
        from pathlib import Path

        from .publish import publish_mirror
        from .server import _default_db_path

        db = Path(args.db) if args.db else _default_db_path()
        out = Path(args.out)
        stats = publish_mirror(db, out)
        import json

        print(f"Published to {out}:")
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    else:
        raise SystemExit(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
