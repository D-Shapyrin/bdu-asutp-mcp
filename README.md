# bdu-asutp-mcp — БДУ АСУ ТП ФСТЭК для LLM

[![Mirror snapshot](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FD-Shapyrin%2Fbdu-asutp-mirror%2Fmain%2Fstats.json&query=%24.snapshot_date&label=mirror%20snapshot&color=blue)](https://github.com/D-Shapyrin/bdu-asutp-mirror)

MCP-сервер поверх [Банка данных угроз безопасности информации в АСУ ТП ФСТЭК России](https://bduasutp.fstec.ru) ([bduasutp.fstec.ru](https://bduasutp.fstec.ru)). Данные хранятся в локальном SQLite-снимке, все инструменты read-only.

Смежный проект: [bdu-fstec-mcp](https://github.com/D-Shapyrin/bdu-fstec-mcp) — обычная БДУ (уязвимости общего назначения, BDU:…).

## Возможности

Восемь инструментов:

- `search_asutp_threats` — поиск угроз (УТП:01…УТП:10) по коду/названию/описанию.
- `get_asutp_threat` — карточка угрозы: описание, способы реализации (СП.x → СПА.x), объекты воздействия (ОА.x), типовые сценарии, где встречается.
- `search_asutp_negative_consequences` — негативные последствия по объектам АСУ ТП с фильтрами по виду деятельности и объекту (для категорирования КИИ по 187-ФЗ).
- `search_asutp_protection_measures` — меры защиты (ИАФ, УПД, АВЗ, РСБ…) с фильтром по группе, уровням АСУ ТП, категориям значимости.
- `search_asutp_software_vulnerabilities` — FTS5-поиск по ~2900 уязвимостям ПО АСУ ТП (BDA:YYYY-NNN) с фильтрами: уровень опасности, год, эксплойт, оборудование.
- `get_asutp_software_vulnerability` — карточка уязвимости: CVSS-векторы, класс, статус, эксплойт, меры снижения, затронутое ПО/оборудование.
- `search_asutp_nsi` — справочники: объекты воздействия (ОА), компоненты (К), нарушители (ВА), способы реализации (СПА), типовые сценарии.
- `get_asutp_stats` — метаданные снимка.

## Установка

```bash
pip install -e .
```

При первом запуске сервер сам скачивает готовый снимок (~1,7 МБ) с зеркала [bdu-asutp-mirror](https://github.com/D-Shapyrin/bdu-asutp-mirror) — секунды. Перекачать принудительно:

```bash
bdu-asutp-mcp refresh
```

Альтернатива (RU-IP): собрать снимок напрямую из API ФСТЭК (~30 мин, сервер ограничивает частоту):

```bash
bdu-asutp-mcp fetch
```

Подготовить артефакты для зеркала после `fetch`:

```bash
bdu-asutp-mcp publish --out /path/to/bdu-asutp-mirror
```

## Подключение

Claude Code: `claude mcp add bdu-asutp -- bdu-asutp-mcp run`

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "bdu-asutp": {"command": "bdu-asutp-mcp", "args": ["run"]}
  }
}
```

## Переменные окружения

| Переменная | По умолчанию | Описание |
| --- | --- | --- |
| `BDU_ASUTP_CACHE_DIR` | `~/.cache/bdu-asutp-mcp` | каталог снимка `bdu_asutp.sqlite` |
| `BDU_ASUTP_DB_URL` | зеркало bdu-asutp-mirror | URL `bdu_asutp.sqlite.gz` |
| `BDU_ASUTP_STATS_URL` | зеркало bdu-asutp-mirror | URL `stats.json` (проверка свежести) |
| `BDU_ASUTP_API_URL` | `https://bduasutp.fstec.ru/bdu-service/api/v1/` | база API для `fetch` |
| `BDU_ASUTP_REQUEST_TIMEOUT` | `60` | таймаут запроса, с |
| `BDU_ASUTP_STALENESS_DAYS` | `30` | порог устаревания снимка |

## Источник данных

Официального API/дампов у БДУ АСУ ТП нет; фетчер использует тот же JSON-интерфейс, что и сам сайт (`/bdu-service/api/v1/…`), без авторизации. Сертификат сайта выдан российским УЦ — фетчер отключает его проверку. Данные — собственность ФСТЭК России; при использовании указывайте источник `https://bduasutp.fstec.ru`.

## Разработка

```bash
pip install -e ".[dev]"
py -3.15 -m pytest tests -q
```
