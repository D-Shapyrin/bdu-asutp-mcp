"""End-to-end test: spawn the real stdio MCP server and exchange JSON-RPC."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from tests.conftest import build_sample_db


@pytest.fixture
def sample_cache(tmp_path: Path) -> Path:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    build_sample_db(cache_dir / "bdu_asutp.sqlite")
    return cache_dir


class _StdioClient:
    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self._proc = proc
        self._request_id = 0

    async def send(self, method: str, params: dict | None = None) -> dict:
        self._request_id += 1
        msg = {"jsonrpc": "2.0", "id": self._request_id, "method": method}
        if params is not None:
            msg["params"] = params
        self._proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self._proc.stdin.drain()
        return await self._recv()

    async def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self._proc.stdin.drain()

    async def _recv(self) -> dict:
        line = await self._proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stream")
        return json.loads(line.decode())


async def _spawn(cache_dir: Path) -> tuple[asyncio.subprocess.Process, _StdioClient]:
    env = {
        **os.environ,
        "BDU_ASUTP_CACHE_DIR": str(cache_dir),
        "BDU_ASUTP_API_URL": "http://127.0.0.1:0/unused",
    }
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "bdu_asutp_mcp.server",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    client = _StdioClient(proc)
    init = await client.send(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"},
        },
    )
    assert init["result"]["serverInfo"]["name"] == "bdu-asutp-mcp"
    await client.notify("notifications/initialized")
    return proc, client


async def _shutdown(proc: asyncio.subprocess.Process) -> None:
    if proc.stdin and not proc.stdin.is_closing():
        proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        proc.terminate()
        await proc.wait()


async def test_e2e_handshake_and_list_tools(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send("tools/list")
        names = {t["name"] for t in resp["result"]["tools"]}
        assert names == {
            "search_asutp_threats",
            "get_asutp_threat",
            "search_asutp_negative_consequences",
            "search_asutp_protection_measures",
            "search_asutp_software_vulnerabilities",
            "get_asutp_software_vulnerability",
            "search_asutp_nsi",
            "get_asutp_stats",
        }
    finally:
        await _shutdown(proc)


async def test_e2e_stats(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send("tools/call", {"name": "get_asutp_stats", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "БДУ АСУ ТП" in text
        assert "Угроз (УТП): 2" in text
    finally:
        await _shutdown(proc)


async def test_e2e_get_threat(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send(
            "tools/call", {"name": "get_asutp_threat", "arguments": {"threat": "УТП:1"}}
        )
        text = resp["result"]["content"][0]["text"]
        assert "УТП:01" in text
        assert "СПА.01.001" in text
        assert "ОА.001" in text
    finally:
        await _shutdown(proc)


async def test_e2e_search_vulnerabilities(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send(
            "tools/call",
            {
                "name": "search_asutp_software_vulnerabilities",
                "arguments": {"query": "WinCC", "has_exploit": True},
            },
        )
        text = resp["result"]["content"][0]["text"]
        assert "BDA:2026-158" in text
        assert "BDA:2025-077" not in text
    finally:
        await _shutdown(proc)


async def test_e2e_search_nsi(sample_cache: Path):
    proc, client = await _spawn(sample_cache)
    try:
        resp = await client.send(
            "tools/call",
            {"name": "search_asutp_nsi", "arguments": {"kind": "violator", "query": ""}},
        )
        text = resp["result"]["content"][0]["text"]
        assert "ВА.001" in text
    finally:
        await _shutdown(proc)
