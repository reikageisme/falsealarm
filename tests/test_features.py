"""Tests for the feature batch: pipe/NDJSON, new modules, recursion helper."""

import asyncio
import json

from falsealarm.core.config import ScanConfig
from falsealarm.core.logger import FalseAlarmLogger
from falsealarm.core.output import OutputManager
from falsealarm.core.scheduler import ScanScheduler
from falsealarm.modules.dirfuzz import DirFuzzModule
from falsealarm.modules.favicon import mmh3_hash


def _discover():
    sc = ScanScheduler.__new__(ScanScheduler)
    sc._modules = {}
    sc.logger = FalseAlarmLogger(silent=True)
    sc._discover_modules()
    return set(sc._modules)


def test_new_modules_are_discovered():
    assert {"favicon", "graphql", "openredirect"} <= _discover()


def test_ndjson_lines_and_flatten():
    res = {"httpprobe": {"data": [{"url": "https://a.com", "alive": True}]}}
    flat = OutputManager.flatten(res)
    assert flat == [{"url": "https://a.com", "alive": True, "_module": "httpprobe"}]
    lines = OutputManager.ndjson_lines(res)
    assert len(lines) == 1
    assert json.loads(lines[0])["_module"] == "httpprobe"


def test_jsonl_file_export(tmp_path):
    res = {
        "portscan": {"data": [{"target": "a.com", "port": 80}, {"target": "a.com", "port": 443}]},
    }
    out = tmp_path / "out.jsonl"
    asyncio.run(OutputManager.export(res, str(out), "jsonl"))
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(records) == 2
    assert {r["port"] for r in records} == {80, 443}


def test_favicon_hash_is_graceful():
    # Returns an int when mmh3 is installed, otherwise None — never raises.
    value = mmh3_hash(b"\x00\x01\x02fake-favicon")
    assert value is None or isinstance(value, int)


def test_dirfuzz_recursion_candidate_rules():
    assert DirFuzzModule._is_dir_candidate({"type": "directory", "payload": "admin", "status": 301})
    assert not DirFuzzModule._is_dir_candidate({"type": "directory", "payload": "app.js", "status": 200})
    assert not DirFuzzModule._is_dir_candidate({"type": "fuzz", "payload": "admin", "status": 200})


def test_config_accepts_jsonl_and_recursion():
    cfg = ScanConfig(target="example.com", format="jsonl", recursion_depth=2)
    cfg.validate()  # should not raise
