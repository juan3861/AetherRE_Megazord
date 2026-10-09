from __future__ import annotations

import json
import hashlib

import pytest

from aether_re.toolchain_lock import (
    ContractError,
    ResourceLimits,
    ToolchainLock,
    WorkerSpec,
    dump_toolchain_lock,
    load_toolchain_lock,
    verify_toolchain_lock,
)


HASH = "a" * 64


def valid_worker(**overrides):
    value = {
        "name": "rizin",
        "version": "0.9.1",
        "official_url": "https://github.com/rizinorg/rizin/releases/tag/v0.9.1",
        "sha256": HASH,
        "license": "LGPL-3.0-or-later",
        "runtime": "none",
        "accepted_profiles": ["elf-x86_64", "pe-x86_64"],
        "argv": ["rz-bin", "-Ij", "{input}"],
        "limits": {
            "cpu_seconds": 60,
            "memory_bytes": 536870912,
            "wall_seconds": 90,
            "output_bytes": 1048576,
        },
    }
    value.update(overrides)
    return value


def valid_lock(**overrides):
    value = {"schema": "toolchain-lock.v1", "tools": [valid_worker()]}
    value.update(overrides)
    return value


def test_toolchain_lock_round_trips_canonically(tmp_path):
    lock = ToolchainLock.from_dict(valid_lock())
    path = tmp_path / "toolchain-lock.v1.json"

    dump_toolchain_lock(lock, path)

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw == valid_lock()
    assert load_toolchain_lock(path) == lock
    assert lock.to_dict() == valid_lock()
    assert lock.tools[0].argv == ("rz-bin", "-Ij", "{input}")


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("version", "latest", "tool_version_invalid"),
        ("version", ">=0.9.1", "tool_version_invalid"),
        ("official_url", "http://github.com/rizinorg/rizin", "tool_url_invalid"),
        ("official_url", "https:///missing-host", "tool_url_invalid"),
        ("sha256", "A" * 64, "tool_hash_invalid"),
        ("sha256", "a" * 63, "tool_hash_invalid"),
        ("argv", "rz-bin -Ij {input}", "tool_argv_invalid"),
        ("argv", ["rz-bin", 7], "tool_argv_invalid"),
        ("argv", [], "tool_argv_invalid"),
        ("accepted_profiles", [], "tool_profiles_invalid"),
        ("runtime", "", "tool_runtime_invalid"),
    ],
)
def test_worker_spec_rejects_unpinned_or_unsafe_fields(field, value, error):
    item = valid_worker(**{field: value})
    with pytest.raises(ContractError, match=error):
        WorkerSpec.from_dict(item)


@pytest.mark.parametrize("missing", ["name", "license", "limits", "argv", "accepted_profiles"])
def test_worker_spec_rejects_missing_or_unknown_fields(missing):
    item = valid_worker()
    item.pop(missing)
    with pytest.raises(ContractError, match="tool_schema_invalid"):
        WorkerSpec.from_dict(item)

    item = valid_worker(extra="not-allowed")
    with pytest.raises(ContractError, match="tool_schema_invalid"):
        WorkerSpec.from_dict(item)


@pytest.mark.parametrize(
    ("limits", "error"),
    [
        ({"cpu_seconds": 0, "memory_bytes": 1, "wall_seconds": 1, "output_bytes": 1}, "resource_limit_invalid:cpu_seconds"),
        ({"cpu_seconds": True, "memory_bytes": 1, "wall_seconds": 1, "output_bytes": 1}, "resource_limit_invalid:cpu_seconds"),
        ({"cpu_seconds": 1, "memory_bytes": 1, "wall_seconds": 1}, "resource_limits_schema_invalid"),
    ],
)
def test_resource_limits_fail_closed(limits, error):
    with pytest.raises(ContractError, match=error):
        ResourceLimits.from_dict(limits)


def test_lock_rejects_wrong_schema_duplicate_tools_and_non_list_tools(tmp_path):
    with pytest.raises(ContractError, match="toolchain_schema_invalid"):
        ToolchainLock.from_dict(valid_lock(schema="toolchain-lock.v2"))
    with pytest.raises(ContractError, match="toolchain_tools_invalid"):
        ToolchainLock.from_dict(valid_lock(tools=valid_worker()))
    with pytest.raises(ContractError, match="toolchain_tools_invalid"):
        ToolchainLock.from_dict(valid_lock(tools=[valid_worker(), valid_worker()]))

    path = tmp_path / "invalid.json"
    path.write_text('{"schema":"toolchain-lock.v1","tools":[]}', encoding="utf-8")
    with pytest.raises(ContractError, match="toolchain_tools_invalid"):
        load_toolchain_lock(path)


def test_verify_toolchain_lock_rehashes_executable_and_fails_closed(tmp_path):
    executable = tmp_path / "worker.exe"
    executable.write_bytes(b"pinned-worker")
    worker = valid_worker(argv=[str(executable)], sha256=hashlib.sha256(executable.read_bytes()).hexdigest())
    report = verify_toolchain_lock(ToolchainLock.from_dict(valid_lock(tools=[worker])))
    assert report["verified"] is True
    executable.write_bytes(b"tampered")
    report = verify_toolchain_lock(ToolchainLock.from_dict(valid_lock(tools=[worker])))
    assert report["verified"] is False
    assert report["tools"][0]["state"] == "hash_mismatch"
