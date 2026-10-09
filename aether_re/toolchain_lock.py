"""Fail-closed, portable lock contract for forensic analysis toolchains.

The lock records only immutable tool acquisition and invocation metadata.  It
never executes a tool; callers must verify the recorded executable hash before
launching a worker.
"""
from __future__ import annotations

import json
import os
import re
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .kernel_contracts import ContractError, SHA256_RE

_SCHEMA = "toolchain-lock.v1"
_VERSION_RE = re.compile(r"^v?[0-9]+(?:\.[0-9]+)+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$")
_SPDX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+(?:OR|AND|WITH)\s+[A-Za-z0-9.+-]+)*$")
_SHELL_PROGRAMS = frozenset({
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "sh", "sh.exe", "bash", "bash.exe", "zsh", "zsh.exe", "fish", "fish.exe",
})
_LIMIT_FIELDS = ("cpu_seconds", "memory_bytes", "wall_seconds", "output_bytes")
_WORKER_FIELDS = {
    "name", "version", "official_url", "sha256", "license", "runtime",
    "accepted_profiles", "argv", "limits",
}


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and "\x00" not in value


def _canonical_strings(value: Any, *, error: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ContractError(error)
    if any(not _nonempty_string(item) for item in value):
        raise ContractError(error)
    normalized = tuple(item.strip() for item in value)
    if len(normalized) != len(set(normalized)):
        raise ContractError(error)
    return normalized


def _valid_official_https_url(value: Any) -> bool:
    if not _nonempty_string(value):
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    )


@dataclass(frozen=True)
class ResourceLimits:
    """Mandatory execution ceilings, all positive integral values."""

    cpu_seconds: int
    memory_bytes: int
    wall_seconds: int
    output_bytes: int

    def __post_init__(self) -> None:
        for name in _LIMIT_FIELDS:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ContractError(f"resource_limit_invalid:{name}")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResourceLimits":
        if not isinstance(value, Mapping) or set(value) != set(_LIMIT_FIELDS):
            raise ContractError("resource_limits_schema_invalid")
        return cls(**dict(value))

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in _LIMIT_FIELDS}


@dataclass(frozen=True)
class WorkerSpec:
    """One hash-pinned tool invocation with no shell interpretation."""

    name: str
    version: str
    official_url: str
    sha256: str
    license: str
    runtime: str
    accepted_profiles: tuple[str, ...]
    argv: tuple[str, ...]
    limits: ResourceLimits

    def __post_init__(self) -> None:
        if not _nonempty_string(self.name):
            raise ContractError("tool_name_invalid")
        if not isinstance(self.version, str) or not _VERSION_RE.fullmatch(self.version):
            raise ContractError("tool_version_invalid")
        if not _valid_official_https_url(self.official_url):
            raise ContractError("tool_url_invalid")
        if not isinstance(self.sha256, str) or not SHA256_RE.fullmatch(self.sha256):
            raise ContractError("tool_hash_invalid")
        if not isinstance(self.license, str) or not _SPDX_RE.fullmatch(self.license):
            raise ContractError("tool_license_invalid")
        if not _nonempty_string(self.runtime):
            raise ContractError("tool_runtime_invalid")
        profiles = _canonical_strings(list(self.accepted_profiles) if isinstance(self.accepted_profiles, tuple) else self.accepted_profiles, error="tool_profiles_invalid")
        argv = _canonical_strings(list(self.argv) if isinstance(self.argv, tuple) else self.argv, error="tool_argv_invalid")
        program = argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if program in _SHELL_PROGRAMS:
            raise ContractError("tool_argv_invalid")
        if not isinstance(self.limits, ResourceLimits):
            raise ContractError("resource_limits_schema_invalid")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "runtime", self.runtime.strip())
        object.__setattr__(self, "accepted_profiles", profiles)
        object.__setattr__(self, "argv", argv)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "WorkerSpec":
        if not isinstance(value, Mapping) or set(value) != _WORKER_FIELDS:
            raise ContractError("tool_schema_invalid")
        try:
            limits = ResourceLimits.from_dict(value["limits"])
        except KeyError as exc:
            raise ContractError("tool_schema_invalid") from exc
        return cls(
            name=value["name"],
            version=value["version"],
            official_url=value["official_url"],
            sha256=value["sha256"],
            license=value["license"],
            runtime=value["runtime"],
            accepted_profiles=value["accepted_profiles"],
            argv=value["argv"],
            limits=limits,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "official_url": self.official_url,
            "sha256": self.sha256,
            "license": self.license,
            "runtime": self.runtime,
            "accepted_profiles": list(self.accepted_profiles),
            "argv": list(self.argv),
            "limits": self.limits.to_dict(),
        }


@dataclass(frozen=True)
class ToolchainLock:
    """A complete v1 lock with uniquely named, hash-pinned worker specs."""

    schema: str
    tools: tuple[WorkerSpec, ...]

    def __post_init__(self) -> None:
        if self.schema != _SCHEMA:
            raise ContractError("toolchain_schema_invalid")
        if not isinstance(self.tools, tuple) or not self.tools or any(not isinstance(tool, WorkerSpec) for tool in self.tools):
            raise ContractError("toolchain_tools_invalid")
        names = tuple(tool.name for tool in self.tools)
        if len(names) != len(set(names)):
            raise ContractError("toolchain_tools_invalid")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolchainLock":
        if not isinstance(value, Mapping) or set(value) != {"schema", "tools"} or value.get("schema") != _SCHEMA:
            raise ContractError("toolchain_schema_invalid")
        raw_tools = value.get("tools")
        if not isinstance(raw_tools, list) or not raw_tools:
            raise ContractError("toolchain_tools_invalid")
        return cls(schema=_SCHEMA, tools=tuple(WorkerSpec.from_dict(item) for item in raw_tools))

    def to_dict(self) -> dict[str, Any]:
        return {"schema": self.schema, "tools": [tool.to_dict() for tool in self.tools]}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("toolchain_json_duplicate_key")
        result[key] = value
    return result


def load_toolchain_lock(path: str | os.PathLike[str]) -> ToolchainLock:
    """Load one JSON lock; malformed JSON and duplicate keys are rejected."""
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            raw = json.load(handle, object_pairs_hook=_reject_duplicate_keys)
    except ContractError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("toolchain_json_invalid") from exc
    return ToolchainLock.from_dict(raw)


def dump_toolchain_lock(lock: ToolchainLock, path: str | os.PathLike[str]) -> None:
    """Write the verified lock as deterministic JSON without following a schema downgrade."""
    if not isinstance(lock, ToolchainLock):
        raise ContractError("toolchain_schema_invalid")
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(lock.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        target.write_text(encoded + "\n", encoding="utf-8")
    except OSError as exc:
        raise ContractError("toolchain_json_write_failed") from exc


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def verify_toolchain_lock(lock: ToolchainLock) -> dict[str, Any]:
    """Rehash pinned executables without executing them or invoking a shell."""
    if not isinstance(lock, ToolchainLock):
        raise ContractError("toolchain_schema_invalid")
    rows: list[dict[str, str]] = []
    for tool in lock.tools:
        executable = Path(tool.argv[0])
        observed = _sha256_file(executable)
        if observed is None:
            state = "executable_missing"
        elif observed != tool.sha256:
            state = "hash_mismatch"
        else:
            state = "verified"
        rows.append({"name": tool.name, "state": state, "expected_sha256": tool.sha256, "observed_sha256": observed or ""})
    return {"schema": "toolchain-verification.v1", "verified": all(row["state"] == "verified" for row in rows), "tools": rows,
            "limitations": ["verification rehashes executable bytes only; it does not execute tools or prove analysis quality"]}
