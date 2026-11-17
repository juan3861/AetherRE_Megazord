"""AetherRE Megazord — API-Hash Resolver (ROR13, DJB2, FNV-1a, CRC32) (GEAR-11).

Pure-static, zero-execution analyzer inspired by OALabs HashDB & FLARE-FLOSS:
- Resolves obfuscated 32-bit API hashes embedded in shellcode, packers, or malware
- Supports ROR13 (Metasploit/CobaltStrike style), DJB2, FNV-1a (32-bit), and IEEE CRC32
- Scans binary blobs for 32-bit little-endian immediate constants matching known APIs
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Any

SCHEMA = "re-megazord-api-hash-resolve.v1"
MAX_SCAN_BYTES = 64 * 1024 * 1024

_KNOWN_APIS: tuple[str, ...] = (
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "VirtualFree",
    "WriteProcessMemory", "ReadProcessMemory", "OpenProcess", "CreateRemoteThread",
    "NtCreateThreadEx", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress", "LdrLoadDll",
    "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetOpenUrlA",
    "HttpOpenRequestA", "HttpSendRequestA", "InternetReadFile",
    "WSAStartup", "WSASocketA", "socket", "connect", "send", "recv", "bind", "listen", "accept",
    "RegOpenKeyExA", "RegSetValueExA", "RegCreateKeyExA",
    "CryptAcquireContextA", "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA",
    "GetModuleHandleA", "GetModuleHandleW", "ExitProcess", "TerminateProcess",
    "SetWindowsHookExA", "GetAsyncKeyState", "GetForegroundWindow",
)


def _ror32(val: int, bits: int) -> int:
    return ((val >> bits) | (val << (32 - bits))) & 0xFFFFFFFF


def hash_ror13(name: str) -> int:
    h = 0
    for ch in name.encode("ascii"):
        h = (_ror32(h, 13) + ch) & 0xFFFFFFFF
    return h


def hash_djb2(name: str) -> int:
    h = 5381
    for ch in name.encode("ascii"):
        h = ((h << 5) + h + ch) & 0xFFFFFFFF
    return h


def hash_fnv1a_32(name: str) -> int:
    h = 0x811C9DC5
    for ch in name.encode("ascii"):
        h ^= ch
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def hash_crc32(name: str) -> int:
    return zlib.crc32(name.encode("ascii")) & 0xFFFFFFFF


_ALGORITHMS = {
    "ror13": hash_ror13,
    "djb2": hash_djb2,
    "fnv1a_32": hash_fnv1a_32,
    "crc32": hash_crc32,
}


def _build_lookup_table() -> dict[int, list[tuple[str, str]]]:
    table: dict[int, list[tuple[str, str]]] = {}
    for api in _KNOWN_APIS:
        for alg_name, fn in _ALGORITHMS.items():
            hv = fn(api)
            table.setdefault(hv, []).append((alg_name, api))
    return table


_LOOKUP_TABLE = _build_lookup_table()


def resolve_api_hash(hash_value: int) -> list[dict[str, str]]:
    """Resolve a single 32-bit integer API hash against known algorithms and APIs."""
    hv = int(hash_value) & 0xFFFFFFFF
    hits = _LOOKUP_TABLE.get(hv, [])
    return [{"algorithm": alg, "api_name": api, "hash_hex": hex(hv)} for alg, api in hits]


def scan_bytes_for_api_hashes(data: bytes, *, max_hits: int = 500) -> dict[str, Any]:
    """Scan binary buffer for 32-bit little-endian constants matching known API hashes."""
    if not isinstance(data, (bytes, bytearray)):
        return {"schema": SCHEMA, "status": "invalid", "code": "bytes_required"}
    blob = bytes(data)
    if len(blob) > MAX_SCAN_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "input_too_large"}
    if len(blob) < 4:
        return {"schema": SCHEMA, "status": "complete", "total_resolved": 0, "resolved_hashes": []}

    hits: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    # Unpack 4-byte uint32 across all alignments (instructions like `mov edx, imm32` are unaligned)
    mv = memoryview(blob)
    for offset in range(0, len(blob) - 3):
        val = int.from_bytes(mv[offset:offset + 4], "little")
        if val in _LOOKUP_TABLE:
            for alg, api in _LOOKUP_TABLE[val]:
                key = (val, offset)
                if key in seen:
                    continue
                seen.add(key)
                hits.append({
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "hash_hex": hex(val),
                    "algorithm": alg,
                    "api_name": api,
                })
                if len(hits) >= max_hits:
                    break
        if len(hits) >= max_hits:
            break

    return {
        "schema": SCHEMA,
        "status": "complete",
        "total_resolved": len(hits),
        "unique_apis": sorted({h["api_name"] for h in hits}),
        "algorithms_matched": sorted({h["algorithm"] for h in hits}),
        "resolved_hashes": hits,
    }


def scan_file_api_hashes(target: str | Path) -> dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    if path.stat().st_size > MAX_SCAN_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "file_too_large", "target": str(path)}
    report = scan_bytes_for_api_hashes(path.read_bytes())
    report["target"] = str(path)
    return report
