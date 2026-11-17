"""Reverse Engineering Graph (AetherRE) — Type Library Engine (TILs).

Banco de dados e motor de ingestão de tipos canônicos de sistemas operacionais:
  1. Catálogo pré-indexado de estruturas fundamentais do Windows SDK, POSIX e Linux NT;
  2. Resolução imediata de assinaturas de APIs de sistema e convenções de chamada;
  3. Casamento determinístico de offsets de memória contra structs conhecidas do SO.
"""

from __future__ import annotations

from typing import Any

SCHEMA = "til-engine-report.v1"

# Catálogo Canônico de Estruturas de SO Pré-Indexadas
CANONICAL_TIL_STRUCTS: dict[str, dict[str, Any]] = {
    "SECURITY_ATTRIBUTES": {
        "os": "windows",
        "size_64": 24,
        "fields": {
            0x00: {"name": "nLength", "size": 4, "type": "DWORD"},
            0x08: {"name": "lpSecurityDescriptor", "size": 8, "type": "LPVOID"},
            0x10: {"name": "bInheritHandle", "size": 4, "type": "BOOL"},
        },
    },
    "STARTUPINFOW": {
        "os": "windows",
        "size_64": 104,
        "fields": {
            0x00: {"name": "cb", "size": 4, "type": "DWORD"},
            0x08: {"name": "lpReserved", "size": 8, "type": "LPWSTR"},
            0x10: {"name": "lpDesktop", "size": 8, "type": "LPWSTR"},
            0x18: {"name": "lpTitle", "size": 8, "type": "LPWSTR"},
            0x20: {"name": "dwX", "size": 4, "type": "DWORD"},
            0x24: {"name": "dwY", "size": 4, "type": "DWORD"},
            0x28: {"name": "dwXSize", "size": 4, "type": "DWORD"},
            0x2C: {"name": "dwYSize", "size": 4, "type": "DWORD"},
            0x3C: {"name": "dwFlags", "size": 4, "type": "DWORD"},
            0x40: {"name": "wShowWindow", "size": 2, "type": "WORD"},
            0x50: {"name": "hStdInput", "size": 8, "type": "HANDLE"},
            0x58: {"name": "hStdOutput", "size": 8, "type": "HANDLE"},
            0x60: {"name": "hStdError", "size": 8, "type": "HANDLE"},
        },
    },
    "PROCESS_INFORMATION": {
        "os": "windows",
        "size_64": 24,
        "fields": {
            0x00: {"name": "hProcess", "size": 8, "type": "HANDLE"},
            0x08: {"name": "hThread", "size": 8, "type": "HANDLE"},
            0x10: {"name": "dwProcessId", "size": 4, "type": "DWORD"},
            0x14: {"name": "dwThreadId", "size": 4, "type": "DWORD"},
        },
    },
    "WIN32_FIND_DATAW": {
        "os": "windows",
        "size_64": 592,
        "fields": {
            0x00: {"name": "dwFileAttributes", "size": 4, "type": "DWORD"},
            0x04: {"name": "ftCreationTime", "size": 8, "type": "FILETIME"},
            0x0C: {"name": "ftLastAccessTime", "size": 8, "type": "FILETIME"},
            0x14: {"name": "ftLastWriteTime", "size": 8, "type": "FILETIME"},
            0x1C: {"name": "nFileSizeHigh", "size": 4, "type": "DWORD"},
            0x20: {"name": "nFileSizeLow", "size": 4, "type": "DWORD"},
            0x2C: {"name": "cFileName", "size": 520, "type": "WCHAR[260]"},
        },
    },
    "sockaddr_in": {
        "os": "posix",
        "size_64": 16,
        "fields": {
            0x00: {"name": "sin_family", "size": 2, "type": "sa_family_t"},
            0x02: {"name": "sin_port", "size": 2, "type": "in_port_t"},
            0x04: {"name": "sin_addr", "size": 4, "type": "struct in_addr"},
            0x08: {"name": "sin_zero", "size": 8, "type": "char[8]"},
        },
    },
}

# Assinaturas de APIs Canônicas
CANONICAL_API_SIGNATURES: dict[str, dict[str, Any]] = {
    "CreateFileW": {
        "return_type": "HANDLE",
        "calling_convention": "win64",
        "params": [
            {"name": "lpFileName", "type": "LPCWSTR"},
            {"name": "dwDesiredAccess", "type": "DWORD"},
            {"name": "dwShareMode", "type": "DWORD"},
            {"name": "lpSecurityAttributes", "type": "LPSECURITY_ATTRIBUTES"},
            {"name": "dwCreationDisposition", "type": "DWORD"},
            {"name": "dwFlagsAndAttributes", "type": "DWORD"},
            {"name": "hTemplateFile", "type": "HANDLE"},
        ],
    },
    "VirtualAlloc": {
        "return_type": "LPVOID",
        "calling_convention": "win64",
        "params": [
            {"name": "lpAddress", "type": "LPVOID"},
            {"name": "dwSize", "type": "SIZE_T"},
            {"name": "flAllocationType", "type": "DWORD"},
            {"name": "flProtect", "type": "DWORD"},
        ],
    },
    "WriteProcessMemory": {
        "return_type": "BOOL",
        "calling_convention": "win64",
        "params": [
            {"name": "hProcess", "type": "HANDLE"},
            {"name": "lpBaseAddress", "type": "LPVOID"},
            {"name": "lpBuffer", "type": "LPCVOID"},
            {"name": "nSize", "type": "SIZE_T"},
            {"name": "lpNumberOfBytesWritten", "type": "SIZE_T *"},
        ],
    },
    "socket": {
        "return_type": "int",
        "calling_convention": "cdecl",
        "params": [
            {"name": "domain", "type": "int"},
            {"name": "type", "type": "int"},
            {"name": "protocol", "type": "int"},
        ],
    },
}


def lookup_til_api(api_name: str) -> dict[str, Any] | None:
    """Busca a assinatura exata de uma API de sistema na biblioteca de tipos."""
    clean = api_name.split(":")[-1].strip()
    return CANONICAL_API_SIGNATURES.get(clean)


def lookup_til_struct(struct_name: str) -> dict[str, Any] | None:
    """Busca os campos e tamanhos de uma estrutura de sistema na biblioteca de tipos."""
    return CANONICAL_TIL_STRUCTS.get(struct_name)


def match_struct_by_field_offsets(offsets: Sequence[int], *, os_filter: str | None = None) -> list[dict[str, Any]]:
    """Identifica quais estruturas de sistema correspondem aos offsets de acesso à memória detectados."""
    target_offsets = set(offsets)
    candidates = []

    for name, s_info in CANONICAL_TIL_STRUCTS.items():
        if os_filter and s_info["os"] != os_filter:
            continue
        struct_offsets = set(s_info["fields"].keys())
        overlap = target_offsets & struct_offsets
        if overlap:
            score = round(len(overlap) / len(target_offsets), 2)
            candidates.append({
                "struct_name": name,
                "os": s_info["os"],
                "total_size": s_info["size_64"],
                "matched_offsets": sorted(overlap),
                "match_score": score,
            })

    candidates.sort(key=lambda x: x["match_score"], reverse=True)
    return candidates
