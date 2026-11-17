"""Reverse Engineering Graph (AetherRE) — Heuristic Semantic Function Labeler.

Inspirado na arquitetura do SymLM (CCS — Context-Sensitive Code Embeddings for
Function Name Prediction).

Em binários com símbolos removidos (stripped binaries), todas as funções
recebem nomes opacos como 'sub_140001020'.
Este motor analisa o 'Calling Context' (APIs chamadas, strings locais, constantes
criptográficas e topologia no grafo) para inferir o papel semântico real da função:
  - Criptografia (AES, RC4, RSA, SHA, MD5);
  - Injeção de Processos (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread);
  - Rede e C2 (WinINet, WinHTTP, Sockets);
  - Persistência e Registro (RegSetValueEx, Scheduled Tasks);
  - Evasão e Anti-Depuração (IsDebuggerPresent, NtQueryInformationProcess);
  - Despachante / Ponto de Entrada (alto out-degree, orquestrador de fluxo).
"""

from __future__ import annotations

import re
from typing import Any, Sequence

SCHEMA = "semantic-labeler.v1"

# Dicionário de Heurísticas de Contexto Semântico (Regexes pré-compiladas)
SEMANTIC_CONTEXT_RULES: list[dict[str, Any]] = [
    {
        "category": "process_injection",
        "tag": "injector",
        "apis": [
            r"VirtualAlloc(?:Ex)?",
            r"WriteProcessMemory",
            r"CreateRemoteThread(?:Ex)?",
            r"NtCreateThreadEx",
            r"QueueUserAPC",
            r"SetThreadContext",
            r"RtlCreateUserThread",
        ],
        "strings": [r"inject", r"payload", r"shellcode", r"remote_thread"],
        "confidence": 0.92,
    },
    {
        "category": "cryptography",
        "tag": "crypto",
        "apis": [
            r"Crypt(?:Encrypt|Decrypt|CreateHash|HashData|AcquireContext)",
            r"BCrypt(?:Encrypt|Decrypt|CreateHash|GenerateSymmetricKey)",
            r"EVP_EncryptInit",
            r"AES_set_encrypt_key",
        ],
        "strings": [
            r"\bAES(?:-128|-192|-256)?\b",
            r"\bRC4\b",
            r"\bChaCha20\b",
            r"\bRSA\b",
            r"\bSHA-?256\b",
            r"\bMD5\b",
            r"cipher",
            r"decrypt",
            r"encrypt",
        ],
        "confidence": 0.90,
    },
    {
        "category": "network_client",
        "tag": "net_c2",
        "apis": [
            r"Internet(?:Open|Connect|ReadFile)[AW]?",
            r"Http(?:OpenRequest|SendRequest)[AW]?",
            r"WSASocket[AW]?",
            r"connect",
            r"send",
            r"recv",
            r"WinHttp(?:Open|Connect|SendRequest)",
        ],
        "strings": [
            r"https?://",
            r"POST\s+",
            r"GET\s+",
            r"User-Agent",
            r"Content-Type",
            r"socket",
        ],
        "confidence": 0.88,
    },
    {
        "category": "registry_persistence",
        "tag": "registry",
        "apis": [
            r"Reg(?:OpenKey|CreateKey|SetValue|DeleteValue|QueryValue)[AW]?(?:Ex)?",
        ],
        "strings": [
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"CurrentVersion\\RunOnce",
            r"SYSTEM\\CurrentControlSet",
        ],
        "confidence": 0.85,
    },
    {
        "category": "anti_analysis",
        "tag": "evasion",
        "apis": [
            r"IsDebuggerPresent",
            r"CheckRemoteDebuggerPresent",
            r"NtQueryInformationProcess",
            r"OutputDebugString[AW]?",
            r"ptrace",
        ],
        "strings": [
            r"debugger",
            r"vboxguest",
            r"vmware",
            r"sandbox",
            r"qemu",
        ],
        "confidence": 0.85,
    },
    {
        "category": "file_io",
        "tag": "file_io",
        "apis": [
            r"CreateFile[AW]?",
            r"WriteFile",
            r"ReadFile",
            r"DeleteFile[AW]?",
            r"FindFirstFile[AW]?",
        ],
        "strings": [r"C:\\", r"\\Temp\\", r"\.tmp\b", r"\.exe\b", r"\.dll\b"],
        "confidence": 0.70,
    },
]

# Pré-compilação de regexes para alta performance
for _rule in SEMANTIC_CONTEXT_RULES:
    _rule["_compiled_apis"] = [re.compile(p, re.IGNORECASE) for p in _rule["apis"]]
    _rule["_compiled_strings"] = [re.compile(p, re.IGNORECASE) for p in _rule["strings"]]


def is_anonymous_function_name(name: str) -> bool:
    """Verifica se o nome da função é genérico/desconhecido (ex: sub_401000, 0x140001000, fn_1)."""
    n = name.strip().lower()
    if not n or n in {"main", "start", "winmain", "dllmain"}:
        return False
    return bool(
        re.match(r"^(?:sub_|fn_|loc_|func_|subroutine_)[0-9a-fA-F]+$", n)
        or re.match(r"^0x[0-9a-fA-F]+$", n)
        or n.isdigit()
        or n.startswith("unknown_")
    )


def infer_function_role(
    *,
    name: str = "",
    calls: Sequence[str] = (),
    strings: Sequence[str] = (),
    in_degree: int = 0,
    out_degree: int = 0,
) -> dict[str, Any]:
    """Infere o papel semântico de uma função baseado no seu contexto de execução."""
    best_category = "general"
    best_tag = "util"
    max_score = 0.0
    matched_evidences: list[str] = []

    all_calls = list(calls)
    all_strings = list(strings)

    for rule in SEMANTIC_CONTEXT_RULES:
        score = 0.0
        evidences: list[str] = []

        # Avaliação de APIs chamadas
        for rx in rule["_compiled_apis"]:
            for call in all_calls:
                clean_call = call.split(":")[-1]  # remove DLL prefix se houver
                if rx.search(clean_call):
                    score += 2.0
                    evidences.append(f"api:{clean_call}")

        # Avaliação de Strings locais
        for rx in rule["_compiled_strings"]:
            for s in all_strings:
                if rx.search(s):
                    score += 1.0
                    evidences.append(f"str:{s[:30]}")

        if score > max_score:
            max_score = score
            best_category = rule["category"]
            best_tag = rule["tag"]
            matched_evidences = evidences

    confidence = min(0.95, round(max_score * 0.2, 2)) if max_score > 0 else 0.40

    # Topologia no grafo: Se não tem chamadas de API conhecidas mas tem alto out-degree
    if max_score == 0:
        if out_degree >= 5 and in_degree <= 1:
            best_category = "orchestrator"
            best_tag = "dispatcher"
            confidence = 0.65
        elif in_degree >= 4 and out_degree == 0:
            best_category = "utility_leaf"
            best_tag = "leaf_helper"
            confidence = 0.60

    # Gera rótulo sugerido
    clean_name = name.strip() or "sub_unknown"
    suggested_label = f"{clean_name}_{best_tag}" if is_anonymous_function_name(clean_name) else clean_name

    return {
        "original_name": clean_name,
        "is_anonymous": is_anonymous_function_name(clean_name),
        "inferred_category": best_category,
        "inferred_tag": best_tag,
        "suggested_label": suggested_label,
        "confidence": confidence,
        "evidences": matched_evidences[:10],
    }


def enrich_callgraph_nodes(
    nodes: dict[str, dict[str, Any]],
    edges: list[tuple[str, str]],
) -> dict[str, dict[str, Any]]:
    """Enriquece todos os nós do callgraph com rótulos semânticos inteligíveis."""
    # Calcula in-degree e out-degree por nó
    in_degrees: dict[str, int] = {}
    out_degrees: dict[str, int] = {}
    for src, dst in edges:
        out_degrees[src] = out_degrees.get(src, 0) + 1
        in_degrees[dst] = in_degrees.get(dst, 0) + 1

    enriched: dict[str, dict[str, Any]] = {}
    for node_name, meta in nodes.items():
        calls = [dst for src, dst in edges if src == node_name]
        in_deg = in_degrees.get(node_name, 0)
        out_deg = out_degrees.get(node_name, 0)

        inference = infer_function_role(
            name=node_name,
            calls=calls,
            strings=[],
            in_degree=in_deg,
            out_degree=out_deg,
        )

        node_data = dict(meta)
        node_data["inferred_role"] = inference["inferred_category"]
        node_data["suggested_label"] = inference["suggested_label"]
        node_data["confidence"] = max(node_data.get("confidence", 0.5), inference["confidence"])
        enriched[node_name] = node_data

    return enriched
