"""AetherRE Megazord — Semantic Capability Detection Engine (CAPA-Style).

Identifica capacidades forenses e de malware (anti-debug, injeção de processos,
criptografia, persistência, C2, evasão e empacotamento) a partir de imports,
strings decodificadas, seções e chamadas extraídas por multi-engines.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Sequence

SCHEMA = "binary-capabilities.v1"

# Regras de Capacidades (MITRE ATT&CK compatíveis)
CAPABILITY_RULES: list[dict[str, Any]] = [
    # Anti-Análise / Anti-Debug
    {
        "id": "anti-analysis/debugger-detection-api",
        "category": "anti-analysis",
        "title": "Detecção de Depurador via API",
        "description": "Verifica a presença de um depurador ativo usando APIs nativas do sistema.",
        "mitre_id": "T1622",
        "severity": "medium",
        "confidence": 0.90,
        "api_patterns": [
            r"^IsDebuggerPresent$",
            r"^CheckRemoteDebuggerPresent$",
            r"^OutputDebugString[AW]?$",
            r"^NtQueryInformationProcess$",
            r"^ZwQueryInformationProcess$",
            r"^ptrace$",
        ],
        "string_patterns": [
            r"debugger detected",
            r"isdebuggerpresent",
            r"please disable your debugger",
        ],
    },
    {
        "id": "anti-analysis/vm-detection",
        "category": "anti-analysis",
        "title": "Detecção de Máquina Virtual / Sandbox",
        "description": "Procura artefatos de virtualização (VMware, VirtualBox, QEMU, Xen) no ambiente.",
        "mitre_id": "T1497.001",
        "severity": "medium",
        "confidence": 0.85,
        "api_patterns": [],
        "string_patterns": [
            r"vboxguest",
            r"vmhgfs",
            r"vmware",
            r"qemu",
            r"vboxservice",
            r"virtualbox",
            r"xen",
            r"bochs",
        ],
    },
    {
        "id": "anti-analysis/timing-checks",
        "category": "anti-analysis",
        "title": "Verificação de Temporização Anti-Análise",
        "description": "Mede ciclos de CPU para detectar latência introduzida por análise dinâmica ou depuração passo-a-passo.",
        "mitre_id": "T1497.003",
        "severity": "low",
        "confidence": 0.75,
        "api_patterns": [
            r"^QueryPerformanceCounter$",
            r"^GetTickCount64?$",
            r"^timeGetTime$",
        ],
        "string_patterns": [],
    },
    # Injeção de Processos
    {
        "id": "process-injection/remote-thread",
        "category": "process-injection",
        "title": "Criação de Thread Remota",
        "description": "Aloca memória em processo remoto e cria thread de execução para injetar código.",
        "mitre_id": "T1055.002",
        "severity": "high",
        "confidence": 0.92,
        "api_patterns": [
            r"^CreateRemoteThread(?:Ex)?$",
            r"^NtCreateThreadEx$",
            r"^RtlCreateUserThread$",
        ],
        "string_patterns": [],
    },
    {
        "id": "process-injection/hollowing-or-injection-primitives",
        "category": "process-injection",
        "title": "Primitivas de Manipulação de Memória Remota",
        "description": "Aloca e escreve memória em processos externos, típico de Process Hollowing ou DLL Injection.",
        "mitre_id": "T1055.012",
        "severity": "high",
        "confidence": 0.88,
        "api_patterns": [
            r"^VirtualAllocEx$",
            r"^WriteProcessMemory$",
            r"^NtUnmapViewOfSection$",
            r"^QueueUserAPC$",
            r"^SetThreadContext$",
        ],
        "string_patterns": [],
    },
    # Criptografia
    {
        "id": "cryptography/windows-crypto-api",
        "category": "cryptography",
        "title": "Operações Criptográficas via Windows Crypto / CNG",
        "description": "Utiliza APIs do subsistema de segurança do Windows para cifragem, decifragem ou hash.",
        "mitre_id": "T1027",
        "severity": "medium",
        "confidence": 0.95,
        "api_patterns": [
            r"^CryptEncrypt$",
            r"^CryptDecrypt$",
            r"^CryptCreateHash$",
            r"^CryptHashData$",
            r"^BCryptEncrypt$",
            r"^BCryptDecrypt$",
            r"^BCryptCreateHash$",
            r"^BCryptGenerateSymmetricKey$",
        ],
        "string_patterns": [],
    },
    {
        "id": "cryptography/known-algorithms",
        "category": "cryptography",
        "title": "Referências a Algoritmos Criptográficos Padrão",
        "description": "Presença de constantes, nomes ou rotinas de algoritmos conhecidos (AES, RSA, RC4, ChaCha20, SHA).",
        "mitre_id": "T1027",
        "severity": "medium",
        "confidence": 0.85,
        "api_patterns": [],
        "string_patterns": [
            r"\bAES(?:-128|-192|-256)?\b",
            r"\bRC4\b",
            r"\bChaCha20\b",
            r"\bRSA\b",
            r"\bSHA-?256\b",
            r"\bSHA-?512\b",
            r"\bMD5\b",
        ],
    },
    # Persistência
    {
        "id": "persistence/registry-run-keys",
        "category": "persistence",
        "title": "Persistência em Chaves Run do Registro",
        "description": "Configura inicialização automática através das chaves Run/RunOnce do Registro do Windows.",
        "mitre_id": "T1547.001",
        "severity": "high",
        "confidence": 0.90,
        "api_patterns": [
            r"^RegSetValueEx[AW]?$",
            r"^RegCreateKeyEx[AW]?$",
        ],
        "string_patterns": [
            r"software\\microsoft\\windows\\currentversion\\run",
            r"software\\microsoft\\windows\\currentversion\\runonce",
        ],
    },
    {
        "id": "persistence/windows-service",
        "category": "persistence",
        "title": "Criação ou Modificação de Serviço do Windows",
        "description": "Interage com o Gerenciador de Controle de Serviços (SCM) para criar ou iniciar serviços persistentes.",
        "mitre_id": "T1543.003",
        "severity": "high",
        "confidence": 0.90,
        "api_patterns": [
            r"^CreateService[AW]?$",
            r"^OpenSCManager[AW]?$",
            r"^StartService[AW]?$",
        ],
        "string_patterns": [],
    },
    # Comunicação em Rede / C2
    {
        "id": "communication/http-network-client",
        "category": "communication",
        "title": "Cliente de Comunicação HTTP / Web",
        "description": "Estabelece conexões de saída HTTP/HTTPS para download de payloads ou comunicação C2.",
        "mitre_id": "T1071.001",
        "severity": "medium",
        "confidence": 0.92,
        "api_patterns": [
            r"^InternetOpen[AW]?$",
            r"^InternetConnect[AW]?$",
            r"^HttpOpenRequest[AW]?$",
            r"^HttpSendRequest[AW]?$",
            r"^WinHttpOpen$",
            r"^WinHttpConnect$",
            r"^URLDownloadToFile[AW]?$",
        ],
        "string_patterns": [
            r"^https?://[a-zA-Z0-9.-]+",
            r"user-agent:\s*",
        ],
    },
    {
        "id": "communication/raw-sockets",
        "category": "communication",
        "title": "Comunicação via Sockets de Baixo Nível (Winsock/BSD)",
        "description": "Abre conexões TCP/UDP cruas para transmissão de dados.",
        "mitre_id": "T1095",
        "severity": "medium",
        "confidence": 0.90,
        "api_patterns": [
            r"^WSAStartup$",
            r"^socket$",
            r"^connect$",
            r"^send$",
            r"^recv$",
            r"^WSASend$",
            r"^WSARecv$",
        ],
        "string_patterns": [],
    },
    # Acesso a Credenciais & Escalação
    {
        "id": "credential-access/security-privileges",
        "category": "credential-access",
        "title": "Habilitação de Privilégios de Depuração ou Token",
        "description": "Tenta adquirir privilégios especiais como SeDebugPrivilege para acessar processos sensíveis.",
        "mitre_id": "T1134.001",
        "severity": "high",
        "confidence": 0.88,
        "api_patterns": [
            r"^AdjustTokenPrivileges$",
            r"^LookupPrivilegeValue[AW]?$",
            r"^OpenProcessToken$",
        ],
        "string_patterns": [
            r"sedebugprivilege",
            r"seimpersonateprivilege",
        ],
    },
    # Evasão e Resolução Dinâmica
    {
        "id": "evasion/dynamic-api-resolution",
        "category": "evasion",
        "title": "Resolução Dinâmica de Funções da API",
        "description": "Obtém ponteiros de funções em tempo de execução via LoadLibrary/GetProcAddress, ocultando a tabela IAT.",
        "mitre_id": "T1027.007",
        "severity": "medium",
        "confidence": 0.85,
        "api_patterns": [
            r"^GetProcAddress$",
            r"^LoadLibrary[A-Z0-9]*$",
            r"^LdrGetProcedureAddress$",
            r"^dlsym$",
            r"^dlopen$",
        ],
        "string_patterns": [],
    },
]

# Pré-compilação de regexes no carregamento do módulo para alta performance
for _rule in CAPABILITY_RULES:
    _rule["_compiled_api"] = [(re.compile(p, re.IGNORECASE), p) for p in _rule.get("api_patterns", [])]
    _rule["_compiled_strings"] = [(re.compile(p, re.IGNORECASE), p) for p in _rule.get("string_patterns", [])]


def detect_capabilities_from_features(
    *,
    imports: Sequence[str] = (),
    strings: Sequence[str] = (),
    sections: Sequence[dict[str, Any]] = (),
    calls: Sequence[str] = (),
) -> list[dict[str, Any]]:
    """Avalia regras de capacidades contra conjunto de sinais estáticos normalizados."""
    detected: list[dict[str, Any]] = []

    # Unifica APIs chamadas e importadas (case-insensitive para matching)
    all_apis = set(imports) | set(calls)
    all_strings = list(strings)

    for rule in CAPABILITY_RULES:
        matches: list[dict[str, str]] = []

        # Validação de APIs com regexes pré-compiladas
        api_compiled = rule.get("_compiled_api") or [(re.compile(p, re.IGNORECASE), p) for p in rule.get("api_patterns", [])]
        for rx, pattern_str in api_compiled:
            for api in all_apis:
                if rx.search(api):
                    matches.append({"type": "api", "matched": api, "pattern": pattern_str})

        # Validação de Strings com regexes pré-compiladas
        str_compiled = rule.get("_compiled_strings") or [(re.compile(p, re.IGNORECASE), p) for p in rule.get("string_patterns", [])]
        for rx, pattern_str in str_compiled:
            for s in all_strings:
                if rx.search(s):
                    # trunca string muito longa para evidência limpa
                    clean_s = s.strip()[:100]
                    matches.append({"type": "string", "matched": clean_s, "pattern": pattern_str})

        if matches:
            detected.append({
                "id": rule["id"],
                "category": rule["category"],
                "title": rule["title"],
                "description": rule["description"],
                "mitre_id": rule.get("mitre_id", ""),
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "evidence_count": len(matches),
                "evidence": matches[:20],  # limita a 20 amostras para contenção
            })

    # Regra adicional para Seções de Alta Entropia (Packing / Compressão)
    for sec in sections:
        entropy = sec.get("entropy", 0.0)
        name = sec.get("name", "")
        if entropy >= 7.2:
            detected.append({
                "id": "evasion/packed-high-entropy-section",
                "category": "evasion",
                "title": f"Seção Empacotada com Alta Entropia ({name})",
                "description": f"A seção {name} possui entropia de Shannon de {entropy:.3f}, indicando dados compactados ou cifrados.",
                "mitre_id": "T1027.002",
                "severity": "high",
                "confidence": 0.90,
                "evidence_count": 1,
                "evidence": [{"type": "section", "matched": name, "entropy": entropy}],
            })

    return detected


def analyze_target_capabilities(target: Path, report_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Analisa um arquivo alvo ou aproveita um relatório existente para detectar capacidades."""
    target_path = Path(target)
    if not target_path.is_file():
        return {
            "schema": SCHEMA,
            "status": "error",
            "target": str(target),
            "target_sha256": None,
            "capabilities": [],
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0},
            "errors": [{"code": "target_not_found"}],
            "limitations": ["arquivo alvo inexistente ou inacessível"],
        }

    digest = hashlib.sha256(target_path.read_bytes()).hexdigest()

    imports: list[str] = []
    strings: list[str] = []
    sections: list[dict[str, Any]] = []
    calls: list[str] = []

    if report_data and isinstance(report_data, dict):
        imports = [str(x) for x in report_data.get("imports", [])]
        strings = [str(x) for x in report_data.get("strings", [])]
        sections = list(report_data.get("sections", []))
    else:
        # Se relatório não foi passado, extrai strings rápidas e triage básica
        raw = target_path.read_bytes()
        # extração ASCII rápida de strings >= 4 chars
        ascii_matches = re.findall(b"[ -~]{4,}", raw)
        strings = [m.decode("ascii", errors="replace") for m in ascii_matches[:20000]]
        # detecção simples de MZ / ELF imports e APIs em texto
        imports = [s for s in strings if re.match(r"^[A-Za-z_][A-Za-z0-9_]{2,60}$", s)]

    capabilities = detect_capabilities_from_features(
        imports=imports,
        strings=strings,
        sections=sections,
        calls=calls,
    )

    summary = {
        "total": len(capabilities),
        "high": sum(1 for c in capabilities if c["severity"] == "high"),
        "medium": sum(1 for c in capabilities if c["severity"] == "medium"),
        "low": sum(1 for c in capabilities if c["severity"] == "low"),
        "categories": sorted({c["category"] for c in capabilities}),
    }

    return {
        "schema": SCHEMA,
        "status": "complete",
        "target": str(target_path.resolve()),
        "target_sha256": digest,
        "capabilities": capabilities,
        "summary": summary,
        "limitations": [
            "capacidades são inferências baseadas em padrões estáticos (APIs e strings)",
            "presença de capacidade não prova execução semântica ou intenção maliciosa sem validação de fluxo",
        ],
    }


def correlate_cross_gear_findings(target: Path) -> dict[str, Any]:
    """Correlaciona achados estáticos entre múltiplos motores (Capabilities + Crypto + Authenticode + Rust/Go)."""
    target_path = Path(target)
    base = analyze_target_capabilities(target_path)
    if base.get("status") != "complete":
        return base

    extra: list[dict[str, Any]] = []
    raw = target_path.read_bytes()

    # Correlacao 1: Constantes criptograficas (GEAR-01)
    try:
        from aether_re.crypto_detect import scan_bytes_for_crypto
        c_res = scan_bytes_for_crypto(raw)
        if c_res.get("identified_algorithms"):
            extra.append({
                "id": "crypto/confirmed-sbox-or-constants",
                "category": "cryptography",
                "title": f"Constantes Criptográficas Confirmadas ({', '.join(c_res['identified_algorithms'])})",
                "description": "S-Boxes ou vetores criptográficos exatos detectados via GEAR-01.",
                "mitre_id": "T1573",
                "severity": "medium",
                "confidence": 0.95,
                "evidence_count": c_res["total_constants_detected"],
                "evidence": [{"type": "crypto_detect", "algorithms": c_res["identified_algorithms"]}],
            })
    except Exception:
        pass

    # Correlacao 2: Authenticode / TLS / Overlay (GEAR-03)
    if raw[:2] == b"MZ":
        try:
            from aether_re.authenticode_audit import audit_pe_authenticode
            a_res = audit_pe_authenticode(raw)
            if a_res.get("status") == "signed_digest_mismatch":
                extra.append({
                    "id": "evasion/authenticode-digest-tampered",
                    "category": "evasion",
                    "title": "Assinatura Authenticode Violada (Digest Mismatch)",
                    "description": "O binário PE possui certificado PKCS#7, porém o digest calculado diverge do SpcIndirectDataContent.",
                    "mitre_id": "T1553.002",
                    "severity": "high",
                    "confidence": 0.99,
                    "evidence_count": 1,
                    "evidence": [{"type": "authenticode", "status": "signed_digest_mismatch"}],
                })
            if a_res.get("has_tls_directory"):
                extra.append({
                    "id": "execution/pe-tls-callbacks",
                    "category": "execution",
                    "title": "Diretório TLS PE Presente (Pré-Entrypoint)",
                    "description": "Executável PE declara diretório TLS, frequentemente usado para inicialização ou anti-debug antes do entrypoint.",
                    "mitre_id": "T1055",
                    "severity": "medium",
                    "confidence": 0.85,
                    "evidence_count": 1,
                    "evidence": [{"type": "pe_tls", "present": True}],
                })
        except Exception:
            pass

    if extra:
        base["capabilities"].extend(extra)
        caps = base["capabilities"]
        base["summary"] = {
            "total": len(caps),
            "high": sum(1 for c in caps if c["severity"] == "high"),
            "medium": sum(1 for c in caps if c["severity"] == "medium"),
            "low": sum(1 for c in caps if c["severity"] == "low"),
            "categories": sorted({c["category"] for c in caps}),
        }
    return base
