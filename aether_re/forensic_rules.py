"""AetherRE Megazord — Forensic Rules & Threat Signature Synthesizer.

Gera assinaturas de detecção de alta fidelidade (YARA e Sigma) a partir da análise
estática, capacidades identificadas (MITRE ATT&CK), strings forenses e bytes de entry point.

Implementa supressão de ruído (false-positive reduction) e garante conformidade
sintática fail-closed.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

from aether_re.capabilities import analyze_target_capabilities
from aether_re.engines import pe_elf, strings_decode, triage

SCHEMA = "forensic-rules-report.v1"

# Ruídos comuns em binários Windows/Linux a suprimir para evitar falsos positivos
COMMON_NOISE_STRINGS = frozenset({
    "this program cannot be run in dos mode",
    "kernel32.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "ntdll.dll",
    "msvcrt.dll",
    "getmodulehandle",
    "getprocaddress",
    "loadlibrary",
    "exitprocess",
    "closehandle",
    "getlasterror",
    "setlasterror",
    "sleep",
    ".text",
    ".data",
    ".rdata",
    ".bss",
    ".rodata",
    ".reloc",
    ".rsrc",
    "gcc: (gnu)",
    "microsoft visual c++",
    "rich",
    "corereadiness",
})


def _sanitize_rule_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not cleaned or not cleaned[0].isalpha() and cleaned[0] != "_":
        cleaned = f"AetherRE_{cleaned}"
    return cleaned[:64]


def _filter_discriminative_strings(raw_strings: list[str], max_count: int = 15) -> list[str]:
    candidates = []
    seen = set()

    for s in raw_strings:
        s_clean = s.strip()
        low = s_clean.lower()
        if len(s_clean) < 6 or len(s_clean) > 256:
            continue
        if any(noise in low for noise in COMMON_NOISE_STRINGS):
            continue
        if low in seen:
            continue
        seen.add(low)
        candidates.append(s_clean)
        if len(candidates) >= max_count:
            break

    return candidates


def generate_yara_rule(
    target_path: Path,
    rule_name: str | None = None,
    *,
    custom_description: str | None = None,
    max_strings: int = 12,
) -> dict[str, Any]:
    """Sintetiza uma regra YARA estrita a partir de características físicas do binário."""
    p = Path(target_path)
    if not p.is_file():
        raise FileNotFoundError(f"Alvo não encontrado: {target_path}")

    raw = p.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    file_size = len(raw)
    magic = triage.detect_magic(raw[:64])
    entropy = round(triage.shannon_entropy(raw[: 4 * 1024 * 1024]), 4)

    # Nome da regra
    safe_name = _sanitize_rule_name(rule_name or f"Malware_{sha256[:12]}")

    # Extração de strings e capacidades
    ascii_s = strings_decode.extract_ascii_strings(raw, min_len=6)
    utf16_s = strings_decode.extract_utf16le_strings(raw, min_len=6)
    all_strings = list(dict.fromkeys(ascii_s + utf16_s))
    selected_strings = _filter_discriminative_strings(all_strings, max_count=max_strings)

    # Análise de capacidades
    caps_report = analyze_target_capabilities(p)
    mitre_ids = [c.get("mitre_id") for c in caps_report.get("capabilities", []) if c.get("mitre_id")]
    mitre_str = ", ".join(sorted(set(mitre_ids))) or "T1027"
    severity = "critical" if caps_report.get("summary", {}).get("high", 0) > 1 else "high"

    # Entry point hex sample
    entry_hex = ""
    if magic == "pe/dos" and len(raw) >= 128:
        try:
            struct_info = pe_elf.run_structure(raw)
            ep_val = struct_info.get("entry_point")
            if ep_val and isinstance(ep_val, str) and ep_val.startswith("0x"):
                ep_int = int(ep_val, 16)
                if 0 < ep_int < len(raw) - 16:
                    entry_hex = raw[ep_int : ep_int + 16].hex()
        except Exception:
            pass

    if not entry_hex and len(raw) >= 32:
        entry_hex = raw[16:32].hex()

    # Formatação das strings em sintaxe YARA
    yara_strings_block = []
    if entry_hex:
        # Formata hex com espaços
        spaced_hex = " ".join(entry_hex[i : i + 2] for i in range(0, len(entry_hex), 2)).upper()
        yara_strings_block.append(f"        $entry_bytes = {{ {spaced_hex} }}")

    for idx, s in enumerate(selected_strings, 1):
        # Escapa aspas e barras invertidas
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        is_wide = s in utf16_s
        modifier = "wide ascii" if is_wide else "ascii"
        yara_strings_block.append(f'        $s{idx} = "{escaped}" {modifier}')

    strings_rendered = "\n".join(yara_strings_block) if yara_strings_block else '        $dummy_hash = "' + sha256 + '"'

    # Condição determinística
    condition_parts = []
    if magic == "pe/dos":
        condition_parts.append("uint16(0) == 0x5A4D")
    elif magic.startswith("elf"):
        condition_parts.append("uint32(0) == 0x464C457F")

    # Limite superior de tamanho: dobro do tamanho do arquivo arredondado para cima
    max_mb = max(1, math_ceil_mb(file_size * 2))
    condition_parts.append(f"filesize < {max_mb}MB")

    if entry_hex:
        condition_parts.append("($entry_bytes or " + f"{min(2, len(selected_strings))} of ($s*))" if selected_strings else "$entry_bytes")
    else:
        req_count = min(3, len(selected_strings)) if selected_strings else 1
        condition_parts.append(f"{req_count} of ($s*)")

    condition_rendered = " and\n        ".join(condition_parts)

    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    desc = custom_description or f"Assinatura forense gerada automaticamente para {p.name}"

    yara_code = f"""rule {safe_name}
{{
    meta:
        description = "{desc}"
        author = "AetherRE Megazord"
        date = "{today}"
        target_sha256 = "{sha256}"
        threat_severity = "{severity}"
        mitre_att_ck = "{mitre_str}"
        entropy = "{entropy}"
        generator = "AetherRE Megazord Forensic Synthesizer"

    strings:
{strings_rendered}

    condition:
        {condition_rendered}
}}
"""

    # Geração de Regra Sigma correspondente
    sigma_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, sha256))
    sigma_yaml = f"""title: Detecção de Execução do Artefato {p.name}
id: {sigma_id}
status: experimental
description: Detecta a criação de processo ou execução com hash correspondente ao artefato auditado pelo Megazord.
author: AetherRE Megazord
date: {today}
references:
  - sha256:{sha256}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Hashes|contains: '{sha256}'
  condition: selection
fields:
  - CommandLine
  - Image
  - ParentImage
  - Hashes
falsepositives:
  - Ambientes de teste autorizados
level: {severity}
"""

    return {
        "schema": SCHEMA,
        "status": "generated",
        "target": str(p.resolve()),
        "target_sha256": sha256,
        "rule_name": safe_name,
        "yara_rule": yara_code,
        "sigma_rule": sigma_yaml,
        "strings_count": len(selected_strings),
        "mitre_techniques": mitre_ids,
        "limitations": [
            "assinatura gerada a partir de observações estáticas do binário",
            "validação em corpus benigno holdout recomendada para aferição de falsos positivos",
        ],
    }


def math_ceil_mb(bytes_val: int) -> int:
    return max(1, (bytes_val + (1024 * 1024 - 1)) // (1024 * 1024))
