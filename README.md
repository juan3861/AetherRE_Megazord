# AetherRE MEGAZORD

Orquestrador de **engenharia reversa + forense de binários** que funde, num único pipeline, o melhor de:

| Fonte | O que o Megazord absorveu |
|-------|---------------------------|
| **Ghidra** | Adapter headless de decompilação + modelo de análise SRE |
| **ImHex** | Triage forense, entropia, vista de bytes, padrões |
| **Cutter/Rizin** | Adapter CLI + disasm estilo radare |
| **HyperDecode** | Auto-decode multi-camada (Base64/hex/URL/XOR) |
| **Unicorn** | Emulação isolada de entry-point PE |
| **Frida** | Scripts de hooks dinâmicos (sem auto-executar malware) |

## Honestidade técnica (importante)

**Não existe** ferramenta que extraia o código-fonte original de *qualquer* caixa-preta com precisão 100%.

O Megazord maximiza:

1. Evidência estrutural (PE/ELF, imports, exports, secções)
2. Strings e payloads ofuscados
3. Disassembly / decompilação (quando Ghidra está presente)
4. Pseudo-fonte semântica com score de confiança
5. Pistas dinâmicas (Frida/Unicorn)

Pseudo-fonte ≠ fonte original. O report deixa isso explícito.

## Uso rápido

```powershell
cd D:\AetherRE_Megazord
py -3.13 -m pip install -r requirements.txt
py -3.13 megazord.py status
py -3.13 megazord.py selftest
py -3.13 megazord.py analyze C:\Windows\System32\notepad.exe
```

Output em `output\<nome>_<timestamp>\`:

- `report.json` — dados completos
- `pseudo_source.c` — esqueleto / decompilação
- `findings.md` — relatório legível
- `strings.txt` — strings extraídas

## Instalação de gigantes (opcional)

Disco C/D neste PC estava apertado; os instaladores grandes ficam **manuais**:

```powershell
powershell -ExecutionPolicy Bypass -File aether_re\install\install_tools.ps1 -Action all-light
powershell -ExecutionPolicy Bypass -File aether_re\install\install_tools.ps1 -Action ghidra-hint
```

## Uso legítimo

- Software teu / com autorização
- Malware em lab isolado
- CTF / pesquisa / auditoria contratada

Não usar para crack, pirataria ou contornar proteções de terceiros.

## Arquitectura

```
megazord.py
 └── pipeline.run_megazord
      ├── engines/triage
      ├── engines/pe_elf
      ├── engines/strings_decode
      ├── engines/disasm
      ├── engines/reconstruct
      └── adapters/ ghidra | rizin | frida | unicorn
```
