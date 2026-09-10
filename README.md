# AetherRE MEGAZORD

Orquestrador de **engenharia reversa + forense de binários** que funde, num único pipeline, o melhor de:

| Fonte | O que o Megazord absorveu |
|-------|---------------------------|
| **Ghidra** | Adapter headless de decompilação + modelo de análise SRE |
| **ImHex** | Triage forense, entropia, vista de bytes, padrões |
| **Cutter/Rizin** | Adapter CLI + disasm estilo radare + análise JSON |
| **HyperDecode** | Auto-decode multi-camada (Base64/hex/URL/XOR) |
| **Unicorn** | Emulação isolada de entry-point PE (Windows fallback seguro) |
| **Frida** | Scripts de hooks dinâmicos (sem auto-executar malware) |
| **angr** | CFG estático + análise simbólica (CFGFast) |
| **Binary Ninja** | Adapter opcional para decompilação MLIL/HLIL (requer licença) |

## Honestidade técnica (importante)

**Não existe** ferramenta que extraia o código-fonte original de *qualquer* caixa-preta com precisão 100%.

O Megazord maximiza:

1. Evidência estrutural (PE/ELF, imports, exports, secções)
2. Strings e payloads ofuscados
3. Disassembly / decompilação (quando Ghidra/Rizin/Binary Ninja estão presentes)
4. Pseudo-fonte semântica com score de confiança calibrado
5. Pistas dinâmicas (Frida/Unicorn)
6. **Consenso por função** com ponderação de fontes, concordância e cobertura

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

- `report.json` — dados completos (evidência por função, consenso, cobertura)
- `pseudo_source.c` — decompilação Ghidra + esqueleto semântico nativo
- `findings.md` — relatório legível por função (consenso, fontes, confiança)
- `strings.txt` — strings extraídas
- `ghidra_export/functions.json` — índice de funções Ghidra (endereço, nome, chamadas, avisos)
- `comparative/function_comparison.csv` — tabela por função com métricas de consenso
- `comparative/source_agreement_matrix.json` — taxas de concordância entre fontes
- `comparative/divergent_functions.json` — funções com discordância entre fontes
- `angr_report.json` — CFG e funções do angr
- `rizin_raw.txt` — saída bruta do Rizin
- `frida_hooks.js` / `frida_HOW_TO.txt` — hooks Frida prontos para uso

## Instalação de gigantes (opcional)

Disco C/D neste PC estava apertado; os instaladores grandes ficam **manuais**:

```powershell
powershell -ExecutionPolicy Bypass -File aether_re\install\install_tools.ps1 -Action all-light
powershell -ExecutionPolicy Bypass -File aether_re\install\install_tools.ps1 -Action ghidra-hint
powershell -ExecutionPolicy Bypass -File aether_re\install\install_tools.ps1 -Action rizin
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
      └── adapters/
           ├── ghidra (headless decompilation)
           ├── rizin (CLI + JSON functions)
           ├── angr (CFGFast CFG)
           ├── frida (hooks generation)
           ├── unicorn (emulation, Windows-safe)
           └── binaryninja (MLIL/HLIL, opcional)
```

## Consenso por função

O motor de consenso pondera evidências de múltiplas fontes por função:

| Fonte | Peso |
|-------|------|
| Ghidra | 0.35 |
| Binary Ninja | 0.20 |
| Rizin | 0.20 |
| angr | 0.15 |
| Nativo (semântico) | 0.10 |

Métricas por função:
- **Confiança**: combinação de confiança ponderada + concordância + cobertura
- **Cobertura**: proporção de fontes que contribuíram para a função
- **Concordância**: Jaccard sobre chamadas/imports + similaridade de nomes
- **Qualidade da evidência**: ponderada pela confiança da fonte

Relatórios comparativos gerados automaticamente:
- `comparative/function_comparison.csv` — métricas por função
- `comparative/source_agreement_matrix.json` — concordância entre pares de fontes
- `comparative/divergent_functions.json` — funções com discordância entre fontes

## CLI

```powershell
# Status dos adaptadores
py -3.13 megazord.py status

# Análise básica
py -3.13 megazord.py analyze C:\Windows\System32\notepad.exe

# Análise com saída customizada
py -3.13 megazord.py analyze C:\Windows\System32\cmd.exe --out D:\AetherRE_Megazord\output\minha_analise

# Auto-test (usa python.exe ou notepad.exe)
py -3.13 megazord.py selftest

# Análise rasa (sem disasm profundo)
py -3.13 megazord.py analyze <arquivo> --shallow

# Análise sem adapters externos
py -3.13 megazord.py analyze <arquivo> --no-adapters
```

## Limitações conhecidas

- Binários packed/cifrados exigem unpack **antes** da análise estática profunda
- Rizin requer instalação separada (winget/chocolatey/GitHub releases)
- Binary Ninja requer licença válida e API Python configurada
- Unicorn em Windows roda em modo seguro (sem emulação real)
- Frida gera scripts — não executa o alvo automaticamente (segurança)
- angr CFG é estático; execução simbólica não é automática
- Pseudo-fonte **NÃO** é código-fonte original

## Exemplos de uso legítimo

```powershell
# Auditoría de software próprio
py -3.13 megazord.py analyze .\meu_programa.exe

# Análise de malware em lab isolado
py -3.13 megazord.py analyze .\sample_malware.bin --out .\relatorios\malware_001

# CTF / engenharia reversa educacional
py -3.13 megazord.py analyze .\challenge.bin --out .\ctf\chal_01
```

## Saída detalhada

Cada análise gera:
- **Report JSON** completo com `merged_functions` (consenso), `function_evidence` (evidência bruta), `adapter_results`, `coverage`, `confidence_rationale`
- **Markdown legível** com tabelas por função, fontes, confiança, chamadas, imports, strings
- **CSV comparativo** para importar em planilhas/BI
- **Matriz de concordância** entre fontes
- **Lista de funções divergentes** para revisão manual

## Dependências

```txt
pefile>=2023.2.7
capstone>=5.0.0
rich>=13.0.0
unicorn>=2.0.1
frida-tools>=14.0.0
angr>=9.0.0
```

Opcionais (requerem instalação separada):
- Ghidra 12.1+ (defina `GHIDRA_HOME`)
- Rizin 0.9+ (no PATH)
- Binary Ninja + API Python (licença necessária)
- Frida tools (pip install frida-tools)
- Unicorn (pip install unicorn)

## Licença

Uso legítimo apenas. Ver seção "Uso legítimo" acima.