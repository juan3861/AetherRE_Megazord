# MAPA DE CAPACIDADES EXISTENTES (EXISTING CAPABILITY MAP)
**Projeto:** AetherRE Megazord
**Data de Inventário:** 2026-10-25
**Ambiente:** Python 3.13.13 (`E:\AetherRE_Toolchain\venv_core_replay_20260924_a`)
**Status:** HOMOLOGADO & VERIFICADO

---

## 1. Motores Core de Análise Estática & Descompilação

| Módulo / Ferramenta | Arquivo de Origem | Capacidade Implementada | Dependência / Engine |
|---|---|---|---|
| **NSA Ghidra Headless Bridge** | `aether_re/ghidra_headless_bridge.py` | Descompilação C industrial headless, High P-Code, injeção de structs C e vtables C++ | Ghidra 12.1.4 + OpenJDK 21 |
| **Ground-Truth Empirical Evaluator** | `aether_re/ground_truth_eval.py` | Medição matemática de preservação de chamadas, loops, branches, fields e lowering de C++ | Nativo (re, AST C) |
| **Webcrack JavaScript Bridge** | `aether_re/webcrack_bridge.py` | Desempacotamento de Webpack/Rollup, desachatamento de CFG (unflattening) e desofuscação JS/TS | Node.js + Webcrack 2.16.0 |
| **Acorn AST JS Deobfuscator** | `aether_re/ast_deobfuscator_acorn.py` | Avaliação constante de strings/números, simplificação lógica booleana e resolução de sentinelas | Acorn 8.14.0 |
| **Universal Container Unpackers** | `aether_re/unpackers.py` | Desempacotamento seguro com contenção de path traversal para NSIS, InnoSetup, Electron ASAR, PyInstaller, ZIP, TAR e Firmware | Nativo + zlib / struct |
| **Windows MiniDump Forensics** | `aether_re/minidump_parser.py` | Parser de cabeçalhos MDMP, mapeamento de módulos carregados, detecção de memória RWX (`0x40`), auditoria de Heap NT e detecção de Heap Spraying | Nativo (struct, ctypes) |
| **Packer & Entropy Analyzer** | `aether_re/packer_detect.py` | Janela deslizante de entropia de Shannon (H), detecção de packers comerciais (UPX, Themida, VMProtect) e headers PE | Nativo (pefile / struct) |
| **Program Dependence Graph & Taint** | `aether_re/pdg_taint.py` | Construção de PDG (dependência de controle + dados) e fatiamento (taint slicing) da fonte ao sink com bounds de recursão | Nativo |
| **Struct & Layout Recovery** | `aether_re/struct_recovery.py` | Reconstrução de layouts de structs C a partir de acessos base-offset de registradores (Hex-Rays / Ghidra style) | Nativo |
| **CFG Dominance Engine** | `aether_re/cfg_dominance.py` | Árvores de dominância (idom), dominância pós-fixa, fronteiras de dominância e detecção de laços naturais via Lengauer-Tarjan | Nativo |
| **Symbolic Path Feasibility** | `aether_re/symbolic_constraints.py` | Verificação de viabilidade (SAT/UNSAT) e propagação de intervalos para ramos de controle | Nativo (DPLL / Interval) + z3 |
| **Binary Diffing & Alignment** | `aether_re/binary_diff.py` | Comparação estrutural de binários (BinDiff style) via casamento bipartido de grafos e similaridade topológica | Nativo |
| **Function SimHash (64-bit)** | `aether_re/function_simhash.py` | SimHash de funções binárias baseado em n-grams de mnemônicos e métricas de grafo (estilo Google SAFE) | Nativo |
| **MITRE ATT&CK Capabilities** | `aether_re/capabilities.py` | Mapeamento de capacidades forenses e de malware em regras semânticas (estilo Mandiant CAPA) | Nativo |
| **YARA & Sigma Generator** | `aether_re/signature_engine.py` | Geração automática de regras forenses YARA e Sigma a partir de strings, opcodes e imports | Nativo |
| **Model Context Protocol (MCP)** | `aether_re/mcp_server.py` | Servidor JSON-RPC 2.0 stdio com 25 ferramentas forenses registradas para agentes de IA | JSON-RPC 2.0 |

---

## 2. Inventário de Ferramentas MCP Ativas (25 Ferramentas)

1. `aether_status` — Estado dos motores e adapters
2. `aether_triage` — Triagem de metadados PE/ELF
3. `aether_inspect` — Inspeção forense profunda
4. `aether_detect_capabilities` — Mapeamento de capacidades MITRE ATT&CK
5. `aether_strings_forensic` — Extração de strings ASCII/Unicode ofuscadas
6. `aether_firmware_qualify` — Qualificação de layout de firmware
7. `aether_source_analyze` — Leitura de fontes C/C++/Python
8. `aether_unpack` — Desempacotador universal de contêineres e instaladores
9. `aether_symbolic_explore` — Exploração de caminhos simbólicos
10. `aether_binary_diff` — Comparação de binários (patch analysis)
11. `aether_generate_yara` — Geração de regras YARA e Sigma
12. `aether_export_graph` — Exportação de callgraphs (Mermaid, DOT, JSON)
13. `aether_function_simhash` — Cálculo de SimHash funcional de 64 bits
14. `aether_packer_detect` — Detecção de packers e cálculo de entropia
15. `aether_graph_analytics` — Métricas topológicas e complexidade ciclomática de McCabe
16. `aether_cfg_dominance` — Árvores de dominância e fronteiras de laço
17. `aether_deobfuscate` — Simplificação de expressões MBA e predicados opacos
18. `aether_abi_infer` — Inferência de ABI e protótipos de função
19. `aether_taint_slice` — Fatiamento de mancha do source ao sink
20. `aether_struct_recovery` — Reconstrução de structs e offsets de campos
21. `aether_check_feasibility` — Viabilidade de restrições com solver SMT
22. `aether_ghidra_decompile` — Descompilação completa via NSA Ghidra Headless
23. `aether_webcrack` — Desofuscação e unbundling de pacotes JS/TS
24. `aether_minidump_audit` — Auditoria de MiniDumps e Heap NT
25. `aether_ground_truth_eval` — Avaliação empírica de fidelidade contra código de referência
