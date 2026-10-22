# Reverse Engineering Graph (AetherRE)

Orquestrador de **engenharia reversa + forense de binários** que funde, num único pipeline, o melhor de:

| Fonte | O que o Megazord absorveu |
|-------|---------------------------|
| **NSA Ghidra 12.1.4** | Descompilação C industrial headless, High P-Code, injeção de structs C e resolução de vtables C++ |
| **Webcrack 2.16.0** | Desempacotamento de Webpack/Rollup, desachatamento de fluxo (unflattening) e deobfuscation JS/TS |
| **Windows DbgHelp** | Captura e auditoria forense de MiniDumps (.dmp), mapeamento de módulos e detecção de memória RWX |
| **Ground Truth Evaluator** | Avaliação matemática empírica de fidelidade de descompilação contra código C/C++ de referência |
| **MCP Server (JSON-RPC)** | Servidor nativo Model Context Protocol expondo 25 ferramentas para agentes de IA |
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

1. Evidência estrutural (PE/ELF, imports, exports, secções, segmentos, símbolos e relocations)
2. Strings e payloads ofuscados
3. Disassembly / decompilação (quando Ghidra/Rizin/Binary Ninja estão presentes)
4. Pseudo-fonte semântica com score heurístico (calibração cega ainda pendente)
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

Instalação **reproduzível do perfil core**: usar `requirements-core.lock` com `--require-hashes` e o wheelhouse fixado; procedimento e limites em `docs/F00_CORE_PROFILE_2026-09-17.md`. A linha `requirements.txt` acima resolve versões móveis e não é prova de instalação reproduzível.

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

Cada execução cria `input.snapshot` verificado e usa `run.lock` para impedir
publicação concorrente no mesmo diretório. O snapshot é somente a entrada da
análise; não é a fonte original e não autoriza execução automática do alvo.

Para retomar o estado local sem depender de uma janela de conversa, execute
`D:\AetherRE_Megazord\restore_session.ps1` (o atalho da área de trabalho já o
chama). Ele grava `output\session_restore_*.json` com status, Git, checkpoints e
hashes dos runs recentes. A rotina é somente leitura e declara
`conversation_restored=false`: o id legado é apenas um rótulo de rastreabilidade.

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
# Servidor MCP nativo JSON-RPC 2.0 (25 ferramentas registradas)
py -3.13 megazord.py mcp

# Descompilação C de nível industrial via NSA Ghidra 12.1.4 Headless
py -3.13 megazord.py ghidra-decompile meu_binario.dll --type-injection --out decompiled.c

# Descompactação e desofuscação de bundles JS/TS via webcrack 2.16.0
py -3.13 megazord.py webcrack bundle.js --out-dir ./unpacked

# Auditoria forense de arquivo MiniDump Windows (.dmp) para módulos e memória RWX
py -3.13 megazord.py minidump-audit dump.dmp

# Avaliação matemática de fidelidade contra código-fonte C/C++ de referência (Ground Truth)
py -3.13 megazord.py ground-truth-bench --target binario.dll --source fonte.c --function nome_funcao

# Status dos adaptadores
py -3.13 megazord.py status

# Análise básica
py -3.13 megazord.py analyze C:\Windows\System32\notepad.exe

# Análise com saída customizada
py -3.13 megazord.py analyze C:\Windows\System32\cmd.exe --out D:\AetherRE_Megazord\output\minha_analise

# Auto-test (usa python.exe ou notepad.exe)
py -3.13 megazord.py selftest

# Leitura estática de projeto Python (não executa imports)
py -3.13 megazord.py source-analyze C:\caminho\do\projeto --out .\source_report.json

# Leitura estática conservadora de C/C++ (não compila nem executa)
py -3.13 megazord.py c-source-analyze C:\caminho\do\projeto --out .\c_source_report.json

# Inventário multi-linguagem limitado por budget
py -3.13 megazord.py project-inventory C:\caminho\do\projeto --out .\inventory.json

# Auditoria estática integrada (inventário + fonte Python/C/C++ + build/riscos)
py -3.13 megazord.py project-audit C:\caminho\do\projeto --out .\project_audit.json

# Snapshot local do escopo inventariado, em diretório NOVO fora do projeto
py -3.13 megazord.py project-snapshot C:\caminho\do\projeto D:\snapshots\projeto_001 --report .\snapshot_create.json
py -3.13 megazord.py project-snapshot-verify D:\snapshots\projeto_001 --expected-manifest-sha256 HASH_DO_RELATORIO --report .\snapshot_verify.json
# Se existir compile_commands.json, cada unidade/flag/hash de fonte é registrado;
# o compilador nunca é executado implicitamente.

# Dependências declaradas versus imports/includes observados (sem instalar)
py -3.13 megazord.py project-dependencies C:\caminho\do\projeto --out .\dependencies.json

# Avaliar leitor de fonte contra oracles do corpus (não executa binários)
# bootstrap_v2 contém relações coerentes com a fonte; v1 é histórico
py -3.13 megazord.py corpus-evaluate .\corpus\bootstrap_v2\manifest.json --out .\corpus_eval.json

# Validar receitas do corpus sem executar binários
py -3.13 megazord.py corpus-validate .\corpus\bootstrap_v2\manifest.json
# Build C somente quando explicitamente solicitado (worker WSL/GCC; não executa binários)
# py -3.13 megazord.py corpus-build-native .\corpus\bootstrap_v2\manifest.json --out .\output\native-build
# Perfis O2/stripped são explícitos: --opt-level=-O2 --no-debug --strip
# Fixtures C sem main declaram build_kind=shared_library no manifesto; o worker
# gera ELF .so com -shared -fPIC, sem executar o binário.
# Avaliar os ELF construídos (hash/símbolos/DWARF; chamadas ficam not_measured)
# py -3.13 megazord.py corpus-evaluate-binaries .\corpus\bootstrap_v2\manifest.json --build-report .\output\native-build\build_report.json --out .\output\binary_eval.json
# O evaluator também verifica o hash da fonte declarado pelo build, o hash do
# oracle e rejeita caminhos de saída/snapshot com traversal ou symlink.
# Medição opcional de calls diretos locais (ELF x86/x86_64; estático):
# acrescente --measure-direct-calls; indiretos/PLT/inlining continuam não medidos.
# Comparar dois perfis do MESMO manifesto e mesmos projetos, sem executar alvos:
# py -3.13 megazord.py compare-binary-profiles --baseline .\output\o0_eval.json --candidate .\output\o2_strip_eval.json --out .\output\profile_delta.json
# status=complete significa comparação válida, NÃO desempenho/precisão suficiente.

# Gerar candidatos conservadores de correlação fonte/binário
py -3.13 megazord.py correlate --source-report .\source_report.json --binary-report .\report.json --out .\correlation.json
# Opcional: anexar unidades declaradas de compile_commands (não executa build)
# py -3.13 megazord.py correlate ... --build-report .\build.json

# Auditar indicadores estáticos de risco
py -3.13 megazord.py risk-audit --source-report .\source_report.json --out .\risk.json

# Validar trace externo sem executar alvo (preserva metadados/proveniência)
py -3.13 megazord.py trace-validate --input .\trace.json --out .\trace_report.json --max-events 100000
# Schema/hash inválidos, registros malformados e truncamento por budget ficam explícitos.

# Validar efeitos coletados contra escopo/política, sem executar alvo
py -3.13 megazord.py effects-validate --input .\effects.json --out .\effects_report.json --allowed-root D:\lab\run

# Validar alegações contra evidências identificadas
py -3.13 megazord.py claims-validate --claims claims.json --evidence evidence.json --out claims_report.json

# Assistência forense offline: hipóteses/experimentos são sempre propostas
py -3.13 megazord.py assist-propose --input evidence.json --out hypotheses.json --question "investigar divergência"
py -3.13 megazord.py assist-verify --proposals hypotheses.json --evidence evidence.json --out hypothesis_review.json
# A verificação confere citações e suporte declarado, mas nunca confirma automaticamente uma hipótese.

# Validar resultado de exploração simbólica produzido por worker isolado
py -3.13 megazord.py symbolic-validate --input symbolic_run.json --out symbolic_report.json
# O contrato impõe hash do alvo, budgets, paths únicos e atestado opcional de
# laboratório. SAT pode indicar contraexemplo; UNSAT/timeout nunca viram prova universal.

# Avaliar os 13 gates F00--F12 contra declarações e evidências hashadas
py -3.13 megazord.py phase-gates --input phase_gate_manifest.json --root . --out phase_gate_report.json
# Uma fase só é QUITADA com implementação, integração, revisão, testes sem
# falhas/skips obrigatórios e evidências regulares verificadas; ausência fica explícita.

# Auditar documentação e resolver apenas links locais dentro da raiz
py -3.13 megazord.py documentation-audit . --out documentation_report.json
# URLs externas são apenas catalogadas; exemplos de comandos nunca são executados.

# Persistir a projeção graph do source-report em SQLite e verificar integridade
py -3.13 megazord.py graph-ingest --input source_report.json --db output\graph.sqlite --run-id run-001 --out graph_ingest.json
py -3.13 megazord.py graph-verify --db output\graph.sqlite --out graph_verify.json
py -3.13 megazord.py graph-node --db output\graph.sqlite --node-id function:main.run --out graph_node.json
# O store é transacional e imutável por identidade; o relatório bruto continua sendo a fonte da evidência.

# Comparar observações externas original/reconstrução sem executar alvos
py -3.13 megazord.py differential-compare --original original_observations.json --reconstructed reconstructed_observations.json --out differential_report.json
# Cada contraexemplo recebe input_sha256 e reproduction_id determinísticos.
# Para reduzir um caso via API, use reduce_counterexample com um oracle booleano
# externo e budgets explícitos; o reducer não executa o alvo.

# Holdout cego/calibração (famílias e evidências disjuntas; declaração explícita)
py -3.13 megazord.py metrics-holdout --input .\predictions.json --out .\holdout_report.json --calibration-frozen
# Cada prediction exige sample_id, evidence_id, family, split, label, score e producer.

# Diagnóstico somente de ferramentas e módulos Python presentes (não instala nem executa alvo)
py -3.13 megazord.py doctor --json

# Gate declarativo forte para futuro laboratório VM (não inicia VM nem alvo)
py -3.13 megazord.py lab-preflight --authorized --isolation vm --runtime-proof --snapshot-id vm-snapshot-001 --rollback --collector-configured --timeout-s 60 --memory-mb 1024
# Opcional: anexar prova materializada do guest; a validação continua sem executar o alvo.
# py -3.13 megazord.py lab-preflight ... --proof .\runtime-proof.json

# Homologar integridade/completude de uma execução já concluída
py -3.13 megazord.py homologate .\output\minha_analise --out .\homologation.json
# Restaurar artefatos de pacote verificado para diretório novo (não executa nem sobrescreve)
py -3.13 megazord.py repro-restore .\minha_analise.repro.zip .\restored-run --out .\restore.json

# Análise rasa (sem disasm profundo)
py -3.13 megazord.py analyze <arquivo> --shallow

# Análise sem adapters externos
py -3.13 megazord.py analyze <arquivo> --no-adapters
```

## Limitações conhecidas

- `project-snapshot` copia apenas o escopo do inventário. Exclusões e cortes ficam no manifesto; `scope=partial` retorna código 2 mesmo com cópia verificada. Hash local não é custódia externa/WORM, e a leitura dupla não detecta mudança que se reverte entre leituras.
- Binários packed/cifrados exigem unpack **antes** da análise estática profunda
- Rizin requer instalação separada (winget/chocolatey/GitHub releases)
- Binary Ninja requer licença válida e API Python configurada
- Unicorn em Windows roda em modo seguro (sem emulação real)
- Frida gera scripts — não executa o alvo automaticamente (segurança)
- angr CFG é estático; execução simbólica não é automática
- ELF32/ELF64 é lido de forma fail-closed: tabelas inválidas, símbolos e relocations são reportados como observações estruturais, não como prova de comportamento
- PE32/PE32+ também preserva seções/segmentos, permissões, DLLs necessárias, exports e relocations; PE truncado/malformado rebaixa para finding explícito, sem inventar estrutura
- `corpus-build-native` é opt-in para fixtures `owned_synthetic` no WSL; WSL não é uma VM de malware e os binários gerados não são executados pelo Megazord
- `compare-binary-profiles` exige manifesto hashado e IDs idênticos; publica regressões e relações não comparáveis sem sugerir equivalência comportamental
- `assist-propose`/`assist-verify` são offline e determinísticos: citações e suporte são verificados, mas hipóteses nunca são promovidas a fatos
- `symbolic-validate` apenas valida artefatos externos bounded; não inicia solver nem executa alvo, e mantém `universal_proof=false` mesmo em UNSAT
- `phase-gates` é um verificador de declarações: não executa testes e não aceita `QUITADA` sem evidência hashada e revisão declarada
- `documentation-audit` extrai headings/fences/links e aponta referências quebradas ou inseguras sem consultar a internet nem executar exemplos
- `graph-ingest`/`graph-verify`/`graph-node` mantêm uma projeção SQLite hashada do grafo; não substituem artefatos brutos, não provam causalidade e não executam o projeto analisado
- Pseudo-fonte **NÃO** é código-fonte original

## Exemplos de uso legítimo

```powershell
# Auditoría de software próprio
py -3.13 megazord.py analyze .\meu_programa.exe

# Amostra hostil: NÃO usar este comando no Windows de trabalho. Somente em
# laboratório descartável, isolado e autorizado após prova operacional F08.

# CTF / engenharia reversa educacional
py -3.13 megazord.py analyze .\challenge.bin --out .\ctf\chal_01
```

## Saída detalhada

Cada análise gera:
- **Report JSON** completo com `merged_functions` (consenso), `function_evidence` (evidência bruta), `adapter_results`, `coverage`, `confidence_rationale`; para ELF, a estrutura preserva também `segments`, `symbols`, `relocations`, `needed_libraries` e `image_base_kind` (`preferred_vaddr`, não load bias runtime)
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
```

Opcionais (requerem instalação separada):
- Ghidra 12.1+ (defina `GHIDRA_HOME`)
- Rizin 0.9+ (no PATH)
- Binary Ninja + API Python (licença necessária)
- Frida tools (`requirements-frida.txt`, somente em ambiente de laboratório autorizado)
- angr (worker/perfil próprio, fora da instalação mínima)

## Licença

Uso legítimo apenas. Ver seção "Uso legítimo" acima.


## Resultados de Benchmarks Ground Truth (NSA Ghidra 12.1.4 Headless)

Fidelidade matemática empírica comparando código descompilado contra código-fonte C/C++ de referência:

| Biblioteca | Alvo Compilado | Linguagem | Exports Avaliados | Fidelidade Global | Exports com 100% de Paridade |
|---|---|---|---|---|---|
| **cJSON** | `cjson.dll` (x64 `/O2`) | C ANSI | 78 exports | **77.17%** | 17 funções |
| **TinyExpr** | `tinyexpr.dll` (x64 `/O2`) | C99 | 5 exports | **81.40%** | 2 funções (`te_free`, `te_interp`) |
| **C++ Poly** | `poly_test.dll` (x64 `/O2 /EHsc`) | C++17 Polymorphic | 4 exports | **100.00%** | 4 funções (todas com 100%) |

Relatórios detalhados com diffs e AST preservada em `engineering_evidence/`.

## Servidor MCP (Model Context Protocol)

O Megazord implementa um servidor MCP oficial com 25 ferramentas forenses registradas via JSON-RPC 2.0 stdio:

- Arquivo de configuração de integração: `aetherre-mcp-config.json`
- Ativação nativa em ferramentas como Gemini CLI, Antigravity, Claude Desktop e Cursor.

## Evidence Kernel

Authorized, immutable universal intake is documented in [docs/EVIDENCE_KERNEL.md](docs/EVIDENCE_KERNEL.md).
