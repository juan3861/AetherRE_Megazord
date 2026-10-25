# ACCEPTANCE CONTRACT (SCOPE FREEZE) — MASTER PROTOCOL ALPHA-C7 DISCOVERY-100
**Document Version:** 3.0.0
**Project:** Reverse Engineering Graph (AetherRE Megazord)
**Repository Root:** `D:\AetherRE_Megazord`
**Git Branch:** `codex/re-megazord-execution`
**Head Commit:** `dc7e05a4b7b6170aac3d13df7df10ff1450476a4` (Release Tag: `v2.0.0-sota-homologated`)
**Timestamp:** 2026-10-25T18:15:00-03:00
**Operational Mode:** `SINGLE_AGENT_WITH_TOOLS` (Auditor Externo via `AetherMind_Strict_Auditor.py` e testes adversariais automatizados)
**Status:** FROZEN & IMMUTABLE BY BUILDER

---

## 1. Canonical Workspace & Baseline Integrity
- **Workspace:** `D:\AetherRE_Megazord`
- **Active Environment:** Python 3.13.13 (`E:\AetherRE_Toolchain\venv_core_replay_20260924_a\Scripts\python.exe`)
- **Decompilation Engine:** NSA Ghidra 12.1.4 Headless + OpenJDK 21 LTS (`E:\AetherRE_Toolchain\ghidra_12.1.4_PUBLIC`)
- **Strict Auditor:** `F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py`
- **Pre-existing Local Modifications:** Branch preservada sem operações destrutivas. Modificações confinadas em `aether_re/`, `megazord.py`, `tests/`, `tools/`, `external_component_candidates/` e `engineering_evidence/`.

## 2. Objective, Domain & Scope Boundaries
- **Objective:** Ativar o protocolo industrial **ALPHA-C7 DISCOVERY-100** para:
  1. Conduzir varredura sistemática e rastreável de 100 repositórios canônicos e únicos no nicho de engenharia reversa e análise binária.
  2. Mapear capacidades existentes (`EXISTING_CAPABILITY_MAP.md`) e lacunas tecnológicas (`TECHNOLOGY_GAP_MAP.md`).
  3. Pontuar componentes (`COMPONENT_SCORECARD.csv`) sob dois eixos: Relevância (0-100) e Prontidão de Integração (0-100).
  4. Realizar staging (em `external_component_candidates/selected/`) e integrar o componente de maior impacto líquido mensurável com modificação mínima e licença compatível (FindCrypt / Detecção Criptográfica Forense em Binários).
  5. Validar via testes de unidade, auditoria adversarial e homologação pelo Guardião Estrito OMEGA.
- **Domain:** Engenharia reversa estática, descompilação automatizada, desofuscação, identificação de primitivas criptográficas, forense de executáveis e memória.
- **Explicit Scope Boundaries:** 100% execução local offline; zero requisições a serviços externos de nuvem; zero quebra de contratos de ferramentas MCP já homologadas.

## 3. Environment, Architecture & Interface Constraints
- **Core Architecture:** Pipeline desacoplado em 4 camadas (Intake -> Normalization -> Analytics -> Interfaces/MCP).
- **Interface Standards:**
  - CLI unificada: subcomandos de `megazord.py`.
  - Protocolo MCP: JSON-RPC 2.0 stdio em `aether_re/mcp_server.py`.
- **Inviolable Fallback Law:** Todo algoritmo ou analisador deve fornecer fallback puro em Python, com profundidade de iteração limitada e zero dependência externa de pacotes compilados obrigatórios no modo seguro.

## 4. Threat Model, Licensing & Privacy
- **Threat Model:** Binários malformados ou ofuscados desenhados para travar decompiler ou parser (bombas zip, loops infinitos de saltos indiretos, estouro de recursão). Todos os motores possuem cotas estritas de tempo e contagem de nós.
- **Licenses:** Licenças compatíveis (MIT, Apache-2.0, BSD-3-Clause, Public Domain). Nenhuma licença viral GPL estrita no código core redistribuível da biblioteca.
- **Privacy:** Processamento estritamente local; zero telemetria.

## 5. Baseline Functional & Performance Profile
- 5/5 testes da suíte empírica do auditor aprovados (`test_empirical_megazord_auditor.py`).
- 12/12 testes de desempacotadores aprovados (`test_unpackers.py`).
- 25 ferramentas MCP ativas e registradas em `mcp_config.json`.
- 100.0% de fidelidade de ground truth em C++ polimórfico de herança simples e múltipla (`poly_test.dll` e `multi_poly.dll`).

## 6. Eliminatory Quality Gates & Precedence
- **Precedência Estrita:** `FAIL` crítico autêntico > `UNKNOWN` / Evidência Incompleta > `Calculated Score`.
- **Critérios Eliminatórios:**
  - Qualquer exceção não tratada ou crash em binário malformado -> `REJECTED`.
  - Violação de licença ou inclusão de código proprietário -> `REJECTED`.
  - Falha na suíte de testes existente ou regressão -> `REJECTED`.
  - Reivindicação sem teste empírico executado -> `BLOCKED`.
- **Nota Mínima:** 95/100 na rubrica ponderada após gates eliminatórios superados.

## 7. Budget & Checkpoints
- **Memória:** < 512 MB peak durante análise.
- **Tempo:** Bounded loops em descompilação e análise de entropia/assinaturas.
- **Audit Ledger:** Fechamento formal dos recibos de teste em `AUDIT_LEDGER_ROOT.json`.
