# ACCEPTANCE CONTRACT (SCOPE FREEZE) — MASTER PROTOCOL ALPHA-C7 DISCOVERY-100 (ROUND 2)
**Document Version:** 3.1.0
**Project:** Reverse Engineering Graph (AetherRE Megazord)
**Repository Root:** `D:\AetherRE_Megazord`
**Git Branch:** `codex/re-megazord-execution`
**Head Commit:** `ccf7315582f3c05c065f4d88e6e87f8725bb796e` (Release Tag: `v2.0.0-sota-homologated`)
**Timestamp:** 2026-10-25T20:05:00-03:00
**Operational Mode:** `SINGLE_AGENT_WITH_TOOLS` (Auditor Externo via `AetherMind_Strict_Auditor.py` e testes adversariais automatizados)
**Target Gear:** `GEAR-02` — Golang Stripped Symbol & pclntab Recovery Engine (`GAP-02`)
**Status:** FROZEN & IMMUTABLE BY BUILDER

---

## 1. Canonical Workspace & Baseline Integrity
- **Workspace:** `D:\AetherRE_Megazord`
- **Active Environment:** Python 3.13.13 (`E:\AetherRE_Toolchain\venv_core_replay_20260924_a\Scripts\python.exe`)
- **Strict Auditor:** `F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py`
- **Baseline Quality:** 6/6 testes aprovados no auditor empírico, 26 ferramentas MCP ativas, zero dívidas técnicas.

## 2. Objective, Domain & Scope Boundaries
- **Objective:** Integrar o motor industrial de recuperação de símbolos e metadados de binários compilados em Go (`aether_re/golang_recover.py`), eliminando o `GAP-02` identificado no catálogo Discovery-100:
  1. Suporte aos magic headers canônicos da `pclntab`: `0xFFFFFFFB` (Go 1.2-1.15), `0xFFFFFFF0` (Go 1.16-1.17), `0xFFFFFFFA` (Go 1.18-1.19), `0xFFFFFFF1` (Go 1.20-1.23+).
  2. Extração segura da tabela de funções (`functab`), cálculo de endereços virtuais (PC) e resolução de strings na `funcnametab`.
  3. Reconhecimento gracioso de binários que não são Go (retorno `is_go_binary: False` sem crash).
  4. Exposição CLI `megazord.py golang-recover <alvo>` e Ferramenta MCP #27 (`aether_golang_recover`).
- **Domain:** Engenharia reversa de linguagens modernas compiladas (Go / Golang), reconstrução de símbolos stripped e mapeamento de chamadas.
- **Explicit Scope Boundaries:** 100% execução local offline; zero requisições externas; zero modificação de dependências globais.

## 3. Eliminatory Quality Gates
- **G01 (No-Crash Non-Go):** Binários PE/ELF não-Go devem retornar `is_go_binary: False` e lista vazia sem lançar exceções não tratadas -> Eliminatório.
- **G02 (Pclntab Parsing):** Mapeamento correto de cabeçalhos de 32-bit e 64-bit, quantum de instrução e tamanho de ponteiro -> Eliminatório.
- **G03 (No Mocking):** Todas as estruturas de teste e extrações devem processar layouts binários reais de acordo com a especificação do runtime do Go (`runtime/symtab.go`) -> Eliminatório.
- **G04 (Unit Suite 100%):** Suíte em `tests/test_golang_recover.py` aprovada com 100% de sucesso -> Eliminatório.
- **G05 (Strict Empirical Auditor):** Script `test_empirical_megazord_auditor.py` (7/7 testes) certificado pelo `AetherMind_Strict_Auditor.py` -> Eliminatório.
