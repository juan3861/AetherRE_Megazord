# CONSULTAS DE PESQUISA E LIMITES DE ESCOPO (SEARCH QUERIES & LIMITS)
**Protocolo:** ALPHA-C7 DISCOVERY-100
**Projeto:** AetherRE Megazord
**Data:** 2026-10-25

---

## 1. Famílias de Consulta Sistemática

Para cobrir a meta de 100 repositórios únicos, reais e canônicos no ecossistema de Engenharia Reversa, Descompilação, Forense e Análise de Binários, as seguintes 10 famílias temáticas foram pesquisadas e cruzadas:

1. **Family 1 — Decompilation & Intermediate Representations (IR):**
   - Queries: `ghidra decompiler`, `binary intermediate representation`, `lifter microcode`, `hlil mlil decompiler`.
2. **Family 2 — Disassembly & Core Frameworks:**
   - Queries: `capstone disassembler`, `radare2 cutter framework`, `binary ninja open source`, `angr binary analysis platform`.
3. **Family 3 — Symbolic Execution & SMT Solvers:**
   - Queries: `symbolic execution engine`, `z3 smt solver`, `manticore binary symbolic`, `triton dynamic binary analysis`.
4. **Family 4 — Binary Diffing & Function Similarity:**
   - Queries: `binary diffing bindiff`, `qbindiff graph matching`, `function simhash embeddings`, `diaphora ghidra diff`.
5. **Family 5 — JavaScript / Webpack Deobfuscation & AST:**
   - Queries: `webcrack webpack deobfuscator`, `js deobfuscation ast acorn`, `control flow unflattening babel`, `javascript unpacker`.
6. **Family 6 — Windows Memory Forensics & MiniDumps:**
   - Queries: `minidump parser windows`, `volatility memory forensics`, `process dump rwx memory`, `heap spray detection forensics`.
7. **Family 7 — Container Unpackers & Format Carvers:**
   - Queries: `innoextract innosetup unpacker`, `nsis installer decompressor`, `pyinstaller extractor pyz`, `asar electron extractor`.
8. **Family 8 — Cryptographic Constant Detection (FindCrypt / SignSearch):**
   - Queries: `findcrypt yara ida`, `signsrch cryptographic signature`, `crypto constant detector binary`, `sbox scanner reverse engineering`.
9. **Family 9 — Golang & Rust Binary Reverse Engineering:**
   - Queries: `go pclntab symbol recovery`, `goresym mandiant`, `rust binary demangler`, `stripped golang binary forensics`.
10. **Family 10 — Threat Forensics, Rules & CAPA:**
    - Queries: `mandiant capa malware capabilities`, `yara rule compiler`, `floss string deobfuscator`, `detect it easy pe analysis`.

---

## 2. Limites Epistemológicos & Anti-Manipulação

1. **Unicidade Canônica:** Forks puros e mirrors foram eliminados; apenas o repositório canônico / upstream é catalogado.
2. **Zero Alucinação:** Todas as 100 URLs no catálogo `DISCOVERY_100_CATALOG.csv` são repositórios reais existentes e amplamente documentados no GitHub ou projetos upstream oficiais.
3. **Diferenciação Estrita entre Repositório e Engrenagem:** O score de maturidade do repositório avalia governança e testes do projeto; o score da engrenagem avalia a aplicabilidade direta da função/algoritmo na lacuna do AetherRE Megazord.
4. **Gates Eliminatórios:** Licenças proprietárias ou virais não autorizadas barram a promoção para staging, independentemente de relevância 100/100.
