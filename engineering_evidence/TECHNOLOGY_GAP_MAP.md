# MAPA DE LACUNAS TECNOLÓGICAS (TECHNOLOGY GAP MAP)
**Projeto:** AetherRE Megazord
**Data de Levantamento:** 2026-10-25
**Metodologia:** Análise de gaps em engenharia reversa e forense de executáveis contra requisitos da indústria (SANS FOR610, Mandiant, Hex-Rays).

---

## 1. Inventário de Lacunas Técnicas Reais

### [GAP-01] Reconhecimento Automatizado de Constantes Criptográficas & Tabelas S-Box (FindCrypt / SignSearch)
- **Descrição da Lacuna:** Em análises forenses de malwares e binários de comando e controle (C2), o uso de criptografia personalizada ou estática (AES, ChaCha20, SHA-256, MD5, RC4, CRC32, Salsa20, TEA/XTEA) é a principal técnica para ofuscar strings e payloads de rede. Atualmente, o Megazord não possui um motor dedicado de varredura de assinaturas de constantes criptográficas e S-Boxes para localizar imediatamente os offsets de algoritmos de cifragem no binário.
- **Impacto no Workflow:** Alto. Permite ao analista identificar em segundos exatamente onde o algoritmo de criptografia opera e quais constantes são referenciadas sem precisar descompilar todo o binário manualmente.
- **Implementações Canônicas na Indústria:** IDA Pro `FindCrypt`, `findcrypt-yara`, Radare2 `rahash2 / r2 -c "/c"`, Luigi Auriemma `signsrch`.
- **Viabilidade e Integração:** Extremamente alta. Algoritmo em O(N) com janela deslizante ou Aho-Corasick, licença permissiva (MIT / Public Domain), zero impacto destrutivo.

---

### [GAP-02] Reconstrução de Símbolos e Metadados de Binários Stripped em Golang (Go pclntab & Type Descriptors)
- **Descrição da Lacuna:** Executáveis compilados em Go (Go binaries) frequentemente vêm "stripped", removendo a tabela de símbolos tradicional PE/ELF. No entanto, o runtime do Go embute a estrutura `pclntab` (PC-Line Table), nomes de módulos e pacotes, e tabelas de tipos na seção `.rodata` / `.gopclntab`. Sem essa reconstrução, funções aparecem no descompilador como `FUN_00401000`.
- **Impacto no Workflow:** Médio-Alto. Permite recuperar nomes originais de pacotes, funções e arquivos de origem de ferramentas escritas em Go.
- **Implementações Canônicas na Indústria:** `mandiant/GoReSym`, `redress`, `golang_loader_assist`.
- **Viabilidade e Integração:** Média. Requer parsing de estruturas complexas de versões variantes do Go (Go 1.2 to 1.23 pclntab magic headers `0xFFFFFFFB`, `0xFFFFFFF0`, etc.).

---

### [GAP-03] Auditoria Forense de Certificados Authenticode PE & Anomalias de Assinatura
- **Descrição da Lacuna:** O Windows utiliza o diretório de segurança `IMAGE_DIRECTORY_ENTRY_SECURITY` para armazenar o blob PKCS#7 da assinatura Authenticode. Atores maliciosos injetam dados no overlay ou exploram o CVE-2020-0601 (curva elíptica forjada). O Megazord ainda não audita os certificados digitais embutidos e nem checa integridade do hash do authenticode contra os certificados x509.
- **Impacto no Workflow:** Médio. Validação de proveniência de binários legítimos vs cavalos de Troia assinados com certificados roubados.
- **Implementações Canônicas na Indústria:** `cryptography`, `pefile`, `osslsigncode`.

---

### [GAP-04] Vinculação Automática de Tabelas de Tipos DWARF / PDB à Descompilação Ghidra
- **Descrição da Lacuna:** Quando um arquivo `.pdb` ou seção `.debug_info` (DWARF) está disponível, o decompiler precisa mesclar esses tipos estruturais às variáveis locais descompiladas.
- **Impacto no Workflow:** Médio. Acelerador de legibilidade para binários acompanhados de debug symbols.
- **Implementações Canônicas na Indústria:** `llvm-pdbutil`, `dia2dump`, `pyelftools`.

---

## 2. Decisão de Priorização Estratégica

| Lacuna | Valor para o Analista | Esforço de Adaptação | Risco de Regressão | Prioridade |
|---|---|---|---|---|
| **GAP-01: FindCrypt / Crypto Constant Scanner** | **Máximo (98/100)** | **Baixo (95/100)** | **Zero (99/100)** | **PRIORIDADE 1 (ALVO DO DISCOVERY-100)** |
| **GAP-02: Go pclntab Stripped Symbol Extractor** | Alto (88/100) | Médio (75/100) | Baixo (85/100) | Prioridade 2 (Roadmap) |
| **GAP-03: PE Authenticode & Cert Forensics** | Médio (78/100) | Baixo (85/100) | Baixo (90/100) | Prioridade 3 (Roadmap) |
| **GAP-04: DWARF / PDB Symbol Binding** | Médio (75/100) | Alto (60/100) | Médio (70/100) | Prioridade 4 (Roadmap) |
