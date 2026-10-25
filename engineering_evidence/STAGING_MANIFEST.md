# MANIFESTO DE STAGING (STAGING MANIFEST)
**Protocolo:** ALPHA-C7 DISCOVERY-100
**Componentes Selecionados:** 
- `GEAR-01` — FindCrypt / Crypto Signature & S-Box Scanner
- `GEAR-02` — GoReSym / Golang Stripped Symbol & pclntab Extractor
**Data:** 2026-10-25

---

## 1. Componente GEAR-01 — FindCrypt / Crypto Scanner
- **Origem Tecnológica:** Baseado nos algoritmos canônicos de `FindCrypt-Ghidra`, `findcrypt-yara` e `signsrch` (Luigi Auriemma)
- **Diretório de Staging:** `external_component_candidates/selected/crypto_detect/`
- **Módulo Destino de Produção:** `aether_re/crypto_detect.py`
- **Licença:** MIT / Public Domain (Totalmente permissiva e compatível)

### Avaliação de Gates Eliminatórios (GEAR-01)
| Gate Eliminatório | Critério | Veredito | Justificativa |
|---|---|---|---|
| **Gate 1 — Licença** | Compatibilidade estrita com MIT/Apache-2.0 | **PASS** | Algoritmos e constantes matemáticas de domínio público e MIT |
| **Gate 2 — Origem Verificável** | Repositório canônico upstream comprovado | **PASS** | URLs `ddis/findcrypt-yara` e `aluigi/signsrch` atestadas |
| **Gate 3 — Vulnerabilidade** | Zero código nativo vulnerável ou dependência binária | **PASS** | Implementação puramente estática e segura com limites de memória |
| **Gate 4 — Não-Duplicação** | Não duplica funcionalidade pré-existente no Megazord | **PASS** | O Megazord não possuía scanner de constantes criptográficas |
| **Gate 5 — Inviolabilidade** | Fallback em Python puro sem C-extensions obrigatórias | **PASS** | Opera com parsing de buffer binário e janela deslizante em memória |

---

## 2. Componente GEAR-02 — GoReSym / Golang pclntab & Symbol Extractor
- **Origem Tecnológica:** Baseado no design de desconstrução da tabela de símbolos `pclntab` do Go (`GoReSym` de Mandiant, `redress` de goretk)
- **Diretório de Staging:** `external_component_candidates/selected/golang_recover/`
- **Módulo Destino de Produção:** `aether_re/golang_recover.py`
- **Licença:** Apache-2.0 (Permissiva e homologada)

### Avaliação de Gates Eliminatórios (GEAR-02)
| Gate Eliminatório | Critério | Veredito | Justificativa |
|---|---|---|---|
| **Gate 1 — Licença** | Compatibilidade estrita com Apache-2.0 | **PASS** | Licença Apache-2.0 em total conformidade com a política do Megazord |
| **Gate 2 — Origem Verificável** | Repositório canônico upstream comprovado | **PASS** | Mandiant/GoReSym e goretk/redress rastreados |
| **Gate 3 — Vulnerabilidade** | Zero parsing inseguro ou estouro de buffer | **PASS** | Parsing de offsets verificado contra o tamanho do buffer (bounds-checked) |
| **Gate 4 — Não-Duplicação** | Não duplica analisadores Go pré-existentes | **PASS** | O Megazord tratava executáveis Go stripados como blob binário genérico |
| **Gate 5 — Versatilidade Multi-Versão** | Suporte às versões Go 1.2 até 1.23+ | **PASS** | Suporta magics 0xFFFFFFFB, 0xFFFFFFF0, 0xFFFFFFFA, 0xFFFFFFF1 |

---

## 3. Primitivas e Constantes Forenses Mapeadas

1. **GEAR-01:**
   - AES S-Box / InvS-Box / Rcon
   - SHA-256 K constants / Initial State
   - MD5 Sine Constants / Initial State
   - ChaCha20 & Salsa20 Key Strings
   - CRC32 IEEE 802.3 & Castagnoli tables
   - TEA / XTEA / XXTEA Golden Ratio Deltas
   - DES / 3DES Permutation tables
   - SM4 S-Box

2. **GEAR-02:**
   - Go 1.2-1.15 Magic `0xFFFFFFFB` (Header com nfunc e functab ponteiros absolutos)
   - Go 1.16-1.17 Magic `0xFFFFFFF0` (Offsets funcnametab, cutab, filetab, pctab)
   - Go 1.18-1.19 Magic `0xFFFFFFFA` (Header modular e offsets 32-bit relativos a textStart)
   - Go 1.20-1.23+ Magic `0xFFFFFFF1` (Header moderno com otimização DWARF inline)
   - Extração de nomes de função, pacotes, namespaces e endereços PC virtuais

---

## 4. Experimentos de Staging & Testes de Contrato
- `external_component_candidates/selected/crypto_detect/test_staging_contract.py` — **PASS**
- `external_component_candidates/selected/golang_recover/test_staging_contract.py` — **PASS**
