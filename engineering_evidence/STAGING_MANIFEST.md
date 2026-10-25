# MANIFESTO DE STAGING (STAGING MANIFEST)
**Protocolo:** ALPHA-C7 DISCOVERY-100
**Componente Selecionado:** `GEAR-01` — FindCrypt / Crypto Signature & S-Box Scanner
**Origem Tecnológica:** Baseado nos algoritmos canônicos de `FindCrypt-Ghidra`, `findcrypt-yara` e `signsrch` (Luigi Auriemma)
**Diretório de Staging:** `external_component_candidates/selected/crypto_detect/`
**Módulo Destino de Produção:** `aether_re/crypto_detect.py`
**Licença:** MIT / Public Domain (Totalmente permissiva e compatível)
**Data:** 2026-10-25

---

## 1. Avaliação de Gates Eliminatórios

| Gate Eliminatório | Critério | Veredito | Justificativa |
|---|---|---|---|
| **Gate 1 — Licença** | Compatibilidade estrita com MIT/Apache-2.0 | **PASS** | Algoritmos e constantes matemáticas de domínio público e MIT |
| **Gate 2 — Origem Verificável** | Repositório canônico upstream comprovado | **PASS** | URLs `ddis/findcrypt-yara` e `aluigi/signsrch` atestadas |
| **Gate 3 — Vulnerabilidade** | Zero código nativo vulnerável ou dependência binária | **PASS** | Implementação puramente estática e segura com limites de memória |
| **Gate 4 — Não-Duplicação** | Não duplica funcionalidade pré-existente no Megazord | **PASS** | O Megazord não possuía scanner de constantes criptográficas |
| **Gate 5 — Inviolabilidade** | Fallback em Python puro sem C-extensions obrigatórias | **PASS** | Opera com parsing de buffer binário e janela deslizante em memória |

---

## 2. Inventário de Primitivas Criptográficas Mapeadas

1. **AES / Rijndael:**
   - S-Box padrão (256 bytes): `63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76...`
   - InvS-Box (256 bytes): `52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb...`
   - Rcon (Round Constants, 10 bytes): `01 02 04 08 10 20 40 80 1b 36`
2. **SHA-256 (FIPS 180-4):**
   - K constants (64 words uint32, 256 bytes): `428a2f98 71374491 b5c0fbcf e9b5dba5...`
   - Initial State (8 words uint32, 32 bytes): `6a09e667 bb67ae85 3c6ef372 a54ff53a...`
3. **MD5 (RFC 1321):**
   - Sine Constants T[1..64] (256 bytes): `d76aa478 e8c7b756 242070db c1bdceee...`
   - Initial State (16 bytes): `01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10`
4. **ChaCha20 & Salsa20:**
   - 16-byte Constant String: `"expand 32-byte k"` (`65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b`)
   - 16-byte Constant String (16-byte key): `"expand 16-byte k"`
5. **CRC32:**
   - Tabela IEEE 802.3 (256 uint32, 1024 bytes) com polinômio `0xEDB88320`
6. **TEA / XTEA / XXTEA:**
   - Constante áurea (Golden Ratio Delta): `0x9E3779B9` e sua negação `0x61C88647`
7. **DES / 3DES (FIPS 46-3):**
   - Initial Permutation (IP) table (64 bytes)
   - Permuted Choice 1 (PC1) table (56 bytes)

---

## 3. Experimento de Staging & Teste de Contrato

Um harness mínimo isolado `external_component_candidates/selected/crypto_detect/test_staging_contract.py` é provisionado para garantir que a varredura atinge 100% de precisão sem falsos positivos em payloads aleatórios.
