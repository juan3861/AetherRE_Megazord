# REGISTRO DE DECISÃO DE CONSENSO SIMULADO (CONSENSUS DECISION)
**Protocolo:** ALPHA-C7 DISCOVERY-100 — Seção 6
**Tópico de Decisão:** Arquitetura do Motor de Detecção Criptográfica (`GEAR-01`)
**Data:** 2026-10-25

---

## 1. Perspectiva AGI (Pragmática / Primeira Ordem)
- **Tese:** Implementar um motor de assinatura puramente baseado em offsets lineares e substrings binárias exatas em Python puro.
- **Argumentos:**
  - Zero dependências externas de compilação (não obriga C++ nem DLLs extras).
  - Execução determinística em microssegundos para binários típicos (PE/ELF de 100KB a 50MB).
  - Facilidade de teste e manutenção: constantes hexadecimais canônicas (AES S-Box, SHA-256 K, ChaCha20 magic, MD5 sine table, CRC32 table) declaradas em tuplas estáticas imutáveis.
- **Risco Identificado:** Varreduras em arquivos massivos (> 200MB) podem ter tempo O(N * M) se implementadas ingenuamente com `data.find()`.

---

## 2. Perspectiva ASI (Sistêmica / Segunda e Terceira Ordem)
- **Tese:** Avaliar riscos sistêmicos de falsos positivos, endianness de compiladores e evasão de constantes por compiladores otimizadores (inlining, constantes geradas em runtime, endianness swap no target).
- **Argumentos:**
  - Compiladores como MSVC e GCC podem armazenar tabelas de 32 bits (ex: SHA-256 K) em Little-Endian (`98 2f 8a 42`) ou Big-Endian (`42 8a 2f 98`). O scanner deve suportar ambos os formatos de empacotamento ou declarar explicitamente a representação padrão.
  - Para evitar falsos positivos em constantes curtas (ex: TEA delta `0x9E3779B9` de 4 bytes), o scanner deve categorizar as detecções por nível de confiança: `HIGH` para tabelas longas (S-Box de 256 bytes, SHA K de 256 bytes) e `MEDIUM` para constantes escalares de 4/8 bytes.
  - Alinhamento de memória: o motor deve reportar não apenas o offset absoluto no arquivo, mas mapear para a Virtual Address (RVA) da seção PE quando disponível.

---

## 3. Síntese do Consenso & Decisão Unificada
- **Decisão:** Aprovada a fusão das perspectivas:
  1. Motor em Python puro sem dependências externas, usando busca binária rápida `bytes.find()` com índices otimizados.
  2. Suporte nativo a Little-Endian e Big-Endian para vetores de palavras uint32 (como SHA-256 e MD5).
  3. Classificação de confiança por densidade de entropia e tamanho de padrão (`CONFIDENCE_HIGH` para tabelas >= 16 bytes; `CONFIDENCE_MEDIUM` para constantes escalares com validação de contexto).
  4. Mapeamento de RVA e nome da seção PE quando o binário for um executável PE/ELF reconhecível.
  5. Fallback inviolável que opera em qualquer blob de bytes arbitrário.
