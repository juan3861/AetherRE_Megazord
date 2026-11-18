# Ground-Truth Full-Project Extraction, C-Tree Structuring & Live Compiled Twin Benchmark

Verificação empírica real (sem mocks): reconstrução de binários MSVC x64 `/O2`, estruturação C-Tree, compilação nativa via MSVC `cl.exe` e execução cruzada com ponteiros reais de heap entre a DLL original e a `reconstructed_twin.dll`.

## 1. Reconstrução + C-Tree + Compilação Nativa MSVC (`GEAR-23` + `ctree_structuring`)

| Binário Real | Alvos | 100% Lifted | C-Tree | Ghidra Ref. | Congruência | Twin DLL Compilada (MSVC) | Structs | Tempo (ms) |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| `cjson.dll` | 78 | 66 | 66 | 78 | **100.0%** | PASS (159232 B) | 7 | 21783.71 |
| `tinyexpr.dll` | 5 | 1 | 1 | 0 | **100.0%** | PASS (126976 B) | 7 | 533.97 |
| `poly_test.dll` | 10 | 3 | 3 | 0 | **100.0%** | PASS (106496 B) | 6 | 443.82 |
| `multi_poly.dll` | 11 | 2 | 2 | 0 | **100.0%** | PASS (106496 B) | 6 | 291.24 |

## 2. Interoperabilidade Ao Vivo em Heap Compartilhado (`DLL Original` <-> `reconstructed_twin.dll`)

| Alvo Executado em CPU Real (x64) | Saída DLL Original | Saída Twin DLL Compilada | Congruência ABI/Heap |
|---|---|---|---|
| `poly_test.dll <-> compiled twin :: FastProcessor shared C++ heap` | `[31, 32, 31]` | `[31, 32, 31]` | **PASS (100%)** |
| `poly_test.dll <-> compiled twin :: CryptoProcessor shared C++ heap` | `[4925, 112]` | `[4925, 112]` | **PASS (100%)** |
| `multi_poly.dll <-> compiled twin :: DualDevice multiple-inheritance heap` | `[100, 777]` | `[100, 777]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: Live cJSON DOM heap traversal & predicates` | `[3, 1, 1, 1, 2854816190048, 0]` | `[3, 1, 1, 1, 2854816190048, 0]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: IEEE-754 XMM GetNumberValue(3.14159/NULL) & SetNumberHelper(99.75)` | `[3.14159, True, 99.75]` | `[3.14159, True, 99.75]` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live CRT Heap DOM Construction (CreateArray+Number+True+Bool+Null) & PrintUnformatted` | `['[42.5,true,false,null]', 4]` | `['[42.5,true,false,null]', 4]` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live Object+String+AddTrue+GetObjectItemCS+Delete` | `['aether_v39', '{"msg":"aether_v39","ok":true}']` | `['aether_v39', '{"msg":"aether_v39","ok":true}']` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live RVA Switch Minify + CreateIntArray + CreateFloatArray` | `['{"x":[1,2],"y":true}', '[10,-20,30]', '[1.5,-2.25]']` | `['{"x":[1,2],"y":true}', '[10,-20,30]', '[1.5,-2.25]']` | **PASS (100%)** |
| `cjson AST :: AddItemToArray + GetArrayItem(1) + GetArraySize` | `[2, 66048]` | `[2, 66048]` | **PASS (100%)** |

## 3. Cópia Perfeita de Projeto Empacotado (Electron ASAR)

- **Arquivos originais:** `3` -> **Reconstruídos:** `3`
- **Congruência SHA-256 byte-a-byte:** **`100.0%`** (`byte_for_byte_sha256_match=True`)

## 4. Limitações Reais Observadas (Verdade Radical)

- Todos os 4 projetos C gêmeos gerados (`cjson`, `tinyexpr`, `poly_test`, `multi_poly`) compilam nativamente em MSVC x64 `/O2` sem erros (incluindo resolução de até 128 sub-rotinas internas `.text` e tabelas RVA de `switch`).
- Em `cjson.dll`, **66/78** exports são 100% elevados (incluindo `cJSON_Minify` com jump-table RVA, `cJSON_CreateIntArray`/`CreateFloatArray` via SIMD `movd`/`movss`/`cvtdq2pd`/`cvtps2pd`, `cJSON_SetValuestring` via `strcpy`, além de construtores, DOM, `cJSON_Delete` recursivo, `cJSON_Duplicate`, `cJSON_GetObjectItem*`, `cJSON_ReplaceItem*` e XMM/CRT), com **78/78** enriquecidos via Ghidra. Os 12 exports restantes (`cJSON_Parse*`/`Print*`/`Compare`/`InitHooks`/`GetErrorPtr`/`Version` — dependentes de `.data` mutável ou `sprintf`/`strtod`) mantêm esqueleto compilável + structs recuperadas; na `tinyexpr.dll`, **1/5** (`te_free` com switch `sub_3410` + `aether_free`) atinge 100%, enquanto `te_eval`/`te_compile`/`te_interp`/`te_print` envolvem callbacks indiretos em nós AST ou formatação CRT.
