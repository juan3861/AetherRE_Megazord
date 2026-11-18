# Ground-Truth Full-Project Extraction, C-Tree Structuring & Live Compiled Twin Benchmark

Verificação empírica real (sem mocks): reconstrução de binários MSVC x64 `/O2`, estruturação C-Tree, compilação nativa via MSVC `cl.exe` e execução cruzada com ponteiros reais de heap entre a DLL original e a `reconstructed_twin.dll`.

## 1. Reconstrução + C-Tree + Compilação Nativa MSVC (`GEAR-23` + `ctree_structuring`)

| Binário Real | Alvos | 100% Lifted | C-Tree | Ghidra Ref. | Congruência | Twin DLL Compilada (MSVC) | Structs | Tempo (ms) |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| `cjson.dll` | 78 | 31 | 31 | 78 | **100.0%** | PASS (127488 B) | 7 | 1936.84 |
| `tinyexpr.dll` | 5 | 0 | 0 | 0 | **0.0%** | PASS (108544 B) | 7 | 395.49 |
| `poly_test.dll` | 10 | 3 | 3 | 0 | **100.0%** | PASS (104960 B) | 6 | 238.66 |
| `multi_poly.dll` | 11 | 2 | 2 | 0 | **100.0%** | PASS (104448 B) | 6 | 238.2 |

## 2. Interoperabilidade Ao Vivo em Heap Compartilhado (`DLL Original` <-> `reconstructed_twin.dll`)

| Alvo Executado em CPU Real (x64) | Saída DLL Original | Saída Twin DLL Compilada | Congruência ABI/Heap |
|---|---|---|---|
| `poly_test.dll <-> compiled twin :: FastProcessor shared C++ heap` | `[31, 32, 31]` | `[31, 32, 31]` | **PASS (100%)** |
| `poly_test.dll <-> compiled twin :: CryptoProcessor shared C++ heap` | `[4925, 112]` | `[4925, 112]` | **PASS (100%)** |
| `multi_poly.dll <-> compiled twin :: DualDevice multiple-inheritance heap` | `[100, 777]` | `[100, 777]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: Live cJSON DOM heap traversal & predicates` | `[3, 1, 1, 1, 2545782810224, 0]` | `[3, 1, 1, 1, 2545782810224, 0]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: IEEE-754 XMM GetNumberValue(3.14159/NULL) & SetNumberHelper(99.75)` | `[3.14159, True, 99.75]` | `[3.14159, True, 99.75]` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live CRT Heap DOM Construction (CreateArray+Number+True+Bool+Null) & PrintUnformatted` | `['[42.5,true,false,null]', 4]` | `['[42.5,true,false,null]', 4]` | **PASS (100%)** |
| `cjson AST :: AddItemToArray + GetArrayItem(1) + GetArraySize` | `[2, 66048]` | `[2, 66048]` | **PASS (100%)** |

## 3. Cópia Perfeita de Projeto Empacotado (Electron ASAR)

- **Arquivos originais:** `3` -> **Reconstruídos:** `3`
- **Congruência SHA-256 byte-a-byte:** **`100.0%`** (`byte_for_byte_sha256_match=True`)

## 4. Limitações Reais Observadas (Verdade Radical)

- Todos os 4 projetos C gêmeos gerados (`cjson`, `tinyexpr`, `poly_test`, `multi_poly`) compilam nativamente em MSVC x64 `/O2` sem erros (incluindo resolução de até 64 sub-rotinas internas `.text`).
- Em `cjson.dll`, **31/78** exports são 100% elevados (incluindo alocadores/construtores `cJSON_CreateArray`, `cJSON_CreateObject`, `cJSON_CreateNumber` via XMM0/128-bit `movups` + hooks CRT `.data`, `cJSON_CreateTrue`/`False`/`Bool`/`Null`/`*Reference`, `cJSON_malloc`/`cJSON_free`, `cJSON_GetNumberValue`/`cJSON_SetNumberHelper`, `cJSON_AddItemToArray`, `cJSON_GetArraySize`/`Item`, `cJSON_DetachItem*`, `cJSON_InsertItemInArray`), com **78/78** exports enriquecidos via cache tipado do Ghidra (`reconstructed_ghidra_reference.c`). Os 47 exports restantes (`cJSON_Parse*`/`Print*`/`Delete`/chamadas internas múltiplas/CRT `sprintf`/`strtod`) mantêm esqueleto compilável + structs recuperadas; o mesmo vale para os 5 exports de `tinyexpr.dll` (onde `te_free` resolve `sub_3410` + `aether_free`).
