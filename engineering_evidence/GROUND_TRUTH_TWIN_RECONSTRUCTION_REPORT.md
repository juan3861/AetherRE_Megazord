# Ground-Truth Full-Project Extraction, C-Tree Structuring & Live Compiled Twin Benchmark

Verificação empírica real (sem mocks): reconstrução de binários MSVC x64 `/O2`, estruturação C-Tree, compilação nativa via MSVC `cl.exe` e execução cruzada com ponteiros reais de heap entre a DLL original e a `reconstructed_twin.dll`.

## 1. Reconstrução + C-Tree + Compilação Nativa MSVC (`GEAR-23` + `ctree_structuring`)

| Binário Real | Alvos | 100% Lifted | C-Tree Structured | Goto Elim. | Congruência | Twin DLL Compilada (MSVC) | Structs | Tempo (ms) |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| `cjson.dll` | 78 | 17 | 17 | 64.71% | **100.0%** | PASS (108544 B) | 7 | 653.81 |
| `tinyexpr.dll` | 5 | 0 | 0 | 0.0% | **0.0%** | PASS (102912 B) | 2 | 98.92 |
| `poly_test.dll` | 10 | 3 | 3 | 100.0% | **100.0%** | PASS (103424 B) | 1 | 152.05 |
| `multi_poly.dll` | 11 | 2 | 2 | 100.0% | **100.0%** | PASS (103424 B) | 1 | 99.29 |

## 2. Interoperabilidade Ao Vivo em Heap Compartilhado (`DLL Original` <-> `reconstructed_twin.dll`)

| Alvo Executado em CPU Real (x64) | Saída DLL Original | Saída Twin DLL Compilada | Congruência ABI/Heap |
|---|---|---|---|
| `poly_test.dll <-> compiled twin :: FastProcessor shared C++ heap` | `[31, 32, 31]` | `[31, 32, 31]` | **PASS (100%)** |
| `poly_test.dll <-> compiled twin :: CryptoProcessor shared C++ heap` | `[4925, 112]` | `[4925, 112]` | **PASS (100%)** |
| `multi_poly.dll <-> compiled twin :: DualDevice multiple-inheritance heap` | `[100, 777]` | `[100, 777]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: Live cJSON DOM heap traversal & predicates` | `[3, 1, 1, 1, 1578087011200, 0]` | `[3, 1, 1, 1, 1578087011200, 0]` | **PASS (100%)** |
| `cjson AST :: AddItemToArray + GetArrayItem(1) + GetArraySize` | `[2, 66048]` | `[2, 66048]` | **PASS (100%)** |

## 3. Cópia Perfeita de Projeto Empacotado (Electron ASAR)

- **Arquivos originais:** `3` -> **Reconstruídos:** `3`
- **Congruência SHA-256 byte-a-byte:** **`100.0%`** (`byte_for_byte_sha256_match=True`)

## 4. Limitações Reais Observadas (Verdade Radical)

- Todos os 4 projetos C gêmeos gerados (`cjson`, `tinyexpr`, `poly_test`, `multi_poly`) compilam nativamente em MSVC x64 `/O2` sem erros.
- Em `cjson.dll`, 17/78 exports são 100% elevados (incluindo `cJSON_AddItemToArray`, `cJSON_GetArraySize`, `cJSON_GetArrayItem`, `cJSON_DetachItemFromArray`, `cJSON_InsertItemInArray`), com estruturação C-Tree completa (e laços `while` recuperados sem `goto`). Os 61 exports restantes e os 5 exports de `tinyexpr.dll` mantêm esqueleto compilável + structs recuperadas por utilizarem instruções SIMD/FPU (`movaps`/`movsd`/`movups`) e chamadas CRT (`malloc`/`free`/`sprintf`).
