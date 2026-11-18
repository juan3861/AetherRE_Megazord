# Ground-Truth Full-Project Extraction, C-Tree Structuring & Live Compiled Twin Benchmark

Verificação empírica real (sem mocks): reconstrução de binários MSVC x64 `/O2`, estruturação C-Tree, compilação nativa via MSVC `cl.exe` e execução cruzada com ponteiros reais de heap entre a DLL original e a `reconstructed_twin.dll`.

## 1. Reconstrução + C-Tree + Compilação Nativa MSVC (`GEAR-23` + `ctree_structuring`)

| Binário Real | Alvos | 100% Lifted | C-Tree | Ghidra Ref. | Congruência | Twin DLL Compilada (MSVC) | Structs | Tempo (ms) |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| `cjson.dll` | 78 | 62 | 62 | 78 | **100.0%** | PASS (125952 B) | 7 | 8683.43 |
| `tinyexpr.dll` | 5 | 0 | 0 | 0 | **0.0%** | PASS (113152 B) | 7 | 386.33 |
| `poly_test.dll` | 10 | 3 | 3 | 0 | **100.0%** | PASS (105472 B) | 6 | 356.31 |
| `multi_poly.dll` | 11 | 2 | 2 | 0 | **100.0%** | PASS (104960 B) | 6 | 230.04 |

## 2. Interoperabilidade Ao Vivo em Heap Compartilhado (`DLL Original` <-> `reconstructed_twin.dll`)

| Alvo Executado em CPU Real (x64) | Saída DLL Original | Saída Twin DLL Compilada | Congruência ABI/Heap |
|---|---|---|---|
| `poly_test.dll <-> compiled twin :: FastProcessor shared C++ heap` | `[31, 32, 31]` | `[31, 32, 31]` | **PASS (100%)** |
| `poly_test.dll <-> compiled twin :: CryptoProcessor shared C++ heap` | `[4925, 112]` | `[4925, 112]` | **PASS (100%)** |
| `multi_poly.dll <-> compiled twin :: DualDevice multiple-inheritance heap` | `[100, 777]` | `[100, 777]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: Live cJSON DOM heap traversal & predicates` | `[3, 1, 1, 1, 2536641196784, 0]` | `[3, 1, 1, 1, 2536641196784, 0]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: IEEE-754 XMM GetNumberValue(3.14159/NULL) & SetNumberHelper(99.75)` | `[3.14159, True, 99.75]` | `[3.14159, True, 99.75]` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live CRT Heap DOM Construction (CreateArray+Number+True+Bool+Null) & PrintUnformatted` | `['[42.5,true,false,null]', 4]` | `['[42.5,true,false,null]', 4]` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live Object+String+AddTrue+GetObjectItemCS+Delete` | `['aether_v39', '{"msg":"aether_v39","ok":true}']` | `['aether_v39', '{"msg":"aether_v39","ok":true}']` | **PASS (100%)** |
| `cjson AST :: AddItemToArray + GetArrayItem(1) + GetArraySize` | `[2, 66048]` | `[2, 66048]` | **PASS (100%)** |

## 3. Cópia Perfeita de Projeto Empacotado (Electron ASAR)

- **Arquivos originais:** `3` -> **Reconstruídos:** `3`
- **Congruência SHA-256 byte-a-byte:** **`100.0%`** (`byte_for_byte_sha256_match=True`)

## 4. Limitações Reais Observadas (Verdade Radical)

- Todos os 4 projetos C gêmeos gerados (`cjson`, `tinyexpr`, `poly_test`, `multi_poly`) compilam nativamente em MSVC x64 `/O2` sem erros (incluindo resolução de até 64 sub-rotinas internas `.text`).
- Em `cjson.dll`, **62/78** exports são 100% elevados (cobrindo construtores, strings, inserção/remoção em arrays e objetos, `cJSON_Delete` recursivo, `cJSON_Duplicate`, `cJSON_GetObjectItem*`, `cJSON_ReplaceItem*`, CRT `malloc`/`free`/`strlen`/`strcmp`/`tolower`/`memcpy`, XMM0/128-bit `movups` e ABI `double`), com **78/78** exports enriquecidos via cache tipado do Ghidra (`reconstructed_ghidra_reference.c`). Os 16 exports restantes (`cJSON_Parse*`/`Print*`/`Compare`/`Minify`/`CreateIntArray`/`CreateFloatArray`/`InitHooks`/`GetErrorPtr`/`Version` — dependentes de switch/jump-tables RVA, `.data` mutável ou SIMD `movd`/`cvtps2pd`) e os 5 exports de `tinyexpr.dll` mantêm esqueleto compilável + structs recuperadas.
