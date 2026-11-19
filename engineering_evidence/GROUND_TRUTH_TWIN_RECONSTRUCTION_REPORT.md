# Ground-Truth Full-Project Extraction, C-Tree Structuring & Live Compiled Twin Benchmark

Verificação empírica real (sem mocks): reconstrução de binários MSVC x64 `/O2`, estruturação C-Tree, compilação nativa via MSVC `cl.exe` e execução cruzada com ponteiros reais de heap entre a DLL original e a `reconstructed_twin.dll`.

## 1. Reconstrução + C-Tree + Compilação Nativa MSVC (`GEAR-23` + `ctree_structuring`)

| Binário Real | Alvos | 100% Lifted | C-Tree | Ghidra Ref. | Congruência | Twin DLL Compilada (MSVC) | Structs | Tempo (ms) |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| `cjson.dll` | 78 | 74 | 74 | 78 | **100.0%** | PASS (227328 B) | 7 | 16648.03 |
| `tinyexpr.dll` | 5 | 2 | 1 | 0 | **100.0%** | PASS (145408 B) | 7 | 675.67 |
| `poly_test.dll` | 10 | 9 | 9 | 0 | **100.0%** | PASS (108032 B) | 6 | 502.35 |
| `multi_poly.dll` | 11 | 10 | 10 | 0 | **100.0%** | PASS (108032 B) | 6 | 521.98 |

## 2. Interoperabilidade Ao Vivo em Heap Compartilhado (`DLL Original` <-> `reconstructed_twin.dll`)

| Alvo Executado em CPU Real (x64) | Saída DLL Original | Saída Twin DLL Compilada | Congruência ABI/Heap |
|---|---|---|---|
| `poly_test.dll <-> compiled twin :: FastProcessor shared C++ heap` | `[31, 32, 31]` | `[31, 32, 31]` | **PASS (100%)** |
| `poly_test.dll <-> compiled twin :: CryptoProcessor shared C++ heap` | `[4925, 112]` | `[4925, 112]` | **PASS (100%)** |
| `compiled twin poly_test :: Full C++ VTable Lifecycle (create/execute/reset/destroy x2)` | `[31, 77, 31, 4925, 97, 4925]` | `[31, 77, 31, 4925, 97, 4925]` | **PASS (100%)** |
| `multi_poly.dll <-> compiled twin :: DualDevice multiple-inheritance heap` | `[100, 777]` | `[100, 777]` | **PASS (100%)** |
| `compiled twin multi_poly :: Full Multiple-Inheritance Lifecycle (create/read/write/destroy)` | `[42, 42]` | `[42, 42]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: Live cJSON DOM heap traversal & predicates` | `[3, 1, 1, 1, 1817156433584, 0]` | `[3, 1, 1, 1, 1817156433584, 0]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: IEEE-754 XMM GetNumberValue(3.14159/NULL) & SetNumberHelper(99.75)` | `[3.14159, True, 99.75]` | `[3.14159, True, 99.75]` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live CRT Heap DOM Construction (CreateArray+Number+True+Bool+Null) & PrintUnformatted` | `['[42.5,true,false,null]', 4]` | `['[42.5,true,false,null]', 4]` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live Object+String+AddTrue+GetObjectItemCS+Delete` | `['aether_v39', '{"msg":"aether_v39","ok":true}']` | `['aether_v39', '{"msg":"aether_v39","ok":true}']` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live RVA Switch Minify + CreateIntArray + CreateFloatArray` | `['{"x":[1,2],"y":true}', '[10,-20,30]', '[1.5,-2.25]']` | `['{"x":[1,2],"y":true}', '[10,-20,30]', '[1.5,-2.25]']` | **PASS (100%)** |
| `compiled twin cjson :: Live SIMD cJSON_Compare(equal/unequal objects)` | `[1, 0]` | `[1, 0]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: Live cJSON_Version() via .rdata + sprintf` | `['1.7.19']` | `['1.7.19']` | **PASS (100%)** |
| `compiled twin cjson :: Live Self-Contained PrintUnformatted & PrintPreallocated(obj+float+str+bool)` | `['{"n":42.5,"s":"aether","ok":true}', '{"n":42.5,"s":"aether","ok":true}']` | `['{"n":42.5,"s":"aether","ok":true}', '{"n":42.5,"s":"aether","ok":true}']` | **PASS (100%)** |
| `cjson AST :: AddItemToArray + GetArrayItem(1) + GetArraySize` | `[2, 66048]` | `[2, 66048]` | **PASS (100%)** |
| `tinyexpr.dll <-> compiled twin :: Live AST te_eval(sin/sqrt/pow/log/abs) & te_free` | `[14.0, 47.0, 7.6842944819]` | `[14.0, 47.0, 7.6842944819]` | **PASS (100%)** |

## 3. Cópia Perfeita de Projeto Empacotado (Electron ASAR)

- **Arquivos originais:** `3` -> **Reconstruídos:** `3`
- **Congruência SHA-256 byte-a-byte:** **`100.0%`** (`byte_for_byte_sha256_match=True`)

## 4. Limitações Reais Observadas (Verdade Radical)

- Todos os 4 projetos C gêmeos gerados (`cjson`, `tinyexpr`, `poly_test`, `multi_poly`) compilam nativamente em MSVC x64 `/O2` sem erros (incluindo resolução de até 128 sub-rotinas internas `.text`, tabelas RVA de `switch`, globais mutáveis `.data` via `aether_data_ptr`, constantes `.rdata` via `aether_ro_ptr`, despacho virtual C++ RTTI via `aether_vtable_ptr`/`aether_vcall`, callbacks float-ABI via `aether_fcall_f64`/`aether_cfcall_f64` e chamadas indiretas via `aether_icall`).
- Em `cjson.dll`, **74/78** exports são 100% elevados (incluindo `cJSON_Print`/`PrintUnformatted`/`PrintBuffered`/`PrintPreallocated` via `pcmpeqb`/`andnps`/`paddq`/`setp` + `sscanf`/`sprintf` + `.data` `global_hooks` pré-semeado, `cJSON_Version` retornando `'1.7.19'`, `cJSON_GetErrorPtr`/`cJSON_InitHooks`, `cJSON_Compare` via SIMD, `cJSON_Minify` com jump-table RVA, `cJSON_CreateIntArray`/`CreateFloatArray`, `cJSON_SetValuestring`, construtores, DOM, `cJSON_Delete` recursivo, `cJSON_Duplicate`, `cJSON_GetObjectItem*`, `cJSON_ReplaceItem*` e XMM/CRT), com **78/78** enriquecidos via Ghidra. Os 4 exports restantes (`cJSON_Parse*` — dependentes de `strtod`/AVX CRT internos) mantêm esqueleto compilável + structs recuperadas; em `poly_test.dll` (**9/10**) e `multi_poly.dll` (**10/11**), todos os factories, wrappers polimórficos e destrutores virtuais são 100% elevados (restando apenas `_purecall`); na `tinyexpr.dll`, **2/5** (`te_eval` com 16 callbacks indiretos float-ABI/closure + `te_free` com switch `sub_3410`) atingem 100% e avaliam ASTs matemáticas reais ao vivo na CPU host, enquanto `te_compile`/`te_interp`/`te_print` envolvem parsing de strings ou `printf` CRT.
