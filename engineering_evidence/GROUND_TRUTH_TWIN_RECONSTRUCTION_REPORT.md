# Ground-Truth Full-Project Extraction, C-Tree Structuring & Live Compiled Twin Benchmark

Verificação empírica real (sem mocks): reconstrução de binários MSVC x64 `/O2`, estruturação C-Tree, compilação nativa via MSVC `cl.exe` e execução cruzada com ponteiros reais de heap entre a DLL original e a `reconstructed_twin.dll`.

## 1. Reconstrução + C-Tree + Compilação Nativa MSVC (`GEAR-23` + `ctree_structuring`)

| Binário Real | Alvos | 100% Lifted | C-Tree | Ghidra Ref. | Congruência | Twin DLL Compilada (MSVC) | Structs | Tempo (ms) |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| `cjson.dll` | 78 | 78 | 78 | 78 | **100.0%** | PASS (276480 B) | 7 | 19723.18 |
| `tinyexpr.dll` | 5 | 5 | 5 | 0 | **100.0%** | PASS (318464 B) | 7 | 2542.69 |
| `poly_test.dll` | 10 | 10 | 10 | 0 | **100.0%** | PASS (103936 B) | 1 | 673.22 |
| `multi_poly.dll` | 11 | 11 | 11 | 0 | **100.0%** | PASS (103936 B) | 1 | 455.0 |

## 2. Interoperabilidade Ao Vivo em Heap Compartilhado (`DLL Original` <-> `reconstructed_twin.dll`)

| Alvo Executado em CPU Real (x64) | Saída DLL Original | Saída Twin DLL Compilada | Congruência ABI/Heap |
|---|---|---|---|
| `poly_test.dll <-> compiled twin :: FastProcessor shared C++ heap` | `[31, 32, 31]` | `[31, 32, 31]` | **PASS (100%)** |
| `poly_test.dll <-> compiled twin :: CryptoProcessor shared C++ heap` | `[4925, 112]` | `[4925, 112]` | **PASS (100%)** |
| `compiled twin poly_test :: Full C++ VTable Lifecycle (create/execute/reset/destroy x2)` | `[31, 77, 31, 4925, 97, 4925]` | `[31, 77, 31, 4925, 97, 4925]` | **PASS (100%)** |
| `multi_poly.dll <-> compiled twin :: DualDevice multiple-inheritance heap` | `[100, 777]` | `[100, 777]` | **PASS (100%)** |
| `compiled twin multi_poly :: Full Multiple-Inheritance Lifecycle (create/read/write/destroy)` | `[42, 42]` | `[42, 42]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: Live cJSON DOM heap traversal & predicates` | `[3, 1, 1, 1, 1754727807360, 0]` | `[3, 1, 1, 1, 1754727807360, 0]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: IEEE-754 XMM GetNumberValue(3.14159/NULL) & SetNumberHelper(99.75)` | `[3.14159, True, 99.75]` | `[3.14159, True, 99.75]` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live CRT Heap DOM Construction (CreateArray+Number+True+Bool+Null) & PrintUnformatted` | `['[42.5,true,false,null]', 4]` | `['[42.5,true,false,null]', 4]` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live Object+String+AddTrue+GetObjectItemCS+Delete` | `['aether_v39', '{"msg":"aether_v39","ok":true}']` | `['aether_v39', '{"msg":"aether_v39","ok":true}']` | **PASS (100%)** |
| `compiled twin -> orig cjson.dll :: Live RVA Switch Minify + CreateIntArray + CreateFloatArray` | `['{"x":[1,2],"y":true}', '[10,-20,30]', '[1.5,-2.25]']` | `['{"x":[1,2],"y":true}', '[10,-20,30]', '[1.5,-2.25]']` | **PASS (100%)** |
| `compiled twin cjson :: Live SIMD cJSON_Compare(equal/unequal objects)` | `[1, 0]` | `[1, 0]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: Live cJSON_Version() via .rdata + sprintf` | `['1.7.19']` | `['1.7.19']` | **PASS (100%)** |
| `compiled twin cjson :: Live Self-Contained PrintUnformatted & PrintPreallocated(obj+float+str+bool)` | `['{"n":42.5,"s":"aether","ok":true}', '{"n":42.5,"s":"aether","ok":true}']` | `['{"n":42.5,"s":"aether","ok":true}', '{"n":42.5,"s":"aether","ok":true}']` | **PASS (100%)** |
| `compiled twin cjson :: Full Live cJSON_Parse -> DOM -> cJSON_PrintUnformatted Roundtrip (78/78)` | `[3.14159, 'aether_78', '{"msg":"aether_78","pi":3.14159,"arr":[1,2,3],"ok":true}']` | `[3.14159, 'aether_78', '{"msg":"aether_78","pi":3.14159,"arr":[1,2,3],"ok":true}']` | **PASS (100%)** |
| `cjson AST :: AddItemToArray + GetArrayItem(1) + GetArraySize` | `[2, 66048]` | `[2, 66048]` | **PASS (100%)** |
| `tinyexpr.dll <-> compiled twin :: Live AST te_eval(sin/sqrt/pow/log/abs) & te_free` | `[14.0, 47.0, 7.6842944819]` | `[14.0, 47.0, 7.6842944819]` | **PASS (100%)** |
| `tinyexpr.dll <-> compiled twin :: Live AST te_print() via aether_printf + aether_ro_ptr` | `[14.0]` | `[14.0]` | **PASS (100%)** |
| `compiled twin tinyexpr :: Live Self-Contained te_interp(pow/fmod) & te_compile(x*x+2*x+1) (5/5)` | `[14.0, 43.0, 1025.0, 36.0, 121.0]` | `[14.0, 43.0, 1025.0, 36.0, 121.0]` | **PASS (100%)** |
| `compiled twin tinyexpr :: Live .rdata Relocated Builtins te_interp(sin/pi/sqrt/pow/ln/e/abs/cos/floor/ceil/fac/ncr/atan2)` | `[47.0, 145.25, 3.1415926536]` | `[47.0, 145.25, 3.1415926536]` | **PASS (100%)** |

## 3. Cópia Perfeita de Projeto Empacotado (Electron ASAR)

- **Arquivos originais:** `3` -> **Reconstruídos:** `3`
- **Congruência SHA-256 byte-a-byte:** **`100.0%`** (`byte_for_byte_sha256_match=True`)

## 4. Limitações Reais Observadas (Verdade Radical)

- Todos os 4 projetos C gêmeos gerados (`cjson`, `tinyexpr`, `poly_test`, `multi_poly`) compilam nativamente em MSVC x64 `/O2` sem erros (incluindo resolução de até 128 sub-rotinas internas `.text`, tabelas RVA de `switch`, globais mutáveis `.data` via `aether_data_ptr`, relocações `DIR64` em `.rdata` via `aether_ro_sec`/`aether_ro_init`, ponteiros de função `.text` via `aether_fn_ptr`, despacho virtual C++ RTTI via `aether_vtable_ptr`/`aether_vcall`, guard CFG `GuardCFDispatchFunctionPointer` + CRT `abort` em `_purecall`, callbacks float-ABI via `aether_fcall_f64`/`aether_cfcall_f64` e chamadas indiretas via `aether_icall`).
- **100% dos alvos elevados nos 4 binários nativos:** `cjson.dll` (**78/78**, **78/78** Ghidra Ref.), `tinyexpr.dll` (**5/5**), `poly_test.dll` (**10/10**, incluindo `IProcessor_v0_slot1` `_purecall`) e `multi_poly.dll` (**11/11**, incluindo `IReader_v0_slot1` `_purecall`) — todos com **100.0%** de estruturação C-Tree e **100.0%** de congruência diferencial em CPU real. Limitações honestas: apenas `cjson.dll` possui cache pré-computado de `ghidra_typed_cache` neste ambiente (os outros 3 ficam em `0` sem Ghidra headless externo), e rotinas terminais CRT como `_purecall`/`abort`/`printf`/`sscanf` mapeiam para stubs determinísticos seguros (`aether_abort` retornando `0`) no runtime gêmeo para preservar segurança de processo.
