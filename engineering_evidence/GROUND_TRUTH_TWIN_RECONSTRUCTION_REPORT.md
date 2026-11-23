# Ground-Truth Full-Project Extraction, C-Tree Structuring & Live Compiled Twin Benchmark

Verificação empírica real (sem mocks): reconstrução de binários MSVC x64 `/O2`, estruturação C-Tree, decodificação Win64 SEH `.pdata`/`.xdata` (`UNWIND_INFO`), reconhecimento CRT FLIRT por CFG, emissão tipada C compilável com propagação de alias (`reconstructed_typed.c`), compilação nativa via MSVC `cl.exe`, linkagem LLVM O3 COFF standalone (`reconstructed_twin_llvm.dll`) e suporte multiarquitetura ELF64 (`x86_64`/`AArch64`) e PE ARM64 (`0xAA64`).

## 1. Reconstrução + C-Tree + Win64 SEH + FLIRT CFG + Typed C + LLVM O3 DLL (`GEAR-23`)

| Binário Real | Alvos | 100% Lifted | C-Tree | Win64 Unwind / SEH | FLIRT CFG | Congruência | MSVC + Typed C DLL | LLVM O3 DLL (COFF Link) | Structs | Tempo (ms) |
|---|---:|---:|---:|---|---|---:|---|---|---:|---:|
| `cjson.dll` | 78 | 78 | 78 | 510 (73 SEH) | 8 | **100.0%** | PASS (437760 B / typed 431616 B) | PASS (508416 B / obj 209960 B) | 7 | 17632.33 |
| `cjson_utils.dll` | 92 | 92 | 92 | 547 (73 SEH) | 8 | **100.0%** | PASS (461312 B / typed 453632 B) | PASS (533504 B / obj 247293 B) | 7 | 33170.6 |
| `tinyexpr.dll` | 5 | 5 | 5 | 528 (69 SEH) | 7 | **100.0%** | PASS (487936 B / typed 483328 B) | PASS (531968 B / obj 185671 B) | 7 | 11023.71 |
| `poly_test.dll` | 10 | 10 | 10 | 332 (60 SEH) | 7 | **100.0%** | PASS (235520 B / typed 235520 B) | PASS (245248 B / obj 3328 B) | 1 | 687.96 |
| `multi_poly.dll` | 11 | 11 | 11 | 333 (60 SEH) | 7 | **100.0%** | PASS (236032 B / typed 236032 B) | PASS (245248 B / obj 3632 B) | 1 | 715.31 |
| `lz4.dll` | 44 | 44 | 44 | 428 (62 SEH) | 7 | **100.0%** | PASS (434176 B / typed 425984 B) | PASS (498176 B / obj 291356 B) | 7 | 34942.26 |

## 2. Interoperabilidade Ao Vivo em Heap Compartilhado (`DLL Original` <-> `reconstructed_twin.dll`)

| Alvo Executado em CPU Real (x64) | Saída DLL Original | Saída Twin DLL Compilada | Congruência ABI/Heap |
|---|---|---|---|
| `poly_test.dll <-> compiled twin :: FastProcessor shared C++ heap` | `[31, 32, 31]` | `[31, 32, 31]` | **PASS (100%)** |
| `poly_test.dll <-> compiled twin :: CryptoProcessor shared C++ heap` | `[4925, 112]` | `[4925, 112]` | **PASS (100%)** |
| `compiled twin poly_test :: Full C++ VTable Lifecycle (create/execute/reset/destroy x2)` | `[31, 77, 31, 4925, 97, 4925]` | `[31, 77, 31, 4925, 97, 4925]` | **PASS (100%)** |
| `multi_poly.dll <-> compiled twin :: DualDevice multiple-inheritance heap` | `[100, 777]` | `[100, 777]` | **PASS (100%)** |
| `compiled twin multi_poly :: Full Multiple-Inheritance Lifecycle (create/read/write/destroy)` | `[42, 42]` | `[42, 42]` | **PASS (100%)** |
| `cjson.dll <-> compiled twin :: Live cJSON DOM heap traversal & predicates` | `[3, 1, 1, 1, 2473084060592, 0]` | `[3, 1, 1, 1, 2473084060592, 0]` | **PASS (100%)** |
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
| `compiled twin cjson_utils :: RFC 6901 Pointer + 6902 Patch + 7396 MergePatch + SortObject (92/92)` | `['Mestre', '/users/1/name', '{"a":{"k":"v"},"users":[{"name":"A"},{"name":"Mestre"}],"z":1}', '[{"op":"replace","path":"/b","value":99},{"op":"add","path":"/c","value":3}]', 0, 1, '{"a":1,"c":42}']` | `['Mestre', '/users/1/name', '{"a":{"k":"v"},"users":[{"name":"A"},{"name":"Mestre"}],"z":1}', '[{"op":"replace","path":"/b","value":99},{"op":"add","path":"/c","value":3}]', 0, 1, '{"a":1,"c":42}']` | **PASS (100%)** |
| `compiled twin lz4 :: LZ4_compressBound + compress_default + compress_fast + cross decompress_safe (44/44)` | `[483, 101, 101, 466]` | `[483, 101, 101, 466]` | **PASS (100%)** |
| `LLVM O3 MCJIT x64 <-> orig lz4.dll :: Native JIT LZ4_compressBound + LZ4_versionNumber` | `[116, 483, 11102]` | `[116, 483, 11102]` | **PASS (100%)** |
| `LLVM O3 Linked DLL <-> orig lz4.dll :: Standalone COFF Link compress_default + cross decompress_safe` | `[101, 466]` | `[101, 466]` | **PASS (100%)** |
| `LLVM O3 Linked DLL <-> orig cjson.dll :: Standalone COFF Link Parse + PrintUnformatted + Delete` | `['{"engine":"AetherRE","llvm_o3":true,"score":99.5}']` | `['{"engine":"AetherRE","llvm_o3":true,"score":99.5}']` | **PASS (100%)** |
| `LLVM O3 Linked DLL <-> orig tinyexpr.dll :: Standalone COFF Link te_interp(.rdata Math Builtins)` | `[47.0, 145.25]` | `[47.0, 145.25]` | **PASS (100%)** |
| `LLVM O3 Linked DLL <-> orig cjson_utils.dll :: Standalone COFF Link SortObject` | `['{"a":1,"z":2}']` | `['{"a":1,"z":2}']` | **PASS (100%)** |
| `LLVM O3 Linked DLL <-> orig poly_test.dll :: Shared C++ RTTI Heap Cross-Execution` | `[31, 32]` | `[31, 32]` | **PASS (100%)** |
| `LLVM O3 Linked DLL <-> orig multi_poly.dll :: Standalone COFF Link Multiple-Inheritance Lifecycle` | `[42, 99]` | `[42, 99]` | **PASS (100%)** |
| `Typed C Struct DLL <-> orig lz4.dll :: Alias-Propagated reconstructed_typed.c Live Compression & Decompression` | `[101, 466]` | `[101, 466]` | **PASS (100%)** |

## 3. Cópia Perfeita de Projeto Empacotado (Electron ASAR)

- **Arquivos originais:** `3` -> **Reconstruídos:** `3`
- **Congruência SHA-256 byte-a-byte:** **`100.0%`** (`byte_for_byte_sha256_match=True`)

## 4. Limitações Reais Observadas (Verdade Radical)

- Todos os 6 projetos C gêmeos gerados (`cjson`, `cjson_utils`, `tinyexpr`, `poly_test`, `multi_poly`, `lz4`) compilam nativamente em MSVC x64 `/O2` sem erros (incluindo promoção `mem2reg` de slots locais de pilha não-escapados em IR/SSA, anotação semântica de structs `double`/`float` e escalares, resolução de até 128 sub-rotinas internas `.text`, pilha TLS Win64 contígua `aether_tls_stack` para hashes de pilha >4 KB em LZ4, instruções SIMD empacotadas `pshufd`/`pmaxud`/`pcmpeqd`/`psubd`, multiplicações `imul`/`mul` 1-operando e `tzcnt`/`rep stos`, tabelas RVA de `switch`, globais mutáveis `.data` via `aether_data_ptr`, relocações `DIR64` em `.rdata` via `aether_ro_sec`/`aether_ro_init`, ponteiros de função `.text` via `aether_fn_ptr`, despacho virtual C++ RTTI via `aether_vtable_ptr`/`aether_vcall`, guard CFG `GuardCFDispatchFunctionPointer` + CRT `abort` em `_purecall`, `calloc`/`__chkstk`/`strrchr` CRT, callbacks float-ABI via `aether_fcall_f64`/`aether_cfcall_f64` e chamadas indiretas via `aether_icall`).
- **Pipeline LLVM IR O3 + COFF `.obj` + Linkagem Nativa Standalone (`reconstructed_twin_llvm.dll`) + MCJIT (`llvmlite`):** Todos os 6 projetos geram `ir/reconstructed_project.ll` validado pelo Verifier C++ do LLVM, otimizado em **O3** (`mem2reg` + `sroa` + `instcombine` + `gvn` + `loop-vectorize`), compilado para objeto Win64 COFF `ir/reconstructed_project.obj` (`codemodel='default'`) e linkado com `src/llvm_runtime_shim.c` (`AETHER_RT_LINK` + `link.exe`) em `reconstructed_twin_llvm.dll` executável diretamente via `ctypes.CDLL` em igualdade bit-a-bit com a DLL original e a twin MSVC.
- **FLIRT por Grafo CFG & Decompilação Tipada (`flirt_cfg.py` + `reconstructed_typed.c`):** Reconhecimento estrutural CRT por topologia de blocos/arestas/backedges + hash de esqueleto mnemônico (`__chkstk`, `__security_check_cookie`, `abort`, `strlen`, `memset`, `memcpy`), além da emissão de `src/reconstructed_typed.c` reescrevendo `aether_mem_read`/`write` para ponteiros de structs tipados (`((RecoveredStruct_REG_t*)(uintptr_t)(REG))->field_0xNN`).
- **100% dos alvos elevados e estruturados em C-Tree nos 6 binários nativos (240/240):** `cjson.dll` (**78/78**, **78/78** Ghidra Ref.), `cjson_utils.dll` (**92/92**, RFC 6901/6902/7396 + Merge Sort), `tinyexpr.dll` (**5/5**), `poly_test.dll` (**10/10**, incluindo `IProcessor_v0_slot1` `_purecall`), `multi_poly.dll` (**11/11**, incluindo `IReader_v0_slot1` `_purecall`) e `lz4.dll` (**44/44** lifted e **44/44** C-Tree após otimização Fase II IR/SSA, compressão byte-a-byte idêntica e descompressão cruzada exata) — todos com **100.0%** de estruturação C-Tree e **100.0%** de congruência diferencial em CPU real. Limitações honestas: (1) apenas `cjson.dll` possui cache pré-computado de `ghidra_typed_cache` neste ambiente (os outros 5 ficam em `0` sem Ghidra headless externo); (2) rotinas terminais CRT como `_purecall`/`abort`/`printf`/`sscanf` mapeiam para stubs determinísticos seguros (`aether_abort` retornando `0`) no runtime gêmeo e no runtime MCJIT para preservar segurança de processo.
