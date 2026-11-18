# Ground-Truth Full-Project Extraction & Twin Reconstruction Benchmark

Verificação empírica real (sem mocks/simulações) contra binários MSVC x64 `/O2` conhecidos e árvore Electron ASAR.

## 1. Reconstrução Nativa (`GEAR-23` + `GEAR-21` + `GEAR-10` RTTI + `GEAR-04` Structs)

| Binário Real | Ground Truth | Alvos (Exports + VTables) | Funções 100% Lifted & Congruentes | Congruência Diferencial | RTTI Usuário | Structs | Tempo (ms) |
|---|---|---:|---:|---:|---|---:|---:|
| `cjson.dll` | cJSON.c (78 exports) | 78 | 14 | **100.0%** | - | 7 | 698.65 |
| `tinyexpr.dll` | tinyexpr.c (5 exports) | 5 | 0 | **0.0%** | - | 2 | 238.95 |
| `poly_test.dll` | poly_test.cpp (4 exports + 3 C++ RTTI classes) | 10 | 3 | **100.0%** | IProcessor, FastProcessor, CryptoProcessor | 1 | 246.76 |
| `multi_poly.dll` | multi_poly.cpp (4 exports + Multiple Inheritance RTTI) | 11 | 2 | **100.0%** | IReader, IWriter, DualDevice | 1 | 173.74 |

## 2. Prova Cruzada em CPU Real (`ctypes.CDLL` na máquina vs C Reconstruído)

| Alvo Executado em CPU Real | Saída Binário Original | Saída C Reconstruído | Congruência Bit-Exata |
|---|---|---|---|
| `poly_test.dll :: FastProcessor::process & reset` | `[31, 32, 31]` | `[31, 32, 31]` | **PASS (100%)** |
| `poly_test.dll :: CryptoProcessor::process` | `[4925, 112]` | `[4925, 112]` | **PASS (100%)** |
| `multi_poly.dll :: DualDevice(100) -> write(777) -> read()` | `[100, 777]` | `[100, 777]` | **PASS (100%)** |
| `cjson.dll :: AddItemToArray + GetArraySize + IsArray/IsTrue/IsString` | `[3, 1, 1, 1, 0]` | `[3, 1, 1, 1, 0]` | **PASS (100%)** |

## 3. Cópia Perfeita de Projeto Empacotado (Electron ASAR)

- **Arquivos originais:** `3` -> **Reconstruídos:** `3`
- **Congruência SHA-256 byte-a-byte:** **`100.0%`** (`byte_for_byte_sha256_match=True`)

## 4. Limitações Reais Observadas (Verdade Radical)

- Funções com chamadas CRT (`malloc`/`free`/`sprintf`), instruções vetoriais SIMD/FPU (`movsd`, `movaps`, `movups`, `xorps` em `tinyexpr.dll` e `cJSON_Parse`) ou salvamento de registradores não-voláteis em pilha (`[rsp + ...]`) são extraídas como esqueleto compilável + assinaturas + structs recuperadas, mas **ainda não são 100% elevadas pelo micro-lifter inline** (dependem da camada completa Ghidra High P-Code -> C-Tree para elevação semântica).
- Funções sem dependência de CRT/SIMD (14 funções de `cjson.dll` incluindo `cJSON_AddItemToArray` e `cJSON_GetArraySize`, além dos métodos virtuais C++ `FastProcessor::process/reset`, `CryptoProcessor::process`, `DualDevice::read/write` recuperados via RTTI em `poly_test.dll` e `multi_poly.dll`) atingiram **100.0% de congruência bit-exata** inclusive contra execução real via `ctypes.CDLL`.
