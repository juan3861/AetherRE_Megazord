# TinyExpr Library Full Ground-Truth Reverse Engineering Benchmark

- **Binary:** `tinyexpr.dll` (Compiled with MSVC 19.44 x64 `/O2`)
- **Reference Ground Truth Source:** `tinyexpr.c`
- **Decompilation Engine:** NSA Ghidra 12.1.4 Headless + OpenJDK 21 LTS
- **Total Library Exports:** `5`
- **Global Average Fidelity:** **`81.4%`**
- **100% Bit-Exact / Callee Matches:** `2 / 5`
- **High Fidelity (>= 70%):** `4 / 5`
- **Decompilation Time:** `58.78s`

## Function Breakdown

| Ordinal | Function Name | Status | Fidelity Score | Calls Preserved | Loop Preserved | Branch Preserved |
|---|---|---|---|---|---|---|
| 1 | `te_compile` | **PASS** | 90.00% | 80.00% | Yes | Yes |
| 2 | `te_eval` | **PARTIAL** | 42.00% | 20.00% | Yes | Yes |
| 3 | `te_free` | **PASS** | 100.00% | 100.00% | Yes | Yes |
| 4 | `te_interp` | **PASS** | 100.00% | 100.00% | Yes | Yes |
| 5 | `te_print` | **PASS** | 75.00% | 50.00% | Yes | Yes |
