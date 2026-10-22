# C++ Virtual Polymorphism Full Ground-Truth Reverse Engineering Benchmark

- **Binary:** `poly_test.dll` (Compiled with MSVC 19.44 x64 `/O2 /EHsc`)
- **Reference Ground Truth Source:** `poly_test.cpp`
- **Decompilation Engine:** NSA Ghidra 12.1.4 Headless + OpenJDK 21 LTS
- **Total Library Exports:** `4`
- **Global Average Fidelity:** **`100.0%`**
- **100% Bit-Exact / Callee Matches:** **`4 / 4`**
- **Decompilation Time:** `42.82s`

## Function Breakdown

| Ordinal | Function Name | Status | Fidelity Score | Calls Preserved | Fields Preserved | Loop Preserved | Branch Preserved |
|---|---|---|---|---|---|---|---|
| 1 | `create_processor` | **PASS** | 100.00% | 100.00% | 100.00% | Yes | Yes |
| 2 | `destroy_processor` | **PASS** | 100.00% | 100.00% | 100.00% | Yes | Yes |
| 3 | `execute_processor` | **PASS** | 100.00% | 100.00% | 100.00% | Yes | Yes |
| 4 | `reset_processor` | **PASS** | 100.00% | 100.00% | 100.00% | Yes | Yes |
