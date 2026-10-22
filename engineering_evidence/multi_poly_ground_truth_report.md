# C++ Multiple Inheritance Ground-Truth Reverse Engineering Benchmark

- **Binary:** `multi_poly.dll` (Compiled with MSVC 19.44 x64 `/O2 /EHsc`)
- **Reference Ground Truth Source:** `multi_poly.cpp`
- **Paradigm:** `DualDevice : public IReader, public IWriter` (Multiple Inheritance, 2 vptrs)
- **Decompilation Engine:** NSA Ghidra 12.1.4 Headless + OpenJDK 21 LTS
- **Total Library Exports:** `4`
- **Global Average Fidelity:** **`100.0%`**
- **100% Bit-Exact / Callee Matches:** **`4 / 4`**
- **Decompilation Time:** `43.53s`

## Function Breakdown

| Ordinal | Function Name | Status | Fidelity Score | Calls Preserved | Fields Preserved | Loop Preserved | Branch Preserved |
|---|---|---|---|---|---|---|---|
| 1 | `create_dual_device` | **PASS** | 100.00% | 100.00% | 100.00% | Yes | Yes |
| 2 | `read_from_device` | **PASS** | 100.00% | 100.00% | 100.00% | Yes | Yes |
| 3 | `write_to_device` | **PASS** | 100.00% | 100.00% | 100.00% | Yes | Yes |
| 4 | `destroy_dual_device` | **PASS** | 100.00% | 100.00% | 100.00% | Yes | Yes |
