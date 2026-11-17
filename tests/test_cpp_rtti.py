from __future__ import annotations

from pathlib import Path

import pytest

from aether_re.cpp_rtti import recover_cpp_rtti, scan_file_cpp_rtti


def test_real_cpp_poly_dll_rtti_vtable_and_hierarchy():
    dll = Path(r"D:\AetherRE_Megazord\external_test_repos\cpp_poly\poly_test.dll")
    if not dll.is_file():
        pytest.skip("poly_test.dll not present")
    res = scan_file_cpp_rtti(dll)
    assert res["status"] == "complete"
    assert res["detected"] is True
    assert res["abi"] == "msvc"
    assert res["total_classes"] >= 1
    assert res["complete_object_locators"] >= 1
    demangled_names = [c["demangled"] for c in res["classes"]]
    assert any("class " in n or "struct " in n for n in demangled_names)
    # At least one polymorphic class should have a resolved vtable RVA or base class
    assert any(c["vtable_rvas"] or c["base_classes"] for c in res["classes"])


def test_itanium_rtti_symbol_extraction():
    blob = b"\x7fELF\x00\x00\x00_ZTV10AetherBase\x00_ZTS13AetherDerived\x00"
    res = recover_cpp_rtti(blob)
    assert res["status"] == "complete"
    assert res["abi"] == "itanium"
    assert res["detected"] is True
    assert res["total_classes"] == 2
    assert any("AetherBase" in c["demangled"] for c in res["classes"])


def test_invalid_rtti_inputs_fail_closed():
    assert recover_cpp_rtti(b"")["status"] == "invalid"
    assert recover_cpp_rtti("bad")["status"] == "invalid"  # type: ignore[arg-type]


def test_missing_rtti_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_cpp_rtti(r"D:\AetherRE_Megazord\missing_cpp_999.dll")
