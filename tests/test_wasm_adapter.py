from aether_re.adapters.wasm import WasmAdapter


def test_wasm_adapter_parses_import_export_and_function_counts():
    parsed = WasmAdapter._parse_wat(
        '(module (import "env" "log" (func)) (func $main) (export "main" (func $main)))'
    )
    assert parsed["functions"] == 1
    assert parsed["function_names"] == ["main"]
    assert parsed["imports"] == [{"module": "env", "name": "log"}]
    assert parsed["exports"] == ["main"]


def test_wasm_adapter_fails_closed_when_executable_is_not_verified(tmp_path):
    adapter = WasmAdapter(str(tmp_path / "missing.exe"))
    assert adapter.available() is False
