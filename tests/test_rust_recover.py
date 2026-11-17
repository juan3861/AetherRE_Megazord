from __future__ import annotations

from pathlib import Path

import pytest

from aether_re.rust_recover import recover_rust_metadata, scan_file_rust


def test_rust_metadata_and_crate_extraction(tmp_path: Path):
    payload = (
        b"MZ\x90\x00"
        b"rustc/1.81.0 (eeb90cda1 2024-09-04)\x00"
        b"C:\\Users\\builder\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\tokio-1.40.0\\src\\runtime\\mod.rs\x00"
        b"C:\\Users\\builder\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\reqwest-0.12.7\\src\\client.rs\x00"
        b"src/beacon/c2_transport.rs\x00"
        b"core::panicking::panic\x00"
        b"_ZN10aether_bin9transport4send17h1234567890abcdefE\x00"
    )
    p = tmp_path / "rust_sample.exe"
    p.write_bytes(payload)

    res = scan_file_rust(p)
    assert res["status"] == "complete"
    assert res["is_rust_binary"] is True
    assert res["rustc_versions"][0]["version"] == "1.81.0"
    assert res["rustc_versions"][0]["commit"] == "eeb90cda1"
    crate_names = {c["name"]: c["versions"] for c in res["crates"]}
    assert crate_names["tokio"] == ["1.40.0"]
    assert crate_names["reqwest"] == ["0.12.7"]
    assert "src/beacon/c2_transport.rs" in res["source_paths"]
    assert any("aether_bin::transport::send" in s["demangled"] for s in res["demangled_symbols"])


def test_non_rust_binary_returns_false():
    res = recover_rust_metadata(b"\x7fELF_PLAIN_C_BINARY_WITHOUT_RUST_METADATA")
    assert res["status"] == "complete"
    assert res["is_rust_binary"] is False
    assert res["total_crates"] == 0


def test_invalid_rust_inputs_fail_closed():
    assert recover_rust_metadata(b"")["status"] == "invalid"
    assert recover_rust_metadata("bad")["status"] == "invalid"  # type: ignore[arg-type]


def test_missing_rust_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_rust(r"D:\AetherRE_Megazord\missing_rust_999.exe")
