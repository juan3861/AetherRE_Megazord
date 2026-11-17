from __future__ import annotations

import base64
from pathlib import Path

import pytest

from aether_re.floss_strings import scan_file_floss_strings, solve_obfuscated_strings


def test_stack_strings_xor_and_base64_recovery(tmp_path: Path):
    # x64 stack string writes: mov dword ptr [rsp+0x20], 'http'; mov dword ptr [rsp+0x24], '://x'
    # c7 44 24 20 68 74 74 70  -> mov dword ptr [rsp + 0x20], 0x70747468 ("http")
    # c7 44 24 24 3a 2f 2f 78  -> mov dword ptr [rsp + 0x24], 0x782f2f3a ("://x")
    # c3                       -> ret
    stack_code = bytes.fromhex("c744242068747470c74424243a2f2f78c3")

    # XOR-encoded C2 URL with key 0x5A
    secret_url = b"https://c2.aether.local/beacon"
    xored = bytes(b ^ 0x5A for b in secret_url)

    # Base64-encoded command
    b64 = base64.b64encode(b"powershell -enc AetherPayload")

    blob = stack_code + b"\x00\x00" + xored + b"\x00\x00" + b64
    p = tmp_path / "obf.bin"
    p.write_bytes(blob)

    res = scan_file_floss_strings(p, is_64bit=True)
    assert res["status"] == "complete"
    assert any("http://x" in s["string"] for s in res["stack_strings"])
    assert any(x["xor_key"] == "0x5a" and "https://c2.aether.local/beacon" in x["decoded"] for x in res["xor_strings"])
    assert any("powershell -enc AetherPayload" in b["decoded"] for b in res["base64_strings"])


def test_invalid_inputs_fail_closed():
    assert solve_obfuscated_strings(b"")["status"] == "invalid"
    assert solve_obfuscated_strings("bad")["status"] == "invalid"  # type: ignore[arg-type]


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_floss_strings(r"D:\AetherRE_Megazord\missing_floss_999.bin")
