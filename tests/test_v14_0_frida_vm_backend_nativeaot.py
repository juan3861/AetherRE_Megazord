from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import threading
import urllib.request

import pefile

from aether_re.adapters.frida_dyn import FridaAdapter
from aether_re.backend_twin_synthesizer import synthesize_backend_twin
from aether_re.cil_decompiler import _lift_cil_body_to_csharp
from aether_re.managed_reconstructors import (
    decode_hermes_bytecode,
    recover_flutter_snapshot,
    recover_il2cpp_metadata,
)
from aether_re.project_reconstructor import _execute_lifted_c_ast
from aether_re.runtime_emitter import _find_msvc_x64_toolchain
from aether_re.vm_devirtualizer import deobfuscate_ollvm_c_predicates, devirtualize_from_live_trace


def test_v140_frida_live_spawn_and_trace_collection(tmp_path: Path) -> None:
    adapter = FridaAdapter()
    assert adapter.available() is True

    c_src = tmp_path / "frida_target.c"
    c_src.write_text(
        """
        #include <windows.h>
        int main(void) {
            void *p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (p) {
                ((volatile char*)p)[0] = 0x41;
                VirtualFree(p, 0, MEM_RELEASE);
            }
            Sleep(300);
            return 0;
        }
        """,
        encoding="utf-8",
    )
    exe_path = tmp_path / "frida_target.exe"
    _, env, cl_exe, _ = _find_msvc_x64_toolchain()
    subprocess.run([cl_exe, "/nologo", "/O2", str(c_src), f"/Fe:{exe_path}"], cwd=str(tmp_path), env=env, check=True, capture_output=True)

    rep = adapter.capture_live_frida_trace(exe_path, tmp_path / "frida_out", timeout_s=1.2)
    assert rep["ok"] is True and rep["executed"] is True and rep["produced_evidence"] is True
    assert rep["modules_count"] >= 2
    assert Path(rep["trace_path"]).is_file()


def test_v140_vm_live_trace_sygus_and_ollvm_deobfuscate() -> None:
    pairs = [
        ((0, 0, 0, 0), -7),
        ((1, 2, 0, 0), -2),
        ((5, 10, 0, 0), 18),
        ((10, 4, 0, 0), 27),
    ]
    res = devirtualize_from_live_trace(pairs, fn_name="recovered_trace_fn")
    assert res["synthesized_formula"] is not None
    assert _execute_lifted_c_ast(res["devirtualized_c"], 7, 3, 0, 0) == (3 * 7 + 3 - 7)

    ollvm_c = """
    int64_t f(int64_t rcx, int64_t rdx) {
        if (((rcx | rdx) - (rcx ^ rdx) - (rcx & rdx)) == 0) {
            return rcx + rdx;
        }
        return -1;
    }
    """
    ob = deobfuscate_ollvm_c_predicates(ollvm_c)
    assert ob["opaque_predicates_collapsed"] == 1
    assert "if (1)" in ob["deobfuscated_c"]


def test_v140_backend_twin_synthesizer_live_http_roundtrip(tmp_path: Path) -> None:
    pcap_mock_rep = {
        "http_events": [
            {"method": "GET", "uri": "/api/v1/license", "host": "api.vendor.local"},
            {"method": "POST", "uri": "/api/v1/telemetry", "host": "api.vendor.local"},
        ],
        "tcp_streams": [],
    }
    twin = synthesize_backend_twin(
        pcap_report=pcap_mock_rep,
        endpoints=[{"method": "GET", "path": "/api/v1/license", "response_status": 200, "response_body": {"licensed": True, "tier": "enterprise"}}],
        output_dir=tmp_path / "backend_twin",
    )
    assert twin["routes_count"] == 2
    assert Path(twin["files_written"]["openapi"]).is_file()
    srv_py = Path(twin["files_written"]["server_py"])
    assert srv_py.is_file()

    # Load and boot synthesized HTTP twin server on 127.0.0.1:0
    spec = importlib.util.spec_from_file_location("twin_srv", srv_py)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    srv = mod.start_twin_server("127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        port = srv.server_port
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/license", timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["licensed"] is True and data["tier"] == "enterprise"
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/telemetry", data=b"{}", method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp2:
            assert resp2.status == 200
            data2 = json.loads(resp2.read().decode("utf-8"))
            assert data2["_request_seq"] == 2
    finally:
        srv.shutdown()
        srv.server_close()


def test_v140_cil_try_catch_il2cpp_flutter_and_hermes(tmp_path: Path) -> None:
    # 1. ECMA-335 Fat Method Header with MoreSects (0x08) SEH try/finally clauses
    il_code = bytes([0x17, 0x0A, 0xDD, 0x02, 0x00, 0x00, 0x00, 0xDC, 0x06, 0x2A])  # 10 bytes + 2B pad = 12
    il_padded = il_code + b"\x00\x00"
    fat_hdr = struct.pack("<HHII", 0x300B, 4, len(il_code), 0)  # flags=0x0B (Fat|MoreSects), hdr=3 dwords
    eh_sect = bytes([0x01, 16, 0, 0]) + struct.pack("<HHBHBI", 0x02, 0, 3, 7, 2, 0)
    raw_pe = bytearray(0x400)
    raw_pe[0:2] = b"MZ"
    struct.pack_into("<I", raw_pe, 0x3C, 0x80)
    raw_pe[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", raw_pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    struct.pack_into("<H", raw_pe, 0x98, 0x020B)
    sec_off = 0x98 + 0xF0
    raw_pe[sec_off : sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", raw_pe, sec_off + 8, 0x200, 0x1000, 0x200, 0x200)
    blob = fat_hdr + il_padded + eh_sect
    raw_pe[0x200 : 0x200 + len(blob)] = blob

    pe = pefile.PE(data=bytes(raw_pe))
    lines = _lift_cil_body_to_csharp(pe, bytes(raw_pe), 0x1000, [], "int", True, b"", {})
    joined = "\n".join(lines)
    assert "try {" in joined and "finally {" in joined

    # 2. IL2CPP global-metadata.dat
    meta = bytearray(256)
    meta[0:4] = b"\xaf\x1b\xb1\xfa"
    struct.pack_into("<i", meta, 4, 29)
    strs = b"PlayerController\x00System.Void\x00GameEngine.Inventory\x00"
    struct.pack_into("<II", meta, 16, 180, len(strs))
    meta[180 : 180 + len(strs)] = strs
    il2 = recover_il2cpp_metadata(bytes(meta), output_dir=tmp_path / "il2cpp")
    assert il2["valid"] is True and il2["version"] == 29 and Path(il2["cs_path"]).is_file()

    # 3. Flutter snapshot + Hermes .hbc
    fl = recover_flutter_snapshot(b"\x00_kDartIsolateSnapshotData\x00package:app/main.dart\x00dart:async\x00", output_dir=tmp_path / "flutter")
    assert fl["detected"] is True and "package:app/main.dart" in fl["packages"]

    hbc = bytearray(128)
    hbc[0:8] = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
    struct.pack_into("<I", hbc, 8, 96)
    struct.pack_into("<I", hbc, 32, 128)
    struct.pack_into("<II", hbc, 40, 12, 4)
    hbc[64:92] = b"authenticateUser\x00fetchToken\x00"
    hb = decode_hermes_bytecode(bytes(hbc), output_dir=tmp_path / "hermes")
    assert hb["valid"] is True and hb["version"] == 96 and "authenticateUser" in hb["strings"]
