from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

import pytest

from aether_re.python_forensics import analyze_pyc, analyze_pyinstaller_carchive, scan_file_python_artifact


def test_pyc_extraction_and_code_object_walking(tmp_path: Path):
    src = (
        "import os\n"
        "def beacon_dispatch(url):\n"
        "    secret = 'https://c2.aether.local/api'\n"
        "    return len(url) + len(secret)\n"
    )
    src_file = tmp_path / "payload.py"
    src_file.write_text(src, encoding="utf-8")

    import py_compile
    pyc_file = tmp_path / "payload.pyc"
    py_compile.compile(str(src_file), cfile=str(pyc_file), doraise=True)

    res = scan_file_python_artifact(pyc_file)
    assert res["status"] == "complete"
    assert res["kind"] == "pyc"
    assert res["total_code_objects"] >= 2
    fn_names = [c["name"] for c in res["code_objects"]]
    assert "beacon_dispatch" in fn_names
    assert "https://c2.aether.local/api" in res["string_constants"]
    assert "os" in res["referenced_names"]


def test_pyinstaller_carchive_cookie_and_toc_parsing(tmp_path: Path):
    # Construct a minimal PyInstaller CArchive
    entry1_data = b"print('hello')\n"
    name1 = b"bootstrap.py\x00\x00\x00\x00"  # padded
    toc_entry = struct.pack(">IIIIBB", 18 + len(name1), 0, len(entry1_data), len(entry1_data), 0, ord("s")) + name1
    toc_off = len(entry1_data)
    toc_len = len(toc_entry)
    pkg_len = toc_off + toc_len + 88
    cookie = struct.pack(">8sIIII64s", b"MEI\x0c\x0b\x0a\x0b\x0e", pkg_len, toc_off, toc_len, 313, b"python313.dll")

    exe = b"MZ" + b"\x00" * 62 + entry1_data + toc_entry + cookie
    p = tmp_path / "packed_py.exe"
    p.write_bytes(exe)

    res = scan_file_python_artifact(p)
    assert res["status"] == "complete"
    assert res["kind"] == "pyinstaller"
    assert res["python_version_code"] == 313
    assert res["pylib_name"] == "python313.dll"
    assert res["total_entries"] == 1
    assert res["entries"][0]["name"] == "bootstrap.py"
    assert res["entries"][0]["typecode"] == "s"


def test_invalid_python_artifacts_fail_closed():
    assert analyze_pyc(b"NOT_PYC")["status"] == "invalid"
    assert analyze_pyinstaller_carchive(b"PLAIN_EXE")["status"] == "not_pyinstaller"


def test_missing_python_artifact_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_python_artifact(r"D:\AetherRE_Megazord\missing_artifact_999.pyc")
