from __future__ import annotations

import io
import json
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from aether_re.unpackers import (
    FIRMWARE_SIGNATURES,
    PYZ_COOKIE,
    SCHEMA,
    UnpackError,
    _sanitize_path,
    detect_container_format,
    unpack_container,
)


def _build_mock_asar(files: dict[str, bytes]) -> bytes:
    """Constrói um pacote ASAR minimal em conformidade com a especificação Electron."""
    header_files: dict[str, dict] = {}
    payload = bytearray()
    offset = 0

    for filename, content in files.items():
        header_files[filename] = {
            "size": len(content),
            "offset": str(offset),
        }
        payload.extend(content)
        offset += len(content)

    header_dict = {"files": header_files}
    header_json = json.dumps(header_dict).encode("utf-8")
    header_len = len(header_json)

    # O formato ASAR tem:
    # 4 bytes de tamanho alinhado (uint32)
    # 4 bytes de tamanho do header payload + 8 (uint32)
    # 4 bytes de tamanho do header payload + 4 (uint32)
    # 4 bytes de tamanho do json string (uint32)
    # json string
    # binary payload
    header_prefix = struct.pack(
        "<IIII",
        4,
        header_len + 8,
        header_len + 4,
        header_len,
    )
    return header_prefix + header_json + bytes(payload)


def test_sanitize_path_safety():
    assert _sanitize_path("foo/bar/baz.txt") == "foo/bar/baz.txt"
    assert _sanitize_path("app\\main.js") == "app/main.js"

    # Zip-slip traversal
    with pytest.raises(UnpackError, match="path_traversal_detected"):
        _sanitize_path("../secret.txt")

    with pytest.raises(UnpackError, match="path_traversal_detected"):
        _sanitize_path("foo/../../etc/passwd")

    with pytest.raises(UnpackError, match="path_traversal_detected"):
        _sanitize_path("/absolute/path.txt")

    # Reserved Windows device names
    with pytest.raises(UnpackError, match="reserved_device_name"):
        _sanitize_path("con.txt")

    with pytest.raises(UnpackError, match="reserved_device_name"):
        _sanitize_path("sub/nul/payload.bin")

    # Invalid names
    with pytest.raises(UnpackError, match="invalid_member_name"):
        _sanitize_path("")


def test_detect_container_format(tmp_path: Path):
    f_unknown = tmp_path / "unknown.bin"
    f_unknown.write_bytes(b"\x00\x01\x02\x03")
    assert detect_container_format(f_unknown) == "unknown"

    f_zip = tmp_path / "sample.zip"
    with zipfile.ZipFile(f_zip, "w") as zf:
        zf.writestr("test.txt", "hello")
    assert detect_container_format(f_zip) == "zip"

    asar_bytes = _build_mock_asar({"test.txt": b"hello"})
    f_asar = tmp_path / "sample.asar"
    f_asar.write_bytes(asar_bytes)
    assert detect_container_format(f_asar) == "asar"

    f_pyz = tmp_path / "frozen.exe"
    f_pyz.write_bytes(b"MZ" + b"\x00" * 50 + PYZ_COOKIE + b"\x00" * 20)
    assert detect_container_format(f_pyz) == "pyinstaller"

    f_fw = tmp_path / "firmware.bin"
    f_fw.write_bytes(b"\x00" * 100 + b"hsqs" + b"\x00" * 50)
    assert detect_container_format(f_fw) == "firmware"


def test_unpack_zip_container(tmp_path: Path):
    zip_path = tmp_path / "app.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("index.js", b"console.log(1);")
        zf.writestr("data/config.json", b'{"key": "val"}')

    out_dir = tmp_path / "out_zip"
    report = unpack_container(zip_path, out_dir)
    assert report["schema"] == SCHEMA
    assert report["status"] == "unpacked"
    assert report["file_count"] == 2
    assert (out_dir / "index.js").read_bytes() == b"console.log(1);"
    assert (out_dir / "data" / "config.json").read_bytes() == b'{"key": "val"}'


def test_unpack_zip_slip_rejection(tmp_path: Path):
    zip_path = tmp_path / "malicious.zip"
    # Monta arquivo zip com travessia de path manualmente
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.txt", b"evil_payload")
    zip_path.write_bytes(buf.getvalue())

    out_dir = tmp_path / "out_evil"
    report = unpack_container(zip_path, out_dir)
    assert report["status"] == "failed"
    assert any("path_traversal_detected" in err.get("detail", "") for err in report["errors"])
    assert not (tmp_path / "evil.txt").exists()


def test_unpack_asar_container(tmp_path: Path):
    asar_data = _build_mock_asar({
        "main.js": b"const x = 42;",
        "package.json": b'{"name": "test-app"}',
    })
    asar_path = tmp_path / "package.asar"
    asar_path.write_bytes(asar_data)

    out_dir = tmp_path / "out_asar"
    report = unpack_container(asar_path, out_dir)
    assert report["status"] == "unpacked"
    assert report["container_format"] == "asar"
    assert report["file_count"] == 2
    assert (out_dir / "main.js").read_bytes() == b"const x = 42;"
    assert (out_dir / "package.json").read_bytes() == b'{"name": "test-app"}'


def test_unpack_asar_budget_exceeded(tmp_path: Path):
    asar_data = _build_mock_asar({"huge.bin": b"A" * 1024})
    asar_path = tmp_path / "big.asar"
    asar_path.write_bytes(asar_data)

    out_dir = tmp_path / "out_big"
    report = unpack_container(asar_path, out_dir, max_file_bytes=512)
    assert report["status"] == "failed"
    assert any("file_budget_exceeded" in err.get("detail", "") for err in report["errors"])


def test_unpack_tar_container(tmp_path: Path):
    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as tf:
        data = b"tar content data"
        ti = tarfile.TarInfo(name="sub/file.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))

    out_dir = tmp_path / "out_tar"
    report = unpack_container(tar_path, out_dir)
    assert report["status"] == "unpacked"
    assert report["file_count"] == 1
    assert (out_dir / "sub" / "file.txt").read_bytes() == b"tar content data"


def test_unpack_pyinstaller_payload(tmp_path: Path):
    exe_path = tmp_path / "app.exe"
    pyz_blob = PYZ_COOKIE + b"\x00\x01\x02\x03\x04"
    exe_path.write_bytes(b"PE_HEADER" + b"\x90" * 32 + pyz_blob)

    out_dir = tmp_path / "out_pyz"
    report = unpack_container(exe_path, out_dir)
    assert report["status"] == "unpacked"
    assert report["container_format"] == "pyinstaller"
    assert (out_dir / "extracted_payload.pyz").read_bytes() == pyz_blob


def test_unpack_firmware_carving(tmp_path: Path):
    fw_path = tmp_path / "dump.bin"
    squashfs_chunk = b"hsqs" + b"\x00" * 64
    fw_path.write_bytes(b"\xff" * 128 + squashfs_chunk + b"\xee" * 128)

    out_dir = tmp_path / "out_fw"
    report = unpack_container(fw_path, out_dir)
    assert report["status"] == "unpacked"
    assert report["container_format"] == "firmware"
    assert report["file_count"] >= 1
    carved_files = list(out_dir.glob("carved_*.bin"))
    assert len(carved_files) >= 1
    assert carved_files[0].read_bytes().startswith(b"hsqs")


def test_unpack_non_existent_file(tmp_path: Path):
    missing = tmp_path / "ghost.zip"
    out_dir = tmp_path / "out_ghost"
    report = unpack_container(missing, out_dir)
    assert report["status"] == "failed"
    assert any(err.get("code") == "target_file_not_found" for err in report["errors"])


def test_unpack_nsis_installer(tmp_path: Path):
    import zlib
    installer = tmp_path / "setup_nsis.exe"
    compressed_payload = zlib.compress(b"MZ_DUMMY_EXECUTABLE_PAYLOAD_CONTENT" * 10)
    nsis_data = (
        b"MZ\x90\x00PE_HEADER_DATA"
        + b"\xef\xbe\xad\xdeNullsoftInst"
        + b"\x00" * 32
        + compressed_payload
    )
    installer.write_bytes(nsis_data)

    out_dir = tmp_path / "out_nsis"
    report = unpack_container(installer, out_dir)
    assert report["status"] == "unpacked"
    assert report["container_format"] == "nsis"
    assert (out_dir / "nsis_header.bin").exists()
    assert (out_dir / "nsis_block_000.bin").read_bytes() == b"MZ_DUMMY_EXECUTABLE_PAYLOAD_CONTENT" * 10


def test_unpack_innosetup_installer(tmp_path: Path):
    installer = tmp_path / "setup_inno.exe"
    inno_data = (
        b"MZ\x90\x00PE_HEADER_DATA"
        + b"Inno Setup Setup Data (6.2.0)"
        + b"\x00" * 100
        + b"PAYLOAD_DATA_CHUNK_123"
    )
    installer.write_bytes(inno_data)

    out_dir = tmp_path / "out_inno"
    report = unpack_container(installer, out_dir)
    assert report["status"] == "unpacked"
    assert report["container_format"] == "innosetup"
    assert (out_dir / "inno_setup_info.json").exists()
    assert (out_dir / "inno_header_block.bin").exists()

