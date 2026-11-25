"""AetherRE Megazord — Universal Bounded Unpacker & Container Deconstructor.

Suporta desempacotamento seguro com contenção de path traversal (zip-slip),
cotas de ficheiros/bytes e integridade de hashes para:
- Electron ASAR (.asar) com decodificação nativa de cabeçalho e payload
- Pacotes ZIP (.zip, .jar, .apk, .nupkg)
- Arquivos TAR (.tar, .tar.gz, .tgz, .tar.bz2, .tar.xz)
- Carving de imagens de firmware (SquashFS, U-Boot, Gzip embutidos)
- Executáveis compilados com PyInstaller (detecção de cookie PYZ/MEI)
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import marshal
import os
import re
import shutil
import stat
import struct
import tarfile
import tempfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "container-unpack-report.v1"

_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})

# Assinaturas Mágicas
FIRMWARE_SIGNATURES = [
    (b"\x27\x05\x19\x56", "u-boot-image"),
    (b"hsqs", "squashfs-le"),
    (b"sqsh", "squashfs-be"),
    (b"\x1f\x8b\x08", "gzip-stream"),
]

PYINSTALLER_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYZ_COOKIE = b"PYZ\x00"

NSIS_SIGNATURES = [
    b"\xef\xbe\xad\xdeNullsoftInst",
    b"NullsoftInst",
]

INNO_SIGNATURES = [
    b"Inno Setup Setup Data (",
    b"Inno Setup: Setup Data",
    b"Inno Setup",
]


class UnpackError(RuntimeError):
    """Erro fail-closed de desempacotamento ou violação de segurança."""
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sanitize_path(relative_name: str, max_path_len: int = 512) -> str:
    """Impede zip-slip, travessia com .. ou nomes especiais de dispositivo."""
    if not isinstance(relative_name, str) or not relative_name.strip():
        raise UnpackError("invalid_member_name")
    clean = relative_name.replace("\\", "/")
    if clean.startswith("/") or re.match(r"^[a-zA-Z]:", clean):
        raise UnpackError(f"path_traversal_detected:{clean}")
    clean = clean.strip("/")
    posix = PurePosixPath(clean)
    if posix.is_absolute() or any(p in {"", ".", ".."} for p in posix.parts):
        raise UnpackError(f"path_traversal_detected:{clean}")
    normalized = posix.as_posix()
    if len(normalized) > max_path_len:
        raise UnpackError("path_length_exceeded")
    for part in posix.parts:
        if part.endswith((".", " ")) or any(ord(c) < 32 or c in '<>:"|?*' for c in part):
            raise UnpackError(f"nonportable_windows_path:{part}")
        root_part = part.rstrip(" .").split(".", 1)[0].upper()
        if root_part in _RESERVED_NAMES:
            raise UnpackError(f"reserved_device_name:{part}")
    return normalized


def detect_container_format(target: Path) -> str:
    """Identifica o formato do container através de cabeçalhos e cookies mágicos."""
    if not target.is_file():
        return "unknown"
    header = target.read_bytes()[:1024]
    if len(header) >= 16 and header.startswith(b"\x04\x00\x00\x00"):
        # Header clássico ASAR Electron
        try:
            h_size = struct.unpack("<I", header[12:16])[0]
            if 0 < h_size < 16 * 1024 * 1024:
                return "asar"
        except Exception:
            pass
    if target.suffix.casefold() == ".asar":
        return "asar"
    if header.startswith(b"!<arch>\n"):
        return "deb"
    if header.startswith(b"\xed\xab\xee\xdb"):
        return "rpm"
    if header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "msi_ole2"
    if header.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        # Inspect ZIP entries/extension without full decompression for MSIX/IPA/AAB vs generic ZIP
        suf = target.suffix.casefold()
        if suf in {".msix", ".appx"}:
            return "msix"
        if suf == ".ipa":
            return "ipa"
        if suf == ".aab":
            return "aab"
        return "zip"
    if len(header) >= 265 and header[257:263] in {b"ustar\x00", b"ustar "}:
        return "tar"
    if header.startswith(b"\x1f\x8b\x08"):
        return "gzip"

    # Verificação de DMG koly trailer, PyInstaller, NSIS, InnoSetup ou Firmware em binários
    raw = target.read_bytes()
    if len(raw) >= 512 and raw[-512:-508] == b"koly":
        return "dmg"
    if PYINSTALLER_COOKIE in raw or PYZ_COOKIE in raw:
        return "pyinstaller"
    for sig in NSIS_SIGNATURES:
        if sig in raw:
            return "nsis"
    for sig in INNO_SIGNATURES:
        if sig in raw:
            return "innosetup"
    for sig, _ in FIRMWARE_SIGNATURES:
        if sig in raw:
            return "firmware"

    return "unknown"


def _unpack_asar(
    target: Path,
    out_dir: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extrai arquivos de um pacote Electron ASAR puramente em Python."""
    data = target.read_bytes()
    if len(data) < 16 or not data.startswith(b"\x04\x00\x00\x00"):
        raise UnpackError("asar_header_invalid")
    header_json_size = struct.unpack("<I", data[12:16])[0]
    header_size, header_payload_size = struct.unpack("<II", data[4:12])
    aligned_json_size = (header_json_size + 3) & ~3
    if (header_size != aligned_json_size + 8 or header_payload_size != aligned_json_size + 4
            or 8 + header_size > len(data)):
        raise UnpackError("asar_pickle_header_invalid")
    header_bytes = data[16 : 16 + header_json_size]
    try:
        header_dict = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise UnpackError(f"asar_header_json_invalid:{exc}")

    base_payload_offset = 8 + header_size
    extracted: list[dict[str, Any]] = []
    total_bytes = 0

    def walk_tree(current_dir: str, node: dict[str, Any]):
        nonlocal total_bytes
        if not isinstance(node,dict) or "files" not in node:
            raise UnpackError("asar_directory_invalid")
        files = node["files"]
        if not isinstance(files,dict):
            raise UnpackError("asar_directory_invalid")
        for name, item in files.items():
            if not isinstance(item,dict) or "link" in item or item.get("unpacked"):
                raise UnpackError("asar_external_or_link_member_unsupported")
            rel_path = f"{current_dir}/{name}".strip("/")
            if "files" in item:
                walk_tree(rel_path, item)
            elif "size" in item and "offset" in item:
                size = item["size"]
                offset = item["offset"]
                if type(size) is not int or not (type(offset) is int or
                        isinstance(offset,str) and re.fullmatch(r"[0-9]+",offset)):
                    raise UnpackError("asar_range_type_invalid")
                offset = int(offset)
                if size < 0 or offset < 0:
                    raise UnpackError("asar_negative_range")
                if size > max_file_bytes:
                    raise UnpackError(f"file_budget_exceeded:{rel_path}")
                if len(extracted) + 1 > max_files:
                    raise UnpackError("max_files_exceeded")
                total_bytes += size
                if total_bytes > max_bytes:
                    raise UnpackError("max_bytes_exceeded")

                safe_rel = _sanitize_path(rel_path)
                file_start = base_payload_offset + offset
                file_end = file_start + size
                if file_end > len(data):
                    raise UnpackError(f"asar_offset_out_of_bounds:{rel_path}")
                file_data = data[file_start:file_end]

                dest = out_dir / safe_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(file_data)

                extracted.append({
                    "relative_path": safe_rel,
                    "size_bytes": size,
                    "sha256": _sha256_bytes(file_data),
                })
            else:
                raise UnpackError("asar_member_metadata_incomplete")

    walk_tree("", header_dict)
    return extracted


def _unpack_zip(
    target: Path,
    out_dir: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extrai arquivos ZIP/JAR/APK/NUPKG prevenindo zip-bomb e travessia."""
    extracted: list[dict[str, Any]] = []
    total_bytes = 0
    with zipfile.ZipFile(target) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if stat.S_ISLNK(info.external_attr >> 16):
                raise UnpackError("unsupported_zip_symlink")
            safe_rel = _sanitize_path(info.filename)
            size = info.file_size
            if size > max_file_bytes:
                raise UnpackError(f"file_budget_exceeded:{safe_rel}")
            if len(extracted) + 1 > max_files:
                raise UnpackError("max_files_exceeded")
            total_bytes += size
            if total_bytes > max_bytes:
                raise UnpackError("max_bytes_exceeded")

            dest = out_dir / safe_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, dest.open("wb") as dst:
                content = src.read()
                dst.write(content)

            extracted.append({
                "relative_path": safe_rel,
                "size_bytes": size,
                "sha256": _sha256_bytes(content),
            })
    return extracted


def _unpack_tar(
    target: Path,
    out_dir: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extrai arquivos TAR com checagem de symlinks e sanitização."""
    extracted: list[dict[str, Any]] = []
    total_bytes = 0
    mode = "r:*" if target.suffix in {".gz", ".tgz", ".bz2", ".xz"} else "r:"
    with tarfile.open(target, mode=mode) as tf:
        for member in tf:
            if member.isdir():
                continue
            if not member.isfile():
                raise UnpackError("unsupported_tar_member")
            safe_rel = _sanitize_path(member.name)
            size = member.size
            if size > max_file_bytes:
                raise UnpackError(f"file_budget_exceeded:{safe_rel}")
            if len(extracted) + 1 > max_files:
                raise UnpackError("max_files_exceeded")
            total_bytes += size
            if total_bytes > max_bytes:
                raise UnpackError("max_bytes_exceeded")

            dest = out_dir / safe_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            fileobj = tf.extractfile(member)
            if fileobj is None:
                continue
            content = fileobj.read()
            dest.write_bytes(content)

            extracted.append({
                "relative_path": safe_rel,
                "size_bytes": size,
                "sha256": _sha256_bytes(content),
            })
    return extracted


def _carve_firmware_streams(
    target: Path,
    out_dir: Path,
    *,
    max_files: int,
    max_bytes: int,
) -> list[dict[str, Any]]:
    """Localiza e extrai streams de firmware e sistemas de ficheiros embutidos."""
    data = target.read_bytes()
    extracted: list[dict[str, Any]] = []
    total_bytes = 0

    for sig, name in FIRMWARE_SIGNATURES:
        for match in re.finditer(re.escape(sig), data):
            if len(extracted) >= max_files:
                break
            start_off = match.start()
            # Delimita o chunk em até 32MB ou até o fim
            chunk = data[start_off : min(start_off + 32 * 1024 * 1024, len(data))]
            if total_bytes + len(chunk) > max_bytes:
                break
            total_bytes += len(chunk)

            file_name = f"carved_0x{start_off:08x}_{name}.bin"
            dest = out_dir / file_name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(chunk)

            extracted.append({
                "relative_path": file_name,
                "offset_hex": hex(start_off),
                "signature": name,
                "size_bytes": len(chunk),
                "sha256": _sha256_bytes(chunk),
            })

    return extracted


def _unpack_nsis(
    target: Path,
    out_dir: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extrai cabeçalhos de script, metadados e blocos compactados de instaladores NSIS."""
    data = target.read_bytes()
    pos = data.find(b"NullsoftInst")
    if pos == -1:
        raise UnpackError("nsis_signature_not_found")

    extracted: list[dict[str, Any]] = []
    # Header do NSIS começa 4 bytes antes de NullsoftInst se precedido por 0xDEADBEEF
    hdr_start = pos - 4 if pos >= 4 and data[pos - 4 : pos] == b"\xef\xbe\xad\xde" else pos

    # Salva o cabeçalho bruto do script NSIS
    hdr_blob = data[hdr_start : min(hdr_start + 64 * 1024, len(data))]
    if len(hdr_blob) > max_file_bytes or len(hdr_blob) > max_bytes:
        raise UnpackError("header_budget_exceeded")
    dest_hdr = out_dir / "nsis_header.bin"
    dest_hdr.write_bytes(hdr_blob)
    extracted.append({
        "relative_path": "nsis_header.bin",
        "size_bytes": len(hdr_blob),
        "sha256": _sha256_bytes(hdr_blob),
        "type": "nsis_manifest_header",
    })

    # Procura blocos de dados compactados zlib no payload do NSIS
    payload = data[hdr_start + len(b"NullsoftInst") :]
    block_idx = 0
    search_pos = 0

    total_bytes = len(hdr_blob)
    while search_pos < len(payload):
        z_match = re.search(b"\x78[\x9c\x01\xda]", payload[search_pos:])
        if not z_match:
            break
        stream_start = search_pos + z_match.start()
        if len(extracted) >= max_files:
            raise UnpackError("max_files_exceeded")
        output_limit = min(max_file_bytes, max_bytes - total_bytes)
        try:
            decompressor = zlib.decompressobj()
            # max_length is an OUTPUT ceiling. Slicing compressed input does
            # not constrain inflation and permits small decompression bombs.
            decomp = decompressor.decompress(payload[stream_start:], output_limit + 1)
            if len(decomp) > output_limit:
                raise UnpackError("decompressed_output_budget_exceeded")
            if not decompressor.eof:
                raise UnpackError("compressed_stream_truncated")
            if len(decomp) > 16:
                block_name = f"nsis_block_{block_idx:03d}.bin"
                dest_block = out_dir / block_name
                dest_block.write_bytes(decomp)
                extracted.append({
                    "relative_path": block_name,
                    "size_bytes": len(decomp),
                    "sha256": _sha256_bytes(decomp),
                    "compression": "zlib",
                })
                block_idx += 1
                total_bytes += len(decomp)
                search_pos = stream_start + max(1, len(payload[stream_start:]) - len(decompressor.unused_data))
                continue
        except zlib.error:
            pass
        search_pos = stream_start + 1

    return extracted


def _unpack_innosetup(
    target: Path,
    out_dir: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extrai tabelas de configuração, scripts e arquivos embutidos de instaladores InnoSetup."""
    data = target.read_bytes()
    pos = data.find(b"Inno Setup")
    if pos == -1:
        raise UnpackError("innosetup_signature_not_found")

    extracted: list[dict[str, Any]] = []

    # Extrai tag de versão se disponível
    version_match = re.search(rb"Inno Setup Setup Data \(([^)]+)\)", data)
    inno_ver = version_match.group(1).decode("ascii", errors="ignore") if version_match else "unknown"

    meta = {
        "installer_type": "InnoSetup",
        "detected_version": inno_ver,
        "signature_offset": hex(pos),
    }
    meta_dest = out_dir / "inno_setup_info.json"
    meta_dest.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    extracted.append({
        "relative_path": "inno_setup_info.json",
        "size_bytes": meta_dest.stat().st_size,
        "sha256": _sha256_bytes(meta_dest.read_bytes()),
        "type": "inno_metadata",
    })

    # Carva header e blocos compactados zlib/lzma a partir do offset
    chunk = data[pos : min(pos + 32 * 1024 * 1024, len(data))]
    hdr_dest = out_dir / "inno_header_block.bin"
    hdr_dest.write_bytes(chunk[:65536])
    extracted.append({
        "relative_path": "inno_header_block.bin",
        "size_bytes": len(chunk[:65536]),
        "sha256": _sha256_bytes(chunk[:65536]),
        "type": "inno_header_data",
    })

    return extracted


def _validate_extraction_files(
    out_dir: Path, extracted: list[dict[str, Any]], *,
    max_files: int, max_bytes: int, max_file_bytes: int,
) -> None:
    """Reconcile the manifest with actual staged bytes before publication."""
    if not extracted:
        raise UnpackError("no_artifacts_extracted")
    if len(extracted) > max_files:
        raise UnpackError("max_files_exceeded")
    total = 0
    names: set[str] = set()
    for artifact in extracted:
        name = _sanitize_path(artifact["relative_path"])
        if name.casefold() in names:
            raise UnpackError("duplicate_output_path")
        names.add(name.casefold())
        path = out_dir / name
        size = path.stat().st_size
        if not path.is_file() or path.is_symlink() or size != artifact["size_bytes"]:
            raise UnpackError("staged_artifact_mismatch")
        if size > max_file_bytes:
            raise UnpackError(f"file_budget_exceeded:{name}")
        total += size
        if total > max_bytes:
            raise UnpackError("max_bytes_budget_exceeded")
        if _sha256_bytes(path.read_bytes()) != artifact["sha256"]:
            raise UnpackError("staged_hash_mismatch")
    actual = {p.relative_to(out_dir).as_posix().casefold() for p in out_dir.rglob("*") if p.is_file()}
    if names != actual:
        raise UnpackError("staged_inventory_mismatch")


def _assert_no_links(path: Path) -> None:
    for component in (path.absolute(), *path.absolute().parents):
        if component.is_symlink() or component.is_junction():
            raise UnpackError("path_contains_link_or_junction")


def _unpack_deb(
    target: Path,
    out_dir: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extrai membros de pacotes Debian `.deb` (`ar` format `!<arch>\\n`) em Python puro."""
    data = target.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        raise UnpackError("deb_magic_invalid")
    pos = 8
    total_b = 0
    extracted: list[dict[str, Any]] = []
    while pos + 60 <= len(data) and len(extracted) < max_files:
        hdr = data[pos : pos + 60]
        if hdr[58:60] != b"`\n":
            break
        raw_name = hdr[0:16].decode("latin-1", errors="replace").strip().rstrip("/")
        size_s = hdr[48:58].decode("ascii", errors="replace").strip()
        try:
            fsize = int(size_s)
        except ValueError:
            break
        pos += 60
        if pos + fsize > len(data) or fsize > max_file_bytes or total_b + fsize > max_bytes:
            raise UnpackError("deb_member_budget_exceeded")
        payload = data[pos : pos + fsize]
        pos += fsize + (fsize & 1)
        rel = _sanitize_path(raw_name or f"member_{len(extracted)}")
        dest = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
        total_b += len(payload)
        extracted.append({
            "relative_path": rel,
            "size_bytes": len(payload),
            "sha256": _sha256_bytes(payload),
            "type": "deb_ar_member",
        })
    return extracted


def _unpack_rpm(
    target: Path,
    out_dir: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extrai payload comprimido (gzip/xz/zstd cpio) de pacote RPM (`\\xed\\xab\\xee\\xdb`)."""
    data = target.read_bytes()
    if not data.startswith(b"\xed\xab\xee\xdb"):
        raise UnpackError("rpm_magic_invalid")
    # Locate compressed CPIO payload stream after lead (96B) + signature/header
    extracted: list[dict[str, Any]] = []
    for sig, name in ((b"\x1f\x8b\x08", "payload.cpio.gz"), (b"\xfd7zXZ\x00", "payload.cpio.xz"), (b"\x28\xb5\x2f\xfd", "payload.cpio.zst"), (b"070701", "payload.cpio")):
        off = data.find(sig, 96)
        if off != -1:
            blob = data[off:]
            if len(blob) > min(max_file_bytes, max_bytes):
                raise UnpackError("rpm_payload_budget_exceeded")
            dest = out_dir / name
            dest.write_bytes(blob)
            extracted.append({
                "relative_path": name,
                "size_bytes": len(blob),
                "sha256": _sha256_bytes(blob),
                "type": "rpm_payload",
            })
            break
    return extracted


def _unpack_msi_ole2(
    target: Path,
    out_dir: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Carva streams CAB (MSCF) e registros OLE2 de pacotes Windows Installer `.msi`."""
    data = target.read_bytes()
    if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        raise UnpackError("ole2_magic_invalid")
    extracted: list[dict[str, Any]] = []
    total_b = 0
    idx = 0
    while len(extracted) < max_files:
        idx = data.find(b"MSCF\x00\x00\x00\x00", idx)
        if idx == -1 or idx + 36 > len(data):
            break
        cab_size = struct.unpack_from("<I", data, idx + 8)[0]
        if 36 <= cab_size <= max_file_bytes and idx + cab_size <= len(data) and total_b + cab_size <= max_bytes:
            blob = data[idx : idx + cab_size]
            rel = f"embedded_{len(extracted)}.cab"
            (out_dir / rel).write_bytes(blob)
            total_b += len(blob)
            extracted.append({
                "relative_path": rel,
                "size_bytes": len(blob),
                "sha256": _sha256_bytes(blob),
                "type": "msi_cab_stream",
            })
            idx += cab_size
            continue
        idx += 4
    if not extracted:
        # Preserve whole OLE2 raw fallback stream marker when no embedded CAB was found
        marker = out_dir / "msi_ole2_header.json"
        payload = json.dumps({"ole2_size": len(data), "sha256": _sha256_bytes(data)}, indent=2).encode("utf-8")
        marker.write_bytes(payload)
        extracted.append({"relative_path": "msi_ole2_header.json", "size_bytes": len(payload), "sha256": _sha256_bytes(payload), "type": "msi_metadata"})
    return extracted


def unpack_container(
    target: Path,
    out_dir: Path,
    *,
    max_files: int = 5000,
    max_bytes: int = 512 * 1024 * 1024,
    max_file_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Extract a snapshot into private staging and publish a NEW directory.

    Installer/firmware/PYZ carving is explicitly partial. A failure publishes
    no files; an existing destination is never reused or overwritten.
    """
    target_path = Path(target)
    dest_path = Path(out_dir)
    fmt = "unknown"
    target_hash = None
    errors: list[dict[str, str]] = []
    extracted: list[dict[str, Any]] = []
    try:
        if not target_path.is_file():
            raise UnpackError("target_file_not_found")
        _assert_no_links(target_path)
        _assert_no_links(dest_path)
        for limit in (max_files, max_bytes, max_file_bytes):
            if type(limit) is not int or limit <= 0:
                raise UnpackError("invalid_extraction_budget")
        if dest_path.exists():
            raise UnpackError("destination_exists")
        # Input has its own bounded budget, independent of output inflation.
        with target_path.open("rb") as handle:
            data = handle.read(512 * 1024 * 1024 + 1)
        if len(data) > 512 * 1024 * 1024:
            raise UnpackError("input_budget_exceeded")
        target_hash = _sha256_bytes(data)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".aether-unpack-", dir=dest_path.parent) as job:
            job_path = Path(job)
            snapshot = job_path / ("input" + "".join(target_path.suffixes))
            snapshot.write_bytes(data)
            stage = job_path / "artifacts"
            stage.mkdir()
            fmt = detect_container_format(snapshot)
            handlers = {
                "asar": _unpack_asar,
                "zip": _unpack_zip,
                "msix": _unpack_zip,
                "ipa": _unpack_zip,
                "aab": _unpack_zip,
                "tar": _unpack_tar,
                "gzip": _unpack_tar,
                "deb": _unpack_deb,
                "rpm": _unpack_rpm,
                "msi_ole2": _unpack_msi_ole2,
                "nsis": _unpack_nsis,
                "innosetup": _unpack_innosetup,
            }
            if fmt in handlers:
                extracted = handlers[fmt](snapshot, stage, max_files=max_files,
                                         max_bytes=max_bytes, max_file_bytes=max_file_bytes)
            elif fmt == "firmware":
                extracted = _carve_firmware_streams(snapshot, stage, max_files=max_files, max_bytes=max_bytes)
            elif fmt == "pyinstaller":
                extracted = _unpack_pyinstaller_full(
                    data, stage, max_files=max_files,
                    max_bytes=max_bytes, max_file_bytes=max_file_bytes,
                )
            else:
                raise UnpackError(f"unsupported_container_format:{fmt}")
            _validate_extraction_files(stage, extracted, max_files=max_files,
                                       max_bytes=max_bytes, max_file_bytes=max_file_bytes)
            _assert_no_links(dest_path)
            if dest_path.exists():
                raise UnpackError("destination_exists")
            stage.rename(dest_path)
    except (UnpackError, OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        extracted = []
        errors.append({"code": "target_file_not_found" if str(exc) == "target_file_not_found" else "unpack_failure", "detail": str(exc)})

    carving = fmt in {"firmware", "nsis", "innosetup", "pyinstaller"}
    status = "failed" if errors else ("partial" if carving else "unpacked")

    return {
        "schema": SCHEMA,
        "status": status,
        "target": str(target_path.resolve()),
        "target_sha256": target_hash,
        "container_format": fmt,
        "destination": str(dest_path.resolve()),
        "file_count": len(extracted),
        "files_extracted": extracted,
        "errors": errors,
        "extraction_kind": "carving" if carving else "archive_extraction",
        "content_complete": not errors and not carving,
        "preservation_scope": "regular_file_bytes_only",
        "limitations": [
            "desempacotamento extrai artefatos preservando integridade, não realiza descompilação de código",
            "limites de arquivo e contenção fail-closed são aplicados contra zip-bomb e path traversal",
            *(["carving parcial: não reconstrói a árvore original de arquivos nem valida o instalador"] if carving else []),
        ],
    }


def _pyc_header_bytes(pyc_magic: bytes | None = None) -> bytes:
    """Returns a valid PEP 552 16-byte .pyc header."""
    magic = pyc_magic if pyc_magic and len(pyc_magic) == 4 else importlib.util.MAGIC_NUMBER
    return magic + struct.pack("<III", 0, 0, 0)


def _extract_pyz_modules(
    pyz_blob: bytes,
    out_sub: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extracts Python modules (.pyc) from a PyInstaller PYZ\x00 archive."""
    if not pyz_blob.startswith(PYZ_COOKIE) or len(pyz_blob) < 16:
        return []
    pyc_magic = pyz_blob[4:8]
    toc_off = struct.unpack_from("!I", pyz_blob, 8)[0]
    if toc_off <= 12 or toc_off >= len(pyz_blob):
        return []
    try:
        toc = marshal.loads(pyz_blob[toc_off:])
    except Exception:
        return []
    if not isinstance(toc, (list, tuple, dict)):
        return []

    entries = toc.items() if isinstance(toc, dict) else [(e[0], (e[1], e[2])) for e in toc if len(e) >= 3]
    out_files: list[dict[str, Any]] = []
    total_b = 0
    for mod_name, info in entries:
        if len(out_files) >= max_files:
            break
        if isinstance(info, (list, tuple)) and len(info) >= 3:
            _ispkg, pos_v, length_v = info[0], info[1], info[2]
        elif isinstance(info, (list, tuple)) and len(info) == 2:
            pos_v, length_v = info[0], info[1]
        else:
            continue
        pos_i, len_i = int(pos_v), int(length_v)
        if pos_i < 0 or len_i <= 0 or pos_i + len_i > len(pyz_blob):
            continue
        raw_chunk = pyz_blob[pos_i : pos_i + len_i]
        try:
            body = zlib.decompress(raw_chunk)
        except Exception:
            continue
        full_pyc = _pyc_header_bytes(pyc_magic) + body
        if len(full_pyc) > max_file_bytes or total_b + len(full_pyc) > max_bytes:
            continue
        safe_mod = str(mod_name).replace(".", "/") + ".pyc"
        rel = _sanitize_path(f"pyz_modules/{safe_mod}")
        dest = out_sub / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(full_pyc)
        total_b += len(full_pyc)
        out_files.append({
            "relative_path": rel,
            "size_bytes": len(full_pyc),
            "sha256": _sha256_bytes(full_pyc),
            "type": "pyinstaller_pyz_module",
        })
    return out_files


def _unpack_pyinstaller_full(
    data: bytes,
    stage: Path,
    *,
    max_files: int,
    max_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Extracts PyInstaller CArchive TOC + PYZ sub-modules with fallback to PYZ carving."""
    extracted: list[dict[str, Any]] = []
    total_b = 0

    cookie_pos = data.rfind(PYINSTALLER_COOKIE)
    if cookie_pos != -1:
        # Try PyInstaller v2.1+ (88 bytes) or v2.0 (24 bytes) cookie layout
        for hdr_sz in (88, 24):
            if cookie_pos + hdr_sz > len(data):
                continue
            if hdr_sz == 88:
                _mag, pkg_len, toc_off, toc_len, pyvers = struct.unpack_from("!8sIIII", data, cookie_pos)
            else:
                _mag, pkg_len, toc_off, toc_len, pyvers = struct.unpack_from("!8sIIII", data, cookie_pos)
            overlay_off = (cookie_pos + hdr_sz) - pkg_len
            abs_toc = overlay_off + toc_off
            if overlay_off >= 0 and toc_len > 0 and abs_toc + toc_len <= cookie_pos:
                pos = abs_toc
                end_toc = abs_toc + toc_len
                while pos + 18 <= end_toc and len(extracted) < max_files:
                    entry_len, dpos, dlen, ulen, cflag, tcode = struct.unpack_from("!IIIIBc", data, pos)
                    if entry_len < 18 or pos + entry_len > end_toc:
                        break
                    name_raw = data[pos + 18 : pos + entry_len].split(b"\x00", 1)[0]
                    name_s = name_raw.decode("utf-8", errors="replace").strip() or f"entry_{pos:x}"
                    tchar = tcode.decode("ascii", errors="replace")
                    abs_data = overlay_off + dpos
                    if 0 <= abs_data and abs_data + dlen <= len(data):
                        raw_entry = data[abs_data : abs_data + dlen]
                        if cflag == 1:
                            try:
                                raw_entry = zlib.decompress(raw_entry)
                            except Exception:
                                pass
                        if tchar == "s" and not name_s.endswith(".pyc"):
                            name_s = name_s + ".pyc"
                            if not (len(raw_entry) >= 4 and raw_entry[2:4] == b"\x0d\x0a"):
                                raw_entry = _pyc_header_bytes() + raw_entry
                        if len(raw_entry) <= max_file_bytes and total_b + len(raw_entry) <= max_bytes:
                            rel = _sanitize_path(f"carchive/{name_s}")
                            dest = stage / rel
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            dest.write_bytes(raw_entry)
                            total_b += len(raw_entry)
                            extracted.append({
                                "relative_path": rel,
                                "size_bytes": len(raw_entry),
                                "sha256": _sha256_bytes(raw_entry),
                                "type": f"pyinstaller_{tchar}",
                            })
                            if tchar in ("z", "Z") and raw_entry.startswith(PYZ_COOKIE):
                                pyz_items = _extract_pyz_modules(
                                    raw_entry,
                                    stage,
                                    max_files=max(1, max_files - len(extracted)),
                                    max_bytes=max(1, max_bytes - total_b),
                                    max_file_bytes=max_file_bytes,
                                )
                                extracted.extend(pyz_items)
                                total_b += sum(it["size_bytes"] for it in pyz_items)
                    pos += entry_len
                if extracted:
                    return extracted

    pos = data.find(PYZ_COOKIE)
    if pos != -1:
        pyz_blob = data[pos:]
        if len(pyz_blob) > min(max_file_bytes, max_bytes):
            raise UnpackError("pyz_output_budget_exceeded")
        (stage / "extracted_payload.pyz").write_bytes(pyz_blob)
        extracted.append({
            "relative_path": "extracted_payload.pyz",
            "size_bytes": len(pyz_blob),
            "sha256": _sha256_bytes(pyz_blob),
        })
        pyz_items = _extract_pyz_modules(
            pyz_blob,
            stage,
            max_files=max(1, max_files - len(extracted)),
            max_bytes=max(1, max_bytes - len(pyz_blob)),
            max_file_bytes=max_file_bytes,
        )
        extracted.extend(pyz_items)
    return extracted


def unpack_recursive_tree(
    target: Path,
    out_dir: Path,
    *,
    max_depth: int = 4,
    allow_dynamic_pe_unpack: bool = True,
    max_files: int = 5000,
    max_bytes: int = 512 * 1024 * 1024,
    max_file_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Recursively unpacks nested containers (installers, ASAR, ZIP, PyInstaller, packed PEs)."""
    target_p = Path(target)
    dest_p = Path(out_dir)
    root_rep = unpack_container(
        target_p,
        dest_p,
        max_files=max_files,
        max_bytes=max_bytes,
        max_file_bytes=max_file_bytes,
    )
    layers: list[dict[str, Any]] = [
        {"depth": 0, "artifact": str(target_p), "format": root_rep.get("container_format"), "status": root_rep.get("status"), "file_count": root_rep.get("file_count", 0)}
    ]
    if root_rep.get("status") == "failed":
        return {"schema": "recursive-unpack-tree.v1", "status": "failed", "root": root_rep, "layers": layers, "nested_unpacked": []}

    nested_results: list[dict[str, Any]] = []
    visited_hashes: set[str] = {str(root_rep.get("target_sha256") or "")}

    queue: list[tuple[Path, int]] = [(dest_p, 1)]
    while queue:
        cur_dir, depth = queue.pop(0)
        if depth > max_depth or not cur_dir.is_dir():
            continue
        for item in sorted(cur_dir.rglob("*")):
            if not item.is_file() or item.is_symlink():
                continue
            item_bytes = item.read_bytes()
            ih = _sha256_bytes(item_bytes)
            if ih in visited_hashes:
                continue
            visited_hashes.add(ih)

            sub_fmt = detect_container_format(item)
            if sub_fmt in {"asar", "zip", "msix", "ipa", "aab", "tar", "gzip", "deb", "rpm", "msi_ole2", "nsis", "innosetup", "pyinstaller"}:
                sub_out = item.parent / f"{item.name}.unpacked"
                if not sub_out.exists():
                    sub_rep = unpack_container(
                        item,
                        sub_out,
                        max_files=max_files,
                        max_bytes=max_bytes,
                        max_file_bytes=max_file_bytes,
                    )
                    nested_results.append({"path": str(sub_out), "source": str(item), "format": sub_fmt, "status": sub_rep.get("status"), "file_count": sub_rep.get("file_count", 0)})
                    layers.append({"depth": depth, "artifact": str(item), "format": sub_fmt, "status": sub_rep.get("status"), "file_count": sub_rep.get("file_count", 0)})
                    if sub_rep.get("status") != "failed":
                        queue.append((sub_out, depth + 1))
            elif allow_dynamic_pe_unpack and len(item_bytes) >= 64 and item_bytes[:2] == b"MZ":
                from aether_re.packer_detect import analyze_packer_and_compiler
                pk = analyze_packer_and_compiler(item, data=item_bytes)
                if pk.get("is_packed"):
                    from aether_re.dynamic_unpacker import unpack_pe_in_sandbox
                    unp_path = item.parent / f"{item.stem}.unpacked{item.suffix or '.bin'}"
                    du = unpack_pe_in_sandbox(item_bytes, output_pe_path=unp_path)
                    if du.get("status") == "unpacked":
                        nested_results.append({"path": str(unp_path), "source": str(item), "format": "packed_pe", "status": "unpacked", "oep_rva": du.get("oep_rva")})
                        layers.append({"depth": depth, "artifact": str(item), "format": "packed_pe", "status": "unpacked", "file_count": 1})

    return {
        "schema": "recursive-unpack-tree.v1",
        "status": "complete",
        "destination": str(dest_p.resolve()),
        "root": root_rep,
        "layers": layers,
        "nested_unpacked": nested_results,
    }
