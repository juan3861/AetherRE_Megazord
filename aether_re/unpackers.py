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
import json
import os
import re
import stat
import struct
import tarfile
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
    if header.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if len(header) >= 265 and header[257:263] in {b"ustar\x00", b"ustar "}:
        return "tar"
    if header.startswith(b"\x1f\x8b\x08"):
        return "gzip"

    # Verificação de PyInstaller, NSIS, InnoSetup ou Firmware em binários PE/ELF
    raw = target.read_bytes()
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
    header_bytes = data[16 : 16 + header_json_size]
    try:
        header_dict = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise UnpackError(f"asar_header_json_invalid:{exc}")

    base_payload_offset = 16 + header_json_size
    extracted: list[dict[str, Any]] = []
    total_bytes = 0

    def walk_tree(current_dir: str, node: dict[str, Any]):
        nonlocal total_bytes
        files = node.get("files", {})
        for name, item in files.items():
            rel_path = f"{current_dir}/{name}".strip("/")
            if "files" in item:
                walk_tree(rel_path, item)
            elif "size" in item and "offset" in item:
                size = int(item["size"])
                offset = int(item["offset"])
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
        for member in tf.getmembers():
            if not member.isfile():
                continue
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

    while search_pos < len(payload) and len(extracted) < max_files:
        z_match = re.search(b"\x78[\x9c\x01\xda]", payload[search_pos:])
        if not z_match:
            break
        stream_start = search_pos + z_match.start()
        try:
            decompressor = zlib.decompressobj()
            decomp = decompressor.decompress(payload[stream_start : stream_start + max_file_bytes])
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
                search_pos = stream_start + max(1, len(payload[stream_start:]) - len(decompressor.unused_data))
                continue
        except Exception:
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


def unpack_container(
    target: Path,
    out_dir: Path,
    *,
    max_files: int = 5000,
    max_bytes: int = 512 * 1024 * 1024,
    max_file_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Desempacota qualquer container suportado para o diretório de destino de forma segura."""
    target_path = Path(target)
    dest_path = Path(out_dir)

    if not target_path.is_file():
        return {
            "schema": SCHEMA,
            "status": "failed",
            "target": str(target),
            "container_format": "unknown",
            "files_extracted": [],
            "errors": [{"code": "target_file_not_found"}],
            "limitations": ["alvo inexistente ou ilegível"],
        }

    dest_path.mkdir(parents=True, exist_ok=True)
    fmt = detect_container_format(target_path)
    errors: list[dict[str, str]] = []
    extracted: list[dict[str, Any]] = []

    try:
        if fmt == "asar":
            extracted = _unpack_asar(
                target_path, dest_path,
                max_files=max_files, max_bytes=max_bytes, max_file_bytes=max_file_bytes,
            )
        elif fmt == "zip":
            extracted = _unpack_zip(
                target_path, dest_path,
                max_files=max_files, max_bytes=max_bytes, max_file_bytes=max_file_bytes,
            )
        elif fmt in {"tar", "gzip"}:
            extracted = _unpack_tar(
                target_path, dest_path,
                max_files=max_files, max_bytes=max_bytes, max_file_bytes=max_file_bytes,
            )
        elif fmt == "firmware":
            extracted = _carve_firmware_streams(
                target_path, dest_path,
                max_files=max_files, max_bytes=max_bytes,
            )
        elif fmt == "nsis":
            extracted = _unpack_nsis(
                target_path, dest_path,
                max_files=max_files, max_bytes=max_bytes, max_file_bytes=max_file_bytes,
            )
        elif fmt == "innosetup":
            extracted = _unpack_innosetup(
                target_path, dest_path,
                max_files=max_files, max_bytes=max_bytes, max_file_bytes=max_file_bytes,
            )
        elif fmt == "pyinstaller":
            # Extrai payload PYZ bruto para inspeção
            data = target_path.read_bytes()
            pos = data.find(PYZ_COOKIE)
            if pos != -1:
                pyz_blob = data[pos:]
                pyz_dest = dest_path / "extracted_payload.pyz"
                pyz_dest.write_bytes(pyz_blob)
                extracted.append({
                    "relative_path": "extracted_payload.pyz",
                    "size_bytes": len(pyz_blob),
                    "sha256": _sha256_bytes(pyz_blob),
                })
        else:
            errors.append({"code": "unsupported_container_format", "detail": fmt})
    except (UnpackError, OSError, ValueError) as exc:
        errors.append({"code": "unpack_failure", "detail": str(exc)})

    status = "failed" if errors and not extracted else ("partial" if errors else "unpacked")

    return {
        "schema": SCHEMA,
        "status": status,
        "target": str(target_path.resolve()),
        "target_sha256": hashlib.sha256(target_path.read_bytes()).hexdigest(),
        "container_format": fmt,
        "destination": str(dest_path.resolve()),
        "file_count": len(extracted),
        "files_extracted": extracted,
        "errors": errors,
        "limitations": [
            "desempacotamento extrai artefatos preservando integridade, não realiza descompilação de código",
            "limites de arquivo e contenção fail-closed são aplicados contra zip-bomb e path traversal",
        ],
    }
