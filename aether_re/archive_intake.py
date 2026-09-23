"""Preflight-first, bounded archive extraction with no link traversal."""
from __future__ import annotations

import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .kernel_contracts import IntakeLimits


class ArchiveRejected(RuntimeError):
    pass


@dataclass(frozen=True)
class ExtractedMember:
    relative_path: str
    path: Path
    size: int
    container_depth: int


_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def detect_archive_kind(path: Path) -> str | None:
    try:
        with Path(path).open("rb") as handle:
            header = handle.read(512)
    except OSError:
        return None
    if header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if len(header) >= 265 and header[257:263] in {b"ustar\x00", b"ustar "}:
        return "tar"
    return None


def _safe_name(name: str, limits: IntakeLimits) -> str:
    if not isinstance(name, str) or not name or "\\" in name or ":" in name or name.startswith("/"):
        raise ArchiveRejected("archive_path_unsafe")
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ArchiveRejected("archive_path_unsafe")
    normalized = pure.as_posix()
    if len(normalized) > limits.max_path_length:
        raise ArchiveRejected("archive_path_length_exceeded")
    for part in pure.parts:
        bare = part.rstrip(" .").split(".", 1)[0].upper()
        if bare in _RESERVED:
            raise ArchiveRejected("archive_path_unsafe")
    return normalized


def _validate_table(rows: list[tuple[str, int, int, object]], limits: IntakeLimits, depth: int) -> list[tuple[str,int,int,object]]:
    if depth > limits.max_archive_depth:
        raise ArchiveRejected("archive_depth_exceeded")
    seen: set[str] = set(); total = 0
    validated: list[tuple[str,int,int,object]]=[]
    for name, size, compressed, item in rows:
        normal=_safe_name(name, limits)
        folded=normal.casefold()
        if folded in seen:
            raise ArchiveRejected("archive_member_duplicate")
        seen.add(folded)
        if isinstance(size,bool) or not isinstance(size,int) or size < 0 or size > limits.max_file_bytes:
            raise ArchiveRejected("archive_file_budget_exceeded")
        if isinstance(compressed,bool) or not isinstance(compressed,int) or compressed < 0:
            raise ArchiveRejected("archive_member_invalid")
        if size / max(compressed,1) > limits.max_compression_ratio:
            raise ArchiveRejected("archive_compression_ratio_exceeded")
        total += size
        if len(validated)+1 > limits.max_files:
            raise ArchiveRejected("archive_file_count_exceeded")
        if total > limits.max_total_bytes:
            raise ArchiveRejected("archive_total_bytes_exceeded")
        validated.append((normal,size,compressed,item))
    return validated


def _preflight_zip(path: Path, limits: IntakeLimits, depth: int) -> list[tuple[str,int,int,object]]:
    try:
        with zipfile.ZipFile(path) as archive:
            rows=[]
            for info in archive.infolist():
                # Directories are not admitted as independent extraction items.
                if info.is_dir():
                    _safe_name(info.filename.rstrip("/"), limits)
                    continue
                mode=(info.external_attr >> 16) & 0xFFFF
                if mode and stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                    raise ArchiveRejected("archive_special_member")
                rows.append((info.filename, info.file_size, info.compress_size, info))
            return _validate_table(rows, limits, depth)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ArchiveRejected("archive_format_unsupported") from exc


def _preflight_tar(path: Path, limits: IntakeLimits, depth: int) -> list[tuple[str,int,int,object]]:
    try:
        with tarfile.open(path, "r:") as archive:
            rows=[]
            for info in archive.getmembers():
                if info.isdir():
                    _safe_name(info.name.rstrip("/"), limits)
                    continue
                if not info.isreg() or info.issym() or info.islnk() or info.isdev() or info.isfifo():
                    raise ArchiveRejected("archive_special_member")
                rows.append((info.name, info.size, info.size, info))
            return _validate_table(rows, limits, depth)
    except (OSError, tarfile.TarError) as exc:
        raise ArchiveRejected("archive_format_unsupported") from exc


def _copy_member(reader: BinaryIO, final: Path, size: int) -> None:
    final.parent.mkdir(parents=True, exist_ok=True)
    fd, tempname=tempfile.mkstemp(prefix=".extract-", suffix=".tmp", dir=final.parent)
    temp=Path(tempname); written=0
    try:
        with os.fdopen(fd,"wb") as writer:
            while True:
                chunk=reader.read(min(1024*1024, size-written+1))
                if not chunk: break
                written += len(chunk)
                if written > size: raise ArchiveRejected("archive_member_size_mismatch")
                writer.write(chunk)
            writer.flush(); os.fsync(writer.fileno())
        if written != size: raise ArchiveRejected("archive_member_size_mismatch")
        os.link(temp, final)
    finally:
        temp.unlink(missing_ok=True)


def extract_archive_bounded(path: Path, destination: Path, *, limits: IntakeLimits, depth: int = 0) -> list[ExtractedMember]:
    path=Path(path); destination=Path(destination)
    kind=detect_archive_kind(path)
    if kind not in {"zip","tar"}: raise ArchiveRejected("archive_format_unsupported")
    table=_preflight_zip(path,limits,depth) if kind=="zip" else _preflight_tar(path,limits,depth)
    if destination.exists(): raise ArchiveRejected("archive_destination_exists")
    staging=destination.parent / f".{destination.name}.staging-{os.getpid()}-{id(table):x}"
    if staging.exists(): raise ArchiveRejected("archive_destination_exists")
    result=[]
    try:
        staging.mkdir(parents=True)
        if kind=="zip":
            with zipfile.ZipFile(path) as archive:
                for name,size,_,info in table:
                    final=staging / Path(*PurePosixPath(name).parts)
                    with archive.open(info, "r") as reader: _copy_member(reader,final,size)
                    result.append(ExtractedMember(name, destination / Path(*PurePosixPath(name).parts),size,depth))
        else:
            with tarfile.open(path,"r:") as archive:
                for name,size,_,info in table:
                    reader=archive.extractfile(info)
                    if reader is None: raise ArchiveRejected("archive_member_invalid")
                    final=staging / Path(*PurePosixPath(name).parts)
                    with reader: _copy_member(reader,final,size)
                    result.append(ExtractedMember(name,destination / Path(*PurePosixPath(name).parts),size,depth))
        # Detect nested archives without recursively extracting target bytes.
        for member in result:
            actual=staging / Path(*PurePosixPath(member.relative_path).parts)
            if detect_archive_kind(actual) is not None and depth + 1 > limits.max_archive_depth:
                raise ArchiveRejected("archive_depth_exceeded")
        os.replace(staging, destination)
        return result
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(destination, ignore_errors=True)
        raise
