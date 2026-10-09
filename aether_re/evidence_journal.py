"""Durable hash-chained JSONL journal for the evidence kernel."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .kernel_contracts import canonical_json, sha256_canonical
from .lock import RunLock, RunLockError

_HASH = "0" * 64

class _DuplicateJSONKeyError(ValueError):
    """Raised when serialized evidence contains a repeated JSON object key."""

def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJSONKeyError(key)
        value[key] = item
    return value


def _path_safety_issue(path: Path, *, expected: str) -> str | None:
    """Detect link traversal and multiply-linked evidence files without resolving first."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    components = [current]
    for part in absolute.parts[1:]:
        current = current / part
        components.append(current)
    final = components[-1]
    final_stat = None
    for component in components:
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            continue
        except OSError:
            return "uninspectable"
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        attributes = getattr(info, "st_file_attributes", 0)
        is_junction = getattr(os.path, "isjunction", None)
        try:
            junction = bool(is_junction and is_junction(component))
        except OSError:
            return "uninspectable"
        if stat.S_ISLNK(info.st_mode) or attributes & reparse_flag or junction:
            return "reparse"
        if component == final:
            final_stat = info
    if final_stat is not None:
        if expected == "directory" and not stat.S_ISDIR(final_stat.st_mode):
            return "not_directory"
        if expected == "file" and not stat.S_ISREG(final_stat.st_mode):
            return "not_regular"
        if expected == "file" and getattr(final_stat, "st_nlink", 1) > 1:
            return "hardlink"
    return None


def _file_identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)

class JournalCorruption(RuntimeError):
    pass

@dataclass(frozen=True)
class JournalEntry:
    schema: str
    sequence: int
    kind: str
    recorded_at: str
    previous_hash: str
    parents: tuple[str, ...]
    payload: Mapping[str, Any]
    entry_hash: str

@dataclass(frozen=True)
class JournalVerification:
    status: str
    entries: int
    head_hash: str
    quarantine_path: Path | None = None

class EvidenceJournal:
    SCHEMA = "evidence-journal-entry.v1"
    _mutexes: dict[str, threading.RLock] = {}
    _mutexes_guard = threading.Lock()

    def __init__(self, case_dir: Path, *, max_event_bytes: int = 1_048_576):
        if isinstance(max_event_bytes, bool) or not isinstance(max_event_bytes, int) or max_event_bytes < 1:
            raise ValueError("journal_event_limit_invalid")
        requested = Path(case_dir)
        if ".." in requested.parts:
            raise JournalCorruption("journal_path_unsafe:case_dir:parent_reference")
        self._requested_case_dir = Path(os.path.abspath(os.fspath(requested)))
        self._assert_safe_path(self._requested_case_dir, "case_dir")
        self._requested_case_dir.mkdir(parents=True, exist_ok=True)
        self._assert_safe_path(self._requested_case_dir, "case_dir")
        if not self._requested_case_dir.is_dir():
            raise JournalCorruption("journal_case_dir_invalid")
        self.case_dir = self._requested_case_dir.resolve()
        self.path = self.case_dir / "journal.jsonl"
        self.head_path = self.case_dir / "journal.head.json"
        self.max_event_bytes = max_event_bytes
        self._assert_safe_storage()
        with self._mutexes_guard:
            self._mutex = self._mutexes.setdefault(str(self.path), threading.RLock())

    @property
    def _writer_lock_path(self) -> Path:
        return self.case_dir / "journal.writer.lock"

    @property
    def _head_temp_path(self) -> Path:
        return self.head_path.with_suffix(".json.tmp")

    @staticmethod
    def _assert_safe_path(path: Path, label: str) -> None:
        expected = "directory" if label == "case_dir" else "file"
        issue = _path_safety_issue(path, expected=expected)
        if issue is not None:
            raise JournalCorruption(f"journal_path_unsafe:{label}:{issue}")

    def _assert_safe_storage(self) -> None:
        self._assert_safe_path(self._requested_case_dir, "case_dir")
        self._assert_safe_path(self.case_dir, "case_dir")
        if not self.case_dir.is_dir():
            raise JournalCorruption("journal_case_dir_invalid")
        self._assert_safe_path(self.path, "journal")
        self._assert_safe_path(self.head_path, "head")
        self._assert_safe_path(self._head_temp_path, "head_temp")
        self._assert_safe_path(self._writer_lock_path, "writer_lock")

    def _assert_head_temp_available(self) -> None:
        self._assert_safe_path(self._head_temp_path, "head_temp")
        if self._head_temp_path.exists():
            raise JournalCorruption("journal_head_temp_exists")

    @contextmanager
    def _writer_lock(self) -> Iterator[None]:
        # Check the path before RunLock can create/read/recover its lock file,
        # and again after acquisition before touching journal state.
        self._assert_safe_storage()
        try:
            with RunLock(self._writer_lock_path):
                self._assert_safe_storage()
                yield
        except RunLockError as exc:
            raise JournalCorruption("journal_writer_locked") from exc

    def _write_temp_exclusive(self, path: Path, data: bytes, label: str) -> tuple[int, int]:
        self._assert_safe_path(path, label)
        if path.exists():
            raise JournalCorruption(f"journal_temp_exists:{label}")
        identity: tuple[int, int] | None = None
        try:
            with path.open("xb") as handle:
                identity = _file_identity(os.fstat(handle.fileno()))
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            self._assert_safe_path(path, label)
            return identity
        except BaseException:
            if identity is not None:
                self._unlink_owned_temp(path, identity)
            raise

    def _unlink_owned_temp(self, path: Path, identity: tuple[int, int]) -> None:
        """Remove a temp only while its directory entry still names our inode."""
        try:
            self._assert_safe_path(path, "temp_cleanup")
            current = os.lstat(path)
            if _file_identity(current) == identity:
                path.unlink()
        except (FileNotFoundError, JournalCorruption, OSError):
            # A replaced/reparse entry is not ours to remove; leave it for review.
            return

    @classmethod
    def open(cls, case_dir: Path, *, max_event_bytes: int = 1_048_576) -> "EvidenceJournal":
        return cls(case_dir, max_event_bytes=max_event_bytes)

    def append(self, kind: str, payload: Mapping[str, Any], parents: Sequence[str] = ()) -> JournalEntry:
        if not isinstance(kind, str) or not kind or not isinstance(payload, Mapping):
            raise JournalCorruption("journal_event_invalid")
        parent_tuple = tuple(parents)
        if any(not isinstance(parent, str) or len(parent) != 64 or any(ch not in "0123456789abcdef" for ch in parent) for parent in parent_tuple):
            raise JournalCorruption("journal_parent_invalid")
        # The local lock protects threaded callers; the create-only RunLock serializes processes.
        with self._mutex:
            with self._writer_lock():
                self._assert_head_temp_available()
                verification = self._scan(allow_truncated_tail=False, check_head=True)
                sequence = verification.entries + 1
                previous = verification.head_hash
                unsigned: dict[str, Any] = {
                    "schema": self.SCHEMA, "sequence": sequence, "kind": kind,
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                    "previous_hash": previous, "parents": list(parent_tuple), "payload": dict(payload),
                }
                encoded_unsigned = canonical_json(unsigned)
                if len(encoded_unsigned) > self.max_event_bytes:
                    raise JournalCorruption("journal_event_budget_exceeded")
                entry_hash = hashlib.sha256(encoded_unsigned).hexdigest()
                row = {**unsigned, "entry_hash": entry_hash}
                encoded = canonical_json(row)
                if len(encoded) > self.max_event_bytes:
                    raise JournalCorruption("journal_event_budget_exceeded")
                with self.path.open("ab") as handle:
                    handle.write(encoded + b"\n")
                    handle.flush(); os.fsync(handle.fileno())
                self._write_head(sequence, entry_hash)
                return JournalEntry(self.SCHEMA, sequence, kind, unsigned["recorded_at"], previous, parent_tuple, dict(payload), entry_hash)

    def _write_head(self, entries: int, head_hash: str) -> None:
        value = {"schema": "evidence-journal-head.v1", "entries": entries, "head_hash": head_hash}
        temporary = self._head_temp_path
        self._assert_safe_storage()
        identity = self._write_temp_exclusive(temporary, canonical_json(value) + b"\n", "head_temp")
        try:
            self._assert_safe_path(self.head_path, "head")
            os.replace(temporary, self.head_path)
            identity = None
        finally:
            if identity is not None:
                self._unlink_owned_temp(temporary, identity)

    def verify(self) -> JournalVerification:
        with self._mutex:
            return self._scan(allow_truncated_tail=False, check_head=True)

    def _scan(self, *, allow_truncated_tail: bool, check_head: bool) -> JournalVerification:
        self._assert_safe_storage()
        if not self.path.exists():
            if self.head_path.exists():
                raise JournalCorruption("journal_head_mismatch")
            return JournalVerification("pass", 0, _HASH)
        raw = self.path.read_bytes()
        verification = self._scan_raw(raw, allow_truncated_tail=allow_truncated_tail)
        if check_head and self.head_path.exists():
            self._check_head(verification.entries, verification.head_hash)
        return verification

    def _scan_raw(self, raw: bytes, *, allow_truncated_tail: bool) -> JournalVerification:
        if not raw:
            return JournalVerification("pass", 0, _HASH)
        lines = raw.splitlines(keepends=True)
        if not raw.endswith(b"\n"):
            if not allow_truncated_tail:
                raise JournalCorruption("journal_truncated_tail")
            lines = lines[:-1]
        previous = _HASH
        count = 0
        for number, chunk in enumerate(lines, 1):
            if not chunk.endswith(b"\n"):
                raise JournalCorruption("journal_truncated_tail")
            try:
                value = json.loads(chunk, object_pairs_hook=_unique_object)
            except _DuplicateJSONKeyError as exc:
                raise JournalCorruption("journal_json_duplicate_key") from exc
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                raise JournalCorruption("journal_json_invalid") from exc
            if not isinstance(value, dict) or set(value) != {"schema","sequence","kind","recorded_at","previous_hash","parents","payload","entry_hash"}:
                raise JournalCorruption("journal_schema_invalid")
            if value.get("schema") != self.SCHEMA or value.get("sequence") != number:
                raise JournalCorruption("journal_sequence_invalid")
            if not isinstance(value.get("kind"), str) or not value["kind"] or not isinstance(value.get("payload"), dict):
                raise JournalCorruption("journal_event_invalid")
            if value.get("previous_hash") != previous or not isinstance(value.get("entry_hash"), str):
                raise JournalCorruption("journal_chain_invalid")
            parents=value.get("parents")
            if not isinstance(parents,list) or any(not isinstance(p,str) or len(p)!=64 or any(c not in '0123456789abcdef' for c in p) for p in parents):
                raise JournalCorruption("journal_parent_invalid")
            unsigned={key:value[key] for key in value if key != "entry_hash"}
            try:
                expected=sha256_canonical(unsigned)
            except Exception as exc:
                raise JournalCorruption("journal_entry_invalid") from exc
            if value["entry_hash"] != expected:
                raise JournalCorruption("entry_hash_mismatch")
            previous=value["entry_hash"]; count=number
        return JournalVerification("pass", count, previous)

    def _check_head(self, entries: int, head_hash: str) -> None:
        self._assert_safe_path(self.head_path, "head")
        try:
            head=json.loads(self.head_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        except _DuplicateJSONKeyError as exc:
            raise JournalCorruption("journal_head_duplicate_key") from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise JournalCorruption("journal_head_invalid") from exc
        if head != {"schema":"evidence-journal-head.v1","entries":entries,"head_hash":head_hash}:
            raise JournalCorruption("journal_head_mismatch")

    def recover_interrupted_tail(self) -> JournalVerification:
        with self._mutex:
            with self._writer_lock():
                # Re-read only after the interprocess writer lock is held. The
                # state may have changed between a caller's earlier observation
                # and this exclusive recovery transaction.
                self._assert_head_temp_available()
                self._assert_safe_storage()
                raw = self.path.read_bytes() if self.path.exists() else b""
                if not raw or raw.endswith(b"\n"):
                    return self._scan(allow_truncated_tail=False, check_head=True)

                # First prove all complete interior records; no interior corruption is recoverable.
                last = raw.rfind(b"\n")
                complete = raw[:last + 1] if last >= 0 else b""
                tail = raw[last + 1:] if last >= 0 else raw
                checked = self._scan_raw(complete, allow_truncated_tail=False)
                digest = hashlib.sha256(tail).hexdigest()
                quarantine = self.case_dir / f"journal.tail.{digest}.quarantine"
                temporary = self.case_dir / f".journal.recovery.{digest}.tmp"
                restore = self.case_dir / f".journal.rollback.{digest}.tmp"
                head_restore = self.case_dir / f".journal.head.rollback.{digest}.tmp"
                old_head = self.head_path.read_bytes() if self.head_path.exists() else None

                # Validate every path used by the recovery transaction before
                # creating the quarantine record or replacing any live file.
                self._assert_safe_path(quarantine, "quarantine")
                self._assert_safe_path(temporary, "recovery_temp")
                self._assert_safe_path(restore, "rollback_temp")
                if old_head is not None:
                    self._assert_safe_path(head_restore, "head_rollback_temp")
                if temporary.exists() or restore.exists() or (old_head is not None and head_restore.exists()):
                    raise JournalCorruption("journal_recovery_temp_exists")

                # Preserve the incomplete tail durably before publishing the
                # verified complete prefix. Existing quarantine is accepted only
                # after its path has passed link checks and its bytes match.
                try:
                    with quarantine.open("xb") as handle:
                        handle.write(tail)
                        handle.flush()
                        os.fsync(handle.fileno())
                except FileExistsError:
                    self._assert_safe_path(quarantine, "quarantine")
                    if quarantine.read_bytes() != tail:
                        raise JournalCorruption("journal_quarantine_collision")

                temporary_identity = self._write_temp_exclusive(temporary, complete, "recovery_temp")
                try:
                    self._assert_safe_path(self.path, "journal")
                    os.replace(temporary, self.path)
                    temporary_identity = None
                    try:
                        self._write_head(checked.entries, checked.head_hash)
                    except BaseException:
                        # A normal exception after the journal replace must restore
                        # the pre-recovery pair. The tail is already quarantined.
                        restore_identity = self._write_temp_exclusive(restore, raw, "rollback_temp")
                        try:
                            os.replace(restore, self.path)
                            restore_identity = None
                            if old_head is None:
                                self._assert_safe_path(self.head_path, "head")
                                self.head_path.unlink(missing_ok=True)
                            else:
                                head_restore_identity = self._write_temp_exclusive(
                                    head_restore, old_head, "head_rollback_temp"
                                )
                                try:
                                    self._assert_safe_path(self.head_path, "head")
                                    os.replace(head_restore, self.head_path)
                                    head_restore_identity = None
                                finally:
                                    if head_restore_identity is not None:
                                        self._unlink_owned_temp(head_restore, head_restore_identity)
                        finally:
                            if restore_identity is not None:
                                self._unlink_owned_temp(restore, restore_identity)
                        raise
                finally:
                    if temporary_identity is not None:
                        self._unlink_owned_temp(temporary, temporary_identity)
                return JournalVerification("recovered_tail", checked.entries, checked.head_hash, quarantine)
