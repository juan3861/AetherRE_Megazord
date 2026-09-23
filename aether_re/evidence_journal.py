"""Durable hash-chained JSONL journal for the evidence kernel."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .kernel_contracts import canonical_json, sha256_canonical
from .lock import RunLock, RunLockError

_HASH = "0" * 64

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
        self.case_dir = Path(case_dir).resolve()
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.case_dir / "journal.jsonl"
        self.head_path = self.case_dir / "journal.head.json"
        self.max_event_bytes = max_event_bytes
        with self._mutexes_guard:
            self._mutex = self._mutexes.setdefault(str(self.path), threading.RLock())

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
            try:
                with RunLock(self.case_dir / "journal.writer.lock"):
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
            except RunLockError as exc:
                raise JournalCorruption("journal_writer_locked") from exc

    def _write_head(self, entries: int, head_hash: str) -> None:
        value = {"schema": "evidence-journal-head.v1", "entries": entries, "head_hash": head_hash}
        temporary = self.head_path.with_suffix(".json.tmp")
        if temporary.exists():
            temporary.unlink()
        with temporary.open("wb") as handle:
            handle.write(canonical_json(value) + b"\n")
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, self.head_path)

    def verify(self) -> JournalVerification:
        with self._mutex:
            return self._scan(allow_truncated_tail=False, check_head=True)

    def _scan(self, *, allow_truncated_tail: bool, check_head: bool) -> JournalVerification:
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
                value = json.loads(chunk)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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
        try:
            head=json.loads(self.head_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JournalCorruption("journal_head_invalid") from exc
        if head != {"schema":"evidence-journal-head.v1","entries":entries,"head_hash":head_hash}:
            raise JournalCorruption("journal_head_mismatch")

    def recover_interrupted_tail(self) -> JournalVerification:
        with self._mutex:
            raw=self.path.read_bytes() if self.path.exists() else b""
            if not raw or raw.endswith(b"\n"):
                return self._scan(allow_truncated_tail=False, check_head=True)
            # First prove all complete interior records; no interior corruption is recoverable.
            last=raw.rfind(b"\n")
            complete=raw[:last+1] if last >= 0 else b""
            tail=raw[last+1:] if last >= 0 else raw
            checked=self._scan_raw(complete, allow_truncated_tail=False)
            digest=hashlib.sha256(tail).hexdigest()
            quarantine=self.case_dir / f"journal.tail.{digest}.quarantine"
            try:
                with quarantine.open("xb") as handle:
                    handle.write(tail); handle.flush(); os.fsync(handle.fileno())
            except FileExistsError:
                if quarantine.read_bytes()!=tail:
                    raise JournalCorruption("journal_quarantine_collision")

            # Do not truncate the live journal in place.  The incomplete tail is
            # durable in quarantine before a create-and-replace commit publishes
            # the verified complete prefix.
            temporary = self.case_dir / f".journal.recovery.{digest}.tmp"
            old_head = self.head_path.read_bytes() if self.head_path.exists() else None
            try:
                with temporary.open("xb") as handle:
                    handle.write(complete); handle.flush(); os.fsync(handle.fileno())
                os.replace(temporary, self.path)
                try:
                    self._write_head(checked.entries, checked.head_hash)
                except BaseException:
                    # A normal exception after the journal replace must restore
                    # the pre-recovery pair.  Abrupt process death still retains
                    # the tail in the already-fsynced quarantine file.
                    restore = self.case_dir / f".journal.rollback.{digest}.tmp"
                    try:
                        with restore.open("xb") as handle:
                            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
                        os.replace(restore, self.path)
                        if old_head is None:
                            self.head_path.unlink(missing_ok=True)
                        else:
                            head_restore = self.case_dir / f".journal.head.rollback.{digest}.tmp"
                            try:
                                with head_restore.open("xb") as handle:
                                    handle.write(old_head); handle.flush(); os.fsync(handle.fileno())
                                os.replace(head_restore, self.head_path)
                            finally:
                                head_restore.unlink(missing_ok=True)
                    finally:
                        restore.unlink(missing_ok=True)
                    raise
            finally:
                temporary.unlink(missing_ok=True)
            return JournalVerification("recovered_tail", checked.entries, checked.head_hash, quarantine)
