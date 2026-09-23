"""Authorized bounded universal intake and local replay verification."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from .archive_intake import ArchiveRejected, detect_archive_kind, extract_archive_bounded
from .custody import create_custody_receipt
from .evidence_journal import EvidenceJournal, JournalVerification
from .evidence_store import EvidenceStore, PublicationError
from .kernel_contracts import ArtifactRef, AuthorizationPolicy, IntakeLimits, canonical_json, sha256_canonical
from .safe_walk import WalkEntry, inventory_tree_bounded


class IntakeRejected(RuntimeError):
    pass

@dataclass(frozen=True)
class IntakeRequest:
    source: Path
    case_dir: Path
    authorization: AuthorizationPolicy
    limits: IntakeLimits
    expand_archives: bool = True
    cancel_check: Callable[[], bool] | None = None

@dataclass(frozen=True)
class IntakeResult:
    case_id: str
    source_kind: str
    root_artifact: ArtifactRef
    artifacts: tuple[ArtifactRef, ...]
    inventory: tuple[dict[str, Any], ...]
    manifest_path: Path
    journal_path: Path
    profile_decision_hash: str = ""

@dataclass(frozen=True)
class CaseVerification:
    status: str
    case_id: str
    journal_verification: JournalVerification
    issues: tuple[str, ...] = ()

@dataclass(frozen=True)
class ReplayReport:
    status: str
    root_sha256: str
    profile_decision_hash: str
    journal_verification: JournalVerification
    issues: tuple[str, ...] = ()


def _regular_nonlink(path: Path) -> bool:
    try:
        st=path.lstat()
        return stat.S_ISREG(st.st_mode) and not path.is_symlink() and not (hasattr(path,"is_junction") and path.is_junction())
    except OSError: return False

def _media_type(path: Path) -> str:
    header=path.open("rb").read(8)
    if header.startswith(b"MZ"): return "application/vnd.microsoft.portable-executable"
    if header.startswith(b"\x7fELF"): return "application/x-elf"
    if header.startswith(b"\0asm"): return "application/wasm"
    if detect_archive_kind(path): return "application/archive"
    return "application/octet-stream"

def _new_atomic_json(value: dict[str,Any], path: Path) -> None:
    if path.exists() or path.is_symlink(): raise IntakeRejected("manifest_destination_exists")
    fd,name=tempfile.mkstemp(prefix=".manifest-",suffix=".tmp",dir=path.parent); temp=Path(name)
    try:
        with os.fdopen(fd,"wb") as handle:
            handle.write(canonical_json(value)+b"\n"); handle.flush(); os.fsync(handle.fileno())
        os.link(temp,path)
    finally: temp.unlink(missing_ok=True)

def _inside(child: Path, parent: Path) -> bool:
    try: child.resolve().relative_to(parent.resolve()); return True
    except ValueError: return False

class IntakeTransaction:
    def __init__(self, request: IntakeRequest):
        self.request=request; self.source=Path(request.source); self.case_dir=Path(request.case_dir)
        self.journal: EvidenceJournal | None=None; self.store: EvidenceStore | None=None
        self.source_kind=""; self.entries: list[WalkEntry]=[]; self.inventory: list[dict[str,Any]]=[]; self.artifacts: list[ArtifactRef]=[]; self.root: ArtifactRef | None=None
        self.admitted_bytes = 0

    @classmethod
    def create(cls, request: IntakeRequest) -> "IntakeTransaction":
        if not isinstance(request.authorization,AuthorizationPolicy) or not request.authorization.allows("static-analysis"):
            raise IntakeRejected("operation_not_authorized")
        if not isinstance(request.limits,IntakeLimits): raise IntakeRejected("intake_limits_invalid")
        transaction=cls(request)
        if transaction.case_dir.exists() or transaction.case_dir.is_symlink(): raise IntakeRejected("case_destination_exists")
        if _inside(transaction.source,transaction.case_dir) or _inside(transaction.case_dir,transaction.source): raise IntakeRejected("source_destination_overlap")
        try: transaction.case_dir.mkdir(parents=True,exist_ok=False)
        except OSError as exc: raise IntakeRejected("case_destination_create_failed") from exc
        transaction.journal=EvidenceJournal.open(transaction.case_dir)
        transaction.store=EvidenceStore(transaction.case_dir)
        transaction.journal.append("case.opened",{"authorization_sha256":sha256_canonical(request.authorization.to_dict())})
        return transaction

    def _cancel(self) -> None:
        if self.request.cancel_check is not None and self.request.cancel_check(): raise IntakeRejected("intake_cancelled")

    def preflight(self) -> None:
        self._cancel()
        if self.source.is_symlink() or (hasattr(self.source,"is_junction") and self.source.is_junction()): raise IntakeRejected("intake_link_forbidden")
        if _regular_nonlink(self.source):
            try:
                size=self.source.stat().st_size
                if size>self.request.limits.max_file_bytes: raise IntakeRejected("intake_file_budget_exceeded")
                if size>self.request.limits.max_total_bytes: raise IntakeRejected("intake_total_bytes_exceeded")
            except OSError as exc: raise IntakeRejected("intake_source_invalid") from exc
            self.source_kind="archive" if detect_archive_kind(self.source) else "file"
            self.entries=[WalkEntry(self.source,self.source.name,"file")]
            return
        try: st=self.source.lstat()
        except OSError as exc: raise IntakeRejected("intake_source_invalid") from exc
        if not stat.S_ISDIR(st.st_mode): raise IntakeRejected("intake_source_invalid")
        self.source_kind="directory"
        try:
            self.entries=inventory_tree_bounded(self.source,max_files=self.request.limits.max_files,max_total_bytes=self.request.limits.max_total_bytes,max_file_bytes=self.request.limits.max_file_bytes,max_path_length=self.request.limits.max_path_length)
        except ValueError as exc: raise IntakeRejected(str(exc)) from exc

    def _publish(self,path:Path,relative:str, *, include_inventory: bool = True) -> ArtifactRef:
        self._cancel(); assert self.store is not None
        try:
            candidate_size = path.stat().st_size
        except OSError as exc:
            raise IntakeRejected("intake_source_invalid") from exc
        if include_inventory and self.admitted_bytes + candidate_size > self.request.limits.max_total_bytes:
            raise IntakeRejected("intake_total_bytes_exceeded")
        try: ref=self.store.publish_file(path,media_type=_media_type(path),origin=relative,authorization=self.request.authorization,max_bytes=self.request.limits.max_file_bytes)
        except PublicationError as exc: raise IntakeRejected(str(exc)) from exc
        if ref.size != candidate_size:
            raise IntakeRejected("source_changed_during_publication")
        self._cancel(); self.store.verify(ref); assert self.journal is not None
        self.journal.append("artifact.published",{"artifact":ref.to_dict()})
        self.artifacts.append(ref)
        if include_inventory:
            self.admitted_bytes += ref.size
            self.inventory.append({"relative_path":relative,"artifact_id":ref.artifact_id,"sha256":ref.sha256,"size":ref.size,"media_type":ref.media_type})
        return ref

    def publish_inventory(self) -> None:
        if self.source_kind in {"file","archive"}:
            self.root=self._publish(self.source,self.source.name)
            if self.source_kind=="archive" and self.request.expand_archives:
                assert self.store is not None
                stage=self.case_dir/"archive-staging"
                try:
                    members=extract_archive_bounded(self.store.resolve(self.root),stage,limits=self.request.limits)
                except ArchiveRejected as exc: raise IntakeRejected(str(exc)) from exc
                for member in members:
                    actual=stage / Path(*member.relative_path.split("/"))
                    self._publish(actual,f"archive/{member.relative_path}")
            return
        for entry in self.entries: self._publish(entry.path,entry.relative_path)
        descriptor={"schema":"directory-root.v1","inventory":sorted(self.inventory,key=lambda x:x["relative_path"])}
        descriptor_path=self.case_dir/".directory-root.json"
        descriptor_path.write_bytes(canonical_json(descriptor))
        try: self.root=self._publish(descriptor_path,"directory-root.json", include_inventory=False)
        finally: descriptor_path.unlink(missing_ok=True)

    def commit(self) -> IntakeResult:
        assert self.root is not None and self.journal is not None and self.store is not None
        identity={"authorization":self.request.authorization.to_dict(),"root_sha256":self.root.sha256,"inventory":sorted(self.inventory,key=lambda x:x["relative_path"])}
        case_id="case-"+sha256_canonical(identity)[:24]
        manifest={"schema":"universal-intake-manifest.v1","case_id":case_id,"source_kind":self.source_kind,"authorization":self.request.authorization.to_dict(),"authorization_sha256":sha256_canonical(self.request.authorization.to_dict()),"limits":self.request.limits.to_dict(),"root_artifact":self.root.to_dict(),"artifacts":[ref.to_dict() for ref in self.artifacts],"inventory":sorted(self.inventory,key=lambda x:x["relative_path"]),"journal":"journal.jsonl","custody":{"external_anchor":False,"mode":"local_detached_hash_chain"},"limitations":["local hash-chain integrity is not WORM, notarization, semantic truth, or proof of lawful acquisition"]}
        manifest_path=self.case_dir/"manifest.json"; _new_atomic_json(manifest,manifest_path)
        manifest_hash=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        self.journal.append("case.intake_completed",{"case_id":case_id,"manifest_sha256":manifest_hash},parents=())
        receipt=create_custody_receipt({"manifest":manifest_path,"journal":self.journal.path},self.case_dir/"custody-receipt.json",metadata={"case_id":case_id})
        if receipt.get("status") != "created": raise IntakeRejected("custody_receipt_failed")
        return IntakeResult(case_id,self.source_kind,self.root,tuple(self.artifacts),tuple(manifest["inventory"]),manifest_path,self.journal.path)

    def record_failure(self, exc: BaseException) -> None:
        if self.journal is None: return
        try: self.journal.append("case.intake_failed",{"error":_safe_error(exc)})
        except BaseException: pass

def _safe_error(exc: BaseException) -> str:
    value=str(exc); return value if value and len(value)<=128 and all(ord(c)>=32 for c in value) else type(exc).__name__

def prepare_case(request: IntakeRequest) -> IntakeResult:
    transaction: IntakeTransaction | None=None
    try:
        transaction=IntakeTransaction.create(request); transaction.preflight(); transaction.publish_inventory(); return transaction.commit()
    except BaseException as exc:
        if transaction is not None: transaction.record_failure(exc)
        if isinstance(exc,IntakeRejected): raise
        raise IntakeRejected(_safe_error(exc)) from exc

def verify_case(case_dir: Path) -> CaseVerification:
    case_dir=Path(case_dir)
    issues=[]; manifest_path=case_dir/"manifest.json"; case_id=""
    try:
        manifest=json.loads(manifest_path.read_text(encoding="utf-8")); case_id=manifest.get("case_id","")
        if not isinstance(manifest,dict) or manifest.get("schema")!="universal-intake-manifest.v1": raise ValueError("manifest_schema_invalid")
        store=EvidenceStore(case_dir)
        refs=[ArtifactRef.from_dict(item) for item in manifest.get("artifacts",[])]
        root=ArtifactRef.from_dict(manifest["root_artifact"])
        if root.artifact_id not in {r.artifact_id for r in refs}: refs.append(root)
        for ref in refs: store.verify(ref)
    except Exception as exc: issues.append(_safe_error(exc))
    try: report=EvidenceJournal.open(case_dir).verify()
    except Exception as exc:
        issues.append(_safe_error(exc)); report=JournalVerification("fail",0,"0"*64)
    return CaseVerification("pass" if not issues and report.status=="pass" else "fail",case_id,report,tuple(issues))

def replay_case(manifest_path: Path, destination: Path) -> ReplayReport:
    manifest_path=Path(manifest_path); source_case=manifest_path.parent
    verification=verify_case(source_case)
    if verification.status != "pass": return ReplayReport("fail","","",verification,verification.issues)
    manifest=json.loads(manifest_path.read_text(encoding="utf-8")); root=ArtifactRef.from_dict(manifest["root_artifact"])
    source=EvidenceStore(source_case).resolve(root)
    result=prepare_case(IntakeRequest(source,Path(destination),AuthorizationPolicy.from_dict(manifest["authorization"]),IntakeLimits.from_dict(manifest["limits"]),False))
    decision_hash=""
    try:
        from .profile_router import route_case
        decision=route_case(result,EvidenceStore(result.manifest_path.parent)); decision_hash=sha256_canonical(decision.to_dict())
        expected=manifest.get("profile_decision_hash","")
        if expected and expected != decision_hash: return ReplayReport("fail",result.root_artifact.sha256,decision_hash,EvidenceJournal.open(result.manifest_path.parent).verify(),("profile_decision_mismatch",))
    except Exception as exc: return ReplayReport("fail",result.root_artifact.sha256,"",EvidenceJournal.open(result.manifest_path.parent).verify(),(_safe_error(exc),))
    return ReplayReport("pass",result.root_artifact.sha256,decision_hash,EvidenceJournal.open(result.manifest_path.parent).verify())
