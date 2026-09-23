"""Create-only content addressed evidence storage."""
from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import asdict
from pathlib import Path

from .evidence import _path_has_link, sha256_file, sha256_file_bounded
from .kernel_contracts import ArtifactRef, AuthorizationPolicy, sha256_canonical


class PublicationError(RuntimeError):
    pass


def _fsync_file(handle: object) -> None:
    os.fsync(handle.fileno())  # type: ignore[attr-defined]


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class EvidenceStore:
    """A content-addressed store which never replaces an existing object."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.objects = self.root / "objects" / "sha256"

    def _copy_fsync_bounded(self, source: Path, max_bytes: int) -> tuple[Path, int, str]:
        self.objects.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".publish-", suffix=".tmp", dir=self.objects)
        temporary = Path(name)
        digest = hashlib.sha256()
        copied = 0
        try:
            with os.fdopen(fd, "wb") as writer, source.open("rb") as reader:
                while True:
                    chunk = reader.read(min(1024 * 1024, max_bytes - copied + 1))
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > max_bytes:
                        raise PublicationError("source_size_budget_exceeded")
                    writer.write(chunk)
                    digest.update(chunk)
                writer.flush()
                _fsync_file(writer)
            return temporary, copied, digest.hexdigest()
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def publish_file(self, source: Path, *, media_type: str, origin: str,
                     authorization: AuthorizationPolicy, max_bytes: int) -> ArtifactRef:
        if not authorization.allows("static-analysis"):
            raise PublicationError("operation_not_authorized")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise PublicationError("source_size_budget_exceeded")
        source = Path(source)
        try:
            if _path_has_link(source) or not source.is_file():
                raise PublicationError("source_must_be_regular_file")
            before = sha256_file_bounded(source, max_bytes)
            temporary, copied, observed = self._copy_fsync_bounded(source, max_bytes)
        except ValueError as exc:
            raise PublicationError(str(exc)) from exc
        try:
            try:
                after = sha256_file_bounded(source, max_bytes)
            except ValueError as exc:
                raise PublicationError(str(exc)) from exc
            if observed != before or after != before:
                raise PublicationError("source_changed_during_publication")
            final = self.objects / before[:2] / before
            final.parent.mkdir(parents=True, exist_ok=True)
            if _path_has_link(final.parent):
                raise PublicationError("object_path_escape")
            try:
                os.link(temporary, final)
                _fsync_directory(final.parent)
            except FileExistsError:
                try:
                    if final.is_symlink() or final.stat().st_size != copied or sha256_file(final) != before:
                        raise PublicationError("object_collision_or_corruption")
                except OSError as exc:
                    raise PublicationError("object_collision_or_corruption") from exc
            return ArtifactRef(
                "artifact-ref.v1", f"sha256:{before}", before, copied,
                media_type, final.relative_to(self.root).as_posix(), origin,
                sha256_canonical(asdict(authorization)),
            )
        finally:
            temporary.unlink(missing_ok=True)

    def resolve(self, ref: ArtifactRef) -> Path:
        try:
            expected = self.root / ref.object_path
            resolved = expected.resolve(strict=False)
            root = self.root.resolve()
            if (resolved != root and root not in resolved.parents) or expected.is_symlink():
                raise PublicationError("object_path_escape")
            if resolved.name != ref.sha256 or resolved.parent.name != ref.sha256[:2]:
                raise PublicationError("object_path_escape")
            return resolved
        except (OSError, ValueError) as exc:
            if isinstance(exc, PublicationError):
                raise
            raise PublicationError("object_path_escape") from exc

    def verify(self, ref: ArtifactRef) -> None:
        path = self.resolve(ref)
        try:
            if not path.is_file() or path.is_symlink() or path.stat().st_size != ref.size or sha256_file(path) != ref.sha256:
                raise PublicationError("object_integrity_mismatch")
        except OSError as exc:
            raise PublicationError("object_integrity_mismatch") from exc