"""Strict, versioned value contracts shared by the Evidence Kernel and adapters."""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """Raised when untrusted contract input is not admitted by a schema."""


class EpistemicState(str, Enum):
    EXACT = "EXACT"
    VERIFIED_RECONSTRUCTION = "VERIFIED_RECONSTRUCTION"
    PROBABILISTIC_INFERENCE = "PROBABILISTIC_INFERENCE"
    HYPOTHESIS = "HYPOTHESIS"
    UNKNOWN = "UNKNOWN"


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Encode a mapping deterministically, rejecting non-finite JSON values."""
    if not isinstance(value, Mapping):
        raise ContractError("canonical_json_invalid")
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContractError("canonical_json_invalid") from exc


def sha256_canonical(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_tuple(value: Any, *, error: str, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or (not allow_empty and not value):
        raise ContractError(error)
    if any(not _nonempty_string(item) for item in value):
        raise ContractError(error)
    normalized = tuple(item.strip() for item in value)
    if len(normalized) != len(set(normalized)):
        raise ContractError(error)
    return normalized


@dataclass(frozen=True)
class AuthorizationPolicy:
    """Authorization is explicit; absence or ambiguity grants no operation."""

    schema: str
    basis: str
    principal: str
    scope: tuple[str, ...]
    case_owner: str | None = None
    allow_static: bool = False
    allow_dynamic: bool = False

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorizationPolicy":
        if not isinstance(value, Mapping):
            raise ContractError("authorization_schema_invalid")
        canonical_fields = {"schema", "basis", "principal", "scope"}
        legacy_fields = {"case_owner", "allow_static", "allow_dynamic"}
        keys = set(value)
        if keys == canonical_fields:
            if value.get("schema") != "authorization-policy.v1":
                raise ContractError("authorization_schema_invalid")
            basis = value.get("basis")
            principal = value.get("principal")
            if basis not in {"owner", "license", "written-permission", "public-authorized"}:
                raise ContractError("authorization_basis_invalid")
            if not _nonempty_string(principal):
                raise ContractError("authorization_principal_invalid")
            scope = _string_tuple(value.get("scope"), error="authorization_scope_invalid", allow_empty=False)
            return cls(
                schema="authorization-policy.v1",
                basis=basis,
                principal=principal.strip(),
                scope=scope,
                case_owner=principal.strip() if basis == "owner" else None,
                allow_static="static-analysis" in scope,
                allow_dynamic="dynamic-execution" in scope,
            )
        if keys == legacy_fields:
            owner = value.get("case_owner")
            allow_static = value.get("allow_static")
            allow_dynamic = value.get("allow_dynamic")
            if not _nonempty_string(owner):
                raise ContractError("authorization_principal_invalid")
            if not isinstance(allow_static, bool) or not isinstance(allow_dynamic, bool):
                raise ContractError("authorization_scope_invalid")
            if not allow_static and not allow_dynamic:
                raise ContractError("authorization_scope_invalid")
            scope = tuple(
                operation
                for enabled, operation in (
                    (allow_static, "static-analysis"),
                    (allow_dynamic, "dynamic-execution"),
                )
                if enabled
            )
            return cls(
                schema="authorization-policy.v1",
                basis="owner",
                principal=owner.strip(),
                scope=scope,
                case_owner=owner.strip(),
                allow_static=allow_static,
                allow_dynamic=allow_dynamic,
            )
        raise ContractError("authorization_schema_invalid")

    def allows(self, operation: str) -> bool:
        return isinstance(operation, str) and operation in self.scope

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "basis": self.basis,
            "principal": self.principal,
            "scope": list(self.scope),
        }


@dataclass(frozen=True)
class IntakeLimits:
    max_files: int = 10_000
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_file_bytes: int = 512 * 1024 * 1024
    max_archive_depth: int = 3
    max_compression_ratio: int = 200
    max_path_length: int = 512

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IntakeLimits":
        if not isinstance(value, Mapping):
            raise ContractError("intake_limits_unknown_field")
        defaults = asdict(cls())
        unknown = set(value) - set(defaults)
        if unknown:
            raise ContractError("intake_limits_unknown_field")
        merged = {**defaults, **dict(value)}
        for name, limit in merged.items():
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
                raise ContractError(f"intake_limit_invalid:{name}")
        return cls(**merged)

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class ArtifactRef:
    schema: str
    artifact_id: str
    sha256: str
    size: int
    media_type: str
    object_path: str
    origin: str
    authorization_sha256: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactRef":
        required = {
            "schema", "artifact_id", "sha256", "size", "media_type",
            "object_path", "origin", "authorization_sha256",
        }
        if not isinstance(value, Mapping) or set(value) != required or value.get("schema") != "artifact-ref.v1":
            raise ContractError("artifact_schema_invalid")
        digest = value.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or value.get("artifact_id") != f"sha256:{digest}":
            raise ContractError("artifact_hash_invalid")
        if isinstance(value.get("size"), bool) or not isinstance(value.get("size"), int) or value["size"] < 0:
            raise ContractError("artifact_size_invalid")
        if not _nonempty_string(value.get("media_type")) or not _nonempty_string(value.get("origin")):
            raise ContractError("artifact_metadata_invalid")
        object_path = value.get("object_path")
        if (
            not _nonempty_string(object_path)
            or "\\" in object_path
            or object_path.startswith("/")
            or any(part in {"", ".", ".."} for part in object_path.split("/"))
        ):
            raise ContractError("artifact_path_invalid")
        authorization_sha256 = value.get("authorization_sha256")
        if not isinstance(authorization_sha256, str) or not SHA256_RE.fullmatch(authorization_sha256):
            raise ContractError("authorization_hash_invalid")
        return cls(**dict(value))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DerivationRecord:
    schema: str
    derivation_id: str
    artifact_id: str
    epistemic_state: EpistemicState
    confidence: float | None
    parents: tuple[str, ...]
    losses: tuple[str, ...] = field(default_factory=tuple)
    product: ArtifactRef | None = None
    producer: Mapping[str, str] = field(default_factory=dict)
    method: str = ""
    limitations: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DerivationRecord":
        if not isinstance(value, Mapping):
            raise ContractError("derivation_schema_invalid")
        if value.get("schema") == "derivation-record.v1":
            return cls._from_v1(value)
        compact_fields = {"derivation_id", "artifact_id", "epistemic_state", "confidence", "parents", "losses"}
        if set(value) == compact_fields:
            return cls._from_compact(value)
        raise ContractError("derivation_schema_invalid")

    @classmethod
    def _from_v1(cls, value: Mapping[str, Any]) -> "DerivationRecord":
        required = {
            "schema", "derivation_id", "product", "parents", "producer", "method",
            "epistemic_state", "confidence", "limitations",
        }
        if set(value) != required:
            raise ContractError("derivation_schema_invalid")
        product = ArtifactRef.from_dict(value.get("product"))
        producer = value.get("producer")
        if not isinstance(producer, Mapping) or set(producer) != {"name", "version"} or any(not _nonempty_string(item) for item in producer.values()):
            raise ContractError("derivation_producer_invalid")
        return cls._validated(
            schema="derivation-record.v1",
            derivation_id=value.get("derivation_id"),
            artifact_id=product.artifact_id,
            product=product,
            producer=MappingProxyType({key: item.strip() for key, item in producer.items()}),
            method=value.get("method"),
            state_value=value.get("epistemic_state"),
            confidence=value.get("confidence"),
            parents=value.get("parents"),
            losses=(),
            limitations=value.get("limitations"),
        )

    @classmethod
    def _from_compact(cls, value: Mapping[str, Any]) -> "DerivationRecord":
        return cls._validated(
            schema="derivation-record.compact.v1",
            derivation_id=value.get("derivation_id"),
            artifact_id=value.get("artifact_id"),
            product=None,
            producer=MappingProxyType({}),
            method="",
            state_value=value.get("epistemic_state"),
            confidence=value.get("confidence"),
            parents=value.get("parents"),
            losses=value.get("losses"),
            limitations=(),
        )

    @classmethod
    def _validated(
        cls,
        *,
        schema: str,
        derivation_id: Any,
        artifact_id: Any,
        product: ArtifactRef | None,
        producer: Mapping[str, str],
        method: Any,
        state_value: Any,
        confidence: Any,
        parents: Any,
        losses: Any,
        limitations: Any,
    ) -> "DerivationRecord":
        if not _nonempty_string(derivation_id) or not _nonempty_string(artifact_id):
            raise ContractError("derivation_identity_invalid")
        if product is not None and not _nonempty_string(method):
            raise ContractError("derivation_method_invalid")
        try:
            state = EpistemicState(state_value)
        except (TypeError, ValueError) as exc:
            raise ContractError("epistemic_state_invalid") from exc
        parent_values = _string_tuple(parents, error="derivation_parents_invalid")
        if state not in {EpistemicState.EXACT, EpistemicState.UNKNOWN} and not parent_values:
            raise ContractError("parents_required")
        if state is EpistemicState.PROBABILISTIC_INFERENCE:
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not math.isfinite(confidence)
                or not 0.0 <= confidence <= 1.0
            ):
                raise ContractError("confidence_invalid")
            normalized_confidence: float | None = float(confidence)
        else:
            if confidence is not None:
                raise ContractError("confidence_forbidden")
            normalized_confidence = None
        loss_values = _string_tuple(losses, error="derivation_losses_invalid")
        limitation_values = _string_tuple(limitations, error="derivation_limitations_invalid")
        return cls(
            schema=schema,
            derivation_id=derivation_id.strip(),
            artifact_id=artifact_id.strip(),
            epistemic_state=state,
            confidence=normalized_confidence,
            parents=parent_values,
            losses=loss_values,
            product=product,
            producer=MappingProxyType(dict(producer)),
            method=method.strip() if isinstance(method, str) else "",
            limitations=limitation_values,
        )

    def validate(self) -> None:
        """Revalidate an already constructed record before it crosses a boundary."""
        self._validated(
            schema=self.schema,
            derivation_id=self.derivation_id,
            artifact_id=self.artifact_id,
            product=self.product,
            producer=self.producer,
            method=self.method,
            state_value=self.epistemic_state.value,
            confidence=self.confidence,
            parents=list(self.parents),
            losses=list(self.losses),
            limitations=list(self.limitations),
        )

    def to_dict(self) -> dict[str, Any]:
        if self.product is None:
            return {
                "derivation_id": self.derivation_id,
                "artifact_id": self.artifact_id,
                "epistemic_state": self.epistemic_state.value,
                "confidence": self.confidence,
                "parents": list(self.parents),
                "losses": list(self.losses),
            }
        return {
            "schema": "derivation-record.v1",
            "derivation_id": self.derivation_id,
            "product": self.product.to_dict(),
            "parents": list(self.parents),
            "producer": dict(self.producer),
            "method": self.method,
            "epistemic_state": self.epistemic_state.value,
            "confidence": self.confidence,
            "limitations": list(self.limitations),
        }
