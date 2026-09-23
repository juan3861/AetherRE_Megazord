"""Strict projection from IR into forensic graph v2 documents."""
from __future__ import annotations
from typing import Any
from aether_re.ir import IRDocument, canonical_ir_dict, validate_ir

def project_ir(document: IRDocument) -> dict[str,Any]:
    validate_ir(document)
    if document.schema != "ir.v1": raise ValueError("ir_schema_unsupported")
    data=canonical_ir_dict(document)
    return {"schema":"forensic-graph.v2","artifact_id":data["artifact_id"],"profile_id":data["profile_id"],"nodes":data["nodes"],"edges":data["edges"],"losses":data["losses"]}