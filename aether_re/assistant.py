"""Assistência forense determinística, offline e subordinada à evidência.

Este módulo é deliberadamente um boundary seguro para futura integração de
LLM: ele cria hipóteses e experimentos sugeridos, mas nunca altera o alvo,
executa conteúdo ou promove uma hipótese a fato confirmado.  A verificação
das citações é feita contra o catálogo de evidências fornecido pelo chamador.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from aether_re.evidence_contract import validate_evidence_records


SCHEMA = "forensic-assistant.v1"
_SUPPORTING_STATES = {"observed", "supported", "confirmed"}
_LIMITATIONS = [
    "provider offline determinístico; nenhum texto é enviado a serviço externo",
    "hipóteses e experimentos são sugestões, nunca fatos confirmados",
    "a validação de citação confere identidade/suporte declarado, não causalidade",
    "conteúdo do alvo é tratado como dado não confiável e não é executado",
]


def _invalid(code: str, detail: str = "") -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "invalid",
        "provider": "offline",
        "proposals": [],
        "errors": [{"code": code, **({"detail": detail} if detail else {})}],
        "summary": {"evidence": 0, "proposals": 0, "review_required": 0},
        "limitations": list(_LIMITATIONS),
    }


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _proposal_id(evidence_id: str, index: int) -> str:
    digest = hashlib.sha256(f"{index}\0{evidence_id}".encode("utf-8")).hexdigest()[:16]
    return f"hyp-{digest}"


def propose_hypotheses(
    evidence: list[dict[str, Any]],
    *,
    question: str = "",
    max_hypotheses: int = 50,
    strict_evidence: bool = False,
) -> dict[str, Any]:
    """Generate bounded, offline follow-up hypotheses from evidence records."""
    if not isinstance(evidence, list):
        return _invalid("evidence_must_be_list")
    if isinstance(max_hypotheses, bool) or not isinstance(max_hypotheses, int) or not 1 <= max_hypotheses <= 1000:
        return _invalid("max_hypotheses_invalid", "integer_range=1..1000")
    if not isinstance(strict_evidence, bool):
        return _invalid("strict_evidence_invalid")
    if not isinstance(question, str):
        return _invalid("question_invalid")
    contract = validate_evidence_records(evidence, strict=strict_evidence)
    if contract.get("status") == "invalid":
        return {
            "schema": SCHEMA,
            "status": "invalid",
            "provider": "offline",
            "question": question,
            "evidence_contract": contract,
            "proposals": [],
            "errors": [{"code": "evidence_contract_invalid", "detail": f"{len(contract.get('errors', []))} error(s)"}],
            "summary": {"evidence": len(evidence), "proposals": 0, "review_required": 0},
            "limitations": list(_LIMITATIONS),
        }
    proposals: list[dict[str, Any]] = []
    for index, record in enumerate(contract.get("records", [])[:max_hypotheses]):
        evidence_id = _text(record.get("evidence_id"))
        method = _text(record.get("method")) or "unknown_method"
        producer = _text(record.get("producer")) or "unknown_producer"
        proposals.append(
            {
                "proposal_id": _proposal_id(evidence_id, index),
                "status": "proposed",
                "hypothesis": f"A observação {evidence_id} ({method}, produtor {producer}) é consistente com a hipótese declarada pelo registro; significado causal permanece não comprovado.",
                "evidence_ids": [evidence_id],
                "counterevidence_ids": [],
                "experiments": [
                    "reexecutar o método em ambiente autorizado usando o mesmo input_hash",
                    "procurar uma observação independente que possa contradizer a hipótese",
                ],
                "review_required": True,
                "auto_confirmed": False,
            }
        )
    status = "complete" if proposals else "insufficient_data"
    return {
        "schema": SCHEMA,
        "status": status,
        "provider": "offline",
        "question": question,
        "evidence_contract": contract,
        "proposals": proposals,
        "errors": [],
        "summary": {"evidence": len(evidence), "proposals": len(proposals), "review_required": len(proposals)},
        "limits": {"max_hypotheses": max_hypotheses},
        "limitations": list(_LIMITATIONS),
    }


def _explicit_support(record: dict[str, Any]) -> bool:
    return record.get("supports") is True and record.get("validation_status") in _SUPPORTING_STATES


def verify_proposals(
    proposals: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    *,
    strict_evidence: bool = False,
) -> dict[str, Any]:
    """Verify proposal citations without ever promoting them to confirmation."""
    schema = "forensic-assistant-verification.v1"
    if not isinstance(proposals, list) or not isinstance(evidence, list):
        return {"schema": schema, "status": "invalid", "results": [], "errors": [{"code": "proposals_and_evidence_must_be_lists"}], "summary": {"proposals": 0, "supported": 0, "inconclusive": 0, "unsupported": 0, "review_required": 0}, "limitations": list(_LIMITATIONS)}
    if not isinstance(strict_evidence, bool):
        return {"schema": schema, "status": "invalid", "results": [], "errors": [{"code": "strict_evidence_invalid"}], "summary": {"proposals": len(proposals), "supported": 0, "inconclusive": 0, "unsupported": 0, "review_required": 0}, "limitations": list(_LIMITATIONS)}
    contract = validate_evidence_records(evidence, strict=strict_evidence)
    errors: list[dict[str, Any]] = []
    if contract.get("status") == "invalid":
        errors.append({"code": "evidence_contract_invalid", "detail": f"{len(contract.get('errors', []))} error(s)"})
    catalog = {str(item.get("evidence_id")): item for item in contract.get("records", []) if isinstance(item, dict) and _text(item.get("evidence_id"))}
    results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, proposal in enumerate(proposals):
        if not isinstance(proposal, dict):
            errors.append({"index": index, "code": "proposal_not_object"})
            continue
        proposal_id = _text(proposal.get("proposal_id"))
        if not proposal_id:
            errors.append({"index": index, "code": "proposal_id_missing"})
            proposal_id = f"<index:{index}>"
        elif proposal_id in seen_ids:
            errors.append({"index": index, "code": "duplicate_proposal_id", "proposal_id": proposal_id})
        seen_ids.add(proposal_id)
        hypothesis = _text(proposal.get("hypothesis"))
        if not hypothesis:
            errors.append({"index": index, "code": "hypothesis_missing", "proposal_id": proposal_id})
        raw_ids = proposal.get("evidence_ids", [])
        if not isinstance(raw_ids, list):
            errors.append({"index": index, "code": "proposal_evidence_ids_must_be_list", "proposal_id": proposal_id})
            raw_ids = []
        ids = [_text(item) for item in raw_ids]
        ids = [item for item in ids if item]
        if len(ids) != len(set(ids)):
            errors.append({"index": index, "code": "proposal_evidence_ids_duplicated", "proposal_id": proposal_id})
            ids = list(dict.fromkeys(ids))
        missing = [item for item in ids if item not in catalog]
        unsupported = [item for item in ids if item in catalog and not _explicit_support(catalog[item])]
        counter_ids = proposal.get("counterevidence_ids", [])
        if not isinstance(counter_ids, list):
            errors.append({"index": index, "code": "counterevidence_ids_must_be_list", "proposal_id": proposal_id})
            counter_ids = []
        counter_ids = [_text(item) for item in counter_ids if _text(item)]
        counter_missing = [item for item in counter_ids if item not in catalog]
        counter_supported = [item for item in counter_ids if item in catalog and _explicit_support(catalog[item])]
        if missing or unsupported or counter_supported:
            verdict = "unsupported"
        elif counter_missing or not ids:
            verdict = "inconclusive"
        else:
            verdict = "supported"
        results.append({"proposal_id": proposal_id, "hypothesis": hypothesis, "verdict": verdict, "evidence_ids": ids, "missing_evidence_ids": missing, "unsupported_evidence_ids": unsupported, "counterevidence_ids": counter_ids, "counterevidence_missing": counter_missing, "review_required": True, "auto_confirmed": False})
    return {
        "schema": schema,
        "status": "invalid" if errors else "complete",
        "evidence_contract": contract,
        "results": results,
        "errors": errors,
        "summary": {"proposals": len(results), "supported": sum(item["verdict"] == "supported" for item in results), "inconclusive": sum(item["verdict"] == "inconclusive" for item in results), "unsupported": sum(item["verdict"] == "unsupported" for item in results), "review_required": len(results), "auto_confirmed": 0},
        "limitations": list(_LIMITATIONS),
    }


def write_assistant_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
