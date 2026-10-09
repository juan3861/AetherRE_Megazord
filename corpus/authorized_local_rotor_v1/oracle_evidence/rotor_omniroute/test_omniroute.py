"""FASE 3 P0 — Testes de contrato do OmniRoute Core (transporte puro).

Contratos verificados aqui:
  Independencia dupla: omniroute nao importa router/*; nenhum modulo de
     router/* importa omniroute (composicao so no chamador).
  Soberania: dispatch NAO decide — provider_name vem de fora; sem score,
     sem cadeia, sem policy dentro do transporte.
  raw != effective: dimensoes capability/availability/health/cost/latency/policy
     SEPARADAS; enforcement de disponibilidade so ocorre se o chamador pedir.
  Erros normalizados: excecao crua NUNCA propaga; telemetria por dispatch.
"""
import copy
import json
import re
import sys
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from omniroute import (  # noqa: E402
    OmniRoute,
    ProviderAdapter,
    ProviderCapabilities,
    ProviderOperatingState,
    ProviderRequest,
    ProviderResponse,
)

BODY = {"messages": [{"role": "user", "content": "oi"}], "max_tokens": 16}


class FakeProvider(ProviderAdapter):
    """Implementacao de contrato para testes (sem rede)."""
    name = "fake"

    def __init__(self, available=True, fail_with=None, garbage=False, sleep_s=0.0):
        self.calls = 0
        self._available = available
        self._fail_with = fail_with
        self._garbage = garbage
        self._sleep_s = sleep_s

    def capabilities(self):
        return ProviderCapabilities(models=["fake-mini"], supports_tools=False,
                                    context_window=1024, metadata={"kind": "test-double"})

    def operating_state(self):
        return ProviderOperatingState(available=self._available, healthy=True,
                                      latency_ms_p50=1.0, cost_hint=0.0,
                                      policy={"kind": "test-double"})

    def health(self):
        return ProviderOperatingState(available=self._available, healthy=self._available,
                                      detail="probe ativo do test-double")

    def invoke(self, request):
        self.calls += 1
        if self._sleep_s:
            import time as _t
            _t.sleep(self._sleep_s)
        if self._fail_with is not None:
            raise self._fail_with
        if self._garbage:
            return {"not": "a ProviderResponse"}
        return ProviderResponse(request_id=request.request_id, provider=self.name,
                                model=request.model, ok=True,
                                body={"choices": [{"message": {"content": "ok"}}]},
                                attempts=1, metadata={"adapter_seen": True})


def _req(**kw):
    d = dict(request_id="req-t1", model="fake-mini", body=copy.deepcopy(BODY))
    d.update(kw)
    return ProviderRequest(**d)


# ── Independencia dupla (§1 removibilidade + soberania de camadas) ────
def test_router_does_not_import_omniroute():
    offenders = []
    for f in BASE.glob("router/**/*.py"):
        if f.name == "providers.py":
            continue  # A8: autorizada integracao de transporte em providers.py pos-R5
        src = f.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"^\s*(from\s+omniroute|import\s+omniroute)", src, re.M):
            offenders.append(str(f.relative_to(BASE)))
    assert offenders == [], f"nucleo router/ acoplado ao omniroute: {offenders}"


def test_omniroute_does_not_import_router():
    forbidden = re.compile(
        r"^\s*(from|import)\s+(router|cognitive|adaptive|shadow|model_registry|"
        r"scores|aggi|gateway|providers|rotor_router)\b", re.M)
    offenders = []
    for f in BASE.glob("omniroute/**/*.py"):
        src = f.read_text(encoding="utf-8", errors="ignore")
        if forbidden.search(src):
            offenders.append(str(f.relative_to(BASE)))
    assert offenders == [], f"omniroute depende do nucleo de decisao: {offenders}"


# ── Registro valida o contrato ────────────────────────────────────────
def test_register_validates_contract(tmp_path):
    r = OmniRoute()
    r.register(FakeProvider())
    assert r.provider_names() == ["fake"]
    with pytest.raises(ValueError):
        r.register(object())  # sem name, sem metodos
    with pytest.raises(ValueError):
        r.register(FakeProvider())  # duplicado: sem sobrescrita silenciosa


# ── Dispatch: caminho feliz normalizado ───────────────────────────────
def test_dispatch_normalized_ok():
    r = OmniRoute()
    prov = FakeProvider()
    r.register(prov)
    req = _req()
    resp = r.dispatch(req, "fake")
    assert prov.calls == 1
    assert isinstance(resp, ProviderResponse) and resp.ok is True
    assert resp.request_id == "req-t1" and resp.provider == "fake" and resp.model == "fake-mini"
    assert resp.body["choices"][0]["message"]["content"] == "ok"
    assert isinstance(resp.latency_ms, float) and resp.latency_ms >= 0
    assert resp.attempts == 1
    assert resp.metadata["within_budget"] is True
    assert resp.error is None


def test_body_never_mutated():
    r = OmniRoute()
    r.register(FakeProvider())
    req = _req()
    snap = copy.deepcopy(req.body)
    r.dispatch(req, "fake")
    assert req.body == snap, "dispatch alterou o body do chamador"


# ── Erros normalizados: nada propaga excecao crua ─────────────────────
def test_unknown_provider_normalized():
    r = OmniRoute()
    resp = r.dispatch(_req(), "nao-existe")
    assert resp.ok is False and resp.attempts == 0
    assert resp.error["class"] == "UnknownProvider"
    assert "nao-existe" in resp.error["message"]


def test_provider_exception_normalized():
    r = OmniRoute()
    r.register(FakeProvider(fail_with=RuntimeError("conexao caiu")))
    resp = r.dispatch(_req(), "fake")
    assert resp.ok is False and resp.attempts == 1
    assert resp.error["class"] == "RuntimeError" and "conexao caiu" in resp.error["message"]


def test_adapter_returning_garbage_normalized():
    r = OmniRoute()
    r.register(FakeProvider(garbage=True))
    resp = r.dispatch(_req(), "fake")
    assert resp.ok is False
    assert resp.error["class"] == "ContractViolation"


# ── raw != effective: dimensoes separadas, enforcement e do chamador ──
def test_dimensions_never_combined():
    st = ProviderOperatingState(available=True, healthy=False, latency_ms_p50=9.9)
    assert not hasattr(st, "score") and not hasattr(st, "rank"), \
        "estado operacional nao pode carregar score/rank combinados"
    caps = ProviderCapabilities(models=["x"])
    assert not hasattr(caps, "score"), "capabilities declaradas nao podem ter score"
    cap = FakeProvider().capabilities()
    state = FakeProvider().operating_state()
    assert type(cap) is not type(state), "declarado e operacional sao dimensoes distintas"


def test_require_available_is_callers_decision():
    prov = FakeProvider(available=False)
    r = OmniRoute()
    r.register(prov)
    # default: transporte puro DESPACHA mesmo com available=False (decidir e do chamador)
    resp = r.dispatch(_req(), "fake")
    assert prov.calls == 1 and resp.ok is True
    # enforcement so acontece se o chamador pedir explicitamente
    resp2 = r.dispatch(_req(request_id="req-t2"), "fake", require_available=True)
    assert prov.calls == 1, "enforcement nao pode ter invocado o adapter"
    assert resp2.ok is False and resp2.error["class"] == "ProviderUnavailable"


# ── Budget compartilhado (disciplina Fase 1) ──────────────────────────
def test_budget_deadline_respected():
    prov = FakeProvider()
    r = OmniRoute()
    r.register(prov)
    resp = r.dispatch(_req(budget_s=0.0), "fake")
    assert prov.calls == 0, "budget expirado nao pode chamar o adapter"
    assert resp.ok is False and resp.error["class"] == "BudgetExceeded"
    resp2 = r.dispatch(_req(request_id="req-t3", budget_s=5.0), "fake")
    assert resp2.ok is True and resp2.metadata["within_budget"] is True


# ── Telemetria por dispatch ───────────────────────────────────────────
def test_telemetry_per_dispatch_with_sink(tmp_path):
    sink = tmp_path / "omniroute_tel.jsonl"
    r = OmniRoute(sink_path=sink)
    r.register(FakeProvider())
    r.dispatch(_req(), "fake")
    r.dispatch(_req(request_id="req-t2"), "fake")
    assert len(r.telemetry) == 2
    for rec in r.telemetry:
        for k in ("request_id", "ts", "provider", "model", "ok", "latency_ms",
                  "error_class", "attempts", "within_budget"):
            assert k in rec, f"telemetria sem campo obrigatorio: {k}"
    lines = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2 and lines[0]["request_id"] == "req-t1"
    # sink quebrado (pai e arquivo) nao pode quebrar o transporte
    bad = tmp_path / "arquivo" / "x.jsonl"
    bad.parent.write_text("sou arquivo", encoding="utf-8")
    r2 = OmniRoute(sink_path=bad)
    r2.register(FakeProvider())
    resp = r2.dispatch(_req(), "fake")
    assert resp.ok is True


# ── Consulta de dimensoes com fail-open ───────────────────────────────
def test_state_and_health_fail_open():
    class SickProvider(FakeProvider):
        def operating_state(self):
            raise RuntimeError("state quebrou")
        def health(self):
            raise RuntimeError("probe quebrou")
    r = OmniRoute()
    r.register(SickProvider())
    assert r.state("fake").detail.startswith("state_error")
    assert r.health("fake").healthy is False
    assert r.capabilities("fake").models == ["fake-mini"]
    assert r.state("nao-existe") is None and r.get("nao-existe") is None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
