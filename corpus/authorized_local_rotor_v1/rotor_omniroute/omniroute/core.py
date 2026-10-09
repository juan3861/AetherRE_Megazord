"""OmniRoute Core — dispatcher de transporte puro (P0).

Regras do dispatcher (nada aqui e inteligencia):
  - NAO decide: `provider_name` chega pronto (ROTOR ou composicao do chamador).
  - Erros NORMALIZADOS: provider desconhecido, indisponivel (quando exigido),
    excecao do adapter, retorno fora do contrato, budget estourado — tudo vira
    ProviderResponse(ok=False, error={class, message}); nada propaga excecao crua.
  - Budget compartilhado por dispatch (disciplina Fase 1): deadline expirado
    ANTES do invoke => ProviderUnavailable/BudgetExceeded sem chamar o adapter;
    apos o invoke, metadata["within_budget"] registra o fato.
  - `require_available` (default False): enforcement de disponibilidade e
    DECISAO de roteamento — o transporte so o aplica se o chamador pedir
    (contrato raw != effective: consultar estado e do chamador).
  - `body` do request NUNCA e mutado.
  - Telemetria: 1 registro por dispatch (request_id, ts, provider, model, ok,
    latency_ms, error_class, attempts, within_budget). Sink JSONL opcional,
    fail-open: telemetria nunca quebra transporte.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .provider import (
    OMNIROUTE_VERSION,
    ProviderAdapter,
    ProviderCapabilities,
    ProviderOperatingState,
    ProviderRequest,
    ProviderResponse,
)

_REQUIRED_METHODS = ("capabilities", "operating_state", "invoke", "health")


class OmniRoute:
    """Registro + despacho. Zero decisao. Composicao com ROTOR acontece no chamador."""

    def __init__(self, sink_path=None):
        self._providers: Dict[str, Any] = {}
        self.telemetry: List[Dict[str, Any]] = []
        self._sink = Path(sink_path) if sink_path else None

    # ------------------------------------------------------------- registro
    def register(self, provider: Any) -> None:
        """Registra um provider validando o contrato P0 (duck-typing explicito).

        Levanta ValueError se: sem nome, metodos ausentes/nao-chamaveis, ou
        nome duplicado (registro e explicito; sem sobrescrita silenciosa).
        """
        if not isinstance(provider, ProviderAdapter):
            missing = [m for m in _REQUIRED_METHODS
                       if not callable(getattr(provider, m, None))]
            if not hasattr(provider, "name") or not str(getattr(provider, "name", "")):
                missing.append("name")
            if missing:
                raise ValueError(f"provider fora do contrato P0, faltando: {missing}")
        name = str(provider.name)
        if not name:
            raise ValueError("provider precisa de name nao-vazio")
        if name in self._providers:
            raise ValueError(f"provider duplicado: {name!r} (sem sobrescrita silenciosa)")
        self._providers[name] = provider

    def provider_names(self) -> List[str]:
        return sorted(self._providers)

    def has(self, name: str) -> bool:
        return name in self._providers

    def get(self, name: str) -> Optional[Any]:
        return self._providers.get(name)

    # ------------------------------------------------- consulta de dimensoes
    def capabilities(self, name: str) -> Optional[ProviderCapabilities]:
        p = self._providers.get(name)
        try:
            return p.capabilities() if p else None
        except Exception as e:
            return ProviderCapabilities(models=[], metadata={"query_error": f"{type(e).__name__}: {e}"})

    def state(self, name: str) -> Optional[ProviderOperatingState]:
        """Ultimo estado operacional conhecido (barato, sem IO)."""
        p = self._providers.get(name)
        try:
            return p.operating_state() if p else None
        except Exception as e:
            return ProviderOperatingState(detail=f"state_error: {type(e).__name__}: {e}")

    def health(self, name: str) -> Optional[ProviderOperatingState]:
        """Probe ATIVO delegado ao adapter (pode custar IO)."""
        p = self._providers.get(name)
        try:
            return p.health() if p else None
        except Exception as e:
            return ProviderOperatingState(healthy=False, detail=f"health_error: {type(e).__name__}: {e}")

    # -------------------------------------------------------------- despacho
    def dispatch(self, request: ProviderRequest, provider_name: str,
                 require_available: bool = False) -> ProviderResponse:
        """Executa UMA tentativa de transporte. Nunca levanta; sempre normaliza."""
        t0 = time.perf_counter()
        rid = request.request_id

        def _err(cls: str, msg: str, attempts: int = 0) -> ProviderResponse:
            return ProviderResponse(request_id=rid, provider=provider_name,
                                    model=request.model, ok=False,
                                    error={"class": cls, "message": msg, "transient": None},
                                    latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                                    attempts=attempts)

        provider = self._providers.get(provider_name)
        if provider is None:
            resp = _err("UnknownProvider",
                        f"provider {provider_name!r} nao registrado "
                        f"(registrados: {self.provider_names()})")
            self._record(resp, t0, within_budget=None)
            return resp

        if require_available:
            st = self.state(provider_name)
            if st is not None and st.available is False:
                resp = _err("ProviderUnavailable",
                            f"{provider_name!r} available=False (enforcement pedido "
                            f"pelo chamador; transporte puro nao decide por conta propria)")
                self._record(resp, t0, within_budget=None)
                return resp

        deadline = t0 + request.budget_s if request.budget_s is not None else None
        if deadline is not None and time.perf_counter() >= deadline:
            resp = _err("BudgetExceeded",
                        f"deadline de {request.budget_s}s esgotado antes do invoke")
            self._record(resp, t0, within_budget=False)
            return resp

        try:
            resp = provider.invoke(request)
            if not isinstance(resp, ProviderResponse):
                resp = _err("ContractViolation",
                            f"adapter retornou {type(resp).__name__}, "
                            f"esperado ProviderResponse", attempts=1)
            else:
                resp.attempts = max(1, int(resp.attempts or 1))
                resp.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        except Exception as e:  # transporte normaliza; excecao crua nunca sobe
            resp = _err(type(e).__name__, str(e), attempts=1)

        within = True
        if deadline is not None:
            within = time.perf_counter() < deadline
        resp.metadata.setdefault("omniroute_version", OMNIROUTE_VERSION)
        resp.metadata["within_budget"] = within
        self._record(resp, t0, within_budget=within)
        return resp

    # ------------------------------------------------------------- telemetria
    def _record(self, resp: ProviderResponse, t0: float, within_budget) -> None:
        rec = {
            "request_id": resp.request_id,
            "ts": time.time(),
            "provider": resp.provider,
            "model": resp.model,
            "ok": resp.ok,
            "latency_ms": resp.latency_ms,
            "error_class": (resp.error or {}).get("class"),
            "attempts": resp.attempts,
            "within_budget": within_budget,
        }
        self.telemetry.append(rec)
        if self._sink is None:
            return
        try:
            self._sink.parent.mkdir(parents=True, exist_ok=True)
            with self._sink.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass  # fail-open: telemetria nunca quebra transporte
