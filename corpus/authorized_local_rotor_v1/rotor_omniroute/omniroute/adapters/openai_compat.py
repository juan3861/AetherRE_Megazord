"""Adapter OpenAI-compatible — PRIMEIRO ProviderAdapter (Fase 3 P2, migracao gradual).

Regras do P2 (diretiva 2026-09-02) que este adapter CODIFICA:
  - Migração de IMPLEMENTAÇÃO, não evolução cognitiva: este adapter NÃO
    importa router/ e NÃO altera F5/scoring/competência/fallback. Ele apenas
    executa UMA tentativa de transporte contra um endpoint OpenAI-compatible.
  - Normalização de payload IDÊNTICA à do path antigo (router/providers.py
    call_backend), para valer a equivalência "mesmo input + mesma política +
    mesmo provider -> comportamento equivalente":
        body["model"] = model_map.get(model, model)
        max_completion_tokens -> max_tokens (se max_tokens ausente)
        stream = False quando o backend não suporta stream
  - R2.2 (2026-09-02): quando definition-driven, o model_map vem da
    DECLARAÇÃO do registry (definition.model_map) — fonte única de fatos;
    model_map explícito + definition juntos é ERRO (sem chute silencioso).
    A tradução é fato declarado executado no payload build; NUNCA influencia
    a seleção de provider (dispatch é por nome; core.py não conhece model_map).
  - invoke() = exatamente 1 tentativa: SEM retry, SEM fallback, SEM breaker
    (isso é política de execução — pertence a camadas superiores).
  - Erros NORMALIZADOS (nunca exceção crua); status HTTP vai no erro para a
    política decidir transitório depois.
  - INV2: operating_state() não inventa disponibilidade — só sucesso de
    transporte observado vira available=True; falha mantém None (desconhecido,
    com o erro em detail). healthy só recebe valor de probe ATIVO (health()).
"""
from __future__ import annotations

import statistics
import time
from typing import Dict, Optional

import httpx

from ..provider import ProviderAdapter, ProviderCapabilities, ProviderOperatingState, ProviderRequest, ProviderResponse

_ACCEPT = "application/json, text/event-stream"


class OpenAICompatAdapter(ProviderAdapter):
    """Envolve UM endpoint OpenAI-compatible (llama.cpp local, gateway publico,
    relay). Um adapter = um provider = um endpoint. Execucao de 1 tentativa."""

    def __init__(self, name: str, base_url: str,
                 models: Optional[list] = None,
                 model_map: Optional[Dict[str, str]] = None,
                 supports_stream: bool = False,
                 tokens: Optional[list] = None,
                 definition=None,
                 client_factory=None,
                 health_timeout_s: float = 5.0):
        if definition is not None:
            # definicao vem do registry: fonte declarativa, zero chute.
            # R2.2: traducao logico->transporte vem da DECLARACAO
            # (definition.model_map, INV5 do registry); model_map explicito
            # junto de definition conflita com a fonte unica de fatos.
            if model_map is not None:
                raise ValueError(
                    "model_map explicito conflita com definition: a traducao "
                    "declarativa vem do registry (fonte unica de fatos)")
            self.name = definition.id
            caps = definition.capabilities.to_contract()
            self._models = list(caps.models)
            self._supports_stream = caps.supports_streaming
            self._model_map = dict(getattr(definition, "model_map", None) or {})
            toks = tokens or (getattr(definition, "metadata", {}) or {}).get("tokens")
        else:
            self.name = name
            self._models = list(models or ([name] if name else []))
            self._supports_stream = bool(supports_stream)
            self._model_map = dict(model_map or {})
            toks = tokens

        from ..credentials import CredentialPolicy
        self.credentials = CredentialPolicy(toks)
        self._base_url = base_url.rstrip("/")
        self._health_timeout_s = health_timeout_s
        self._client: Optional[httpx.Client] = (client_factory() if client_factory else None)
        # estado observado (INV2: comeca tudo desconhecido)
        self._ever_ok = False
        self._latency_samples: list[float] = []
        self._last_detail = ""
        self._healthy: Optional[bool] = None

    # ------------------------------------------------------------ contrato
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(models=list(self._models),
                                    supports_streaming=self._supports_stream)

    def operating_state(self) -> ProviderOperatingState:
        p50 = round(statistics.median(self._latency_samples), 1) if self._latency_samples else None
        return ProviderOperatingState(
            available=True if self._ever_ok else None,   # INV2: falha nao inventa False
            healthy=self._healthy,                        # so probe ativo preenche
            latency_ms_p50=p50,
            policy={"adapter": "openai_compat"},
            detail=self._last_detail)

    def health(self) -> ProviderOperatingState:
        """Probe ATIVO: GET {base}/models. Nao altera availability (INV3)."""
        try:
            resp = self._client_get_models()
            self._healthy = resp.status_code < 400
            detail = f"probe GET /models -> HTTP {resp.status_code}"
        except Exception as e:
            self._healthy = False
            detail = f"probe falhou: {type(e).__name__}: {e}"
        return ProviderOperatingState(available=None, healthy=self._healthy,
                                      detail=detail)

    def _client_get_models(self):
        c = self._client or self._make_client()
        return c.get(f"{self._base_url}/models",
                     timeout=httpx.Timeout(self._health_timeout_s))

    def _make_client(self) -> httpx.Client:
        return httpx.Client(limits=httpx.Limits(max_keepalive_connections=10))

    def _client_for(self) -> httpx.Client:
        if self._client is None:
            self._client = self._make_client()
        return self._client

    # --------------------------------------------------------------- invoke
    def invoke(self, request: ProviderRequest) -> ProviderResponse:
        t0 = time.perf_counter()
        body = dict(request.body)  # NUNCA mutar o body do chamador
        body["model"] = self._model_map.get(request.model, request.model)
        if "max_completion_tokens" in body and "max_tokens" not in body:
            body["max_tokens"] = body.pop("max_completion_tokens")
        if not self._supports_stream:
            body["stream"] = False
        headers = {"Content-Type": "application/json", "Accept": _ACCEPT}
        timeout = httpx.Timeout(max(1.0, request.timeout_s),
                                connect=min(15.0, max(1.0, request.timeout_s)),
                                read=max(1.0, request.timeout_s), write=15.0)

        def _err(cls: str, msg: str, extra: Optional[dict] = None) -> ProviderResponse:
            self._last_detail = msg
            err = {"class": cls, "message": msg, "transient": None}
            if extra:
                err.update(extra)
            return ProviderResponse(request_id=request.request_id, provider=self.name,
                                    model=request.model, ok=False, error=err,
                                    latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                                    attempts=1)

        try:
            resp = self._client_for().post(f"{self._base_url}/chat/completions",
                                           json=body, headers=headers, timeout=timeout)
        except httpx.TimeoutException as e:
            return _err("TimeoutError", f"{self.name}: timeout apos "
                                        f"{request.timeout_s:.1f}s ({e})")
        except httpx.HTTPError as e:
            return _err(type(e).__name__, f"{self.name}: {e}")

        if resp.status_code >= 400:
            snippet = ""
            try:
                snippet = resp.text[:200]
            except Exception:
                pass
            return _err("HTTPStatusError",
                        f"{self.name} HTTP {resp.status_code}: {snippet}",
                        extra={"http_status": resp.status_code})

        # validacao de conteudo IDENTICA ao path antigo (_check_empty, nao-stream)
        try:
            data = resp.json()
        except Exception:
            data = None  # path antigo: erro de parse passa silenciosamente
        if data is not None:
            choices = data.get("choices") or []
            msg = (choices[0].get("message") or {}) if choices else {}
            if not (msg.get("content") or msg.get("tool_calls")
                    or msg.get("reasoning_content") or msg.get("reasoning")):
                return _err("EmptyResponse", f"{self.name}: resposta vazia")

        lat = round((time.perf_counter() - t0) * 1000, 2)
        self._ever_ok = True                       # evidencia de transporte OK
        self._latency_samples.append(lat)
        if len(self._latency_samples) > 50:
            self._latency_samples = self._latency_samples[-50:]
        self._last_detail = f"HTTP 200 ({lat:.1f}ms)"
        return ProviderResponse(request_id=request.request_id, provider=self.name,
                                model=request.model, ok=True, body=data,
                                latency_ms=lat, attempts=1)

    def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            self._client.close()
