"""OmniRoute P0 — CONTRATO do provider (infraestrutura de transporte, zero inteligencia).

Posicao na arquitetura (diretiva do dono do roadmap, 2026-09-02):

    USER / AGENT
         |
         v
    OmniRoute (transporte/API)          <- este pacote
         |
         v
    ROTOR (decisao)                     <- router/ (F5, congelado; decide)
         |
    Provider x Provider x Provider      <- adapters (P2 migra os backends existentes)
         |
    Verifier -> Outcome -> Memory

Mapeamento do contrato P0 exigido:
    identity       -> ProviderAdapter.name
    capabilities   -> ProviderAdapter.capabilities()      (declarado)
    availability   -> ProviderOperatingState.available    (observado)
    invoke()       -> ProviderAdapter.invoke()
    health()       -> ProviderAdapter.health()            (probe ativo)
    latency        -> ProviderOperatingState.latency_ms_p50 / ProviderResponse.latency_ms
    cost           -> ProviderOperatingState.cost_hint
    errors         -> ProviderResponse.error              (normalizado, nunca excecao crua)
    metadata       -> *.metadata

Contratos constitucionais codificados aqui:
  - SOBERANIA: ROTOR decide; OmniRoute apenas DESPACHA o que foi decidido.
    Nenhuma funcao deste pacote escolhe modelo, reordena cadeia ou calcula score.
  - RAW != EFFECTIVE (evidencia Fase 2 live, 49/54): a decisao crua do motor nao
    e a decisao executavel. O estado operacional e dimensoes SEPARADAS que o
    chamador consulta; o transporte nunca as combina nem as esconde.
  - Dimensoes SEPARADAS por contrato: capability (declarado) / availability /
    health / cost / latency / policy. PROIBIDO combinar em score cognitivo —
    nao contamina o F5 (congelado).
  - §1 Removibilidade: omniroute NAO importa nada de router/; nenhum modulo de
    router/ importa omniroute. A composicao acontece no chamador (testada).
  - Erros NORMALIZADOS: falha de transporte vira ProviderResponse(ok=False,
    error={class, message, transient}); excecao crua nunca vazia para cima.
  - Sem inteligencia no P0: 1 tentativa por dispatch, sem retry, sem breaker,
    sem policy de roteamento. Essas politicas pertencem a decisao (ROTOR/composicao).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

OMNIROUTE_VERSION = "fase3-omniroute-0.1"


@dataclass
class ProviderCapabilities:
    """O que o provider DECLARA ser — fato estatico, nunca score."""
    models: List[str]
    modalities: List[str] = field(default_factory=lambda: ["text"])
    supports_tools: bool = False
    supports_streaming: bool = False
    context_window: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderOperatingState:
    """Como o provider ESTA agora — fato operacional, dimensoes SEPARADAS.

    Campo ausente = None (desconhecido), nunca chute. Proibido derivar um
    score combinado destes campos dentro do OmniRoute.
    """
    available: Optional[bool] = None        # roteavel agora? verdade operacional
    healthy: Optional[bool] = None          # probe ativo passou?
    latency_ms_p50: Optional[float] = None  # latencia observada (nao declarada)
    cost_hint: Optional[float] = None       # custo relativo (declarado/observado)
    policy: Dict[str, Any] = field(default_factory=dict)  # rotulos, ex: {"local": True}
    detail: str = ""


@dataclass
class ProviderRequest:
    """Pedido normalizado. `model` ja vem decidido de fora (ROTOR/chamador)."""
    request_id: str
    model: str
    body: Dict[str, Any]                 # payload OpenAI-compativel como lingua franca
    timeout_s: float = 300.0
    budget_s: Optional[float] = None     # deadline compartilhado (disciplina Fase 1)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderResponse:
    """Resposta normalizada. `error` sempre dict {class, message, transient?}."""
    request_id: str
    provider: str
    model: str
    ok: bool
    body: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    latency_ms: Optional[float] = None   # autoritativo: medido pelo dispatcher
    attempts: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class ProviderAdapter(ABC):
    """Contrato P0 do provider. Implementacoes (P2) vao envolver os backends
    existentes de router/providers.py e os GatewayTransport de router/gateway.

    Subcontratos:
      - capabilities():  o que DECLARA saber fazer (estatico).
      - operating_state(): ultimo estado conhecido, BARATO, sem IO de rede.
      - health():        probe ATIVO (pode custar IO); retorna ProviderOperatingState
                         com healthy preenchido.
      - invoke():        EXATAMENTE 1 tentativa (retry/policy sao de outra camada).
                         Deve capturar as proprias falhas em ProviderResponse.error;
                         se uma excecao escapar, o core normaliza.
    """
    name: str = ""

    @abstractmethod
    def capabilities(self) -> ProviderCapabilities: ...

    @abstractmethod
    def operating_state(self) -> ProviderOperatingState: ...

    @abstractmethod
    def invoke(self, request: ProviderRequest) -> ProviderResponse: ...

    @abstractmethod
    def health(self) -> ProviderOperatingState: ...
