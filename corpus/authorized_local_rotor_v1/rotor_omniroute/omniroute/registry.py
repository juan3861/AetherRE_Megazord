"""OmniRoute P1 — Provider Registry DECLARATIVO (fatos, nunca competencia).

Regra-mestra (diretiva 2026-09-02): Registry CONHECE recursos; OmniRoute
TRANSPORTA; ROTOR DECIDE. O registry responde apenas:

    "O que e este provider e o que ele declara oferecer?"

Ele NAO responde (e nao pode responder) "qual provider e melhor". Invariantes:

  INV1 — Registry nao roteia: nenhuma best_provider/choose_provider/rank_*
         existe aqui (testado por contrato). Se aparecer, e vazamento.
  INV2 — Registry nao inventa disponibilidade: sem evidencia, available=None
         (nunca True por default). O YAML nem pode declarar availability:
         so "source: runtime" e aceito. Evidencia Fase 2: 49/54 snapshots
         exigiram correcao entre decisao raw e realidade operacional.
  INV3 — Health NAO e Availability: tipos separados (HealthResult x
         AvailabilityState), gravados por metodos separados; um pode ser OK
         e o outro false.
  INV4 — Cost/latency NAO sao competencia: proibido fitness/quality/score
         derivado aqui. latency declarada estatica e rejeitada no schema
         (latencia e metrica OBSERVADA; mora no runtime state).
  INV5 — transport.model_map (R2.2, diretiva 2026-09-02) e FATO DECLARADO de
         traducao logico->transporte, validado no schema (chaves dentro de
         capabilities.models). Nunca decisao: a camada de despacho
         (omniroute/core.py) nem conhece o conceito (contrato AST). Regra
         congelada: nenhum vinculo provider.id -> endpoint/model por
         inferencia historica — ou e declarado aqui, ou nao existe.

Declarado != observado (colapso proibido):
    capabilities = contrato estatico (ProviderDefinition/CapabilityDeclaration)
    availability = estado runtime   (ProviderRuntimeState.availability)
    health       = resultado de probe (ProviderRuntimeState.health)
    latency      = metrica observada  (ProviderRuntimeState.latency)
    cost         = informacao economica (declarada no yaml OU observada no runtime)

P1.1: definicao e runtime state sao TIPOS E ARMAZENAMENTOS SEPARADOS
(`self._definitions` x `self._runtime`) mesmo morando no mesmo pacote —
evita a divida arquitetural de colapsa-los depois.

Isolamento: este modulo nao importa nada de router/ (testado).
"""
from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .provider import ProviderCapabilities

OMNIROUTE_REGISTRY_VERSION = "fase3-registry-1.1"  # 1.1: transport.model_map (R2.2)

_ALLOWED_PROTOCOLS = {"openai_compatible", "browser", "local", "custom"}
_CAP_BOOL_KEYS = ("text", "json", "tools", "vision", "streaming")


class SchemaError(ValueError):
    """Declaracao de provider fora do schema. Erros sao coletados, nao fail-first."""


# ────────────────────────── FATOS DECLARADOS (estaticos, imutaveis) ──────────

@dataclass(frozen=True)
class CapabilityDeclaration:
    """Contrato estatico do que o provider DECLARA. Bool = declarado, nao medido."""
    text: bool = False
    json: bool = False
    tools: bool = False
    vision: bool = False
    streaming: bool = False
    models: Tuple[str, ...] = ()
    context_window: Optional[int] = None
    # R2.1 (diretiva 2026-09-02): distincao explicita capacidade x politica.
    # Sao fatos ESTATICOS declarados (declarado != observado), nunca medidos:
    #   context_train_capability = capacidade NATIVA do modelo (GGUF n_ctx_train)
    #   context_runtime_limit    = politica de launch (--ctx-size)
    context_train_capability: Optional[int] = None
    context_runtime_limit: Optional[int] = None

    def to_contract(self) -> ProviderCapabilities:
        """Ponte para o contrato P0 (traducao de tipo, zero inteligencia)."""
        modalities = [m for m, ok in (("text", self.text), ("vision", self.vision)) if ok]
        return ProviderCapabilities(
            models=list(self.models),
            modalities=modalities or ["text"],
            supports_tools=self.tools,
            supports_streaming=self.streaming,
            context_window=self.context_window,
        )


@dataclass(frozen=True)
class CostInfo:
    """Informacao economica. Campo separado — nunca entra em qualidade."""
    input: Optional[float] = None      # por 1M tokens de entrada (ou unidade declarada)
    output: Optional[float] = None
    currency: Optional[str] = None
    source: str = "declared"


# Origem de fato runtime que significa "veio da declaracao" — proibida.
# Declarado != observado: nenhum estado runtime pode nascer do YAML, de uma
# capacidade declarada ou de um default. (constante do eixo runtime; usada
# por AvailabilityState/LatencyInfo/ProviderRuntimeState, abaixo.)
_FORBIDDEN_RUNTIME_ORIGINS = frozenset(
    {"declared", "capability", "capabilities", "schema", "static", "yaml",
     "definition", "default", "assumed", "inferred"})


@dataclass(frozen=True)
class LatencyInfo:
    """Metrica OBSERVADA (INV4). Em definicao estatica e sempre None (schema rejeita valor).

    Fechos congelados (eixo runtime, 2026-09-02):
      - `source` so aceita "observed": latencia declarada e rejeitada no schema
        e nao pode ser reconstruida aqui (declarado != observado);
      - `p50_ms` exige `samples > 0`: mediana sem amostra e fabricacao.
    """
    p50_ms: Optional[float] = None
    samples: int = 0
    source: str = "observed"

    def __post_init__(self) -> None:
        if self.source != "observed":
            raise ValueError(
                f"LatencyInfo.source={self.source!r}: latencia e metrica OBSERVADA "
                "(invariante 4) — nao existe latencia declarada; use "
                "ProviderRuntimeState.record_latency_sample(ms)")
        if (self.p50_ms is None) != (self.samples == 0):
            raise ValueError(
                "LatencyInfo inconsistente: p50_ms exige samples>0 e samples==0 "
                "exige p50_ms=None (mediana sem amostra e fabricacao, invariante 4)")
        if self.p50_ms is not None and not math.isfinite(float(self.p50_ms)):
            raise ValueError("LatencyInfo.p50_ms deve ser finito (sem NaN/inf)")


@dataclass(frozen=True)
class AvailabilityState:
    """INV2: sem evidencia => available=None (desconhecido), nunca True.

    Fechos congelados (eixo runtime, 2026-09-02):
      - fonte de origem declarativa e rejeitada: disponibilidade nunca vem do
        YAML nem de capacidade declarada;
      - `source="unknown"` <=> `available is None`: sem procedencia nao ha fato,
        e sem fato nao ha procedencia (None nunca e False disfarcado).
    """
    available: Optional[bool] = None
    source: str = "unknown"
    detail: str = ""
    updated_at: Optional[float] = None

    def __post_init__(self) -> None:
        if str(self.source).strip().lower() in _FORBIDDEN_RUNTIME_ORIGINS:
            raise ValueError(
                f"AvailabilityState.source={self.source!r}: disponibilidade NAO e "
                "derivada de declaracao/capacidade (invariante 2); o unico fato "
                "aceito e observacao via ProviderRuntimeState.record_availability()")
        if self.available is not None and not isinstance(self.available, bool):
            raise ValueError("AvailabilityState.available deve ser bool ou None (desconhecido)")
        if (self.source == "unknown") != (self.available is None):
            raise ValueError(
                "AvailabilityState inconsistente: source='unknown' exige "
                "available=None, e available!=None exige uma origem observada")


@dataclass(frozen=True)
class HealthResult:
    """INV3: tipo proprio — health e o resultado de um PROBE, nao availability."""
    healthy: Optional[bool] = None
    detail: str = ""
    checked_at: Optional[float] = None

    def __post_init__(self) -> None:
        if self.healthy is not None and not isinstance(self.healthy, bool):
            raise ValueError("HealthResult.healthy deve ser bool ou None (probe nao rodou)")


@dataclass(frozen=True)
class ProviderDefinition:
    """Fato estatico declarado em YAML. Imutavel por construcao (frozen)."""
    id: str
    name: str
    capabilities: CapabilityDeclaration
    protocol: str
    endpoint: Optional[str] = None
    availability_source: Optional[str] = None   # so "runtime" e aceito no schema
    health_probe: Optional[str] = None          # "active" | "passive" (declaracao do metodo)
    cost: Optional[CostInfo] = None
    metadata: Any = None                        # MappingProxyType read-only
    # R2.2: traducao logico->transporte DECLARADA (fato estatico, read-only).
    model_map: Any = None                       # MappingProxyType read-only

    @property
    def provenance(self) -> Dict[str, Any]:
        """Retorna mapeamento de proveniência/evidência declarado em metadata (R2.2)."""
        if isinstance(self.metadata, (dict, MappingProxyType)):
            prov = self.metadata.get("provenance")
            if isinstance(prov, (dict, MappingProxyType)):
                return dict(prov)
            ev = {}
            for k, v in self.metadata.items():
                if "evidence" in k or k in ("physical_evidence", "remote_evidence", "r1_evidence"):
                    ev[k] = v
            return ev
        return {}

    def as_dict(self) -> Dict[str, Any]:
        meta = dict(self.metadata) if isinstance(self.metadata, MappingProxyType) else self.metadata
        mm = dict(self.model_map) if isinstance(self.model_map, MappingProxyType) else self.model_map
        return {
            "id": self.id, "name": self.name, "protocol": self.protocol,
            "endpoint": self.endpoint,
            "capabilities": {k: getattr(self.capabilities, k)
                             for k in ("text", "json", "tools", "vision", "streaming")},
            "models": list(self.capabilities.models),
            "context_window": self.capabilities.context_window,
            "context_train_capability": self.capabilities.context_train_capability,
            "context_runtime_limit": self.capabilities.context_runtime_limit,
            "model_map": dict(mm) if mm else None,
            "availability_source": self.availability_source,
            "health_probe": self.health_probe,
            "cost": dict(self.cost.__dict__) if self.cost else None,
            "metadata": meta,
            "provenance": self.provenance,
        }


# ────────────────────────── FATOS OBSERVADOS (runtime, P1.1) ─────────────────

@dataclass
class ProviderRuntimeState:
    """Estado runtime SEPARADO da definicao (P1.1). Comeca 100% desconhecido.

    So registra fatos que chegam de fora (probe/dispatch/composicao). Nenhum
    metodo calcula competencia ou ordena providers (INV1/INV4).

    EIXO RUNTIME (contrato congelado, 2026-09-02) — o que esta classe NAO faz:
      - nao recebe, nao le e nao conhece `ProviderDefinition`/`CapabilityDeclaration`:
        disponibilidade/health/latencia nunca sao derivaveis de capacidade
        declarada (nem de `context_runtime_limit`, que e politica de launch);
      - nao fabrica fato: `None` (desconhecido) nunca vira True/False por
        default, coerção ou ausencia de argumento — `record_*` com None e erro;
      - nao compara, ordena, pontua nem elege providers: um estado e de UM
        provider; qualquer ranking e decisao do ROTOR, nao do registry;
      - escrita e 1:1 por fato: availability <- record_availability,
        health <- record_health, latency <- record_latency_sample (contrato AST).
    """
    provider_id: str
    availability: AvailabilityState = field(default_factory=AvailabilityState)
    health: HealthResult = field(default_factory=HealthResult)
    latency: LatencyInfo = field(default_factory=LatencyInfo)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    _latency_samples: List[float] = field(default_factory=list, repr=False)

    # ------------------------------------------------------- escrita (fatos)
    def record_availability(self, available: bool, source: str = "observed",
                            detail: str = "") -> None:
        """Registra fato de disponibilidade observado (nunca chutado).

        `available` e obrigatoriamente bool: None significa "desconhecido" e
        NAO pode ser coagido a False — isso fabricaria um fato negativo.
        """
        if not isinstance(available, bool):
            raise ValueError(
                "record_availability: 'available' deve ser bool observado; None = "
                "desconhecido (invariante 2) e NAO pode ser coagido a False")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("record_availability: 'source' (procedencia) obrigatoria")
        self.availability = AvailabilityState(available=available, source=source,
                                              detail=detail, updated_at=time.time())

    def record_health(self, healthy: bool, detail: str = "") -> None:
        """Registra resultado de probe (INDEPENDENTE de availability — INV3).

        Nao toca `availability`: probe OK e "disponivel agora" sao dimensoes
        distintas, e nenhuma deriva da outra.
        """
        if not isinstance(healthy, bool):
            raise ValueError(
                "record_health: 'healthy' deve ser bool resultado de um probe; "
                "None = probe nao rodou (invariante 3), nunca False fabricado")
        self.health = HealthResult(healthy=healthy, detail=detail,
                                   checked_at=time.time())

    def record_latency_sample(self, ms: float) -> None:
        """Agrega amostra observada (estatistica descritiva, nao competencia).

        Unico caminho que produz `latency`. Nao existe latencia declarada:
        o schema rejeita `latency.p50_ms` estatico e LatencyInfo exige samples.
        """
        if isinstance(ms, bool) or not isinstance(ms, (int, float)):
            raise ValueError("record_latency_sample: amostra deve ser numero (ms)")
        if not math.isfinite(float(ms)) or float(ms) < 0:
            raise ValueError("record_latency_sample: amostra deve ser >= 0 e finita")
        self._latency_samples.append(float(ms))
        if len(self._latency_samples) > 100:
            self._latency_samples = self._latency_samples[-100:]
        samples = list(self._latency_samples)
        self.latency = LatencyInfo(
            p50_ms=round(statistics.median(samples), 1),
            samples=len(samples), source="observed")

    def record_error(self, error_class: str, message: str = "") -> None:
        if not isinstance(error_class, str) or not error_class.strip():
            raise ValueError("record_error: error_class obrigatorio (string nao-vazia)")
        self.errors.append({"ts": time.time(), "class": error_class, "message": message})

    # --------------------------------------------------------- leitura (fatos)
    def has_availability_fact(self) -> bool:
        """Ha fato de disponibilidade observado? (None => nao; nunca um palpite.)"""
        return self.availability.available is not None

    def snapshot(self) -> Dict[str, Any]:
        """Fatos runtime de UM provider, como dados puros (sem agregacao).

        Nenhum numero aqui e competencia: sao dimensoes separadas
        (INV3/INV4) e o chamador (ROTOR) e quem decide o que fazer com elas.
        """
        return {
            "provider_id": self.provider_id,
            "availability": {
                "available": self.availability.available,
                "source": self.availability.source,
                "detail": self.availability.detail,
            },
            "health": {
                "healthy": self.health.healthy,
                "detail": self.health.detail,
            },
            "latency": {
                "p50_ms": self.latency.p50_ms,
                "samples": self.latency.samples,
                "source": self.latency.source,
            },
            "errors": len(self.errors),
        }


# ─────────────────────────────────────────────────────────────────────────────

def _frozen_meta(d: Optional[Dict[str, Any]]) -> Any:
    return MappingProxyType(dict(d or {}))


def _validate(raw: Any, origin: str) -> ProviderDefinition:
    """Valida o schema de UM arquivo. Coleta TODOS os erros antes de falhar."""
    errs: List[str] = []

    def want(cond: bool, msg: str) -> None:
        if not cond:
            errs.append(msg)

    want(isinstance(raw, dict), "raiz do documento deve ser um mapping")
    if errs:
        raise SchemaError(f"{origin}: " + "; ".join(errs))

    prov = raw.get("provider")
    want(isinstance(prov, dict), "secao 'provider' ausente ou invalida")
    pid = name = None
    if isinstance(prov, dict):
        pid = prov.get("id")
        name = prov.get("name")
        want(isinstance(pid, str) and bool(pid.strip()), "provider.id obrigatorio (string nao-vazia)")
        want(isinstance(name, str) and bool(name.strip()), "provider.name obrigatorio (string nao-vazia)")
        want(set(prov) <= {"id", "name"}, f"provider: chaves desconhecidas {sorted(set(prov) - {'id', 'name'})}")

    caps_raw = raw.get("capabilities")
    want(isinstance(caps_raw, dict), "secao 'capabilities' obrigatoria")
    caps = CapabilityDeclaration()
    if isinstance(caps_raw, dict):
        unknown = set(caps_raw) - set(_CAP_BOOL_KEYS) - {"models", "context_window",
                                                         "context_train_capability",
                                                         "context_runtime_limit"}
        want(not unknown, f"capabilities: chaves desconhecidas {sorted(unknown)}")
        for k in _CAP_BOOL_KEYS:
            if k in caps_raw:
                want(isinstance(caps_raw[k], bool), f"capabilities.{k} deve ser bool")
        models = caps_raw.get("models", [])
        want(isinstance(models, list) and all(isinstance(m, str) for m in models),
             "capabilities.models deve ser lista de strings")
        cw = caps_raw.get("context_window")
        want(cw is None or isinstance(cw, int), "capabilities.context_window deve ser int ou null")
        # R2.1: distincao capacidade nativa x politica de launch (ints declarados)
        for _k in ("context_train_capability", "context_runtime_limit"):
            _v = caps_raw.get(_k)
            want(_v is None or isinstance(_v, int),
                 f"capabilities.{_k} deve ser int ou null (fato declarado, nunca medido)")
        if not errs:
            caps = CapabilityDeclaration(
                **{k: caps_raw[k] for k in _CAP_BOOL_KEYS if k in caps_raw},
                models=tuple(models), context_window=cw,
                context_train_capability=caps_raw.get("context_train_capability"),
                context_runtime_limit=caps_raw.get("context_runtime_limit"))

    transport = raw.get("transport")
    want(isinstance(transport, dict) and "protocol" in transport,
         "secao 'transport' obrigatoria com 'protocol'")
    protocol = endpoint = model_map_raw = None
    if isinstance(transport, dict):
        protocol = transport.get("protocol")
        want(protocol in _ALLOWED_PROTOCOLS,
             f"transport.protocol '{protocol}' fora de {sorted(_ALLOWED_PROTOCOLS)}")
        endpoint = transport.get("endpoint")
        want(endpoint is None or isinstance(endpoint, str), "transport.endpoint deve ser string")
        model_map_raw = transport.get("model_map")
        want(set(transport) <= {"protocol", "endpoint", "model_map"},
             f"transport: chaves desconhecidas {sorted(set(transport) - {'protocol', 'endpoint', 'model_map'})}")
        # R2.2 (INV5): model_map e FATO declarado de traducao
        # {modelo_logico: modelo_transportado}. Validado como schema; a
        # traducao em si executa no transporte (payload build), nunca aqui —
        # o registry apenas CONHECE o vinculo (regra congelada: sem
        # inferencia historica).
        if "model_map" in transport:
            want(isinstance(model_map_raw, dict) and len(model_map_raw) > 0,
                 "transport.model_map deve ser mapping nao-vazio "
                 "{modelo_logico: modelo_transportado}")
            if isinstance(model_map_raw, dict):
                declared_models = set(models) if isinstance(caps_raw, dict) else set()
                for mk, mv in model_map_raw.items():
                    want(isinstance(mk, str) and bool(mk.strip()),
                         f"transport.model_map: chave invalida {mk!r} (string nao-vazia)")
                    want(isinstance(mv, str) and bool(mv.strip()),
                         f"transport.model_map[{mk!r}]: valor invalido (string nao-vazia)")
                    want(mk in declared_models,
                         f"transport.model_map[{mk!r}]: modelo logico fora dos "
                         f"capabilities.models declarados {sorted(declared_models)}")

    # INV2: availability e SEMPRE runtime; o yaml so pode dizer isso.
    avail = raw.get("availability")
    avail_source = None
    if avail is not None:
        want(avail == {"source": "runtime"},
             "availability: unico valor aceito e {source: runtime} — registry NAO "
             "inventa disponibilidade (invariante 2); fato observado mora no runtime state")
        if avail == {"source": "runtime"}:
            avail_source = "runtime"

    # INV3: o yaml declara o METODO de probe; jamais o resultado.
    hraw = raw.get("health")
    probe = None
    if hraw is not None:
        want(isinstance(hraw, dict) and set(hraw) <= {"probe"}
             and hraw.get("probe") in ("active", "passive"),
             "health: so {probe: active|passive} (declaracao do metodo) — resultado "
             "de health e fato observado, mora no runtime state (invariante 3)")

    # INV4: custo pode ser declarado (fato economico); latencia NAO (e observada).
    craw = raw.get("cost")
    cost = None
    if craw is not None:
        if not isinstance(craw, dict):
            errs.append("cost: deve ser mapping com input/output/currency")
        else:
            want(set(craw) <= {"input", "output", "currency"},
                 f"cost: chaves desconhecidas {sorted(set(craw) - {'input', 'output', 'currency'})}")
            for k in ("input", "output"):
                if craw.get(k) is not None:
                    want(isinstance(craw[k], (int, float)) and not isinstance(craw[k], bool),
                         f"cost.{k} deve ser numero ou null")
            want(craw.get("currency") is None or isinstance(craw.get("currency"), str),
                 "cost.currency deve ser string ou null")
            if not errs:
                cost = CostInfo(input=craw.get("input"), output=craw.get("output"),
                                currency=craw.get("currency"), source="declared")

    lraw = raw.get("latency")
    if lraw is not None:
        want(isinstance(lraw, dict) and set(lraw) <= {"p50_ms"}
             and lraw.get("p50_ms") is None,
             "latency: p50_ms estatico rejeitado — latencia e metrica OBSERVADA; "
             "declare nada aqui e use ProviderRuntimeState (invariante 4)")

    meta = raw.get("metadata")
    want(meta is None or isinstance(meta, dict), "metadata deve ser mapping ou ausente")
    if isinstance(meta, dict):
        _forbidden_decision_keys = frozenset({
            "priority", "weight", "quality_score", "rank", "ranking",
            "preferred", "tier", "fallback_order", "preference", "score",
            "selection_policy", "best_for", "fitness"
        })
        forbidden_in_meta = set(meta) & _forbidden_decision_keys
        want(not forbidden_in_meta,
             f"metadata: chaves de decisao ou ranking proibidas {sorted(forbidden_in_meta)} "
             "(invariante 1: Registry nao roteia e nao expressa preferencia)")

    want(set(raw) <= {"provider", "capabilities", "transport", "availability",
                      "health", "cost", "latency", "metadata"},
         f"chaves de topo desconhecidas: {sorted(set(raw) - {'provider', 'capabilities', 'transport', 'availability', 'health', 'cost', 'latency', 'metadata'})}")

    if errs:
        raise SchemaError(f"{origin}: " + "; ".join(errs))
    assert isinstance(pid, str) and isinstance(name, str) and isinstance(protocol, str)
    return ProviderDefinition(id=pid, name=name, capabilities=caps, protocol=protocol,
                              endpoint=endpoint, availability_source=avail_source,
                              health_probe=probe, cost=cost, metadata=_frozen_meta(meta),
                              model_map=(MappingProxyType(dict(model_map_raw))
                                         if model_map_raw else None))


class ProviderRegistry:
    """Registro declarativo. DETERMINISTICO (ids sempre ordenados, sem ordem de
    insercao exposta). Nao roteia, nao pontua, nao inventa disponibilidade."""

    def __init__(self) -> None:
        self._definitions: Dict[str, ProviderDefinition] = {}
        self._runtime: Dict[str, ProviderRuntimeState] = {}
        self.version = OMNIROUTE_REGISTRY_VERSION

    # ------------------------------------------------------------- registro
    def register_definition(self, definition: ProviderDefinition) -> None:
        if not isinstance(definition, ProviderDefinition):
            raise ValueError("esperado ProviderDefinition (use load_file/load_dir para YAML)")
        if definition.id in self._definitions:
            raise ValueError(f"provider duplicado: {definition.id!r} (sem sobrescrita silenciosa)")
        self._definitions[definition.id] = definition
        self._runtime[definition.id] = ProviderRuntimeState(provider_id=definition.id)

    def load_file(self, path: Path) -> int:
        path = Path(path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.register_definition(_validate(raw, origin=str(path)))
        return 1

    def load_dir(self, path: Path) -> int:
        """Carrega todos os *.yaml de um diretorio. ATOMICO: valida tudo antes
        de registrar qualquer coisa; duplicatas (inclusive no lote) abortam sem
        registrar nada."""
        path = Path(path)
        files = sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml"))
        parsed: List[ProviderDefinition] = []
        for f in sorted(files):
            raw = yaml.safe_load(f.read_text(encoding="utf-8"))
            parsed.append(_validate(raw, origin=str(f)))
        seen = set(self._definitions)
        for d in parsed:
            if d.id in seen:
                raise SchemaError(f"duplicata no lote/existente: {d.id!r}")
            seen.add(d.id)
        for d in parsed:
            self.register_definition(d)
        return len(parsed)

    # ---------------------------------------------------------------- leitura
    def __len__(self) -> int:
        return len(self._definitions)

    def __contains__(self, provider_id: object) -> bool:
        return provider_id in self._definitions

    def ids(self) -> List[str]:
        return sorted(self._definitions)

    def get(self, provider_id: str) -> Optional[ProviderDefinition]:
        """Lookup por ID. Definicao e frozen — imutavel por construcao."""
        return self._definitions.get(provider_id)

    def capabilities_of(self, provider_id: str) -> Optional[CapabilityDeclaration]:
        d = self._definitions.get(provider_id)
        return d.capabilities if d else None

    def to_contract_capabilities(self, provider_id: str) -> Optional[ProviderCapabilities]:
        """Ponte para o contrato P0 (traducao de tipo, zero decisao)."""
        d = self._definitions.get(provider_id)
        return d.capabilities.to_contract() if d else None

    def runtime(self, provider_id: str) -> Optional[ProviderRuntimeState]:
        """Estado runtime SEPARADO da definicao (P1.1)."""
        return self._runtime.get(provider_id)

    def runtime_all(self) -> Dict[str, ProviderRuntimeState]:
        return {k: self._runtime[k] for k in sorted(self._runtime)}

    def resolve_wire_model(self, provider_id: str, logical_model: str) -> str:
        """Resolve o identificador fisico (no fio) para um modelo logico (R2.2/R2.3).

        Identidades distintas e reconciliadas:
            provider_id != backend_id != model_id

        Apenas executa a traducao estatica declarada em transport.model_map.
        NUNCA infere, nunca escolhe provider, nunca calcula score.
        """
        defn = self.get(provider_id)
        if defn is None:
            raise KeyError(f"provider {provider_id!r} desconhecido")
        mm = dict(defn.model_map) if defn.model_map else {}
        return mm.get(logical_model, logical_model)
