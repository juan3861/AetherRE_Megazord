"""OmniRoute R3 — Runtime Observation Sensor (Fatos observados discretos 1:1).

Regra nuclear (Marco R3):
  "O R3 pode observar que um provider foi ruim sem ter permissão para concluir
   que ele é ruim."

Fronteira ontológica:
  A8 = Transporte protegido (execução)
  R2 = Conhecimento factual protegido (declaração / proveniência)
  R3 = Realidade operacional observada (sensor passivo 1:1)
  R4 = Histórico e telemetria temporal (agregações / séries)
  F5 = Inteligência de decisão soberana (ROTOR)

Invariantes de R3:
  1. Sensor passivo: zero lógica decisória, zero ranking, zero preferência.
  2. Zero agregação: R3 não conhece R4; não calcula médias, p50/p95, taxas ou scores.
  3. Integridade factual: latency_ms é estritamente derivado de (finished_at - started_at) * 1000;
     status e success possuem correlação lógica consistente.
  4. Identidade quádrupla: preserva provider_id, backend_id, model_id e wire_model.
  5. Medição estrita de tokens: apenas valores aferidos localmente pelo runtime;
     declarações externas de usage pertencem a R2/proveniência, não ao R3.
  6. Falha-segura (Fail-Open): a observação nunca interrompe ou degrada o transporte.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

_VALID_STATUSES: Set[str] = {
    "success",
    "http_error",
    "timeout",
    "connection_error",
    "empty_response",
}


@dataclass(frozen=True, slots=True)
class RuntimeObservationRecord:
    """Registro atômico de uma observação de runtime 1:1. Imutável por construção."""

    request_id: str
    provider_id: str
    backend_id: str
    model_id: str
    wire_model: str
    started_at: float
    finished_at: float
    latency_ms: float
    ttft_ms: Optional[float] = None
    status: str = "success"
    http_status: Optional[int] = None
    error_class: Optional[str] = None
    error_message: Optional[str] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    streamed: bool = False
    success: bool = True
    observed_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        # 1. Identificadores obrigatórios
        for attr in ("request_id", "provider_id", "backend_id", "model_id", "wire_model"):
            val = getattr(self, attr)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"RuntimeObservationRecord: '{attr}' deve ser string não-vazia")

        # 2. Consistência cronológica
        if not math.isfinite(self.started_at) or not math.isfinite(self.finished_at):
            raise ValueError("RuntimeObservationRecord: timestamps started_at e finished_at devem ser finitos")
        if self.finished_at < self.started_at:
            raise ValueError(
                f"Inconsistência cronológica: finished_at ({self.finished_at}) < started_at ({self.started_at})"
            )

        # 3. Derivação e integridade estrita de latency_ms
        if not math.isfinite(self.latency_ms) or self.latency_ms < 0:
            raise ValueError("RuntimeObservationRecord: latency_ms deve ser número finito >= 0")
        expected_latency = (self.finished_at - self.started_at) * 1000.0
        if abs(self.latency_ms - expected_latency) > 1.5:  # tolerância de 1.5ms para precisão de ponto flutuante
            raise ValueError(
                f"Inconsistência factual de latência: latency_ms={self.latency_ms:.3f} "
                f"difere de finished_at - started_at ({expected_latency:.3f}ms)"
            )

        # 4. Consistência de ttft_ms
        if self.ttft_ms is not None:
            if not math.isfinite(self.ttft_ms) or self.ttft_ms < 0:
                raise ValueError("RuntimeObservationRecord: ttft_ms deve ser número finito >= 0 ou None")
            if self.ttft_ms > self.latency_ms + 1.5:
                raise ValueError(
                    f"Inconsistência de ttft: ttft_ms ({self.ttft_ms:.3f}) não pode exceder latency_ms ({self.latency_ms:.3f})"
                )

        # 5. Validação de status e correlação de success
        if self.status not in _VALID_STATUSES:
            raise ValueError(
                f"RuntimeObservationRecord.status inválido: {self.status!r}. "
                f"Valores permitidos: {sorted(_VALID_STATUSES)}"
            )

        if not isinstance(self.success, bool):
            raise ValueError("RuntimeObservationRecord: 'success' deve ser booleano estrito")

        if self.success:
            if self.status != "success":
                raise ValueError(
                    f"Inconsistência factual: success=True exige status='success', recebido status={self.status!r}"
                )
            if self.http_status is not None and self.http_status >= 400:
                raise ValueError(
                    f"Inconsistência factual: success=True incompatível com http_status={self.http_status}"
                )
            if self.error_class is not None:
                raise ValueError(
                    f"Inconsistência factual: success=True não pode conter error_class={self.error_class!r}"
                )
        else:
            if self.status == "success":
                raise ValueError(
                    "Inconsistência factual: success=False não pode ter status='success'"
                )

        # 6. Tokens: estritamente None ou int >= 0 (medição local comprovada)
        for tok_attr in ("input_tokens", "output_tokens"):
            tval = getattr(self, tok_attr)
            if tval is not None:
                if not isinstance(tval, int) or isinstance(tval, bool) or tval < 0:
                    raise ValueError(f"RuntimeObservationRecord.{tok_attr} deve ser int >= 0 ou None")

        # 7. Flags e tipos
        if not isinstance(self.streamed, bool):
            raise ValueError("RuntimeObservationRecord: 'streamed' deve ser bool")

    def as_dict(self) -> Dict[str, Any]:
        """Serialização factual discreta."""
        return {
            "request_id": self.request_id,
            "provider_id": self.provider_id,
            "backend_id": self.backend_id,
            "model_id": self.model_id,
            "wire_model": self.wire_model,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "latency_ms": self.latency_ms,
            "ttft_ms": self.ttft_ms,
            "status": self.status,
            "http_status": self.http_status,
            "error_class": self.error_class,
            "error_message": self.error_message,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "streamed": self.streamed,
            "success": self.success,
            "observed_at": self.observed_at,
        }


def create_observation(
    request_id: str,
    provider_id: str,
    backend_id: str,
    model_id: str,
    wire_model: str,
    started_at: float,
    finished_at: float,
    status: str = "success",
    http_status: Optional[int] = None,
    ttft_ms: Optional[float] = None,
    error_class: Optional[str] = None,
    error_message: Optional[str] = None,
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
    streamed: bool = False,
    observed_at: Optional[float] = None,
) -> RuntimeObservationRecord:
    """Fábrica determinística de observação de runtime.

    Calcula latency_ms = (finished_at - started_at) * 1000 automaticamente,
    garantindo que não haja duas fontes de verdade.
    Deriva success = (status == "success").
    """
    latency_ms = max(0.0, (finished_at - started_at) * 1000.0)
    success = (status == "success")

    clean_err_msg = str(error_message)[:200] if error_message else None

    kwargs: Dict[str, Any] = {
        "request_id": request_id,
        "provider_id": provider_id,
        "backend_id": backend_id,
        "model_id": model_id,
        "wire_model": wire_model,
        "started_at": started_at,
        "finished_at": finished_at,
        "latency_ms": latency_ms,
        "ttft_ms": ttft_ms,
        "status": status,
        "http_status": http_status,
        "error_class": error_class,
        "error_message": clean_err_msg,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "streamed": streamed,
        "success": success,
    }
    if observed_at is not None:
        kwargs["observed_at"] = observed_at

    return RuntimeObservationRecord(**kwargs)


class RuntimeObserver:
    """Coletor passivo de observações de runtime com garantia Fail-Open.

    Esta classe é um SENSOR passivo:
      - Registra fatos emitidos por despachos;
      - Repassa eventos para ouvintes registrados (ex: sink de arquivo ou telemetria);
      - ZERO inteligência: não compara providers, não calcula médias, não altera chamadas;
      - Fail-Open absoluto: se qualquer sink falhar, a exceção é capturada silenciosamente
        e o transporte continua sem impacto.
    """

    def __init__(self) -> None:
        self._sinks: List[Callable[[RuntimeObservationRecord], None]] = []
        self._buffer: List[RuntimeObservationRecord] = []
        self._max_buffer: int = 1000

    def add_sink(self, sink: Callable[[RuntimeObservationRecord], None]) -> None:
        """Registra um ouvinte para receber observações brutas."""
        if callable(sink):
            self._sinks.append(sink)

    def record(self, observation: RuntimeObservationRecord) -> bool:
        """Registra uma observação discretizada com isolamento Fail-Open.

        Retorna True se registrada com sucesso, False em caso de falha absorvida.
        NUNCA lança exceção para a camada chamadora.
        """
        if not isinstance(observation, RuntimeObservationRecord):
            return False

        try:
            # Manutenção de buffer em memória (limitado, sem agregação)
            self._buffer.append(observation)
            if len(self._buffer) > self._max_buffer:
                self._buffer.pop(0)

            # Despacho para sinks registrados
            for sink in self._sinks:
                try:
                    sink(observation)
                except Exception:
                    pass  # Fail-open: falha de sink secundário nunca interrompe

            return True
        except Exception:
            return False  # Fail-open absoluto

    def recent_records(self) -> List[RuntimeObservationRecord]:
        """Retorna cópia rasa dos registros recentes observados (ordem temporal)."""
        return list(self._buffer)

    def clear(self) -> None:
        """Limpa o buffer recente."""
        self._buffer.clear()
