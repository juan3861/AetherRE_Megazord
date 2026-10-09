"""OmniRoute R4 — Historical Observation Aggregator & Factual Telemetry.

Constitutional Invariant:
  R3: "Happened X"
  R4: "In the last N events (or window T), happened X times, with latency percentiles P"
  F5: "Therefore, for THIS request, choose Y"

R4 is strictly a factual statistical aggregator.
Prohibited: routing, provider selection, winner, ranking, priority, weight, quality_score, fallback.
"""
from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from omniroute.observation import RuntimeObservationRecord


@dataclass(frozen=True, slots=True)
class HistoricalMetrics:
    provider_id: str
    backend_id: Optional[str] = None
    model_id: Optional[str] = None
    wire_model: Optional[str] = None

    window_start: float = 0.0
    window_end: float = 0.0
    sample_count: int = 0

    success_count: int = 0
    error_count: int = 0
    timeout_count: int = 0
    http_error_count: int = 0
    connection_error_count: int = 0
    empty_response_count: int = 0

    success_rate: float = 0.0

    latency_mean: float = 0.0
    latency_min: float = 0.0
    latency_max: float = 0.0
    latency_p50: float = 0.0
    latency_p95: float = 0.0
    latency_p99: float = 0.0

    ttft_mean: Optional[float] = None
    ttft_p50: Optional[float] = None
    ttft_p95: Optional[float] = None

    tokens_in_total: int = 0
    tokens_out_total: int = 0
    tokens_in_mean: float = 0.0
    tokens_out_mean: float = 0.0


def _percentile(values: Sequence[float], p: float) -> float:
    """Calculate percentile using linear interpolation between closest ranks."""
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    sorted_v = sorted(values)
    k = (len(sorted_v) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_v[int(k)]
    d0 = sorted_v[int(f)] * (c - k)
    d1 = sorted_v[int(c)] * (k - f)
    return d0 + d1


class HistoricalAggregator:
    """Passive historical observation aggregator."""

    def __init__(self, max_history: int = 10000):
        self.max_history = max_history
        self._history: deque[RuntimeObservationRecord] = deque(maxlen=max_history)
        self._lock = threading.Lock()

    def record(self, observation: RuntimeObservationRecord) -> None:
        """Ingest a single 1:1 runtime observation from R3."""
        if not isinstance(observation, RuntimeObservationRecord):
            raise TypeError("HistoricalAggregator.record requires RuntimeObservationRecord instance")
        with self._lock:
            self._history.append(observation)

    def record_many(self, observations: Sequence[RuntimeObservationRecord]) -> None:
        """Ingest multiple runtime observations."""
        with self._lock:
            for obs in observations:
                if isinstance(obs, RuntimeObservationRecord):
                    self._history.append(obs)

    def get_metrics(
        self,
        provider_id: str,
        backend_id: Optional[str] = None,
        model_id: Optional[str] = None,
        wire_model: Optional[str] = None,
        window_seconds: Optional[float] = None,
        last_n: Optional[int] = None,
    ) -> HistoricalMetrics:
        """Calculate statistical metrics for specified dimensions and window."""
        with self._lock:
            records = list(self._history)

        now = time.time()
        filtered: List[RuntimeObservationRecord] = []

        for r in records:
            if r.provider_id != provider_id:
                continue
            if backend_id is not None and r.backend_id != backend_id:
                continue
            if model_id is not None and r.model_id != model_id:
                continue
            if wire_model is not None and r.wire_model != wire_model:
                continue
            if window_seconds is not None:
                if (now - r.observed_at) > window_seconds:
                    continue
            filtered.append(r)

        if last_n is not None and last_n > 0:
            filtered = filtered[-last_n:]

        sample_count = len(filtered)
        if sample_count == 0:
            return HistoricalMetrics(
                provider_id=provider_id,
                backend_id=backend_id,
                model_id=model_id,
                wire_model=wire_model,
                window_start=now - (window_seconds or 0),
                window_end=now,
                sample_count=0,
            )

        success_count = sum(1 for r in filtered if r.success)
        error_count = sample_count - success_count
        timeout_count = sum(1 for r in filtered if r.status == "timeout")
        http_error_count = sum(1 for r in filtered if r.status == "http_error")
        connection_error_count = sum(1 for r in filtered if r.status == "connection_error")
        empty_response_count = sum(1 for r in filtered if r.status == "empty_response")
        success_rate = round(success_count / sample_count, 4)

        latencies = [r.latency_ms for r in filtered if math.isfinite(r.latency_ms)]
        latency_mean = round(sum(latencies) / len(latencies), 3) if latencies else 0.0
        latency_min = round(min(latencies), 3) if latencies else 0.0
        latency_max = round(max(latencies), 3) if latencies else 0.0
        latency_p50 = round(_percentile(latencies, 50), 3) if latencies else 0.0
        latency_p95 = round(_percentile(latencies, 95), 3) if latencies else 0.0
        latency_p99 = round(_percentile(latencies, 99), 3) if latencies else 0.0

        ttfts = [r.ttft_ms for r in filtered if r.ttft_ms is not None and math.isfinite(r.ttft_ms)]
        ttft_mean = round(sum(ttfts) / len(ttfts), 3) if ttfts else None
        ttft_p50 = round(_percentile(ttfts, 50), 3) if ttfts else None
        ttft_p95 = round(_percentile(ttfts, 95), 3) if ttfts else None

        in_toks = [r.input_tokens for r in filtered if r.input_tokens is not None]
        out_toks = [r.output_tokens for r in filtered if r.output_tokens is not None]
        tokens_in_total = sum(in_toks)
        tokens_out_total = sum(out_toks)
        tokens_in_mean = round(tokens_in_total / len(in_toks), 1) if in_toks else 0.0
        tokens_out_mean = round(tokens_out_total / len(out_toks), 1) if out_toks else 0.0

        w_start = min(r.observed_at for r in filtered)
        w_end = max(r.observed_at for r in filtered)

        return HistoricalMetrics(
            provider_id=provider_id,
            backend_id=backend_id,
            model_id=model_id,
            wire_model=wire_model,
            window_start=w_start,
            window_end=w_end,
            sample_count=sample_count,
            success_count=success_count,
            error_count=error_count,
            timeout_count=timeout_count,
            http_error_count=http_error_count,
            connection_error_count=connection_error_count,
            empty_response_count=empty_response_count,
            success_rate=success_rate,
            latency_mean=latency_mean,
            latency_min=latency_min,
            latency_max=latency_max,
            latency_p50=latency_p50,
            latency_p95=latency_p95,
            latency_p99=latency_p99,
            ttft_mean=ttft_mean,
            ttft_p50=ttft_p50,
            ttft_p95=ttft_p95,
            tokens_in_total=tokens_in_total,
            tokens_out_total=tokens_out_total,
            tokens_in_mean=tokens_in_mean,
            tokens_out_mean=tokens_out_mean,
        )

    def get_all_metrics(
        self,
        window_seconds: Optional[float] = None,
        last_n: Optional[int] = None,
    ) -> Dict[str, HistoricalMetrics]:
        """Return metrics for all active provider_ids observed in the window."""
        with self._lock:
            providers = set(r.provider_id for r in self._history)
        return {
            pid: self.get_metrics(pid, window_seconds=window_seconds, last_n=last_n)
            for pid in sorted(providers)
        }

    def clear(self) -> None:
        with self._lock:
            self._history.clear()

    @property
    def total_records(self) -> int:
        with self._lock:
            return len(self._history)
