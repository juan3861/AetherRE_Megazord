"""FASE 3 P2 — GATE de equivalencia comportamental (antigo path x OmniRoute).

Criterio do dono do roadmap: "mesmo input + mesma politica + mesmo provider ->
comportamento equivalente". Este teste roda os dois paths LADO A LADO contra o
mesmo endpoint stub e compara as 11 dimensoes exigidas:

  provider chamado | payload enviado | resposta | erro | timeout |
  retry/fallback (1 tentativa em ambos) | disponibilidade | latencia |
  telemetria | request_id | provider indisponivel

PROIBICOES do P2 verificadas por indirecao aqui: nada disso exige alterar
F5, scoring, competencia ou fallback — os paths sao executados como estao.
"""
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "tests"))

from _omniroute_stub import run_equivalence_scenarios  # noqa: E402

REQUIRED_DIMENSIONS = ["provider_called", "payload_sent", "response", "error",
                       "timeout", "retry_fallback_single_attempt", "availability",
                       "latency_recorded", "telemetry", "request_id",
                       "unavailable_provider"]


def test_p2_behavioral_equivalence_gate():
    out = run_equivalence_scenarios()
    dims = out["dimensions"]
    for d in REQUIRED_DIMENSIONS:
        assert dims.get(d) is True, f"dimensao de equivalencia FALHOU: {d}\n" \
                                    f"cenario: {out['scenarios']}"
    assert out["equivalent"] is True
    # diferencas estruturais declaradas (aditivas, nao comportamentais)
    assert out["structural_differences"], "diferencas aditivas devem estar documentadas"
    # timeout bounded em ambos os paths
    assert out["scenarios"]["timeout"]["old_elapsed_s"] < 5.0
    assert out["scenarios"]["timeout"]["new_elapsed_s"] < 5.0


if __name__ == "__main__":
    sys.exit(__import__("pytest").main([__file__, "-v"]))
