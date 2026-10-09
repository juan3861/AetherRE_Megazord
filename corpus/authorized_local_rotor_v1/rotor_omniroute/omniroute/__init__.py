"""OmniRoute — camada de transporte independente (Fase 3, P0).

Uso (composicao acontece NO CHAMADOR — nunca dentro de router/ nem daqui):

    from omniroute import OmniRoute, ProviderRequest
    route = OmniRoute()
    route.register(MyAdapter())          # adapter implementa o contrato P0
    resp = route.dispatch(
        ProviderRequest(request_id="r1", model="gpt-oss-20b", body={...}),
        provider_name="llamacpp-local",  # decidido por ROTOR/chamador
    )
    if not resp.ok: print(resp.error)    # erro normalizado, nunca excecao crua

Independencia (testada): este pacote nao importa nada de router/; nenhum
modulo de router/ importa este pacote. Ver tests/test_omniroute.py.
"""
from .core import OmniRoute  # noqa: F401
from .credentials import CredentialPolicy  # noqa: F401
from .history import HistoricalAggregator, HistoricalMetrics  # noqa: F401
from .observation import RuntimeObservationRecord, RuntimeObserver, create_observation  # noqa: F401
from .provider import (  # noqa: F401
                       OMNIROUTE_VERSION,
                       ProviderAdapter,
                       ProviderCapabilities,
                       ProviderOperatingState,
                       ProviderRequest,
                       ProviderResponse,
)

__all__ = ["OMNIROUTE_VERSION", "ProviderAdapter", "ProviderCapabilities",
           "ProviderOperatingState", "ProviderRequest", "ProviderResponse",
           "CredentialPolicy", "OmniRoute",
           "RuntimeObservationRecord", "create_observation", "RuntimeObserver",
           "HistoricalMetrics", "HistoricalAggregator"]

