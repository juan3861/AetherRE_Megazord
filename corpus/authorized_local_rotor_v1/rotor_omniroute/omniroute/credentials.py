"""OmniRoute Credential Policy — gerenciamento de pools de credenciais/tokens.

Separação de responsabilidades:
  - ROTOR / Providers: decisão cognitiva e seleção de provider. Zero conhecimento de tokens.
  - OmniRoute / Adapter / CredentialPolicy: transporte + credenciais de acesso e rotação.
"""
from __future__ import annotations

from typing import Dict, List, Optional


class CredentialPolicy:
    """Gerencia um pool de tokens de autenticação Bearer para um adaptador de transporte.
    
    A rotação de credenciais é isolada na camada de transporte (OmniRoute),
    mantendo a propriedade: rotação de credenciais != seleção de provider.
    """

    def __init__(self, tokens: Optional[List[str]] = None):
        self._tokens = [str(t).strip() for t in (tokens or []) if t and not str(t).startswith("${")]
        self._idx = 0

    @property
    def has_tokens(self) -> bool:
        return len(self._tokens) > 0

    @property
    def tokens(self) -> List[str]:
        return list(self._tokens)

    def current_auth_header(self) -> Dict[str, str]:
        """Retorna o cabeçalho Authorization com o token ativo."""
        if not self._tokens:
            return {}
        tok = self._tokens[self._idx % len(self._tokens)]
        return {"Authorization": f"Bearer {tok}"}

    def rotate(self) -> Optional[str]:
        """Rotaciona para o próximo token no pool."""
        if not self._tokens:
            return None
        self._idx = (self._idx + 1) % len(self._tokens)
        return self._tokens[self._idx]

    def attempts(self):
        """Generator de auth headers para cada token do pool, na ordem de rotação.

        Encapsula a política de credencial: 'quantas tentativas' e 'qual token
        usar em cada tentativa' pertencem ao CredentialPolicy, não ao chamador.
        O chamador itera e usa o header; não conhece o pool, não decide quando
        rotacionar, não conhece o número de tokens.

        Garante equivalência semântica com o loop anterior:
            tokA → falha → tokB → falha → (esgotado)
        A decisão de parar (BackendError) ao esgotar pertence ao chamador,
        que simplesmente percebe que o generator acabou.

        Yields:
            dict[str, str]: cabeçalho Authorization com o token da tentativa.
        """
        for i in range(len(self._tokens)):
            tok = self._tokens[(self._idx + i) % len(self._tokens)]
            yield {"Authorization": f"Bearer {tok}"}
