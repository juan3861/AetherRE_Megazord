# Tipos PDB opcionais no caso universal

`CasePolicy` aceita `debug_pdb`, `dia_helper` e `dia_dll` somente como conjunto completo com `request_native_reconstruction=True`. Configuração parcial, vazia ou de tipo inválido é recusada antes de intake ou worker. CLI `universal` expõe as três opções; a rota explícita JavaScript recusa o pedido de tipos nativos.

O pedido PDB é aplicável ao perfil `native-pe`. Outros perfis registram `debug_types_require_native_pe`, sem solicitar DIA. A reconstrução IR suportada pelo perfil continua disponível, com ausência de adaptador explícita. Isso não acrescenta suporte DWARF.

O caso PE executa uma extração DIA sobre o snapshot de intake, com o contrato de [PDB/DIA](PDB_DIA_TYPE_CONTRACT.md). O relatório observado é publicado create-only como `native_debug_types.json`, até8MiB em UTF-8 incluindo indentação e newline. O resultado nativo referencia caminho/SHA-256, binding, cobertura, hashes e worker. Os snapshots privados são preservados sob `native_debug_worker`; há uma extração por caso, sem repetir o helper para cada função.

O seletor Ghidra aceita `debug_report` pré-observado para reutilização interna. Relatório e paths de ferramentas não podem ser misturados. A seleção continua revalidando o payload High P-Code e, por função, digests do relatório, hash do alvo, RVA único e tipo de retorno suportado. A aceitação desse objeto em processo comprova consistência com os digests fornecidos; não autentica um produtor que controla os dados e os próprios digests.

A tradução IR bruta é preservada quando o debug falha, está parcial, foi alterado, não suporta o retorno ou exige bits ausentes no IR. Nesses casos `debug_return_adapter.status=unavailable`, há motivo explícito e o caso nativo é parcial. Não se recupera assinatura original ou ABI de entrada com esse adaptador.

Denominadores separados: `total_functions`, `attempted_functions`, `reconstructed_functions`, `unsupported_functions`, `debug_adapted_functions` e `debug_unavailable_functions`. Para pedido debug, os dois últimos somam as funções tentadas; sem pedido, ambos ficam zero. A quota de8MiB do envelope nativo inclui adaptadores, grafos, metadados, contadores e formatação final. Uma função que não cabe não entra no denominador de tentadas e `truncated=true` permanece explícito.

Certificação continua `abstained`; `dynamic_status=not_requested` para o caso estático. A DLL analisada não é executada. Prova real de cliente local, testes e revisão interna não constituem VM/restore, cliente cloud E2E, corpus externo, WORM, recuperação da fonte original ou certificação F00–F12.
