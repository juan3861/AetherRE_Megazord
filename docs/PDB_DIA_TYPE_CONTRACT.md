# PDB/DIA — símbolos, tipos observados e adaptador de retorno

O lote08 amplia `tools/dia_extract.cpp` e `aether_re/pdb_dia.py`, sem criar outro backend. O helper é uma ferramenta de análise fornecida explicitamente pelo operador; o alvo PE não é carregado ou executado. SDK/helper/PDB/PE são capturados e hashados antes da leitura. Informações de debug vinculadas são evidência observada; não provam comportamento ou recuperação universal da fonte/ABI.

## Execução e identidade

`extract_pdb_symbols(pdb_path, helper_path=..., dia_dll=..., binary_path=None, temp_work_dir=None)` usa snapshots privados e `run_bounded` com árvore requerida, memória, timeout e captura limitados. Recusa exit não zero, timeout, exaustão, captura incompleta, árvore não contida, links/hardlinks, alteração dos snapshots e JSON inválido/duplicado/não finito. As contagens, enumerações e capacidades são validadas; claims ou campos desconhecidos não atravessam o contrato como prova. Falhas preservam metadados do worker e hashes já capturados. `temp_work_dir` conserva snapshots; sem ele, a área privada é temporária.

Há reserva para os bytes dos snapshots mais128MiB. O temporário padrão precisa ter espaço; caso contrário tenta `~/.aetherre/tmp`. Destino explícito sem reserva é recusado. Essa seleção foi necessária quando TEMP físico em E: ficou sem espaço; não apaga dados. O inventário deste lote não é WORM.

Com PE fornecido, os hashes capturados do helper e da DLL DIA devem diferir do hash do alvo. Igualdade é recusada antes de iniciar o worker, inclusive para cópias em caminhos distintos. Isso evita solicitar execução do alvo como helper ou seu carregamento como DLL DIA.

Quando PE é fornecido, o consumidor lê seu CodeView RSDS e exige GUID, age e machine compatíveis com o PDB lido. O mapeamento do diretório exige intervalo dentro de SizeOfImage e dentro dos headers ou de uma seção com bytes no arquivo. Não há fallback arbitrário RVA→offset bruto. RVA e PointerToRawData do payload, quando ambos fornecidos, devem concordar; diretório/payload truncado, fora de intervalo ou mapeado de modo ambíguo é recusado. `target_identity_bound` é separado de `target_types_bound`: o segundo exige também o inventário de tipos completo observado.

## Tipos e denominadores

O schema de símbolos v1 permanece, com capacidade opcional `function_types`. Cada função tem symIndexId, RVA e referência ao tipo da assinatura. O grafo tem nós por ID, tag, nome, largura em bytes, BasicType, count, calling convention, target e parâmetros ordenados quando disponíveis. Propriedade com S_FALSE é null, nunca um zero inventado. FunctionType aponta para retorno e tipos dos argumentos; pointer/array/typedef/enum usam referências. UDT é explicitamente `opaque_layout=true`; campos, bases, qualifiers e layout completo não são recuperados aqui.

Limites:8192 tipos,65536 consultas/arestas,512 parâmetros por assinatura e max_symbols explícito. A enumeração verifica uma entrada adicional para distinguir limite exato de truncamento. `type_count`, `type_edges`, referências, tags/BasicType, propriedades essenciais, contagem de parâmetros, completude e formas contraditórias são conferidos. Truncamento ou tipos incompletos produzem partial. `type_coverage` separa funções totais, assinaturas observadas, tipos e layouts opacos. Ausência de capacidade antiga é unavailable para tipos, sem inventar grafo.

A capacidade `function_types` exige `enumeration_complete` boolean explícito; ausência é contrato inválido. `false` mantém o resultado parcial. A compatibilidade com o helper antigo sem tipos não implica comprovação de enumeração do contrato novo.

Digest do payload bruto normalizado e digest de binding/hashes capturados detectam mutações do relatório em processo. Não são assinatura de terceiro nem defesa contra alguém que controla host, dados e digests. `type_recovery_proved`, `binary_equivalence_proved` e `original_source_recovered` continuam false.

## Retorno escalar separado da tradução IR

`pdb_return_contract` exige relatório completo vinculado ao SHA-256 do PE e uma função única no RVA solicitado. Resolve enum/typedef com detecção de ciclo e aceita somente inteiros signed/unsigned de1/2/4/8 bytes com BasicType suportado. Tipo ausente, não escalar, ambiguidade ou digest alterado abstêm.

`GhidraDecompilationResult.select_reconstruction(..., debug_pdb=..., dia_helper=..., dia_dll=...)` lê o PDB com vínculo ao mesmo binário e calcula RVA a partir da base/endereço do programa. Mantém `structured_c_source` do IR observado e acrescenta `debug_return_adapter`: wrapper separado que restringe os bits definidos pelo retorno de debug e transporta interpretação signed em unsigned64. Não amplia bits ausentes no IR. A assinatura de entrada continua transportando varnodes; mapeamento de parâmetros/registradores e ABI completa não são recuperados por esse wrapper.

CLI: `ghidra-decompile TARGET --reconstruct-function NAME --debug-pdb PDB --dia-helper HELPER --dia-dll DLL --out NOVO.json`. MCP usa os campos homônimos. Configuração parcial ou sem seleção de reconstrução é recusada antes do worker. Não se altera o High P-Code bruto usando a fonte de referência.

## Provas e limites atuais

Evidência em `C:/Users/juanp/Documents/Codex/audits/aetherre-20261028/implementation-08/`. Baseline real do helper antigo:2 símbolos e identidade PE/PDB compatível, sem tipos. Contraprovas reproduziram falso complete com exit7/captura/árvore inválidas, inventários/claims incorretos, vínculo por RVA não mapeado ou fora de SizeOfImage, hardlink pós-worker e formas de tipos inconsistentes; os REDs foram preservados.

Helper novo real: PDB próprio vinculado identifica narrow1byte, wide4bytes e parâmetros4bytes. Corpus nativo adicional:6 funções/19 tipos, ordem de parâmetros mistos1/8/2bytes, signed char, pointer→UDT opaco, function pointer, pointer→array de3elementos/12bytes, void e enumeração exata/parcial. A DLL não foi executada.

Coleta própria Ghidra+PDB+adaptador:456 comparações em MSVC Od/O2 sem divergência do adaptador contra referência/Python. O IR bruto preservado teve210 divergências de retorno integral da função narrow nessa coleta. GUID e age divergentes foram recusados em leituras reais. Depois da correção SizeOfImage, nova leitura DIA/parser regenerou contratos/fontes idênticos aos compilados, com hashes vinculados ao receipt anterior. Corpus do revisor para adaptador signed/unsigned8/16/32/64 usa DIA/vínculo simulados e tem escopo separado da prova nativa.

Somente executáveis próprios benignos de validação foram executados em processos contidos. Não é VM/restore, amostra hostil, holdout independente ou auditoria humana externa. Binários stripped sem debug, DWARF integrado, tipos complexos completos, memória/chamadas, ABI, replay/carga, WORM e gates globais continuam em dívida. A contraprova histórica292 do lote07 não foi apagada nem retroativamente quitada.

Referências primárias: [FunctionType](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/functiontype), [IDiaSymbol::get_type](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiasymbol-get-type), [BasicType](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/basictype), [IDiaSymbol::get_length](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiasymbol-get-length), [DIA PDB identity validation](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiadatasource-loadandvalidatedatafrompdb).
