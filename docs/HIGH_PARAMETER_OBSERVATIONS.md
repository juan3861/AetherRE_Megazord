# Parâmetros observados após a decompilação

O exportador estático pode publicar `high_parameter_observation` por função. É uma observação do `LocalSymbolMap`/`HighSymbol` do Ghidra depois de `decompileFunction`, separada de `storage_observation`, que descreve a base do programa antes dessa chamada. A quantidade de parâmetros pode divergir entre os estágios. Nenhuma quantidade é promovida automaticamente a aridade original do fonte.

## Contrato de admissão

Schema `observed-high-parameters.v1`, com `stage=high_function_after_decompilation`, SHA256 do alvo e endereço canônico da função. A observação exige o IR correspondente no mesmo registro. O parser valida identidade, shape, tipos exatos, ordinais contíguos e referências a IDs que efetivamente existem no inventário do IR. O campo é opcional para exports históricos; se estiver presente e inválido, o export é recusado.

Cada parâmetro registra ordinal do inventário, category_index, nome, datatype name/tamanho e flags is_parameter/hidden_return/this_pointer/type_locked/name_locked. Esses são dados observados da ferramenta; flags falsas não provam ausência de argumentos ocultos e locks não provam tipos originais.

`instances.available` distingue uma HighVariable disponível de sua ausência. Quando disponível, `total` conta todas as instâncias devolvidas pela API, `observed` preserva somente os IDs existentes no IR exportado e `omitted` conta as restantes. `total = len(observed) + omitted`. Uma instância omitida não é um parâmetro fabricável. Quando a HighVariable está indisponível, a disponibilidade é falsa e as listas/contagens ficam vazias/zero; não se alega enumeração conhecida.

Limites: 128 parâmetros, 32768 instâncias no total, nomes/tipos com até 4096 caracteres e 256 KiB para a representação compacta de orçamento. Essa representação é JSON UTF-8, sem espaços de separadores, sem escape HTML e com escape de U+2028/U+2029 conforme o Gson instalado. Não depende da ordem dos membros do objeto para medir bytes. O limite global do resumo e os demais limites do export continuam aplicáveis. A representação foi comparada com a biblioteca Java real; aumentar margem não substitui alinhar os dois lados.

## Associação publicada pela reconstrução

`high_parameter_input_associations` tem schema `observed-high-parameter-input-associations.v1`. Associa somente IDs que constam como input no IR verificado e como instâncias observadas do HighSymbol. Não converte instâncias intermediárias em inputs, não amplia registradores, não reordena argumentos e não cria varnodes.

Um input associado a vários parâmetros produz `ambiguous_input_association`; o parâmetro sem input observado produz `no_observed_input`. Os IDs sem associação admitida ficam em `unbound_inputs`, com metadados observados de espaço/offset/largura/persistência/unaffected. A contagem de instâncias omitidas permanece visível. As associações preservam pertencimento no modelo do decompilador; não são prova de igualdade entre largura do tipo observado e largura dos valores, nem de layout original de ABI.

`complete` cobre exclusivamente esse inventário de associações: IR estruturalmente válido, sem live-ins não resolvidos, todos os inputs associados sem ambiguidade, cada parâmetro com associação, enumerações disponíveis e nenhuma instância omitida. Um inventário vazio pode satisfazer essas condições mesmo quando o decompilador perdeu argumentos presentes no fonte. Portanto `abi_recovered=false`, `source_parameter_count_proved=false` e `call_semantics_proved=false` são obrigatórios, inclusive quando `complete=true`.

O digest canônico capturado na admissão é conferido antes de reconstruir, inclusive se a observação tiver sido removida. O relatório publica o digest da observação e a referência ao IR. Essa proteção detecta mutação em memória; a proveniência binária exige o export verificado e seus recibos. O JSON isolado com um SHA256 declarado não autentica quem o produziu.

## Fronteira de prova

O novo relatório não habilita CALL/CALLIND, resolve imports, recupera varargs, certifica retorno/clobbers nem altera os parâmetros da função C reconstruída. Pseudo-fonte não é o código-fonte original. O caso próprio de varargs que declara dois parâmetros no fonte mas tem inventário observado vazio permanece uma contraprova da suficiência do High P-Code.

As provas de desenvolvimento ficam em `F:/AetherRE_Audits/aetherre-20261030/implementation-14`. Recibos anteriores e posteriores à correção de orçamento são separados. Suíte focal, comparação de serializadores e revisão interna têm escopos distintos; não substituem corpus externo, holdout, execução dinâmica governada ou revisão humana independente. Nenhum gate F00–F12 é promovido por este contrato.
