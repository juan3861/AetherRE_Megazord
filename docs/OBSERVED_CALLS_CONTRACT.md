# Inventário observado de chamadas — início da dependência13

`inventory_observed_calls(export, max_functions=256, max_calls=1024)` lê um exportGhidra já admitido. A ponte revalida a identidade/digest/IR/graph antes de inventariar os operandos. Alteração do payload faz a operação falhar, em vez de reutilizar o grafo antigo.

CALL tem alvo direto somente quando seu operando é endereço em espaço de memória. Uma correspondência exata com endereço no inventário produz `inventory_address_match`, sem afirmar comportamento do callee. Endereço observado fora do inventário fica explicitamente externo ao inventário. CALLIND mantém alvo não resolvido. CALLOTHER é operação de usuário e seu índice não é convertido em endereço de função.

Argumentos são varnodes em slots observados, com largura; retorno é varnode/width quando o IR o define. Não se atribui registrador original, convenção de chamada, hidden argument, varargs ou pureza por dedução. `abi_recovered=false`, `call_semantics_proved=false`, `call_executed=false` permanecem explícitos. Um inventário de chamadas não habilita CALL/CALLIND na reconstrução C.

Denominadores incluem total de funções, funções examinadas, com IR verificado, sem IR e truncamento. `complete` vale só para inventário com IR de todas as funções e sem corte; não é completude de semântica. Há limites de funções/chamadas/saída. Identidades são SHA256 do mesmo alvo mais endereço canônico; nomes são rótulos, não chaves de vínculo.

Prova inicial: testes de alvo direto/indireto/usuário/mutação/quota e replay offline de export real17funções com6CALL e1CALLIND. Não foi iniciado outro Ghidra nessa prova e não houve execução de ELF. Integração nas interfaces, metadados de armazenamento dos parâmetros, resolução governada de callees e semântica de chamada ainda são próximos trabalhos. Revisão atual13 e regressão integral após adição ainda não foram concluídas.

## Observação de armazenamento da base de dados do Ghidra

O exportv2 pode conter `storage_observation` com schema `observed-function-storage.v1`, por função. O campo é opcional para aceitar exports históricos. Quando presente, o parser exige endereço correspondente ao registro, origem de assinatura consistente, parâmetros com ordinais contíguos, tipos de flags exatos, nomes/tamanhos limitados e armazenamento coerente. Dados inválidos recusam o export; não são ignorados.

Cada parâmetro/retorno registra nome, datatype name/length e SourceType observados, auto_parameter, forced_indirect e layout com tamanho, flags unassigned/void/bad e varnodes de armazenamento (espaço, offset hexadecimal, tamanho). Peças compostas preservam a ordem observada; sobreposição no mesmo espaço e tamanho total incoerente são recusados. Tipos de comprimento desconhecido(-1) permanecem desconhecidos. Não se exige igualdade entre comprimento do tipo e tamanho do armazenamento, pois indireção forçada pode existir.

Calling-convention name, custom variable storage e variadic são observações da base do programa. A coleta ocorre antes de `decompileFunction` para cada função. Portanto não é um vínculo completo entre HighParam/HighSymbol e cada live-in do High P-Code produzido depois. O próximo contrato precisa demonstrar essa correspondência e tratar parâmetros automáticos, indiretos, fragmentados e varargs com prova própria. `abi_recovered=false` permanece obrigatório.

As APIs usadas foram verificadas via javap no SoftwareModeling.jar da instalação Ghidra12.1.4 local. Observações não provam tipos originais nem autorizam CALL na reconstrução. O export real novo e os testes sintéticos são provas distintas; não declarar o export real concluído até seu recibo terminal.

## Correspondência conservadora com entradas do High P-Code

`bind_observed_storage` compara cada peça do parâmetro com live-ins do IR pelo espaço, offset e tamanho exatos. Não amplia registradores, reordena argumentos nem cria entradas implícitas. Uma única correspondência recebe `exact_storage_match`; candidatos múltiplos ou compartilhados por parâmetros recebem `ambiguous_storage`. Peças sem correspondência ficam `unresolved`. As demais entradas permanecem em `unbound_inputs`, com suas flags observadas de persistência e unaffected.

A seleção de reconstrução publica `storage_input_binding` quando o export contém essa observação. O digest canônico capturado na admissão é conferido antes de consumir o campo, inclusive quando ele foi removido posteriormente. Exports históricos sem o campo permanecem aceitos. O digest detecta mutação em memória; a proveniência do alvo depende do export verificado e de seu recibo. O JSON de armazenamento isolado não autentica a origem binária.

`complete` nesse objeto cobre exclusivamente o inventário de armazenamento de entrada: exige IR estruturalmente válido, ausência de live-ins não resolvidos, todos os parâmetros correspondentes e nenhuma entrada restante. Não prova retorno, clobbers, tipos originais, ABI nem comportamento de CALL. `abi_recovered=false` e `call_semantics_proved=false` permanecem explícitos, inclusive quando `complete=true`.

O replay dos exports reais de desenvolvimento encontrou 21 parâmetros com correspondência exata nas 11 funções PE. Nas 17 funções ELF, a única observação de parâmetro anterior à decompilação não correspondeu a uma entrada, e quatro live-ins ficaram sem vínculo. Uma sonda separada de HighParam/HighSymbol posterior à decompilação observou dois parâmetros e manteve três entradas sem vínculo. Esses são estágios diferentes do Ghidra; a sonda experimental não é o contrato canônico e não resolve automaticamente ponteiros unaffected, parâmetros ausentes ou ABI. Os artefatos ficam em `implementation-13` no diretório de auditoria local, com hashes e escopos separados.

## Contraprova com declarações de fonte conhecidas

O fixture próprio `owned-call-shapes` foi compilado para PE64 em `/Od` e `/O2`, sem carregar as DLLs. Cada build contém 11 funções exportadas: chamadas diretas/indiretas, seis argumentos, retorno de estrutura, varargs, chamada externa e escrita em memória. As receitas e os hashes do fonte e dos binários estão preservados junto aos exports estáticos de cada build.

Nas 22 observações de função ocorreram quatro diferenças entre a quantidade de parâmetros declarados no fonte e a quantidade observada na base do Ghidra, além de duas diferenças no indicador variádico. Incluem parâmetro adicional de retorno de estrutura e ausência de parâmetros em um chamador de varargs. Essas diferenças têm causas e significados distintos; não são uma taxa de erro de recuperação em corpus independente.

Um caso tem zero parâmetros e zero entradas no IR observado, apesar de declarar dois parâmetros no fonte. Portanto `storage_input_binding.complete=true` pode coexistir com argumentos do fonte ausentes: o objeto só compara dois inventários observados. Esse resultado não autoriza inferir aridade original nem semântica de chamada. O reconstrutor continua recusando CALL/CALLIND. O inventário de chamadas conta os opcodes CALL, CALLIND e CALLOTHER do High P-Code; não prova que o decompilador preservou todos os argumentos ou todas as transferências de controle do binário. A próxima recuperação precisa preservar também evidência do call site e distinguir explicitamente os estágios anteriores e posteriores à decompilação.

A sonda experimental separada de instruções/P-Code bruto foi executada nos dois builds próprios: oito locais de chamada em /Od e cinco em /O2. As 91 observações de instrução, incluindo janelas contíguas anteriores, tiveram seus bytes conferidos contra as DLLs originais pelas posições PE correspondentes. Em `owned_varargs_caller` /Od, o High P-Code registra um argumento de CALL, enquanto a janela de instruções contém preparação de ECX/RDX/R8/R9. Isso preserva a diferença entre estágios sem inventar correspondência semântica. Uma janela linear não prova caminho viável nem definições que alcançam a chamada. A sonda não cobre saltos de cauda e não foi incorporada ao parser canônico. Evidência: RAW_CALLSITE_BYTE_REVALIDATION.json e RAW_CALLSITE_CHECKPOINT.json no diretório local de auditoria; o exportador canônico ficou inalterado.
