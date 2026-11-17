# High P-Code observado — contrato estruturado

O lote 06 estende a exportação Ghidra v2 com um arquivo `ghidra-high-pcode.v1` por função. O produtor lê `HighFunction`, seus blocos e operações nativas; não extrai CFG do texto C. O consumidor valida esse arquivo e o projeta no contrato existente `ir.v1`. Esta é uma representação observada do descompilador, com larguras de armazenamento, CFG e def-use. Pseudo-fonte não é código-fonte original; validade estrutural não prova semântica binária ou recuperação de tipos.

## Identidade e representação

Cada arquivo vincula SHA-256 do alvo e endereço qualificado da função. O contexto preserva language/compiler IDs, endian, base da imagem e espaços de endereço com ID, largura e tamanho da unidade endereçável. Varnodes preservam espaço, offset hexadecimal, tamanho em bytes, flags e operação definidora quando existente. Não se deduz o tipo original a partir do tamanho.

Blocos têm inventário de operações em ordem de execução dentro do bloco. Predecessores e sucessores retêm slots recíprocos; `CBRANCH` preserva os destinos false/true. Operações têm opcode, operandos ordenados, saída e sequência nativa PC/time/order. Cada entrada de `MULTIEQUAL` mantém seu predecessor por slot. A ordem global de impressão de P-Code não substitui essa ordem por bloco.

O validador confere identidade, referências, inventário exato, definições únicas, formas/larguras dos opcodes cobertos, reciprocidade de arestas, posição dos terminadores e dominância de definições. Para phi, a dominância é verificada no predecessor correspondente. Live-ins sem declaração de entrada permanecem relatados como não resolvidos. Bloco terminal vazio marcado como completo é recusado; um export explicitamente incompleto pode conservá-lo como `partial`.

High P-Code pode substituir o endereço de retorno por um marcador constante, inclusive não zero e de tamanho diferente do ponteiro. Esse marcador é preservado literalmente e não interpretado como destino runtime nem prova de retorno normal. Destinos dinâmicos de `CALLIND`, `BRANCHIND` e `RETURN` continuam sujeitos à largura do espaço da instrução e às verificações de definição/uso. O valor retornado continua operando como dado, sem dispensar sua dominância.

## Efeitos, limites e estados

LOAD/STORE são classificados como efeitos de leitura/escrita; o seletor constante deve identificar um espaço declarado e o ponteiro deve ter a largura correspondente. Isso não resolve aliases, ordenação de memória, validade de endereço ou comportamento externo. Chamadas e controle indireto permanecem explícitos, sem resolução de todos os alvos ou modelagem de ABI. `INDIRECT` e opcodes sem modelo permanecem em `effects.unmodeled`; não são descartados nem convertidos em prova.

Limites por função: 512 blocos, 8.192 operações, 32.768 varnodes, 4.096 arestas, 512 entradas por operação e 2 MiB de JSON bruto. O payload continua no orçamento acumulado da exportação v2. O consumidor mantém as verificações de UTF-8/JSON, links, inventário e quotas do contrato anterior.

`summary.status=structurally_valid` significa consistência estrutural do export completo; `partial` informa incompletude. Os nós e arestas são inferência probabilística com confiança não calibrada e perdas explícitas. `semantic_equivalence_proved`, `binary_semantics_recovered` e `original_source_recovered` permanecem false. Nenhum desses estados promove gate F00–F12.

## API, CLI e MCP

`GhidraFunctionInfo` expõe `pcode_ir`, `ir_analysis` e `normalized_ir`. O resultado fornece `ir_coverage()` com denominadores total/structurally_valid/partial/unavailable e `select_ir_graph(selector)`. A seleção aceita identidade `hash!space:address` ou nome único; ausência e ambiguidade são erros.

CLI: `ghidra-decompile TARGET --ir-function NAME --out NOVO.json`. MCP: `aether_ghidra_decompile` com `ir_function`. Ambas as interfaces entregam um grafo selecionado com teto de 1 MiB e resumos das funções, sem incluir todos os grafos por padrão. A CLI exige JSON para seleção de IR e conserva a publicação create-only. Seleção inválida não publica saída.

## Prova e trabalho restante

A evidência local do lote 06 fica em `C:/Users/juanp/Documents/Codex/audits/aetherre-20261028/implementation-06/`. Uma DLL própria compilada com MSVC foi analisada estaticamente pelo Ghidra instalado; o alvo não foi executado. O corpus contém aritmética, branch/phi, loop, load/store e chamadas. A coleta confere hashes, inventário por função e igualdade do histograma de opcodes entre a impressão textual e os blocos estruturados. Essa comparação examina dois percursos do mesmo backend; não constitui oracle semântico independente.

Faltam semântica bitvector/memória/flags/ABI, recuperação de tipos com proveniência, conexão com SSA/C-Tree e pipeline universal, correlação fonte/build/binário/trace, corpus independente, laboratório com restore, replay/carga, WORM e revisão humana externa. A revisão de outro agente é revisão interna.

Referências primárias: [P-Code Operation Reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html), [Additional P-Code Operations](https://ghidra.re/ghidra_docs/languages/html/additionalpcode.html), [PcodeBlock API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeBlock.html), [ActionPrototypeTypes no Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc).
