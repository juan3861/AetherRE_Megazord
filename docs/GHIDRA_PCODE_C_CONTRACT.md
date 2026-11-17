# Reconstrução C derivada de High P-Code

O lote 07 conecta `ghidra-high-pcode.v1` ao módulo C-Tree existente. `aether_re/ghidra_pcode_c.py` revalida identidade/estrutura e produz efeitos, predicados e transferências por bloco; `structure_control_flow` estrutura esse CFG ou conserva transferências explícitas. Não se extrai semântica do texto C do Ghidra. Não é recuperação de código-fonte original ou equivalência universal com o binário.

## Modelo e abstenção

Varnodes de 1/2/4/8 bytes são transportados como `unsigned long long` de exatamente 64 bits, com máscara explícita em entradas e resultados. A assinatura gerada usa a ordem original dos varnodes de entrada e reporta o vínculo parâmetro/espaço/offset/largura. Essa assinatura transporta valores do IR; não é a assinatura original nem uma ABI recuperada. O ambiente que compilar a saída deve confirmar o carrier de 64 bits.

O modelo cobre adição/subtração/multiplicação modular, bitwise, comparação signed/unsigned, carry/overflow, booleanos, extensão signed/unsigned, concatenação/extração, contagem de bits/zeros, deslocamentos e aritmética numérica PTRADD/PTRSUB. Signed é interpretado como complemento de dois por fórmulas unsigned; não depende de overflow signed C ou right-shift de inteiro negativo. Shifts zero ou maiores/iguais à largura são tratados antes do deslocamento C. BOOL usa interpretação lógica zero/não zero; a especificação P-Code restringe booleanos a true/false.

Phi é cópia paralela na aresta. Para cada aresta que entra em bloco com MULTIEQUAL, um bloco sintético captura todas as fontes em temporários antes de atualizar qualquer destino. Preserva slots dos predecessores e evita destruir valores em ciclos como troca `(a,b)=(b,a)`.

Memória, chamadas, indiretas, floats, divisão/remainder, operações desconhecidas, storage persistente/externo, larguras não cobertas, live-ins não resolvidos e IR parcial não recebem C. A recusa é por função integral, com razões explícitas e `structured_c_source=null`. Entrada com backedge/phi sem predecessor ou retorno ausente/inconsistente também abstém. RETURN não zero pode ser halt especial; essa reconstrução não interpreta o marcador como retorno normal.

`status=complete` significa tradução do subconjunto de High P-Code observado para C-Tree. Não significa recuperação de tipos ou preservação do contrato ABI original. `binary_equivalence_proved`, `original_source_recovered` e `abi_recovered` são false. O parser verifica sintaxe; compilação e teste diferencial são evidências separadas.

## Interfaces e integração

`GhidraDecompilationResult.select_reconstruction(selector)` aceita identidade ou nome único. Um digest canônico do payload é capturado quando `GhidraFunctionInfo` é construído, além do hash do arquivo bruto. A seleção verifica esse digest e a projeção/summary; mutação posterior de PC, contexto, ordem de inputs ou operação é recusada. Um produtor confiável e custódia do objeto continuam necessários; isso não protege contra um administrador que possa adulterar dados e digests juntos.

CLI: `ghidra-decompile TARGET --reconstruct-function NAME --out NOVO.json`. MCP: `aether_ghidra_decompile` com `reconstruct_function`. A resposta contém relatório de tradução, C, C-Tree, inputs e proveniência. Recusa/seleção inválida não publica output CLI e define sucesso false. O limite de resposta é 1 MiB, com publicação create-only existente.

`universal TARGET --out NOVO --native-reconstruction --ghidra-timeout 180` opta pelo worker estático para native-pe/native-elf/macho. O worker recebe o snapshot admitido pelo intake, não o caminho mutável do alvo. Artefatos Ghidra são preservados na pasta do caso. `native_reconstruction.json` e o campo homônimo em `case_report.json` contêm grafos/relatórios por função e denominadores total/attempted/reconstructed/unsupported, além de truncated e razões de falha. Limites: 50 funções e 8 MiB dos bytes finais do relatório, incluindo envelope/indentação/newline. Uma função que excede a seleção vira entrada inválida explícita; não aborta as outras. Falha do backend fica distinta de função não modelada. O caminho universal continua com certificação abstained e execução dinâmica desativada.

## Evidência e contraprova real

Evidência em `C:/Users/juanp/Documents/Codex/audits/aetherre-20261028/implementation-07/`. O corpus escalar sintético de 122 casos/164 pares de inputs foi compilado em MSVC Od/O2 e comparado com aritmética inteira Python independente. São 40.016 execuções, zero divergências na coleta final com wrappers de assinaturas compatíveis. Uma coleta anterior tinha functionpointer incompatível no driver para uma função de um argumento; foi preservada e não conta como prova final. A revisão interna executou corpus e laço phi próprios separadamente.

A cadeia fonte própria → DLL MSVC → Ghidra → IR → C-Tree → executável de validação cobriu 11 funções: oito traduzíveis, três com memória/chamada recusadas sem fonte. Houve 3.200 retornos reconstruídos e 3.200 de referência em duas otimizações. **Foram observadas 292 divergências de retorno integral**, todas em `owned_slice`: fonte unsigned char/8 bits, High P-Code inferido com retorno de 32 bits. Sete das oito funções tiveram retorno integral igual em todas as entradas; na oitava só os oito bits declarados pela fonte coincidiram. Os bits superiores e a largura inferida permanecem em dívida. A saída não foi corrigida usando o oracle.

Somente executáveis próprios benignos de validação foram executados no host, em workers limitados por tempo/memória/captura/árvore. A DLL analisada não foi executada. Isso não é laboratório VM, holdout independente ou auditoria humana externa. Semântica de memória/chamadas/ABI, tipos com proveniência, corpus independente, replay e gates F00–F12 continuam necessários.

Referências primárias: [P-Code Operation Reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) e [Additional P-Code Operations](https://ghidra.re/ghidra_docs/languages/html/additionalpcode.html).
