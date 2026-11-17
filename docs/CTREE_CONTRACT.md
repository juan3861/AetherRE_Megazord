# C-Tree sobre CFG C explícito

Contrato `ctree-structuring-report.v2`, implementado em `aether_re/ctree_structuring.py`. A API transforma predicados e efeitos C fornecidos pelo chamador. Não recupera esses efeitos de nomes de blocos ou bytes de máquina. Pseudo-fonte não é código-fonte original.

```python
structure_control_flow(nodes, edges, idom, natural_loops, entry,
    block_semantics=semantics,
    function_signature="int recovered(int x)",
    declarations=["int r = 0;"])
```

Cada bloco contém `statements` (expressões C, sem declarações ou controle de fluxo próprio) e um `terminator`:

| kind | Campos |
|---|---|
| `return` | `value`: expressão ou `None` para função void |
| `jump` | `target` |
| `branch` | `condition`, `true`, `false` |
| `switch` | `expression`, `cases` com `{value, target}`, `default` |

Os alvos do terminador devem corresponder exatamente aos sucessores do CFG. A API recalcula dominadores, loops naturais e reducibilidade; hints fornecidos são conferidos e não autorizam descartar caminhos. Blocos inalcançáveis são inventariados e não emitidos. Cada bloco alcançável deve aparecer exatamente uma vez na árvore emitida.

`status=incomplete` significa que faltam efeitos, predicados, terminadores ou contexto de função; nenhuma fonte ou porcentagem é publicada. Entradas malformadas retornam `status=invalid` com erros. `status=complete` significa que a transformação do CFG C fornecido foi materializada e validada sintaticamente. Esse estado também abrange `strategy=explicit_cfg`, que preserva labels e gotos quando a região não pode ser estruturada pelo reconhecedor.

O reconhecedor estrutura sequências, joins de condicionais, switches e loops naturais reconhecidos, inclusive loops aninhados. Os efeitos do header permanecem dentro de cada iteração; a condição de saída é derivada do predicado real. `break` e `continue` seguem as fronteiras do loop. CFG irredutível, múltiplos destinos de saída de loop, switch dentro de loop, ausência de saída e regiões compartilhadas não reconhecidas preservam o CFG explícito. Literais compostos também usam fallback: inserir escopos novos pode reduzir sua duração de armazenamento.

## Tradução lexical e validação

Modelo explícito: a interface textual normaliza CRLF e CR para LF; depois aplica trigraphs C11 na fase 1, emendas de linhas na fase 2 e comentários. Cada fragmento original é processado uma única vez. Diretivas de pré-processador são recusadas; macros, includes e contexto de typedef externo não são inferidos. O mapeamento de CR físico não é presumido como idêntico em todos os compiladores.

Tokens de string são protegidos antes do parser e restaurados separadamente no gerador. Isso preserva a diferença entre `"\x4" "1"` e `"\x41"`, assim como fronteiras de escapes octais. A API não decodifica o conjunto de caracteres da plataforma por heurística. Pontos de interrogação literais são escapados na emissão para evitar introduzir um trigraph na recompilação. Prefixos originais são preservados quando aceitos pelo parser; sintaxe não suportada causa abstenção, sem fonte publicada.

`c_syntax_checked=true` é parse de sintaxe, não compilação. Permanecem `c_type_checked=false`, `compile_verified=false`, `semantic_equivalence_proved=false` e `binary_semantics_recovered=false`. A API não invoca compilador nem executa código recebido. Tipos, ABI, aliasing, comportamento indefinido, macros e efeitos externos exigem contexto e validação posteriores. O contrato não qualifica entradas C arbitrárias como equivalentes.

## Contagens e limites

`raw_gotos_count` conta os transfers do CFG explícito canônico, incluindo o salto inicial. `gotos_remaining` conta nós goto na árvore publicada. A porcentagem deriva dessas contagens; mede redução local de transfers, não fidelidade semântica. O campo legado `raw_gotos_estimated` fica nulo.

Limites: 256 blocos, 2.048 arestas, 1.024 hints de loop, 2.048 statements, 1.024 declarações, 4.096 caracteres por fragmento, 1 MiB acumulado de fragmentos, 8.192 tokens de string, 20.000 nós AST examinados, 2 MiB de fonte emitida. Profundidade de região acima de 128 usa fallback; excesso de orçamento de entrada é inválido.

## Evidência local e integração pendente

Em 28/10/2026, as contraprovas focais cobrem joins, efeitos de header, break/continue, switch, irreducibilidade, hints falsos, semântica ausente/contraditória, limites, escopo de literal composto, comentários, emendas de linha, trigraphs e escapes de strings adjacentes. O corpus próprio compilado contém 58 CFGs (18 padrões dirigidos e 40 DAGs), 24 entradas por CFG, MSVC C11 com trigraphs habilitados, nas otimizações `/Od` e `/O2`: 2.784 execuções da transformação e 2.784 do CFG C bruto, comparadas a um interpretador de referência. Retorno e sequência completa dos eventos observadores coincidiram em todos esses casos.

Esse corpus é próprio e benigno; não é holdout independente, prova geral de C, execução de amostras analisadas ou laboratório de malware. O interpretador usa um subconjunto pequeno de C, sem overflow nos casos examinados. A tentativa adicional com CR isolado foi recusada na compilação do baseline MSVC; não foi normalizada silenciosamente nem entrou no denominador nativo. CR/CRLF/LF são cobertos por testes do contrato da interface textual. A revisão de outro agente é interna. Recibos e fontes do corpus ficam em `C:/Users/juanp/Documents/Codex/audits/aetherre-20261028/implementation-04/`.

Permanece pendente ligar o contrato ao lifting/IR real dos binários, memória/flags/ABI/tipos e aos fluxos CLI/MCP/pipeline universal, com denominadores e proveniência. Nenhum gate F00–F12 é promovido por esta API ou por seus testes.
