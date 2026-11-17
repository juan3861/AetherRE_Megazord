# Evolução ao teto verificável do auditor forense

**Objetivo integral:** elevar o AetherRE a auditor forense avançado de engenharia reversa de ponta, conforme F00–F12 da planta-mãe. Este plano não substitui nem reduz os requisitos do plano-mãe.

**Especificações:** `docs/PLANO_MESTRE_ENGENHARIA_FORENSE_2026-09-15.md`, `docs/EVIDENCE_KERNEL.md`, `docs/EXTERNAL_EVIDENCE_HANDOFF.md`; auditoria atual em `C:/Users/juanp/Documents/Codex/audits/aetherre-20261028/AUDITORIA_AETHERRE_2026-10-28.md`.

**Arquitetura:** evoluir os módulos existentes, mantendo evidência bruta, identidade de entrada, resultados inconclusivos e limites explícitos. CLI, MCP e pipelines devem convergir nos mesmos contratos e workers governados. Testes locais não promovem gates externos.

**Restrições:** preservar o worktree e seus arquivos não rastreados; backup hashado antes das alterações; não emitir certificados nem revisão independente; não executar amostras hostis no host; pseudo-fonte não é fonte original. D:/E: sem reserva para operações pesadas; evidência nova em C:.

## Sequência executável e critérios

1. **F00/F02 — Contenção de extração.** `aether_re/unpackers.py`, `tests/test_unpackers.py`: testes RED para expansão zlib, quota acumulada, limite por arquivo, truncamento e destinos existentes; impor limites antes da publicação e preservar outputs anteriores. Validar todos os formatos, sem converter carving em extração completa. Publicação com inventário exato e sem sucesso para execução incompleta.
2. **F05 — Go real.** `aether_re/golang_recover.py`, `tests/test_golang_recover.py`: corrigir offsets conforme runtime/gosym, fixtures independentes com base por versão, arquitetura/endianness, truncamento e falsos candidatos. Confirmar nomes/endereço em executável Go real contra parser de referência, sem executar o alvo.
3. **F09 — SMT.** `aether_re/smt_solver.py`, testes dedicados: substituir eval por AST restrita, recusar expressões não suportadas, manter UNKNOWN distinto de UNSAT, deadline e limites de entrada. Contradições, bitvectors, parsing parcial e tentativa de efeito não podem produzir prova de SAT/UNSAT completa.
4. **F01/F10 — Avaliação honesta.** `ground_truth_eval.py`, consumidores CLI/MCP/benchmarks e testes: ausência ou parse inválido não recebe score; separar similaridade estrutural de equivalência; remover remapeamento que usa resposta do oracle; integrar contraprovas semânticas e efeitos, com execução apenas no laboratório autorizado.
5. **F05/F06/F09 — Reconstrução semântica.** SSA por bloco, dominância e phi por predecessor; C-Tree com predicados e efeitos, irreducibilidade explícita; tipos DWARF/PDB/ABI, chamadas indiretas e correlação fonte/build/binário/trace. Validar recompilação/diferencial em corpus próprio antes de generalizar.
6. **F01/F02/F11 — Integração governada.** Consolidar versões/workers das bridges, hashes, budgets, cancelamento/descendentes, stdout limitado e estados. Completar o pipeline universal com workers reais. Corrigir mapa de fases e configurar/classificar fixtures obrigatórias sem mascarar skips.
7. **F03/F04/F07/F10 — Qualidade independente.** Corpus autorizado por família e perfil, oráculos e holdout independente, métricas de relações e risco, contraprovas, calibração congelada, ECE/Brier/IC e ablação. Catálogo de ferramentas não conta como validação de capacidade.
8. **F08/F09 — Laboratório real.** Verificar armazenamento e isolamento; boot/lease/nonce, marcador benigno, coleta no guest, restore e ausência do marcador. Repetição e limpeza verificadas. Jamais substituir por atestado sintético.
9. **F00/F12 — Operação e homologação externa.** Candidato imutável incluindo trabalho não commitado, instalação/replay limpos, carga/caos/RSS/IO/p50/p95, custódia WORM com recusa de alteração, revisão humana independente com identidade e chaves sob custódia externa. Retificação aditiva dos claims históricos, sem apagar evidência.

Cada tarefa: contraprova RED → implementação → GREEN focal → regressão apropriada → recibo hashado e ledger. Não commitar em massa o trabalho preexistente. A conclusão do objetivo depende de evidência atual para todos os requisitos F00–F12 e todos os perfis declarados; melhorias intermediárias mantêm o objetivo ativo.

## Riscos de revisão

- Um formato reconhecido pode conter somente uma assinatura: não declarar extração completa.
- Byte budget comprimido não limita saída; quota é sobre bytes efetivamente publicados.
- Fixture criada com os mesmos offsets errados do parser dá falso verde: comparar com fonte oficial local e binário real.
- Solver que ignora restrições ou retorna UNKNOWN não prova viabilidade/inviabilidade.
- Scores, assinaturas e manifests locais não provam semântica, independência, VM ou WORM.

## Execução da tarefa 5 — contrato C-Tree

Corrigir o módulo existente com semântica explícita por bloco: statements C, terminador return/jump/branch/switch, assinatura e declarações da função. Sem esse contexto, retornar incompleto, sem pseudo-condições ou percentuais. Validar sintaxe C e correspondência exata entre terminadores/arestas, recomputar dominância/laços/reducibilidade, estruturar sequências, joins, condicionais, switches e loops naturais com efeitos do header por iteração e break/continue. Para regiões não reconhecidas/irredutíveis, preservar o CFG integral com labels/gotos. Contagens e métricas derivam do código produzido; não são equivalência binária.

Prova: RED de placeholders, join duplicado/perdido, efeito de header, break/continue, switch, irreducibilidade, ausência/contradição de semântica, metadados forjados, budgets e fragmentos C com controle de fluxo não declarado; GREEN com parse/inventário. Compilar e executar somente fixtures próprias benignas, com oráculo independente por interpretação do CFG e comparação diferencial de resultados/efeitos, workers limitados e hashes em C:. Revisão interna focal, regressão configurada e receipt antes de reportar avanço. Preservar a obrigação posterior de conectar semântica real de binários ao módulo e validar em laboratório/corpus independente.

## Execução das tarefas 5/6 — exportação Ghidra e tipos observados

Corrigir ambos os lados do contrato existente. Produtor publica schema v2, hash do alvo carregado, inventário completo por endereço qualificado, sucesso/falha por função, fonte individual e tipo/assinatura observados. Consumidor recusa schema antigo sem denominador, hash divergente, contagem inconsistente, identidade duplicada, fontes ausentes ou fora do diretório, UTF-8 inválido e artefatos acima do orçamento. Identidade é hash+espaço/endereço, nunca nome. Consulta por nome só resolve candidato único; CLI/MCP/benchmarks precisam consumir o contrato e expor estado e recortes de inventário.

Remover a mutação cJSON fixa do caminho genérico e conservar o script legado como entrada compatível que exporta tipos do programa sem injetar hipóteses. Reportar `external_types_injected=false` e origem de assinatura observada; isso não quita a recuperação de tipos DWARF/PDB/ABI. Falhas/exports incompletos são parciais, sem sucesso amplo. Limitar artefatos no produtor e validar quotas/links/identidade no consumidor. Preservar o worker governado e receipts existentes. RED de perda por nome, denominador incorreto, ausência de fonte, falsificação e quotas; smoke estático real benigno nos dois caminhos, revisão interna, regressão configurada e selo. Não executar o binário analisado.

## Execução da tarefa 5/6 — High P-Code estruturado derivado do alvo

Estender o produtor Ghidra existente para exportar IR por função: contexto de arquitetura/endereços, blocos e arestas ordenados, operações em ordem de bloco e sequência nativa, varnodes com espaço/offset/largura e definição, phi com predecessor por slot. Não deduzir CFG de nomes/texto C. Ausência/ambiguidade e operações/efeitos não modelados devem permanecer explícitos. High P-Code otimizado é representação do descompilador e não recuperação completa de flags/ABI ou equivalência binária.

Consumidor valida identidade, limites, referências, CFG recíproco, inventário, definições únicas, larguras suportadas, dominância e associação de phi por aresta antes de projetar no IR/grafo existente com proveniência do artefato. Conservar todos os efeitos desconhecidos como perdas/abstenções, sem fabricar predicados. API entrega IR integral validado e análise; CLI/MCP mostram denominadores e permitem selecionar uma função por identidade ou nome único para obter seu grafo. Conectar posteriormente esse IR a SSA/C-Tree e pipeline universal continua obrigatório, sem reclassificar o teto como simples exportação.

Prova: RED de truncamento de largura, phi/predecessor errado, referências/arestas/definições inválidas, uso antes de definição, efeitos não modelados e falsos claims; produtor Java real em DLL próprio benigno com aritmética, branch/phi, loop, load/store e chamadas; comparar inventários/valores do IR e textos/snapshot, chamada MCP real com seleção de função, revisão interna, regressão configurada e receipt. Não executar o alvo analisado. Manter requisitos de tipos/ABI, corpus independente, laboratório/restore e homologação externa.

## Lote 07 — reconstrução C derivada de High P-Code

Executar a integração prevista nas tarefas 5/6, sem nova stack: `ghidra_pcode_c.py` valida novamente o export com identidade/hash e produz semântica por bloco para `structure_control_flow`. Usar carriers unsigned long long de 64 bits com máscaras explícitas para varnodes de 1/2/4/8 bytes, sem casts signed dependentes da implementação nem shifts indefinidos. Modelar aritmética modular, comparação signed/unsigned, carries, bool, extensão, concatenação/extração, deslocamentos e ponteiros apenas como valores numéricos. Operações sem modelo (incluindo divisão por enquanto, memória, chamadas, indiretas e floats) fazem abster a função integral; não descartar efeitos ou inferir tipos/ABI.

Phi é atribuição paralela na aresta: inserir bloco sintético por aresta com snapshots de todas as entradas antes de atualizar saídas. Manter função de entrada explicitamente em ordem de varnode, assinatura de transporte sem alegar ABI original, proveniência por operação/bloco e limite de saída. Retornos constantes não zero no slot0 podem representar halt especial; abster até distinguir esse caso pelo produtor. Entrada parcial, live-in não resolvido, entrada com backedge/phi ou largura não coberta não publica C.

Expor por função na API existente, seleção CLI/MCP e integrar como artefato opcional ao caso universal nativo com worker Ghidra governado e snapshot do intake. Não promover certificado. REDs para overflow, signed/unsigned, shift >=largura, phi circular/paralelo e branch polarity, recusa de efeitos e hash divergente. Compilar reconstruções e referências próprias benignas com MSVC e comparar execuções limitadas/isoladas do processo; não executar a DLL estática anterior nem alvos hostis. Preservar receipts anteriores, backup de arquivos tocados e source inventory, revisão interna, regressão configurada e novo receipt.

## Lote08 — tipos de debug DIA/PDB com vínculo

Contraprova do lote07 exige tipos com proveniência: owned_slice fonte8bits/IR32bits,292 divergências integrais. Baseline local confirmou SDK/helper existentes compiláveis, PDB próprio com dois símbolos e GUID/age compatíveis com PE, mas tipos ausentes. Probe determinístico confirmou falso complete do wrapper com exit7/captura incompleta/árvore não contida.

Corrigir primeiro `aether_re/pdb_dia.py`: snapshots privados/verificados de helper/DIA/PDB/PE, hashes antes da execução, árvore de processo requerida, memória/tempo/captura limitados, recusa de exitnãozero/captura incompleta/JSON duplicado/contagem ou referência inválida. Preservar relatório e worker também em falha. Extensão opcional binary_path exige GUID+age/machine PE/PDB. Tipos não vinculados não são tipos do alvo.

Estender `tools/dia_extract.cpp` no caminho existente: grafo por symIndexId de function signature→return/parameters, bases/pointers/arrays/typedefs, propriedades disponíveis somente com S_OK. Ausência, truncamento e quotas explícitos, sem zerar tipos ausentes. Enumeração/tipos/arestas limitada. Conservar contrato de símbolos para consumidores existentes e declarar capacidades/denominadores adicionais. Corrigir builder para MSVC realmente instalado se necessário. Validar tipos/referências e proveniência no consumidor, PDB trocado/GUIDage divergente e fixtures próprias reais.

Integrar contrato de retorno debug ao resultado/CLI/MCP sem alterar High P-Code bruto: adapter separado para os bits de retorno definidos pelo tipo vinculado, conservando a tradução IR observada. Não inferir ABI completa de registros ou assumir que PDB correto prova comportamento. Comparar adapter e referência próprias benignas, manter contraprova histórica intacta; revisão interna, regressão estável e receipt encadeado. DWARF, structs/classes completas, memória/chamadas e todos os requisitos externos permanecem obrigatórios.


## Lote09 — tipos vinculados no caso universal

Conforme implementation-09/PLAN.md: configuração explícita antecipada, DIA uma vez por PE admitido, publicação separada limitada/create-only, seleção por RVA/digests, preservação do IR em falha debug, contadores reconciliados, prova CLI real e revisão/regressão de fontes finais. Não ampliar claims para ABI, DWARF ou equivalência binária. Objetivo global continua ativo.


## Lote10 — build DIA publicado

Conforme implementation-10/PLAN.md/DESIGN.md: resolver versãoVSconfigurada, compilar helperpróprio emjobprivado comsnapshots/hash/workercontido, limparenv/parserCMD, publicarcreate-only eprovarDIAestático sobrePE/PDBpróprios. Guardsshell/SDK/versão/status devemterRED/GREENe revisão; sódepois congelar/regredir/selar. Isso não quita lock/replayglobal ou gates.
