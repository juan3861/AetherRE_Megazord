# RE_Megazord — Plano Mestre de Engenharia e Validação

Data: 2026-09-15 | Revisão: 1 | Estado: PLANEJADO, NÃO IMPLEMENTADO
Projeto: D:\AetherRE_Megazord | Baseline observado: d557080
Direção: Ruan | Planejamento: Codex

## 1. Missão e critério de verdade

Evoluir incrementalmente a implementação existente para desconstruir e auditar projetos inteiros: fonte, dependências, configuração, build, binário, execução e documentação. Entregar arquitetura reconstruída, fluxos, comportamento, riscos e contradições com evidências verificáveis.

“101% / engenharia 2077” define ambição de rigor, não uma métrica científica. Não prometer recuperar informação perdida na compilação, demonstrar ausência universal de vulnerabilidades ou equivalência irrestrita entre programas. Garantias devem nomear domínio, hipóteses, limites e método.

Regras:
- Reutilizar engines/adapters; não recriar o projeto do zero.
- O núcleo governa evidências, políticas e conclusões; ferramentas externas são adapters.
- Separar observação, inferência, hipótese, experimento e prova formal limitada.
- Concordância entre ferramentas não é ground truth; ferramentas correlacionadas não são testemunhas independentes.
- Sem evidência suficiente: inconclusivo/abstenção, nunca sucesso presumido.
- Cada fase exige implementação integrada, testes executados, artefatos e revisão de aprovação.
- A leitura de fonte não executa imports, hooks, build ou instaladores implicitamente.
- Executar alvos apenas em escopo autorizado e ambiente isolado; nunca malware no host de trabalho.
- Não transmitir fonte, segredos ou binários a serviços externos sem política explícita.

## 2. Baseline empírico

Auditoria da task, antes deste plano:
- CLI binária real; Ghidra, Rizin e angr produziram evidência no teste novo de calc.exe.
- D:\AetherRE_Megazord\output\codex_audit_20260915_calc\report.json: 71 funções, 18 tri-source, 11 bi-source, confidence=0.696. Esse número não é precisão medida.
- D:\AetherRE_Megazord\output\final_notepad\report.json: histórico com 872 funções, 114 tri-source, 301 bi-source e 457 single-source; não foi nova execução do Notepad.
- Python 3.11: 12 passed, 1 failed, 1 skipped. Python 3.13 com autoload de plugins desativado: 13 passed, 1 failed. Falha Frida: KeyError('executed'). Ambiente 3.13 normal falha antes da coleta por plugin externo nengo.
- Frida não detectado no PATH deste processo, mas executáveis existem na pasta Scripts; não concluir desinstalação.
- Funções Binary Ninja não consumidas pelo consenso; ferramenta indisponível.
- Ghidra limitado a 200 exportações; ausências sobrescritas no pipeline; JSON salvo antes do pseudo-fonte definitivo; matriz por pares incorreta.
- Consenso de pesos constantes e acordo 1.0 para fonte única; cobertura não representa programa compreendido.
- Uma fixture PE64; faltam corpus independente e precisão demonstrada.
- BAT abre pasta, mas não restaura conversa; RESTORE_SESSION.txt não rastreado.

Host verificado: Xeon E5-2697 v3, 28 processadores lógicos, 31.8 GiB RAM. Espaço livre aproximado: C: 4.1 GiB, D: 9.2 GiB, F: 34.9 GiB. Medir novamente antes das campanhas.

Nenhuma instalação grande, download integral de corpus ou VM é autorizada automaticamente por este plano. Capacidade de virtualização, imagens, licenças, armazenamento e compiladores serão validados. Não apagar originais para abrir espaço.

## 3. Arquitetura proposta

Fluxo: Intake -> Inventário -> Análise fonte/binário/build -> Evidências -> Grafo de correlação -> Hipóteses/experimentos -> Verificação -> Relatório.

Camadas novas ou estendidas sob D:\AetherRE_Megazord\aether_re:
1. intake: escopo, snapshots, hashes, formatos, extração segura.
2. contracts: AnalysisRun, Artifact, Evidence, Claim, Experiment, AdapterResult, Capability, CoverageLedger versionados.
3. runtime: scheduler, workers, limites, cancelamento, checkpoint e cache.
4. source: parsing, símbolos, referências e fluxos por linguagem.
5. binary: engines/adapters atuais evoluídos, arquitetura e identidade de endereço.
6. build: receitas, flags, toolchains, símbolos e artefatos.
7. evidence: objetos por conteúdo, manifestos e trilha de derivação.
8. graph: projeção consultável de relações comprovadas/inferidas; não substitui o bruto.
9. analysis: hipóteses, contradições, arquitetura e vulnerabilidades.
10. experiments: traces, fuzzing e exploração simbólica limitada.
11. reporting: JSON/Markdown/SARIF e interface de revisão.
12. verification: benchmarks, calibração, ablação e replay.

Persistência inicial: SQLite para metadados, blobs endereçados por hash e projeção de grafo substituível. Não instalar banco distribuído sem necessidade medida. O grafo MCP disponível para Rotor não comprova indexação do Megazord; futura integração será adapter opcional.

Evidence: evidence_id, run_id, input_hash, producer/version, config_hash, UTC timestamps, target identity, source span/module+RVA/trace interval, method, raw_artifact_hash, assumptions, limits, dependencies, validation_status.

AdapterResult: estado em unavailable/skipped/queued/running/succeeded/partial/failed/timed_out/cancelled; available, executed e produced_evidence são distintos. Nenhuma ausência desaparece.

Claim: statement, scope, evidence_ids, counterevidence_ids, confidence_kind, calibration_id, limitations, reviewer, state. Hash verifica integridade relativa ao manifesto, não verdade semântica. Assinatura exige custódia de chave confiável.

## 4. Sequência e dependências

Caminho: F00 -> F01 -> F02 -> F03 -> F04/F05 -> F06 -> F07 -> F08 -> F09 -> F10 -> F11 -> F12.
F03 cresce ao longo das fases. F04/F05 podem avançar independentemente depois dos contratos; F06 exige ambas. F08 exige capacidade e isolamento aprovados. A redação deste plano não aciona agentes nem execução paralela.

### F00 — Preservação, escopo e ambiente reproduzível

Objetivo: impedir perda e tornar diagnóstico/testes repetíveis.

Entregas:
- Snapshot de hashes, Git status/diff, índice da conversa e manifesto dos outputs, sem mover originais.
- Perfil inicial: fonte Python e C/C++; PE32/64 e ELF x86/x64. Cada combinação tem suporte explícito, nunca “universal” implícito.
- Ambiente isolado: escolher Python por compatibilidade medida; workers distintos se angr exigir outro runtime.
- Dependências travadas por perfil; versões de Java/Ghidra/Rizin/parsers registradas.
- Descoberta de executáveis sem depender só do PATH; doctor com diagnóstico acionável.
- Orçamento de armazenamento/backup e retomada real documentada, separada da CLI de análise.

Testes: bootstrap limpo, PATH mínimo, dependência ausente, Java inválido, fixture ausente, disco sem reserva, restauração do manifesto, diferenças entre runtimes.

Gate G00: baseline reproduzido com falhas atuais preservadas; prechecks falham de forma controlada. Correções F01, não maquiagem de testes, produzem o primeiro verde.

### F01 — Corrigir a verdade do pipeline existente

Objetivo: retirar falsos sucessos antes de ampliar capacidade.

Entregas:
- Preservar todos os estados e padronizar retornos Frida/Unicorn.
- Persistir snapshot definitivo único para JSON, C e Markdown.
- Acordo por par; fonte única recebe não aplicável e falta de corroboração explícita.
- Separar disponibilidade, participação de fontes e cobertura sobre funções conhecidas.
- Deduplicar evidências; repetição do mesmo produtor não aumenta confiança.
- Consumir funções Binary Ninja quando existirem; sem licença, indisponível, não falso sucesso.
- Corrigir chamadas angr e conferir tipos reais do grafo contra microbinário conhecido.
- Ghidra: orçamento configurável, descobertas/tentativas/sucessos/falhas/cortes registrados.
- Outputs isolados por run_id; não reutilizar C antigo após falha sem validação.

Testes: regressão de cada defeito; trio com pares diferentes; permutação; duplicata; Ghidra falha com C antigo; mais de 200 funções; exceção em available(); limites e cancelamento.

Gate G01: regressões corrigidas, suíte completa obrigatória verde sem skips obrigatórios, calc reproduzido com proveniência. Confidence permanece heurístico até F10.

### F02 — Contratos, custódia e runtime governado

Objetivo: conclusões reproduzíveis e execuções controladas.

Entregas:
- Schemas versionados; migração de reports legados preservando originais.
- Manifestos e cadeia de derivação; cache por input/toolchain/config/schema.
- Scheduler por custo, budgets de CPU/RAM/disco/tempo, cancelamento de árvore de processos.
- Workers externos; checkpoints transacionais; publicação atômica; locks; retomada idempotente.
- Intake protege contra symlinks/junctions, traversal de arquivos compactados, arquivos gigantes e bombas de descompressão.
- Evitar troca do alvo entre hash e análise por snapshot validado.

Testes: corrupção de byte, kill durante escrita, corrida de jobs, disco cheio, processo órfão, cache obsoleto, troca de arquivo, cancelamento antes/depois de checkpoint.

Gate G02: adulterações semeadas detectadas; replay estático consistente; nenhum acesso fora de escopo nos casos testados; jobs terminam ou são canceláveis dentro do budget.

### F03 — Corpus e oráculos independentes

Objetivo: medir acerto e limites.

Entregas:
- Bootstrap de 20 microprojetos próprios/autorizados com fonte, expectativa e receita reproduzível.
- Matriz pairwise de arquitetura/compilador/otimização/stripping/símbolos/imports/indireção; não explodir combinações sem benefício.
- 10+ miniprojetos com documentação verdadeira/falsa, código morto, ciclos, feature flags, mocks e implementação não chamada.
- Subconjunto selecionado de SARD/Juliet com negativos correspondentes.
- Projetos reais distintos como validação externa; variantes do mesmo projeto não contam como observações independentes.
- Splits por família: desenvolvimento, calibração e holdout cego. Variantes da mesma origem ficam no mesmo grupo.
- Ground truth por símbolos/builds instrumentados/inspeção; inlining e otimização admitem relações muitos-para-muitos.

Testes: recompilação, rótulo incompatível, vazamento entre splits, duplicata, par vulnerável/corrigido, encoding e paths Windows/Linux.

Gate G03: todas amostras com origem, autorização, hash, objetivo, oráculo e limites. Sintéticos, microbinários compilados e projetos reais reportados separadamente.

### F04 — Leitura semântica de projetos e arquitetura

Objetivo: compreender relações, não só extrair nomes.

Entregas:
- Inventário com exclusões, vendor, gerados, submódulos e artefatos embutidos.
- Parsing incremental e frontend semântico por linguagem.
- Python: AST/imports conservadores; reflexão/import dinâmico explicitamente incertos.
- C/C++: Clang com compile_commands e flags reais; não resolver macros/templates por regex.
- Grafo de módulos, funções, tipos, chamadas, configuração, testes e dependências.
- Adapters de framework validados para rotas/serviços; inferências marcadas.
- Documentação ligada ao código; grau zero do grafo não prova código morto.

Testes: shadowing, homônimos, decorators, callbacks, namespaces, macros, function pointers, ciclos, imports condicionais, testes só com mocks, erros sintáticos.

Gate G04: precisão/recall por relação no corpus suportado; arestas não resolvidas explícitas; nenhuma execução implícita do alvo.

### F05 — Engenharia reversa estrutural de binários

Objetivo: correlacionar funções sem confundir arquitetura e endereços.

Entregas:
- Identidade: hash + módulo + arquitetura + espaço de endereço + offset/RVA + instância de carga quando dinâmica.
- PE/ELF: seções, segmentos, imports, exports, relocations, símbolos e permissões.
- Ghidra/Rizin estruturados; CFG angr separado de execução simbólica; disassembly separado de decompilação.
- Arquitetura explícita, nunca assumir x86 para entrada desconhecida.
- Contadores de descoberta/decompilação/falhas; budgets não confundidos com completude.
- Extensões .NET, DEX, Mach-O e ARM64 com adapters e gates próprios, posteriores ao perfil inicial.

Testes: PE32/64, ELF32/64, módulos com endereço repetido, ASLR, rebasing, truncamento, stripping, seções sobrepostas, convenções de chamada, 201+ funções, entradas não executáveis.

Gate G05: conformidade no corpus; limites explícitos; falha de parser não inventa funções; fonte preferida não elimina contraprovas.

### F06 — Fonte ↔ build ↔ binário ↔ comportamento

Objetivo: verificar se o artefato corresponde ao projeto alegado.

Entregas:
- Receitas, compiladores, flags, dependências, hashes e símbolos PDB/DWARF quando disponíveis.
- Correlação por símbolos/debug info/estrutura, com fallback probabilístico identificado.
- Relações 1:N/N:1 de inlining, especialização, fusão e eliminação.
- Diferenças entre builds: código, dependências e mudanças comportamentais.
- Ligações especificação->módulo->função->binário->teste/trace.
- Build tratado como execução de código em worker isolado, não operação inocente.

Testes: O0/O2/O3, stripping, renomeação, mudança real em branch, eliminação no linker, flags contraditórias, artefato de outra fonte.

Gate G06: erro/acerto por família; ambiguidade preservada; texto semelhante não comprova equivalência.

### F07 — Auditoria forense, riscos e dependências

Objetivo: produzir achados acionáveis com caminho de evidência.

Entregas:
- Fluxo de dados/fronteiras de confiança, sanitizadores e sinks por linguagem/framework.
- Auditoria promessa/entrega: módulo não chamado, adapter sem evidência, testes só com mock, persistência não integrada.
- SBOM/dependências diretas/transitivas, lockfiles, vendoring e configuração.
- Separar presença de componente, risco catalogado e alcançabilidade demonstrada.
- Fontes externas com data/cache; ausência de match não prova ausência de risco.
- Adapters estáticos opcionais e política de confidencialidade.

Testes: vulnerável/corrigido, sanitização, biblioteca presente não usada, vendoring renomeado, segredos sintéticos, chamadas indiretas, claim documental falso.

Gate G07: achados têm versão/local/caminho/limites; severidade não confunde certeza; crítico confirmado exige evidência causal suficiente.

### F08 — Laboratório dinâmico e traces

Pré-requisito: disco/virtualização/imagens/snapshot/rollback/rede aprovados. Container não é equivalente a VM para alvos hostis.

Entregas:
- VMs descartáveis Windows/Linux sem credenciais do host ou montagem gravável do projeto; rede bloqueada por padrão.
- Canal de coleta limitado, quotas, heartbeat e encerramento de processos do job.
- Frida/eventos tipados com sequência, relógio, thread/processo e módulo carregado.
- Observação de arquivos/processos/rede/memória conforme escopo e ambiente.
- Unicorn como emulação limitada com modelos de imports explícitos, não Windows completo.
- Registrar falhas da instrumentação e efeitos de observação/anti-debug.

Testes: alvos benignos controlados, subprocesso, conexão bloqueada, perda de trace, timeout, guest crash, marcador secreto sintético do host, rollback/repetição e órfãos.

Gate G08: isolamento/coleta passam nos casos testados; traces reais correlacionados; não prometer sandbox inviolável.

### F09 — Fuzzing, simbólico e equivalência limitada

Objetivo: descobrir contraexemplos e verificar comportamento reconstruído.

Entregas:
- Harnesses com oráculos, seeds, corpus e minimização de falhas.
- Fuzzing guiado por cobertura e sanitizers onde suportados.
- angr com objetivos concretos e budgets de estado/tempo; UNSAT no modelo não significa segurança universal.
- Comparação original/reconstrução por saída, efeitos e exceções, não só texto.
- Hipóteses de ABI/memória/ambiente/undefined behavior explícitas; reproduzir contraexemplo fora do solver quando possível.
- Packed/ofuscado: amostras próprias e unpack isolado; nenhuma promessa universal contra protetores.

Testes: overflow conhecido, branch raro, parser malformado, reconstrução adulterada, função pura equivalente, efeito colateral omitido, timeout e estado não modelado.

Gate G09: bugs semeados reproduzidos, reconstruções incorretas rejeitadas; equivalência só com escopo/método; amostragem não é prova universal.

### F10 — Consenso calibrado e avaliação cega

Objetivo: substituir score ornamental por métricas confiáveis.

Entregas:
- Normalização semântica de calls/imports/callsites; endereços e nomes não comparados como strings incompatíveis.
- Deduplicação e produtores correlacionados agrupados.
- Calibração por tarefa, não confidence universal.
- Precisão/recall/F1, falsos positivos/negativos, Brier, ECE, risco seletivo vs cobertura e IC.
- Calibração congelada antes do holdout; não treinar nos casos da aprovação.
- Ablação: ferramentas sozinhas, ensemble simples, governado e versão anterior; custo/benefício medido.

Testes: duplicação não aumenta confiança; contraprova reduz certeza; fonte única/fora de distribuição permite abstenção; produtor corrompido; classe rara.

Gate G10: metas da seção 6 verificadas com amostra suficiente; caso contrário score rotulado heurístico. Não substituí-las por nota “94/100”.

### F11 — Inteligência assistida e revisão

Objetivo: acelerar investigação sem fabricação de provas.

Entregas:
- LLM recebe evidência identificada; propõe hipóteses, nomes, explicações e experimentos.
- Verificador confere existência e suporte das citações; ID válido não basta se não sustenta a frase.
- Sem alteração automática do alvo nem achado crítico confirmado só por texto de modelo.
- README/comentários/strings do alvo tratados como conteúdo não confiável.
- UI com grafo, comparação por fonte, divergências, desconhecidos, timeline e evidência bruta.
- CLI offline sem LLM; provider substituível, budgets e política de dados.

Testes: função inventada, citação falsa/irrelevante, prompt injection, indisponibilidade, contexto truncado, segredo sintético, discordância do revisor.

Gate G11: nenhuma alegação sem suporte promovida no corpus adversarial; incertezas preservadas; funcionamento offline e cancelamento. Modelo escolhido por benchmark e disponibilidade/custo verificados, não por marketing.

### F12 — Homologação independente e operação

Objetivo: produto reproduzível e operável com limites conhecidos.

Entregas:
- Auditoria do próprio Megazord e projetos distintos, mantendo rótulos cegos fora do contexto do investigador.
- Pacote de reprodução: locks, manifestos, logs, datasets permitidos, métricas e limitações.
- Instalação limpa, migração, backup/restore e retomada após crash.
- Carga/caos e perfil CPU/RAM/IO, cache cold/warm e cancelamento.
- Certificação por perfil; formato/plugin novo não herda aprovação.
- Atualização de ferramenta depende de diferencial no corpus congelado.

Testes: fonte->build->binário->trace->achado, reinstall, worker morto, disco cheio, provider off, schema antigo, adulteração e repetição de campanha.

Gate G12: nenhum P0/P1 de integridade aberto; suíte/perfis obrigatórios aprovados; revisão independente por categoria. Opcionais ausentes permanecem explícitos.

## 5. Catálogo de testes e evidências

Níveis: unitários; propriedades/metamórficos; contratos; integração com ferramentas reais; E2E; diferenciais; fuzzing; segurança; resiliência; benchmark cego/calibração/ablação.

Cada run deve preservar: manifesto, ambiente, comandos, stdout/stderr por tool, resultados JUnit/JSON, métricas, artefatos brutos por hash, limites, decisão do gate e comparação com baseline. Armazenamento/retencão definidos pelo budget; não copiar blobs grandes desnecessariamente.

Falha obrigatória bloqueia o gate. Skip exige capability opcional ausente e motivo. Doubles validam contrato, não integração real. Não mudar expectativa só para ficar verde; contratos alterados exigem migração/revisão dos consumidores.

## 6. Metas iniciais propostas — não resultados obtidos

| Dimensão | Medida / meta inicial |
|---|---|
| Integridade | Detectar 100% das adulterações semeadas; não implica garantia universal |
| Estados | 100% dos jobs/adapters do corpus obrigatório com terminal/motivo |
| Proveniência | 100% dos achados confirmados com cadeia verificável |
| Fonte | Precisão >=99% de relações resolvidas no perfil delimitado; recall separado |
| Binário | Precisão >=95%, recall >=90% nas fixtures não ofuscadas com ground truth, por arquitetura |
| Correlação | Precisão >=98% dos matches aceitos, cobertura/abstenção publicadas |
| Risco | Alvo >=99% de precisão para confirmados, com IC95% e amostra suficiente |
| Recall de risco | >=90% dos bugs semeados suportados por família; fora de suporte separado |
| Calibração | ECE alvo <=0.05, bins/amostra/IC explícitos; Brier comparado ao baseline |
| Testes | Zero falha e zero skip obrigatório |
| Código crítico | Alvos branch coverage >=90% e mutation >=80%; não equivalem a correção |
| Replay | Três reexecuções estáticas normalizadas no mesmo perfil |
| Recursos | Budgets e p50/p95 publicados; corte sempre explícito |

Congelar metas antes do holdout; não baixá-las após ver resultado para aprovar. Mudanças prospectivas documentadas. Reportar denominadores, projetos independentes, correlação entre variantes e IC apropriados. Precisão extrema exige amostra suficiente; contagem pequena não autoriza certeza estatística. Traces dinâmicos não recebem exigência artificial de determinismo.

## 7. Performance máxima no host real

- Medir custo por engine/tamanho/funções, peak RSS e IO antes de otimizar.
- Começar com um worker pesado e ampliar por orçamento observado: 28 threads não justificam 28 análises pesadas em 32 GiB.
- Perfis triage/estático profundo/comportamental com budgets distintos e resultado parcial explícito.
- Cache por conteúdo, parsing incremental e invalidação por dependências.
- Executar ferramenta cara quando acrescenta informação; medir ganho e não apenas quantidade de ferramentas.
- Separar metadados/blobs; compactação e quotas sem apagar originais automaticamente.
- Cold/warm separados; comparação no mesmo hardware, flags e amostras.
- Ganho de velocidade não conta se reduz silenciosamente recall, funções ou evidências.
- Capacidade para VMs calculada com imagens+snapshots+traces+reserva, antes de criar laboratório.
- Não presumir GPU, modelo gigante ou necessidade de compra.

## 8. Tecnologias candidatas e fontes verificadas

Adotar o mínimo necessário; cada dependência exige teste de compatibilidade, licença aplicável, versão fixada, proveniência, custo e fallback. A lista não significa instalação concluída nem revisão exaustiva do estado da arte.

- Manter Ghidra/Rizin/angr/Capstone/pefile antes de ampliar decompiladores.
- Tree-sitter: parsing incremental, não resolução semântica completa. Clang LibTooling: C/C++ com contexto de compilação. [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) / [Clang](https://clang.llvm.org/docs/LibTooling.html).
- Ghidra SLEIGH/p-code: representação especializada de binário; não forçar todas linguagens num IR com perda semântica. [SLEIGH](https://ghidra.re/ghidra_docs/languages/html/sleigh.html).
- Rizin estruturado e angr para objetivos simbólicos delimitados. [Rizin](https://github.com/RizinOrg/rizin) / [angr](https://api.angr.io/en/stable/core-concepts/symbolic.html).
- LIEF candidato à ampliação de formatos, comparado aos parsers atuais. [LIEF](https://github.com/lief-project/LIEF).
- CodeQL opcional para consultas/data flow, condicionado a licença/ambiente. [CodeQL](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/).
- Frida para instrumentação controlada, API conferida na versão fixada. [Frida](https://frida.re/docs/javascript-api/).
- libFuzzer candidato para harnesses nativos conforme toolchain/plataforma. [LLVM](https://llvm.org/docs/LibFuzzer.html).
- Syft candidato para SBOM; inventário não prova alcançabilidade. [Syft](https://github.com/anchore/syft).
- ILSpy para trilha .NET e JADX para DEX/Android; extensões posteriores com corpus próprio. [ILSpy](https://github.com/ICSharpCode/ILSpy) / [JADX](https://github.com/skylot/jadx).
- SARD/Juliet como referência de defeitos, complementada por projetos próprios/reais. [NIST SARD](https://www.nist.gov/itl/csd/secure-systems-and-applications/samate/software-assurance-reference-dataset-sard) / [Juliet](https://samate.nist.gov/SARD/documentation).
- Binary Ninja opcional: licença não resolve integração ausente. Ferramentas comerciais só após ganho demonstrado.

Consultado em 2026-09-15. As fontes sustentam capacidades gerais, não desempenho/integração neste host. Verificar versões e termos antes de instalar; não se afirma superioridade sobre todas ferramentas existentes.

## 9. Primeiro lote de execução

| ID | Trabalho | Aceitação |
|---|---|---|
| RE-001 | Baseline/ambientes | Manifesto e falhas reproduzidas |
| RE-002 | Contratos adapters | Sucesso/ausência/erro/timeout sem chaves faltantes |
| RE-003 | Preservar ausentes | Frida/BN continuam no report com motivo |
| RE-004 | Snapshot único | JSON e C têm pseudo-fonte consistente e hashes |
| RE-005 | Matriz por pares | 0.65 e 0.075 não viram média igual para ambos |
| RE-006 | Fonte única/cobertura | Acordo N/A e denominadores explícitos |
| RE-007 | Consumo Binary Ninja | Double passa contrato; integração real só com ferramenta |
| RE-008 | Chamadas angr | Destinos conhecidos no microbinário recuperados |
| RE-009 | Budget Ghidra | 201+ funções completas ou corte declarado |
| RE-010 | Outputs antigos | Falha não reaproveita C sem validação |
| RE-011 | Ambiente/PATH Frida | Testes isolados de plugins globais, descoberta diagnosticável |
| RE-012 | Regressão e diff | Corpus próprio + calc + Notepad, logs e métricas |

Diretórios de testes propostos: D:\AetherRE_Megazord\tests\contracts, D:\AetherRE_Megazord\tests\regression, D:\AetherRE_Megazord\tests\integration e D:\AetherRE_Megazord\tests\fixtures. Ainda não criados por este plano.

Marcos:
- M1: F00-F02 + corpus bootstrap F03; pipeline honesto e reproduzível.
- M2: F04-F07; compreensão fonte/binário e auditoria no perfil inicial.
- M3: F08-F10; laboratório, contraexemplos e métricas calibradas.
- M4: F11-F12; assistência governada e homologação.

Não prometer prazo final antes de medir M1, capacidade e throughput. Estimativas por lote depois de observar esforço/dependências. Esforço não é prova de qualidade.

## 10. Encerramento obrigatório por fase

1. Conferir Git status/mudanças alheias; não sobrescrever outro operador.
2. Definir contrato e teste de regressão que falha quando aplicável.
3. Implementar mudança mínima integrada com compatibilidade/migração explícita.
4. Executar unidade, contratos, integração real e suíte completa do perfil.
5. Comparar baseline, acerto, regressões, custo e erros.
6. Publicar gate com links/hashes e classificar QUITADA, PARCIALMENTE QUITADA, NÃO QUITADA ou NÃO COMPROVADA.
7. Gate crítico reprovado impede declarar conclusão; trabalho independente não esconde dívida.
8. Registrar próximo lote e retomada sem depender de janela/BAT decorativo.

Estado: PLANO ENTREGUE. Fases futuras não implementadas. Primeiro trabalho técnico: F00/F01, não adicionar UI/plugins ou porcentagens de marketing.

## Anexo de execução empírica — 16/09/2026

O texto acima é o plano original; a frase histórica “fases futuras não implementadas” não foi apagada. O estado verificado no ciclo atual é:

| Fase | Estado | Prova mínima disponível | Dívida que continua |
|---|---|---|---|
| F00 | PARCIALMENTE QUITADA | doctor, snapshot verificado, restore local, manifests/checkpoints | matriz completa de ambientes, disco/VM e recuperação de todos os incidentes ainda não demonstrada |
| F01 | PARCIALMENTE QUITADA | adapters com estados explícitos, snapshot canônico, suíte verde | Binary Ninja indisponível e cobertura de defeitos/toolchains ainda limitada |
| F02 | PARCIALMENTE QUITADA | contratos, hashes, locks, cache, checkpoints e publicação atômica testados | campanha de adulteração/concorrência/disco cheio em escala ainda pendente |
| F03 | PARCIALMENTE QUITADA | bootstrap v2 com 20 projetos e splits declarados | oracle sintético, sem compilador C e sem projetos independentes |
| F04 | PARCIALMENTE QUITADA | leitores Python/C estáticos e grafo conservador | Clang/semântica completa, macros/templates e corpus independente pendentes |
| F05 | PARCIALMENTE QUITADA | PE32/PE32+, ELF32/ELF64, DWARF opcional, seções/segmentos/símbolos/relocations | CFG/disassembly ELF, PDB/COFF completo, ASLR/rebase e corpus real independente |
| F06 | PARCIALMENTE QUITADA | correlação por símbolos ELF/exports como candidatos com ambiguidade preservada | build/debug/trace equivalence e precisão independente não comprovadas |
| F07 | PARCIALMENTE QUITADA | auditorias estáticas de risco/dependência/taint com limitações | alcançabilidade causal, SBOM amplo e validação dinâmica pendentes |
| F08 | PARCIALMENTE QUITADA | política de efeitos e adapters sem execução automática | VM descartável, traces reais e rollback não demonstrados |
| F09 | NÃO QUITADA | scaffolding e budgets de fuzz/simbólico | contraexemplos reais e equivalência comportamental não executados |
| F10 | NÃO QUITADA | métricas e avaliação sintética | calibração cega, IC/ECE/Brier e holdout independente ausentes |
| F11 | PARCIALMENTE QUITADA | claims estritas e revisão de suporte | LLM/UI adversarial e operação offline completa não comprovadas |
| F12 | PARCIALMENTE QUITADA | homologação/repro de runs PE/ELF selecionados | instalação limpa, revisão independente e gate sem P0/P1 global ainda não atingidos |

Este anexo não transforma qualquer score, suíte ou homologação em aprovação global. O projeto segue **PARCIALMENTE QUITADO** e continua em dívida nas lacunas listadas.

## Atualização F06 — 16/09/2026

A auditoria de build agora lê `compile_commands.json` de forma estática, registra unidades, flags, compilador declarado, escopo e hash da fonte, com `executed=false` e falhas explícitas. Isso melhora a ponte fonte→build, mas não altera o gate: sem compilação controlada, debug info e vínculo binário independente, F06 permanece **PARCIALMENTE QUITADA**.

A ponte F06 foi ampliada com `--build-report`: candidatos de correlação recebem contexto de `compile_commands` e hash de fonte quando disponível, mantendo `requires_validation=true`. O gate continua parcial por ausência de build/debug/trace independente.

## Atualização F03/F05/F06 — 16/09/2026

O corpus C `bootstrap_v2` foi compilado somente após acionamento explícito do worker WSL/GCC. Os dez ELF gerados tiveram hash e identidade estrutural verificados, e o avaliador binário encontrou DWARF nos dez casos. As métricas são evidência de integração no corpus sintético, não aprovação independente: precisão de candidatos ficou baixa por ruído de símbolos de runtime, relações foram mantidas `not_measured` e nenhum binário foi executado.

A execução nativa explícita reduziu a lacuna “sem compilador C” para o corpus próprio: GCC no WSL produziu 10 ELF com DWARF verificável, sem execução dos alvos. Isso não fecha F03/F06, pois o oracle continua sintético e relações/semântica independentes ainda não foram validadas.

As variantes F03/F05/F06 agora incluem O2 com e sem DWARF/stripping. O resultado stripped com recall 0,0 foi mantido como limite observável; não há promoção automática baseada apenas no build verde.
