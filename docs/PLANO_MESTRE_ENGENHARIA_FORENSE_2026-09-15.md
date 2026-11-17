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

## Plano de execução reuse-first — 12/10/2026

### Alvo e limite verificável

Elevar a extração e reconstrução **ao máximo tecnicamente defensável por envelope de capacidade**, sem prometer recuperar fonte original perdida na compilação, descriptografar conteúdo sem chave, ou garantir equivalência de qualquer software arbitrário. O produto deve distinguir sempre: observação, inferência, reconstrução, comportamento medido e propriedade não recuperável. `pseudo-fonte ≠ fonte original`.

### Estratégia para montar as engrenagens existentes

1. **Inventariar antes de adquirir:** consultar os adapters e locks existentes, identificar gaps por formato/arquitetura e reusar os workers já presentes. Não incorporar duplicatas nem baixar uma segunda ferramenta para a mesma função sem benchmark comparativo.
2. **Acoplar por processo/contrato:** ferramenta externa recebe argv estruturado, input imutável/hash-pinado, cwd temporário, timeout, budget de memória/CPU/output e versão/hash/licença fixados; saída hostil é validada e normalizada.
3. **Especializar e normalizar:** manter ILs nativas/Java/.NET/WASM e artefatos de domínio como fontes de evidência; mapear para IR canônica sem apagar campos nativos nem divergências. Cada transformação escreve um `LossLedger` (preservado, inferido, perdido, desconhecido).
4. **Correlacionar, não colapsar:** manter relações origem→build→símbolo→função→efeito como hipóteses com evidência, regra, confiança e contraexemplo. Sem símbolo/source map/debug info, baixa confiança e abstenção são resultados válidos.
5. **Separar estático e dinâmico:** static workers nunca executam alvo. Execução só com autorização, VM descartável, rede privada/bloqueada, snapshot conhecido, trace assinado e rollback materialmente verificado.
6. **Medir por envelope:** corpus autorizado por família e linguagem, divisão dev/calibration/blind holdout por projeto/família, oráculos independentes, métricas por perfil e revisão externa antes de qualquer promoção.

### Sequência prioritária de fechamento

| Ordem | Fase executável | Resultado exigido |
|---:|---|---|
| 0 | Custódia do checkout e da evidência; preservar o worktree sujo e o VHDX parcial | inventário, hashes, branch/HEAD e nenhum descarte/reset |
| 1 | Caminho econômico de VM usando formato nativo comprovado | não converter o VHD de 32 GB para VHDX quando a imagem/guest permite Gen1; não reservar uma segunda cópia se o parent validado será reutilizado |
| 2 | Provar provisioning real, isolado e desligado | parent validado, switch `Private`, disco diferencial, VM `Off`, checkpoint anterior à execução; isso **não** equivale a trace/rollback |
| 3 | Completar transport e guest qualification | hash do payload conferido no guest, nonce/lease, collector de eventos, assinatura confiável, amostra benigna e recuperação por snapshot |
| 4 | Fechar extração estática reuse-first | workers reais nos perfis declarados, IR + LossLedger, resultados diferenciais e limites/abstenção |
| 5 | Corpus e teste cego | famílias disjuntas, licença/autorização, oráculos independentes, métricas com denominadores/IC |
| 6 | Replay, revisão independente e release | duas reproduções offline, assinatura externa, âncora imutável, gates recalculados pelo certificador |

### Decisão de execução atual — redução de espaço e de risco

A imagem autorizada existente é VHD. A documentação da Microsoft recomenda Generation 1 para VHD e Generation 2 para VHDX; Ubuntu 24.04 consta como suportado em ambas as gerações. Portanto, o provisionador passa a selecionar Gen1 nativamente para esse VHD, evitando a conversão Gen2 que falhou por CRC e a reserva adicional de aproximadamente 32 GB. O artefato VHDX parcial antigo permanece intacto e não é adotado nem removido por este caminho. A seleção é fail-closed para Gen1 quando a fonte for VHDX. Fontes: [geração de VM e formatos de disco](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/should-i-create-a-generation-1-or-2-virtual-machine-in-hyper-v) e [matriz de suporte Ubuntu/Hyper-V](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/should-i-create-a-generation-1-or-2-virtual-machine-in-hyper-v).

O teste de espaço passa a distinguir **criar** vs **reutilizar** parent materializado: criação reserva o tamanho lógico do arquivo + folga downstream; reutilização validada exige apenas a reserva downstream e 1 GiB de margem. Manifesto órfão, parent sem manifesto ou hash/contrato divergente continuam recusados.

### Trabalho iniciado e estado não promovido

- `tools/hyperv_provision.ps1`: parâmetro `-VmGeneration Auto|1|2`; modo `Auto` escolhe VHD→Gen1 e VHDX→Gen2, sem conversão desnecessária. Gen1 só é aceito para fonte VHD. Disco diferencial mantém formato do parent; secure boot é configurado apenas em Gen2. O script continua criando somente VM `Off`, switch privado e checkpoint pré-execução; não inicia guest nem declara rollback.
- Reuso do parent existente deixou de exigir reserva para duplicar os 32 GB. Sem alteração/deleção do parent ou do VHDX parcial.
- TDD: regressão inicial **5 RED** (plano de geração ausente e reutilização recusada por reserva de cópia); focada pós-fix: `tests/test_hyperv_provision_script.py tests/test_hyperv_preflight.py` — **33 passed**, exit 0.
- Suíte integral pós-fix: **803 passed, 3 skipped, 0 failed, 0 errors**; JUnit `E:\AetherRE_Evidence\megazord-ceiling-20261012-vmgen1\pytest-full.xml` SHA-256 `50DBCBAC0136FBC1E94D855A269C836F99DFEF4E4E61EDA1150A917C9AFC86D2`; log SHA-256 `F65E11C236231B4CFBA9874CE1729CD643DF2FD284B9D5BBD659EC715E0E20BA`.
- Próximo bloqueio imediato: terminar preflight elevado de leitura e, se parent/hash/espaço/VM inventory passarem, provisionar somente a VM offline. Até lá, provisioning real permanece pendente; nenhuma amostra executada.
- **Nada aqui promove gate ou certificado.** F08/F09 seguem parciais; G3/G5/G8/G9 e perfis faltantes seguem com dívida. Não calcular score a partir desta suíte.

## Execução verificada — 12/10/2026 — caminho nativo Hyper-V Generation 1

**Checkpoint:** 16:01 -03:00. Branch/HEAD `codex/re-megazord-execution` / `42775fc8266f2cf2ff0b4a8dc1833f20dc4db186`; 15 registros pendentes no worktree. Sem commit, reset, limpeza ou promoção de gate.

### Mudança e integração

- `tools/hyperv_provision.ps1` agora escolhe a geração pelo formato do parent validado quando `-VmGeneration Auto`: VHD → Gen1 e VHDX → Gen2; recusa Gen1 se a fonte for VHDX e só converte VHD para VHDX no override explícito Gen2. Mantém private switch, disco diferencial, VM desligada e checkpoint anterior à execução.
- O cálculo de espaço separa uma cópia física nova da reutilização de um parent com manifesto, hash e contrato validados. Reuso reserva somente o espaço downstream + 1 GiB; não duplica os 32 GB existentes.
- Hashes grandes usam `Get-FileSha256Fast`: FileStream sequencial de 8 MiB; teste compara SHA-256 com o algoritmo legado em arquivo vazio e em entrada de múltiplos buffers. A implementação ainda lê por completo os arquivos grandes; o ciclo de provisionamento demorou 11m39s, então throughput/progress reporting é dívida de eficiência, não “instantâneo”.
- O `.gen2.vhdx` parcial de 32,25 GB permaneceu preservado e não foi adotado nem removido. Nenhuma fonte, corpus ou amostra foi executada.

### Testes e integridade local

- TDD no provisionador: os testes RED detectaram plano de geração ausente e bloqueio de espaço no reuso; depois, teste RED do hash streaming ausente. Verdes: `tests/test_hyperv_provision_script.py tests/test_hyperv_preflight.py` — **34 passed**.
- Suíte integral após todas as mudanças: **804 passed, 3 skipped, 0 failed, 0 errors** (807 testes, 274,714 s), Python 3.13.13, exit 0. Skips identificados: 2 fixtures Ghidra ausentes (`GHIDRA_HOME`) e 1 fixture MSVC ausente (`MEGAZORD_MSVC_PE_FIXTURE`).
- JUnit `E:\AetherRE_Evidence\megazord-ceiling-20261012-fastsha-final\pytest-full.xml`, SHA-256 `F29044FD510D493DD52F8E8DB750702588D6EB311B4DBF169F4EDDB3AC5E693A`; log SHA-256 `08205EE0D2715E333B6A35A103CF5BB4BDD8B2618DDD82E5AB037F5D8AE55844`.
- `megazord.py status`, `megazord.py selftest` e `git diff --check`: exit 0. O selftest analisou o Python 3.13 como PE e escreveu artefatos de demonstração; isso não é corpus independente nem aprovação de precisão.

### Prova Hyper-V recém-produzida

- Preflight elevado somente de leitura passou: 0 VMs antes da criação; 7 switches pré-existentes; Hyper-V/VMMS ativos; source e parent reconhecidos como VHD Fixed; espaço livre `78.640.717.824` bytes, reserva de reuso `52.077.789.184` bytes. JSON `E:\AetherRE_Evidence\megazord-ceiling-20261012-vmgen1\hyperv-preflight-staged.json`, SHA-256 `A2A5F64B332D4E8EFE8F6EC06702282B65FA45D9C82AE02FFF02927066B91CA9`.
- Provisionador real, elevado, exit 0; relatório `E:\AetherRE_DynamicLab\provisioning-reports\hyperv-provision-20261012T184258Z-eb7f818f.json`, SHA-256 `E502749F72FE4AB3ACF43E215F0B1877E4944C02F71B142BF18908BB8D25AE31`, status `provisioned_offline_pre_execution`.
- Artefatos: VM `AetherRE-Ubuntu-Noble-85907e22`, ID `88ac73d9-76e7-429f-a8ac-51c08a53fa60`, Generation 1, `Off`; switch `AetherRE-Private-85907e22`, tipo `Private`, sem NAT/external; parent VHD Fixed já existente; diferencing VHD 143.360 bytes, SHA-256 `5a809dac89161cc4154cc07a1a11033ac035879a627fc887c54189f646040873`; checkpoint `pre-execution-85907e22` criado antes de qualquer guest execution.
- Verificação Hyper-V pós-provisionamento, em segundo processo elevado somente de leitura: `PASS`; VM Off/Gen1, switch Private, uma NIC ligada somente a ele, checkpoint presente e cadeia do differencing disk apontando ao parent esperado. JSON `E:\AetherRE_Evidence\megazord-ceiling-20261012-vmgen1\hyperv-post-provision-verify.json`, SHA-256 `B3328701558EBFCD0B48AC25DD832D19BC064810BDAA5C8A43E544A124E8A81E`.
- **Limite:** guest não foi iniciado; nenhuma amostra/benign marker foi executada; não há trace comportamental nem rollback após execução. Um checkpoint pré-execução criado não prova que restauração funcione. Primeiro gate Hyper-V local está concluído somente como provisioning offline; F08/F09 permanecem PARCIAIS/NAO COMPROVADAS para execução dinâmica.

### Placar honesto e próximo salto

```text
Provisionamento Hyper-V nativo e verificado         [██████████] concluído localmente
Boot guest + transport/lease + collector de eventos  [░░░░░░░░░░] pendente
Execução benigna + trace + restore/rollback           [░░░░░░░░░░] pendente
Corpus independente/holdout nos perfis                [░░░░░░░░░░] pendente
Revisão externa assinada + âncora WORM                [░░░░░░░░░░] pendente
Homologação estrita F00–F12                           [░░░░░░░░░░] 0/13 QUITADA
```

Release segue **PARCIALMENTE QUITADA**. Nenhuma evidência acima é assinada por revisor externo ou ancorada em WORM; nenhum gate foi recalculado/promovido. Os 75% históricos não são métricas atuais. Próximo trabalho é colocar o guest sob transport governado e provar `boot → nonce/lease → executar marcador benigno autorizado → coletar trace assinado → restaurar checkpoint → verificar estado/hash`, com rede bloqueada. Só então considerar F08/F09; G3/G5, G8/G9 e os perfis ainda sem corpus/oráculo continuam dívida. **Continua em dívida.**

## Subgate incremental — verificador read-only do estado Hyper-V — 2026-10-12

**Capturado:** 2026-10-12 16:43 -03. Branch/HEAD `codex/re-megazord-execution` / `42775fc8266f2cf2ff0b4a8dc1833f20dc4db186`; 19 registros pendentes no worktree, preservados. Não houve commit, limpeza, reset, execução de guest nem promoção de gate.

### Peças implementadas e integradas

- `tools/hyperv_observe.ps1` coleta, sob UAC normal/elevado, somente a leitura: VM/estado/geração, tipo e identidade do switch, NICs, discos realmente anexados, todos os usuários do switch, SHA-256 do disco filho e checkpoint. Falha antes de gravar se o processo não for administrador. Não inicia guest, não executa amostra nem altera recursos Hyper-V.
- `aether_re/hyperv_observation.py` compara a observação recente com o relatório exato de provisionamento, exige collector elevado, janela máxima de 1 h, VM Off, switch Private sem outra VM conectada, exatamente um NIC/disco esperado, parent/path/type/tamanho/hash do filho e checkpoint correspondente. Rejeita campos faltantes, JSON com chaves duplicadas, constantes não-JSON, entradas stale e colisão entre arquivo de saída e entradas. Resultado `verified_current_state` não é elegível para gate; registra hash dos dois inputs e limites.
- `megazord hyperv-observation-verify` expõe o verificador. `tools/hyperv_observe_and_verify.bat` oferece um clique com prompt UAC padrão, sem bypass de policy, grava evidência em `E:\AetherRE_Evidence` e executa a comparação offline. As exceções `.gitignore` foram acrescentadas para que ambos scripts sobrevivam a checkout limpo.

### Verificação e evidência

- TDD do verificador: RED reproduziu ausência da API, aceitação indevida de campo de identidade ausente, aceitação indevida de switch compartilhado/disco não anexado e sobrescrita de entrada. GREEN final: `tests/test_hyperv_observation.py` **21 passed**.
- Regressão integral, Python 3.13.13, plugins externos desativados: **825 passed, 3 skipped, 0 failed, 0 errors** (828 casos), **263,37 s**, exit 0. Skips: 2 fixtures Ghidra sem `GHIDRA_HOME`; 1 fixture MSVC sem `MEGAZORD_MSVC_PE_FIXTURE`.
- JUnit: `E:\AetherRE_Evidence\megazord-hyperv-observe-final-20261012T193857Z-1c92a00a\pytest-full.xml`, SHA-256 `771C6E5634B7DC57C2D029A411722B96FA8A3732E65E892C248D720F2A09A730`; log SHA-256 `C72ED29BC158774D8CED155487AFF05D29378F9E2991285F9CFA98C2FA95AAE7`.
- `megazord status`, `megazord selftest`, `compileall`, parser PowerShell e `git diff --check`: exit 0. A verificação antiga `hyperv-provision-independent-readonly-check.v1` foi recusada como incompatível (`invalid`, 0 checks), resultado SHA-256 `A592C43DFAF184BA5C78D996D99AADFF448237970D2DC181D29A42BD57B87EB8` em `E:\AetherRE_Evidence\megazord-hyperv-observe-20261012T193022Z-ff743b17\legacy-observation-rejected.json`.
- Execução real do collector sem elevação: exit 3, mensagem explícita de recusa; nenhum arquivo de observação foi criado. Isso confirma fail-closed, **não** estado Hyper-V atual.

### Impacto e limite

```text
VM isolada provisionada Off + checkpoint                     [FEITO ANTERIORMENTE; OFFLINE]
Collector/verificador atual read-only + testes                [FEITO LOCALMENTE; 21/21]
Observação fresca pelo botão/UAC e comparação do host real    [PENDENTE]
Transport governado + boot + marcador benigno + trace         [PENDENTE]
Restore do checkpoint + rollback verificado                   [PENDENTE]
Corpus/oráculos/holdout independentes nos perfis               [PENDENTE]
Revisão independente + WORM + certificação final               [PENDENTE]
F00–F12 estritos                                                [0/13 QUITADA]
```

**F08/F09 continuam PARCIALMENTE QUITADAS/NAO COMPROVADAS**: o observer não foi executado elevado e não há guest, amostra, trace ou rollback. O botão está em `D:\AetherRE_Megazord\tools\hyperv_observe_and_verify.bat`; ao ser executado, pede consentimento UAC normal e apenas observa o VM existente. G3/G5 (corpus e oráculos), G8 (terceiro), G9 (WORM), certificados estáticos e promoção permanecem pendentes. Sem porcentagem técnica recalculada; 75% permanece histórico. **Continua em dívida.**

## Checkpoint de execução reuse-first — 2026-10-12 17:10 -03

**Status:** a fatia de correlação de identidade exata foi implementada e verificada; não é certificação de perfil nem homologação universal. **Branch/HEAD:** `codex/re-megazord-execution` / `42775fc8266f2cf2ff0b4a8dc1833f20dc4db186`. **Worktree:** 20 registros pendentes antes deste checkpoint; alterações anteriores preservadas, sem commit/reset/clean/stash. Nenhum gate promovido.

### Mudança e teste

- TDD RED: os testes novos falharam como esperado quando `build_artifact_correspondence` ainda não existia e quando uma identidade conflitante da REA poderia ser vinculada indevidamente. GREEN: `tests/test_rea_static_adapter.py tests/test_rea_cli.py` **12 passed** (5,63 s).
- Implementado `build_artifact_correspondence(...)` em `aether_re/rea_static.py`. A ligação exige caminho relativo normalizado, SHA-256, tamanho confirmado pelo snapshot/AetherRE e referência de arquivo explícita na evidência REA. Caminhos inseguros e digests conflitantes são recusados/desvinculados; conflitos e não correspondências permanecem registrados.
- Sem fusão semântica: `artifact-correspondence.v1` informa `same_input_bytes_only`; `semantic_graph_merge=not_attempted`; `cross_engine_correlation.status=not_attempted`. Nenhuma inferência de comportamento, equivalência, recuperação de fonte ou presença/ausência é adicionada.

### Execução material

- Worker REA real revalidado contra lock: REA 6.4.0, MIT, Node v22.22.0, verificação `verified=true`, issues vazias. Hashes travados: tarball `59eb1604b8db75f522d4a975c36ce6b4a2ad465e43bad165f9a8f728391db9b8`; pacote `e9ff3a7a206d80fb83258190e7f8b5e18feb55a2753318bd423c97aa393293f8`; dependências `80d9148c1192a73164aadfa14f09831576e573ba589835f6bf1a236500b377fc`; Node `bae898add4643fcf890a83ad8ae56e20dce7e781cab161a53991ceba70c99ffb`.
- Smoke static-only real em fixture local benigno JavaScript/Electron, nunca executado: `rea-js-analyze` exit 0; 3 arquivos no snapshot, 2 arquivos JS parseados, 12 findings, 0 parse failures. Correspondência: 3/3 arquivos com identidade exata por caminho+bytes, 0 conflitos, 1 referência sem identidade exata (raiz não mapeada). Relatório `E:\AetherRE_Evidence\megazord-reuse-ceiling-20261012T2001Z\analysis-run\rea-federated-report.v1.json`, SHA-256 `0A3D8384675450D8EEEDA1E33339266E61958960C41DDCAF40BF06F59EAFC2AE`.
- Verificador externo ao repo, autocheck local: **20/20 checks**; resultado `E:\AetherRE_Evidence\megazord-reuse-ceiling-20261012T2001Z\rea-smoke-verification.v1.json`, SHA-256 `E6FC332BCCA5620071FEEBDF4B8622B964DA7507409727774C07FE3EFFCE7170`. O próprio artefato declara `release_certified=false`, `independent_reviewer=false`, `worm_anchored=false`, `gate_promotion=false`.
- Suíte integral pós-integração: **828 passed, 3 skipped, 0 failed, 0 errors** (831 coletados), Python 3.13.13, plugins externos desativados, 319,05 s, exit 0; 1 warning CFFI em teste de status. Skips: duas fixtures Ghidra/`GHIDRA_HOME` e uma fixture MSVC/`MEGAZORD_MSVC_PE_FIXTURE`. JUnit `E:\AetherRE_Evidence\megazord-reuse-ceiling-20261012T2001Z\pytest-full-attempt2.xml`, SHA-256 `99127AD231C7BCC0619925407E650DF40614E2D87A8DD81B2519CEBD4EAEE2EF`; log SHA-256 `CA6C98771B4BD749CD43801EA9C3DFE3B5EFD60F98141BE5B1AC5DF465D0327E`.
- `megazord status`, `megazord selftest`, `compileall` e `git diff --check`: exit 0. A primeira chamada do pytest com argumento JUnit malformado não coletou testes (exit 4); foi repetida com sintaxe correta e o resultado acima. A primeira chamada REA apontou para pasta de saída previamente criada (exit 2, sem evidência); rerun em diretório novo terminou com exit 0. Bundles anteriores foram mantidos sem reescrever hashes.
- Hashes do código/teste atual: `aether_re/rea_static.py` `10628338369A7FC9144BF8DFFB19DC98AF10FF4DDD000091E6CF64174AE40CBA`; `tests/test_rea_static_adapter.py` `145FEC1754A4AE2E343ECC5C0BA0ECC25C25EF84C0ACD555CD8A41842F95FC30`.

### Impacto e dívidas F00–F12

```text
F00 cadeia externa/WORM                         [PENDENTE]
F01/F02 adapter e identidade de bytes            [IMPLEMENTADO + TESTADO LOCALMENTE; sem promoção]
F03 corpus, licença, oracle e blind holdout       [PENDENTE]
F04/F05 8 perfis certificados                    [0/8; esta fatia é somente smoke REA]
F06 guest transport e trace                      [PENDENTE]
F07 proveniência/certificação independente        [PENDENTE]
F08/F09 VM dinâmica e rollback                   [PARCIAIS/NAO COMPROVADAS; sem guest/trace/rollback]
F10 métricas cegas/calibração                     [PENDENTE]
F11 revisor externo                              [PENDENTE]
F12 release certificada                          [PENDENTE]
F00–F12 estritos                                 [0/13 QUITADA]
```

Sem percentual global novo: 75% permanece histórico. Release **PARCIALMENTE QUITADA**; zero gates estritos quitados. Ainda falta: corpus/oráculos independentes e holdout por perfil, workers e certificados dos outros perfis, guest com execução/trace/rollback reais, revisão assinada de terceiro, WORM externo e decisão de promoção do proprietário. Pseudo-fonte não é fonte original; smoke estático não demonstra comportamento. **Continua em dívida.**
## Revalidação final reuse-first — 2026-10-12 17:16 -03

Este registro complementa e **supersede os denominadores de teste anteriores neste ciclo**; não altera o estado de gates. Foram adicionados testes fail-closed para colisão de caminhos por case-folding (`Main.js`/`main.js`), conflito de byte length no inventário AetherRE e ID de nó REA duplicado.

- Focada `tests/test_rea_static_adapter.py tests/test_rea_cli.py`: **15 passed**, 0 falhas/erros/skips, 2,10 s.
- Suíte integral final, Python 3.13.13, plugin autoload desativado: **831 passed, 3 skipped, 0 failed, 0 errors**, 834 coletados, 284,27 s, exit 0. Os três skips continuam sendo duas fixtures Ghidra/`GHIDRA_HOME` e uma fixture MSVC/`MEGAZORD_MSVC_PE_FIXTURE`. JUnit `E:\AetherRE_Evidence\megazord-reuse-ceiling-20261012T2001Z\pytest-full-final.xml`, SHA-256 `06B91BCE56CD8F73E59C04B96CBC2B808E75E5FFD8978ECDECABB3AA57AD9D9B`; log SHA-256 `AF95F333D8C08FCF1DFCCE3E4F2D487143ECE9098303DBEC4F43DFC6350FE614`.
- Revalidação final: `megazord status=0`, `megazord selftest=0`, `compileall=0`, `git diff --check=0`. Worktree continua com 20 registros, branch/HEAD inalterados (`codex/re-megazord-execution` / `42775fc8266f2cf2ff0b4a8dc1833f20dc4db186`). SHA do teste atualizado: `tests/test_rea_static_adapter.py` `CF89BFCE3DB5326D6A10E255EC403F4838ECBC80322965D437C3FFFC9CB0D086`.
- O smoke real e seu recibo 20/20 permanecem válidos porque o código de produção e a amostra não mudaram; o incremento final desta revalidação foi apenas cobertura adicional de teste. Bundle permanece em `E:\AetherRE_Evidence\megazord-reuse-ceiling-20261012T2001Z\`.

**Conclusão limitada:** subfatia de identidade exata implementada, executada e coberta pelos testes locais. Não significa perfil JavaScript certificado, fusão semântica, equivalência comportamental, homologação por terceiro ou evidência WORM. F00–F12 seguem **0/13 QUITADA**, release **PARCIALMENTE QUITADA**; F08/F09, G3/G5, G8/G9 e perfis restantes continuam em dívida.