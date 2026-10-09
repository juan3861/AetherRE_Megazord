# F03 — corpus complexo próprio (evidência parcial)

Data: 17/09/2026. Escopo: dez miniprojetos Python próprios em `corpus/complex_v1/`, gerados por `tools/complex_corpus.py`, além dos 20 microprojetos anteriores em `corpus/bootstrap_v2/`. Os dez são **desenvolvimento/calibração**, não holdout cego nem ground truth independente. O gerador e o oracle foram escritos pelo mesmo autor; nenhum alvo foi executado.

## Casos e verificações

Famílias: documentação falsa, código potencialmente morto, feature flag, teste com mock, ciclo de imports, import dinâmico, decorator, callback, alias/homônimos e fallback de exceção. Cada projeto contém fonte principal, módulo auxiliar, `README.md`, `config.json` e oracle; o caso de mock também contém teste. O manifesto traz hash SHA-256 de fonte, oracle e cada arquivo auxiliar declarado. O validador recusa adulteração de auxiliar antes de compilar; o avaliador também recusa antes de pontuar. O validador compila todos os `.py` declarados, não só o arquivo principal. `py_compile` não executa código-alvo.

Evidência local: `output/f03_complex_build_validation_v3.json` registra 10/10 projetos validados e 32 arquivos Python compilados, sem erros de manifesto. `output/f03_complex_source_eval_v3.json` registra 10/10 projetos processados, sem erros de integridade. A suíte global em `output/project_suite_20260917_v156.log` registra 302 testes aprovados. `complete` nesses relatórios significa **processamento concluído**, não aprovação de acurácia ou fase.

Métricas por projeto (médias aritméticas, oracle sintético): desenvolvimento n=7, recall de relações resolvidas 0,929; calibração n=3, recall 0,5 e precision 0,667. O caso alias/homônimos tem precision=0 e recall=0 na métrica atual. A métrica reduz símbolos a nomes finais (`_leaf`), colapsando identidades homônimas, e não prova resolução qualificada. Rótulos sobre documentação falsa, mocks, flags, alcançabilidade e caminhos de exceção estão registrados, mas **não são pontuados** como verdade semântica. Relação indireta callback não é provada estaticamente.

## Pendências para aprovar F03

- Oracle externo e independente, com origem/autorização/revisão e adjudicação de discordâncias.
- Subconjunto SARD/Juliet com negativos correspondentes e controles de licença/custódia.
- Projetos reais distintos; variantes do mesmo projeto não contam como amostras independentes.
- Split cego por família/origem, sem vazamento de geração/autoria; não usar esta calibração como holdout.
- Matriz pairwise de arquitetura, compilador, otimização, stripping, símbolos, imports e indireção.
- Métrica por identidade qualificada, estratificação de ambiguidades, IC/calibração e limites por perfil.
- Compilação não comprova execução segura; validação dinâmica requer VM descartável e autorização explícita.

Classificação do gate F00–F12 (`output/f12_phase_gate_report_v10.json`): **F03 NÃO QUITADA**. Há componentes entregues parcialmente, mas implementação e integração da fase inteira não foram comprovadas. O gate global permanece `false` (0/13 fases quitadas). Continua em dívida.
