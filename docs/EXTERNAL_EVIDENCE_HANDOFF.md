# RE_Megazord — Handoff de Evidência Externa

Este documento define o mínimo necessário para fechar os gates que não podem
ser concluídos apenas por testes locais. Cada item deve ser entregue com
origem, autorização, hash SHA-256 e data de coleta.

## 1. Corpus independente e oráculo (F03/F10)

- Pelo menos 10 projetos autorizados, fora do corpus Juliet e fora de qualquer
  projeto previamente usado em desenvolvimento ou calibração.
- Para cada projeto: fonte, licença/autorização, commit ou release imutável,
  manifesto de hashes e oracle versionado por humano independente.
- Split congelado antes de revelar rótulos: development, calibration e blind
  holdout; nenhuma família pode cruzar splits.
- Critério: o avaliador consegue recomputar hashes, recusar adulteração e
  medir precisão, recall, FPR, abstenção e intervalos de confiança no holdout.

## 2. Laboratório guest descartável (F08/F09)

- VM com snapshot inicial verificável, rede negada por padrão e coletor de
  trace dentro do guest.
- Prova de rollback: hash/marker antes da execução, alteração controlada,
  restauração de snapshot e ausência da alteração após o restore.
- Só executar alvos explicitamente autorizados; nunca usar host como alvo.
- Critério: evidência temporal do guest, rollback e limpeza; WSL por si só não
  satisfaz este item.

## 3. Custódia externa WORM (F00/F02/F12)

- Repositório/serviço com retenção imutável, identidade do escritor, data e
  política de retenção verificáveis.
- Subir snapshot, manifesto, logs e relatórios de teste; registrar URI/ID e
  digest de cada objeto.
- Critério: tentativa de alteração/remoção recusada pela política durante a
  janela de retenção.

## 4. Revisão independente (F11/F12)

- Revisor sem participação na implementação nem acesso prévio aos rótulos do
  holdout.
- Parecer assinado contendo escopo, versão/digests auditados, comandos usados,
  achados por severidade e declaração explícita sobre P0/P1.
- Critério: reprodução independente do pacote, validação do gate e nenhuma
  conclusão além das evidências disponíveis.

## Material já pronto para receber os insumos

- Gate scope-clean: `output/f12_phase_gate_report_v170.json`.
- Corpus Juliet hash-bound: `output/f03_scope_ground_truth_audit_20260921.json`.
- Perfil offline e testes: `requirements-core.lock`, `requirements-test.lock`
  e `output/f12_full_clean_suite_20260921.junit.xml`.
- Política e traces locais: `aether_re/lab_policy.py`, `aether_re/trace.py` e
  `output/f08_lab_capability_probe_20260921_f08agent.json`.

Sem esses insumos, os gates permanecem parcialmente quitados por definição.

## Atualização de candidatura — 28/09/2026

Substituir as referências históricas por estes artefatos ao solicitar revisão:

- replay A/B atual: `E:\AetherRE_Evidence\closure-20260927-223522\replay-final-ab-comparison.json`, SHA-256 `ce6f8954c45fbff8a6dc9bc30b1b9f0c01c93e9232d034f02d653494ca708277`;
- campanha F02/F11 atual: `E:\AetherRE_Evidence\closure-20260927-223522\mandatory-validation-campaign-current-v3.json`, SHA-256 `be5c2c93d1d7bf77e55659fd8f3accbc38aeda018fcea92a80bf208d494c2e5e`;
- gates atuais: `E:\AetherRE_Evidence\closure-20260927-223522\phase-gates-current-v4.json`, SHA-256 `538768c822c5dbd8b972a94c4114efa07ff4c5d4e02111b686a78afef7c14143`;
- template de VM: `E:\AetherRE_Evidence\closure-20260927-223522\dynamic-lab-handoff-template.zip`, SHA-256 `bf93cf907e9aa602a0d00c953a6589ef5a75639a5453c0c954c2237b1054c959`; ele é `NOT_EXECUTED`, não uma atestação.

O corpus externo precisa cobrir separadamente `native-pe`, `native-elf`,
`dotnet`, `jvm`, `android-apk`, `wasm`, `macho` e `firmware`, com licença,
autorização, família, SHA-256 e splits development/calibration/blind disjuntos
por família. O revisor recalcula métricas por perfil: precisão, recall, F1,
FP/FN, cobertura, abstenção, Brier, ECE e IC95%.

O retorno dinâmico deve ser `dynamic-lab-handoff.v1` assinado, com os quatro
contratos ligados por guest/snapshot/nonce e IDs de evidência distintos. WSL,
container e host direto não satisfazem F08/F09. O review deve usar chave Ed25519
externa ao repositório; a âncora WORM deve fornecer URI, retenção, escritor e
prova de recusa de alteração/remoção. Só então `release-build` poderá ficar
pronto para decisão explícita do proprietário.
