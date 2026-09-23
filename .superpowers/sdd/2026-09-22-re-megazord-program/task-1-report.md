# Task 1 — Baseline do programa RE_Megazord

Status: QUITADA para o escopo da Task 1.

## Escopo entregue

- `tools/f00_program_baseline.py` produz `program-baseline.v1` de forma
  determinística, com hash SHA-256 e escrita atômica.
- `tests/test_program_baseline.py` cobre exclusão de artefatos Rotor e de uma
  distribuição gerada do Ghidra, sem excluir `tools/audit.py`.
- `docs/evidence/program-baseline.schema.json` fixa o contrato do relatório.

## RED/GREEN

O brief registrou um RED independente: a enumeração incluía
`tools/ghidra_12.1.2_PUBLIC/ghidra.jar`. Ao assumir a tarefa, o checkout já
continha o filtro correto em `EXCLUDED_DIRS` e a normalização por `casefold()`
em `safe_iter_files`; portanto, a falha não foi reproduzível localmente e não
foi fabricada alterando código de produção. O teste de regressão executado no
checkout atual ficou GREEN:

```text
tests/test_program_baseline.py: 2 passed
```

## Verificação executada

```text
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
Python 3.13 pytest tests/test_program_baseline.py tests/test_project_snapshot.py -q
15 passed in 2.63s
```

Captura real:

```text
schema: program-baseline.v1
included_count: 1719
excluded_count: 57
all_hashes_valid: true
report_sha256: 75d9c39f0309b4f9072796b1a9ffd429f1f463628979d8f0f61d733659f3dd71
output: D:\AetherRE_Megazord\output\f00_program_baseline.json
```

## Preocupações

- O baseline captura o estado atual do checkout; mudanças posteriores exigem
  nova captura e comparação de manifesto.
- A exclusão de distribuições geradas é uma lista explícita. Uma nova
  distribuição de ferramenta só deve entrar na lista após teste de regressão
  que preserve os scripts próprios adjacentes.

## Correção após revisão

- O relatório agora registra `git status --porcelain=v1` (incluindo hash dos
  bytes brutos, código de retorno e indisponibilidade explícita).
- JUnit é proveniência opcional via `--junit`, com caminho, SHA-256, tamanho e
  resumo normalizado; ausência é representada por `provided: false`.
- `samples/generated` e todos os seus descendentes são podados sem remover o
  irmão `samples/keep.py`.
- A regra ampla `tools/` do `.gitignore` foi substituída por `tools/*` com
  allowlist explícita dos scripts versionados da Task 1.
- O hashing falha fechado quando assinatura/tamanho do arquivo muda durante a
  leitura; os testes validam SHA-256 conhecido e o documento completo contra o
  JSON Schema Draft 2020-12.

Verificação da correção:

```text
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
Python 3.13 pytest tests/test_program_baseline.py tests/test_project_snapshot.py -q
18 passed in 2.63s
```
