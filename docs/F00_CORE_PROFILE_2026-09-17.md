# F00 — perfil core reproduzível (Windows amd64 / CPython 3.13)

Estado: **PARCIAL**. Perfil mínimo estático instalado e testado em venv novo; não representa o produto integral nem a homologação F00.

## Entradas fixadas

- `requirements.txt`: somente pefile, Capstone, Rich e Unicorn como dependências diretas do core.
- `requirements-core.lock`: sete distribuições exatas com SHA-256 do wheel; inclui dependências transitivas.
- `requirements-frida.txt`: Frida CLI opcional, fora do core. O download `--only-binary=:all:` da lista antiga falhou para `frida-tools>=14` neste Python/índice; instalar sdist sem revisão não foi usado como atalho.
- `output/wheelhouse_core_20260917/`: sete wheels obtidos para este perfil (18.953.771 bytes); artefato local ignorado pelo Git, não custódia externa.

## Replay de instalação sem rede

```powershell
cd D:\AetherRE_Megazord
py -3.13 -m venv output\clean_core_venv_20260917
output\clean_core_venv_20260917\Scripts\python.exe -m pip install --no-index --only-binary=:all: --find-links output\wheelhouse_core_20260917 --require-hashes -r requirements-core.lock
output\clean_core_venv_20260917\Scripts\python.exe -m pip check
```

Resultado observado em 17/09/2026: criação exit 0; instalação offline com hashes exit 0; `pip check` sem requisitos quebrados. `megazord.py status` exit 0, Frida/angr/Binary Ninja explicitamente indisponíveis no venv core. `megazord.py doctor --json` exit 0. Análise estática sem adapters de `samples/fixtures/notepad_reference.exe` exit 0, seguida de `homologate` **pass para aquele run raso**, sem provar engenharia reversa completa. Auditoria de projeto sobre `D:\AetherRE_Megazord_scope_snapshot_20260917_v1\files` exit 2, `partial`, como esperado pelo escopo.

Evidências: `output/f00_core_wheel_download_20260917.log`, `output/f00_clean_core_install_20260917.log`, `output/f00_clean_core_status_20260917.log`, `output/f00_clean_core_doctor_20260917.json`, `output/f00_clean_core_binary_run_20260917/`, `output/f00_clean_core_homologation_20260917.json`, `output/f00_clean_core_project_audit_20260917.json`.

## Dívidas de F00

- Wheelhouse ainda não tem espelho/assinatura/custódia externa; hashes locais não garantem disponibilidade futura.
- Perfil é Windows amd64/CPython 3.13; outros Python/OS/arquiteturas exigem locks e campanhas próprios.
- Integração real de Ghidra/Rizin/angr/Frida, worker dinâmico, CLI opcional e suíte completa em instalação limpa não foram homologados.
- Testar PATH mínimo, Java inválido, ferramenta ausente, migração/replay e restauração sem depender do host atual.
- O wheel instalado executa código de terceiros na instalação/import; venv não é fronteira de segurança para pacote hostil.

Continua em dívida.

## Bundle offline testado

`output/f00_core_offline_bundle_20260917.zip` foi gerado com timestamps ZIP fixos, contendo os sete wheels, o lock e `wheelhouse_manifest.json`; SHA-256 do ZIP: `09c1b4c29790f67e76bf854615a089de53b2d07b5f5e4fcb5d100eb238d13b89`. SHA-256 do lock: `34a1719f374ff012ea186474315722a8ea8359a6cff17b70b72376998a403b86`. O bundle foi extraído em diretório novo; nomes, tamanhos e hashes dos sete wheels foram verificados. Um **segundo venv limpo** instalou o core exclusivamente desse bundle, offline e com `--require-hashes`: `output/f00_core_bundle_replay_install_20260917.log`, exit 0; `pip check`, `megazord status` e homologação do run raso anterior também passaram. Isto comprova replay do **perfil core neste host/plataforma**, não do conjunto completo de adapters e laboratórios.
