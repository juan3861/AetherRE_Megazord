# Auditoria integral — AetherRE Megazord: onde parou e o que falta para 100%

Data da auditoria: **2026-10-09** (auditoria somente-leitura sobre o worktree; nenhum
arquivo do projeto foi alterado, movido, commitado ou limpo).

Este documento é um **relatório de auditoria**. Ele **não** emite atestado, certificado,
`gate_passed` nem promoção de percentual. Ele também **não** substitui revisão independente.

---

## 1. Veredito atual (reconfirmado nesta auditoria, não herdado do ledger)

| Indicador | Valor verificado hoje | Como foi verificado |
|---|---|---|
| Release | **PARCIALMENTE QUITADA** | `phase-gates` reproduzido; 13/13 fases parciais |
| Gates QUITADA | **0 / 13** | `E:\AetherRE_Evidence\closure-20260927-223522\phase-gates-current-v4.json` |
| `gate_passed` | **false** | idem; `errors: []`, `quitada: 0`, `received: 13` |
| Suíte de testes atual | **778 passed, 0 failed, 0 errors, 0 skipped** | execução própria; JUnit SHA-256 `F5F6BEBB5232E1B6FA51C82EA7FC2B3FCC3F61CE4A014BA19D21E0975C367D89` |
| `status` / `selftest` CLI | exit 0 / exit 0 | execução própria |
| Replay A/B anterior | 749/749 em A e B, hashes conferidos | `closure-gen2-vhdx-20261001T080600Z` |
| Último commit Git | `38a14f4`, **23/09/2026 04:14** | `git log` |
| Worktree | **573 registros** (39 modificados + 534 não rastreados) | `git status --porcelain -uall` |

O placar formal continua **0/13 gates QUITADA**. Nada nesta auditoria mudou esse estado.

---

## 2. Onde o trabalho realmente parou

O ledger vivo (`.superpowers\sdd\2026-09-24-economic-ceiling-plan\progress.md`) termina
em **2026-09-30 22:51**. Mas o trabalho continuou depois e **não foi registrado**:

| Marco | Data/hora (local) | Observação |
|---|---|---|
| Último commit Git | 23/09 04:14 | **Todo o trabalho desde então está sem commit** |
| Última entrada do ledger | 30/09 22:51 | ledger para aqui |
| Delta pós-ledger no repo | 30/09 23:21 → **01/10 05:56** | 22 arquivos, nenhum registrado |
| Última escrita de evidência | 01/10 05:52 (VHDX) / 06:03 (relatório VM) | workstream Hyper-V não registrado |
| Hoje | **09/10 20:04** | **~8 dias parado** |

### 2.1 O que os últimos agentes estavam fazendo quando pararam

1. **Endurecimento do kernel de evidências** (30/09 23:21–23:59): novos `cache.py`,
   `lock.py` (`RunLock` com token de dono e recuperação de órfão), `homologation.py`,
   e `pipeline.py` passou a adquirir o lock e a auditar o pacote publicado
   (`audit_run_package(..., active_lock=run_lock)`), falhando fechado.
2. **Camada de release** (01/10 05:33–05:56): `release_builder.py` (exige 13 documentos
   `gate-evidence.v1` com `status=QUITADA`), `release_inventory.py` (explicitamente
   **não certificante**: nasce `NOT_CERTIFIED`, `promoted_gates=[]`), e os CLI
   `release-build` / `release-inventory` / `homologate`.
3. **Provisionamento de VM Hyper-V** (30/09 03:22 → 01/10 06:03): `tools\hyperv_provision.ps1`
   (797 linhas) + 8 tentativas reais e **elevadas** de provisionar VM.
4. A suíte foi de 680 → **749** (01/10 05:18) → **778** (estado atual), mas a versão
   final da árvore (05:56) **nunca teve a suíte completa rodada nem o ledger atualizado**.

**Conclusão:** o trabalho parou no meio da milha final — com a camada de release recém-criada
e o provisionamento de VM falhando — e ficou 8 dias sem retomada, sem commit e sem registro.

---

## 3. O que existe hoje (inventário)

- **`aether_re\`: 106 módulos** (78 top-level, 15 adapters, 13 engines); `tests\`: **137 arquivos**
  `test_*.py`; **65 subcomandos** na CLI `megazord.py`.
- Formatos/perfis com código: PE, ELF, DWARF, PDB/CodeView, WASM, JVM/JAR, .NET/ILSpy,
  Android/APK, Mach-O (shim), firmware (layout).
- Adaptadores: Ghidra, Rizin, angr, unicorn, capstone, pefile, WASM, JVM, ILSpy, Android;
  Frida e Binary Ninja **indisponíveis** (`binaryninja.py` é placeholder declarado).
- **Evidência** em `E:\AetherRE_Evidence` (~50 bundles, todos os hashes conferidos nos
  bundles inspecionados) e **`E:\AetherRE_DynamicLab` = 90,83 GB** (imagem Ubuntu Noble,
  pai materializado, VHDX gerado, 8 relatórios de provisionamento) — este último
  **não consta em nenhum documento do projeto**.

---

## 4. Os 13 gates e os bloqueios exatos

Critério mecânico de `QUITADA` (`aether_re\phase_gates.py:96-107`): `implementation=true`
**e** `integration=true` **e** `reviewed=true` **e** `tests.passed>0` **e** `failed=0`
**e** `skipped=0` **e** evidência não-vazia com todos os SHA-256 conferidos, sem erro estrutural.
`gate_passed=true` exige `errors=[]` **e** `quitada=13` (`phase_gates.py:300`).

| Fase | impl | integ | **reviewed** | tests (p/f/s) | Evidência | Condição que falha | Classe |
|---|---|---|---|---|---|---|---|
| F00 | true | true | **false** | 570/0/**3** | 4 ok | `reviewed`; `skipped` | externo + config (obsoleto) |
| F01 | true | true | **false** | **0**/0/0 | 1 ok | `reviewed`; `passed>0` | externo + declaração |
| F02 | true | true | **false** | 570/0/**3** | 3 ok | `reviewed`; `skipped` | externo + config (obsoleto) |
| F03 | true | true | **false** | **0**/0/0 | 1 ok | `reviewed`; `passed>0` | externo + declaração |
| F04 | true | true | **false** | **0**/0/0 | 3 ok | `reviewed`; `passed>0` | externo + declaração |
| F05 | true | true | **false** | **0**/0/0 | 1 ok | `reviewed`; `passed>0` | externo + declaração |
| F06 | true | true | **false** | **0**/0/0 | 2 ok | `reviewed`; `passed>0` | externo + declaração |
| F07 | true | true | **false** | **0**/0/0 | 1 ok | `reviewed`; `passed>0` | externo + declaração |
| F08 | true | true | **false** | **0**/0/0 | 1 ok | `reviewed`; `passed>0`; **VM real** | externo + técnico |
| F09 | true | true | **false** | **0**/0/0 | 1 ok | `reviewed`; `passed>0`; **depende de F08** | externo + técnico |
| F10 | true | true | **false** | 570/0/**3** | 3 ok | `reviewed`; `skipped` | externo + config (obsoleto) |
| F11 | true | true | **false** | 570/0/**3** | 2 ok | `reviewed`; `skipped` | externo + config (obsoleto) |
| F12 | true | true | **false** | **0**/0/0 | 2 ok | `reviewed`; `passed>0`; WORM | externo |

Resumo exato: **13/13 falham por `reviewed`; 9 falham por `tests.passed=0`; 4 falham por
`skipped=3`; 0 falham por evidência ausente/divergente** (25/25 hashes conferem).

### 4.1 Dois bloqueios são obsoletos e já estão resolvidos na árvore atual

Verificado nesta auditoria, nos mesmos testes:

- **Sem** `GHIDRA_HOME` e `MEGAZORD_MSVC_PE_FIXTURE`: `22 passed, 3 skipped`.
- **Com** as duas variáveis: **`25 passed, 0 skipped`**.

Ou seja, os 3 skips que travam F00/F02/F10/F11 são **puramente configuração** e já não
existem quando o ambiente é o correto. A declaração de 28/09 é que está defasada.

### 4.2 O gate é declarativo — e isso é uma fragilidade estrutural

`phase_gates.py` lê `reviewed` como **booleano declarado**. Uma edição do JSON de entrada
levaria `gate_passed` a `true` **sem qualquer mudança material no repositório**. A barreira
real contra isso não é o `phase-gates`, e sim o `release-certify`
(revisão independente Ed25519 + trust map externo). **Esta auditoria não materializou essa
declaração hipotética, de propósito** — fabricá-la seria autoautorização (regra 1 do `AGENTS.md`).

---

## 5. As frentes que faltam para 100%

### Frente A — Revisão independente das 13 fases (**EXTERNO — bloqueio duro**)
`reviewed=true` em 13/13 exige revisor de terceiro sem participação na implementação.
O autor não pode certificar a própria obra. **Não é resolvível internamente.**

### Frente B — Declaração de gates regenerada (**INTERNO — barato, alto retorno**)
A entrada canônica é de **28/09** e precede toda a árvore atual.
- Atribuir contagem de teste às **9 fases** hoje em `passed=0`.
- Refazer a declaração com **778/0/0/0** em vez de 570/0/3.
- Re-hashear as evidências atuais.
Isso remove 13 dos bloqueios não-externos, mas **não** produz `QUITADA` sozinho (falta `reviewed`).

### Frente C — F08/F09: VM real com snapshot/rollback (**TÉCNICO + EXTERNO**)
Estado verificado:
- Host: Hyper-V **instalado** — serviço `vmms` **Running/Automatic**, `vmms.exe` presente,
  módulo PowerShell presente, 32 GB RAM, 28 threads, discos **Healthy**.
- Token atual **não elevado**: `Get-VM` e `Get-VMSwitch` retornam **permissão negada**;
  `C:\ProgramData\Microsoft\Windows\Hyper-V` está **vazio (zero VMs)**.
- **8 tentativas elevadas** de provisionamento, **todas `blocked_or_partial`**:
  falhas em `create_differencing_disk` (`0xC03A001A`, disco esparso), em
  `create_vm_offline` (gen2 não aceita `.vhd`) e em `convert_parent_for_generation2` (erro de CRC).
- **Verificação própria do artefato final**: `ubuntu-noble-parent-fixed.gen2.vhdx` (30 GB)
  tem assinatura `vhdxfile` correta e **Headers 1 e 2 com CRC-32C válido**, mas o
  **último 1 MiB está 100% zerado** — ausência de footer/Region Table. Conversão **incompleta**.
- O `.vhd` materializado **perdeu o atributo `SparseFile`** (ficou só `Archive`), ou seja a
  densificação funcionou; o bloqueio restante é a conversão gen2 e o boot do guest.
- A versão atual do script (`hyperv_provision.ps1`, editado 01/10 05:37) **nunca foi executada
  end-to-end** (nenhum relatório iniciado depois disso).
- **Mesmo um sucesso do script não fecharia F08/F09**: ele cria a VM **desligada**
  (`Off`), nunca liga o guest, e grava `guest_started=false`, `rollback_proven=false`.
  Checkpoint de VM desligada **não** é prova de snapshot/rollback.

### Frente D — Corpus e oráculo independentes, 8 perfis (**EXTERNO**)
Verificado executando `corpus-registry-validate`: **`NAO_COMPROVADA`, exit 3**, com
exatamente dois bloqueios: `blind_oracle_required` e `oracle_attestation_required`.
- Registry atual: **18 artefatos** — 6 desenvolvimento + 2 calibração + 10 "blind".
- Origem: **8 sintéticos próprios** (`bootstrap_corpus.py`) + **10 do NIST Juliet v1.3**.
- Cobertura: **apenas 2 perfis** (`native-elf`, `native-pe`) — **faltam 6** dos 8 exigidos
  (`dotnet`, `jvm`, `android-apk`, `wasm`, `macho`, `firmware`).
- O rótulo "blind" é **herdado** de manifesto antigo; o próprio autor declara que
  **não** é holdout novo, cego e independente.
- Falta: oráculo separado (`blind-oracle.v1`) **assinado Ed25519 por dono independente** +
  **trust map externo** ao repo e ao corpus.
- Lock de material atual: `2d581bfef8876cf2dbb9842af64281ae93e864c52fd6153ed83908c3965a367e`.

### Frente E — Ghidra governado (**TÉCNICO**)
Ghidra 12.1.4 foi baixado e verificado por hash, e a análise direta via `java.exe` funciona
(104/104 funções em `where.exe`). Mas: `worker_eligible=false`, `worker_qualified=false`,
`gate_passed=false`; **Ghidra continua fora dos locks de toolchain**. Faltam lock governado,
atestação de isolamento e certificado de corpus/oráculo do worker.

**O bloqueio do lock foi provado pelo conteúdo dos arquivos:** `tools\toolchain.lock.json` e
`tools\static_workers.lock.json` contêm apenas **rizin, wabt e binaryen** — **Ghidra não está
em nenhum deles**; e `requirements-core.lock`, `requirements-test.lock` e
`requirements-angr.lock` têm **0 ocorrências de "ghidra"**. O blocker declarado
*"not in governed toolchain lock"* é fato, não estimativa.
Ressalva: a alegação de integridade do ZIP contra o "official release digest" compara com um
digest **declarado localmente** — auditoria offline **não** a verificou contra a origem oficial.

### Frente F — Certificação externa final (**EXTERNO**)
`release-build` exige, dentro de um `release-root` fechado: **13 documentos `gate-evidence.v1`
com `status=QUITADA`**, um **commit Git de 40 caracteres**, o **lock de toolchain** e o
**lock de corpus**. Depois, `release-certify` exige **`independent-review.v1` assinado
Ed25519 por revisor externo** + **trust map externo**. Falta também a **âncora WORM** externa.
Note que o `--commit` obrigatório implica que **o candidato precisa estar commitado** — hoje
ele não está.

**Varredura forense de 4.828 JSONs em todo o acervo `E:\AetherRE_Evidence` — nenhum campo de
sucesso externo existe:**

| Campo procurado | Ocorrências reais |
|---|---|
| `"certified": true` | **0** |
| `"worker_eligible": true` | **0** |
| `"worker_qualified": true` | **0** |
| `"external_anchor": true` | **0** |
| `"signed": true` | **0** |
| `"gate_passed": true` | 627 — **todas** dentro de `pytest-temp*` (fixtures de teste); **0 fora** |

- **G8 (revisão independente):** existe **exatamente um** trust map Ed25519 não-fixture no
  acervo — `task3_windows_sandbox_slice_20260924_v8\trust-map.json`, com
  `key_id: "task3-local-sandbox-collector"`. É a chave do **próprio coletor local do autor**;
  o payload assinado declara `"not_independently_attested"`. **Auto-assinatura, não terceiro.**
  Todos os demais trust maps estão em diretórios com nome de teste pytest
  (`external-attestations-tests-*`, `pytest-temp-*`) — são **fixtures**, e há risco real de
  serem citados como atestação externa.
- **G9 (WORM):** **NÃO ENCONTRADO**. "WORM" aparece no acervo **apenas como negação
  explícita** (ex.: `EVIDENCE_KERNEL.md:30` — `external_anchor=false; it is not WORM…`).
  O único `worm-attestation.json` é fixture de teste
  (`object_uri: "s3://forensic-evidence/releases/megazord-abc123.tar"`): **forma de documento,
  não registro real**.

---

## 6. Achados críticos de auditoria (riscos)

1. **Risco de perda de ~2,5 semanas de trabalho.** O último commit é de **23/09**. Tudo
   depois disso — 573 registros, incluindo **61 módulos de `aether_re\`** (`phase_gates.py`,
   `homologation.py`, `release_builder.py`, `release_certification.py`, `corpus_registry.py`,
   `lab_policy.py`, `lock.py`, `toolchain_lock.py`, `trace.py`) e **110 arquivos de teste** —
   existe **apenas no worktree sujo**, sem commit, sem tag, sem stash.
   Um `git clean -fdx` destruiria o projeto. (A própria `AGENTS.md` alerta sobre isso.)
2. **O ledger está desatualizado e é enganoso em um ponto.** Ele não registra os 22 arquivos
   do delta nem o workstream Hyper-V. A entrada de 30/09 afirma que o token Hyper-V não era
   elevado — verdadeiro para aquela sondagem — mas existem **8 execuções elevadas** registradas
   em `E:\AetherRE_DynamicLab`. Quem ler só o ledger conclui que não houve tentativa real.
3. **`phase-gates` é satisfazível por edição de declaração** (§4.2). O valor probatório
   depende inteiramente de `release-certify`. Recomenda-se **não** tratar `gate_passed=true`
   do `phase-gates` como prova isolada.
4. **Teste com nome enganoso.** `tests\test_hyperv_provision_script.py:47`
   (`test_only_unique_private_network_and_differencing_gen2_vm_are_provisioned`) apenas
   verifica **presença de strings** no `.ps1` — não cria switch, disco nem VM.
5. **`homologate` pela CLI não exercita o caminho forte.** `megazord.py:1240` chama
   `audit_run_package(run_dir, target=...)` **sem `active_lock`**, então as checagens de posse
   de lock (`homologation.py:242-260`) não rodam por esse caminho; e **nenhum teste** referencia
   o subcomando `homologate`.
6. **Documentação-fonte desatualizada.** `AGENTS.md` aponta o hub em `D:\AetherMind_HUB\`,
   que **não existe**; e diz que `D:` tem 5,8 GB livres quando hoje tem **95,0 GB**
   (C: 6,8 · E: 136,2 · F: 39,6 — todos os discos `Healthy`). Ficam 3,15 GB / 66.340 arquivos
   em `output\` legado.
7. **Placar "75% técnico" — fonte localizada, matriz não reprodutível.** O número não está no
   repositório; ele vive em `E:\AetherRE_Evidence\continue-20260930-final\verification-summary.v1.json`,
   campo `progress.technical_percent: 75`, cujo próprio campo `basis` diz
   `"last formal matrix 39/52; not recalculated"`. A **matriz de 52 itens não existe no repo**,
   então o número **não é reproduzível nem auditável**. Não deve ser citado como métrica.
8. **Nomes de bundle que prometem mais do que entregam (risco de citação indevida).**
   `closure-gen2-vhdx-20261001T080600Z` **não contém VHDX algum** — só o A/B de testes; e os
   testes que passam ali (`test_generation2_parent_converts_vhd_to_vhdx_and_reuses_verified_copy`)
   são asserções sobre o **script PowerShell**, não execuções. `sparse-copy-probe-20261001T031140Z`
   traz dois arquivos de 16 MiB com o **mesmo SHA-256** e **nenhum manifesto/scope-note**.
   `closure-20261001T0240Z-A` e `ghidra-where-12.1.4-20260930` estão **completamente vazios**.
   Um bundle nomeado "gen2-vhdx" ao lado de um VHDX realmente corrompido é exatamente o tipo de
   artefato que pode ser citado como prova de algo que não foi provado.
9. **`E:\AetherRE_DynamicLab` (90,83 GB) está FORA do acervo de custódia.** Os 8 relatórios de
   provisionamento de VM não têm hash no acervo `E:\AetherRE_Evidence`. Devem ser incorporados
   com hash, ou a lacuna registrada explicitamente.
10. **`g5-…075930Z\SHA256SUMS.txt` está malformado** (uma linha com 4 pares hash+arquivo
    concatenados, não parseável) e foi auto-marcado `DO_NOT_USE.txt`; corrigido só no re-run
    `080348Z`. O `closure-postfix-20261001T030104Z-ab-comparison.v1.json` (v1 defeituoso,
    118 KB) permanece no acervo sem marcação, embora a v2 o declare *"defective and is not
    authoritative"*.
11. **Único `status: "QUITADA"` não-fixture do acervo** está em
    `f00-task1-final-evidence-v2.json`, com escopo **auto-limitado** a "F00/F02 custody
    reconciliation only". Não cobre isolamento dinâmico, comportamento de alvo, cobertura de
    formatos nem reconstrução universal — e não tem assinatura de terceiro.

---

## 7. Caminho ordenado para 100%

**Etapa 1 — Proteger e congelar (hoje, interno).**
Commitar o candidato (ou materializar um `release-root` fechado). Sem isso não há
`--commit` para o release e todo o trabalho segue em risco.

**Etapa 2 — Reconstruir a declaração de gates com a árvore atual (interno).**
Rodar a suíte com o ambiente correto (778/0/0/0), regenerar a entrada com contagem de teste
por fase, re-hashear as evidências. Elimina os bloqueios de "declaração" e de "3 skips".
Resultado esperado: 13/13 ainda **PARCIALMENTE QUITADA** (falta `reviewed`), mas sem
pendências internas.

**Etapa 3 — Fechar F08/F09 até o limite do host (técnico).**
Corrigir a conversão gen2 (validar o footer do VHDX, hoje zerado), criar switch isolado,
subir o guest, ligar a VM, provar rollback com marcador (hash antes → alteração → restore →
ausência da alteração), coletar trace, e emitir `dynamic-lab-handoff.v1`. Exige **sessão
elevada**. Sem revisor externo isso ainda não é `QUITADA` — mas é o que falta de engenharia.

**Etapa 4 — Toolchain: Ghidra no lock (técnico).**
Materializar o lock governado com Ghidra, atestação de isolamento e certificado
corpus/oráculo do worker; rodar `toolchain-verify` verde.

**Etapa 5 — Insumos externos (bloqueio duro, não resolvível internamente).**
- Corpus independente para os **6 perfis faltantes**, com licença, família, hashes e splits
  disjuntos + **oráculo cego assinado Ed25519** por dono independente + trust map externo.
- **Revisor independente** com parecer assinado (escopo, digests, comandos, achados, P0/P1).
- **Âncora WORM** externa (URI, retenção, escritor, prova de recusa de alteração).

**Etapa 6 — Release e promoção (do proprietário/terceiro).**
`release-build` com os 13 `gate-evidence.v1` + commit + locks → `release-certify` com
`independent-review.v1`. **A promoção de `gate_passed` é ato do proprietário e do revisor
externo, nunca do agente.**

---

## 8. Limites desta auditoria

- Não emiti atestado, certificado, `gate_passed` nem promoção de percentual.
- Não declarei `reviewed=true` nem fabriquei a declaração que tornaria o gate verde.
- Não alterei, movi, apaguei nem commitei nada; não usei `git clean`/`reset --hard`/`checkout .`.
- Não executei alvos hostis nem liguei VMs; as verificações de Hyper-V foram somente-leitura.
- Buckets do acervo `E:\AetherRE_Evidence` podados (`candidate`, `lane-*`, `pytest-temp*`)
  não foram varridos em profundidade total.

---

## Anexo — Verificações independentes desta auditoria

| Verificação | Resultado | Hash/comando |
|---|---|---|
| Suíte completa da árvore atual | **778 passed / 0 failed / 0 errors / 0 skipped**, exit 0 | JUnit SHA-256 `F5F6BEBB5232E1B6FA51C82EA7FC2B3FCC3F61CE4A014BA19D21E0975C367D89` |
| Replay A/B de 01/10 (749/749) | **hashes conferem** | A `c9cf35c1…` · B `3404027f…` (recalculados por mim) |
| `phase-gates` reproduzido | `status=partial`, `gate_passed=false`, `quitada=0`, exit 2 | entrada `phase-gate-manifest-current.v3.json` |
| `corpus-registry-validate` | `NAO_COMPROVADA`, exit 3, 18 entradas | lock `2d581bfe…`; erros `blind_oracle_required`, `oracle_attestation_required` |
| Skips são só configuração | sem env: 22 passed/3 skipped → com env: **25 passed/0 skipped** | `GHIDRA_HOME` + `MEGAZORD_MSVC_PE_FIXTURE` |
| VHDX gerado (30 GB) | Headers 1/2 **CRC-32C válidos**; **último 1 MiB 100% zerado** | sonda própria `vhdx_probe.py` |
| Discos físicos | todos `Healthy` / `OK` | `Get-PhysicalDisk` |
| Hyper-V | `vmms` Running; `Get-VM`/`Get-VMSwitch` → **permissão negada**; 0 VMs | `Get-Service`, `Get-VM` |
| Provisionamento Hyper-V | **8/8 `blocked_or_partial`** | `E:\AetherRE_DynamicLab\provisioning-reports\` |
| Git | HEAD `38a14f4` (23/09), 573 registros, sem tags/stash | `git log`, `git status` |
| Hashes declarados no acervo | **40/40 conferem, 0 divergentes, 0 ausentes** | `Get-FileHash` em 11 bundles |
| Varredura de campos de sucesso | `certified:true` **0** · `worker_eligible:true` **0** · `external_anchor:true` **0** · `signed:true` **0** · `gate_passed:true` só em `pytest-temp` | 4.828 JSONs |
| Ghidra no lock | **ausente** (lock tem rizin/wabt/binaryen) | `tools\toolchain.lock.json` |
| Trust map Ed25519 de terceiro | **inexistente**; o único não-fixture é do próprio autor | `task3_…_v8\trust-map.json` |
| Âncora WORM | **não encontrada** | acervo completo |

Evidência local desta auditoria: `E:\AetherRE_Evidence\audit-gap-analysis-20261009T200440\`
(com `scope-note.md` e `SHA256SUMS.txt`; bundle **local mutável**, sem gate, sem certificado,
sem assinatura — o nome foi trocado de `audit-100pct-…` para não afirmar cobertura inexistente).

**Positivo a registrar:** a disciplina de hashing do projeto é real — os 40 digests declarados
nos bundles inspecionados conferem, e o projeto rejeita explicitamente o próprio inventário
como prova de gate (`release_builder.py:134-135`) e nasce `NOT_CERTIFIED`
(`release_inventory.py:304-319`). O problema não é fabricação de prova; é **ausência de
insumos externos** e **trabalho não commitado/registrado**.
