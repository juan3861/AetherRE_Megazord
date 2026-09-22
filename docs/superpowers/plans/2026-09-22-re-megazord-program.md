# RE_Megazord Maximum Forensic Engineering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transformar o RE_Megazord existente em uma plataforma de reconstrução e auditoria forense por perfis, com evidência rastreável, execução contida e certificação F00–F12 sem alegações universais não comprovadas.

**Architecture:** Um Evidence Kernel central recebe artefatos por Universal Intake e despacha workers isolados mediante Profile Router. Backends produzem observações para IR/grafo com proveniência; consenso, reconstrução diferencial, calibração e gates publicam apenas capacidades comprovadas.

**Tech Stack:** Python 3.13, pytest, JSON/JSONL determinístico, subprocessos PowerShell limitados, Ghidra, Rizin, angr/Z3, Unicorn, Frida, ILSpy, JADX/Apktool, WABT/Binaryen e hypervisor Windows disponível.

**Spec:** `docs/superpowers/specs/2026-09-22-universal-forensic-reconstruction-design.md`

## Global Constraints

- Projeto alvo exclusivo: `D:\AetherRE_Megazord`; Rotor-LLM é fora de escopo.
- Interpretador canônico neste host: `C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe`.
- Estados epistemológicos: `EXACT`, `VERIFIED_RECONSTRUCTION`, `PROBABILISTIC_INFERENCE`, `HYPOTHESIS`, `UNKNOWN`.
- Estados de dívida: `QUITADA`, `PARCIALMENTE_QUITADA`, `NAO_QUITADA`, `NAO_COMPROVADA`.
- Execução de alvo desconhecido no host é proibida; dinâmica depende do gate de VM real.
- Ferramentas externas são pinadas por versão, hash e licença e executadas fora do processo central.
- Outputs de ferramentas são dados hostis e precisam de validação de schema e limites.
- Holdout cego não pode ser usado para tuning; contaminação exige substituição do split.
- Um gate só passa com evidência hash-validada; percentual não substitui F00–F12.
- O worktree já contém mudanças do usuário: cada commit deve incluir apenas os arquivos da tarefa.

## Review Focus

- Arquivo válido por extensão, porém com magic bytes conflitantes, deve ser classificado pelo conteúdo e registrar conflito.
- Archive bomb, path traversal ou symlink escape deve falhar fechado antes de criar arquivo fora do caso.
- Worker que termina após timeout ou cancelamento não pode publicar evidência tardia.
- Evidência cujo pai foi adulterado deve invalidar todos os descendentes durante replay.
- Perfil sem corpus cego suficiente deve permanecer `NAO_COMPROVADA`, mesmo com smoke tests verdes.

---

## Estrutura de execução

Este programa é dividido em três planos independentes e um fechamento integrado:

1. `docs/superpowers/plans/2026-09-22-evidence-kernel-intake.md`
2. `docs/superpowers/plans/2026-09-22-static-profiles-and-reconstruction.md`
3. `docs/superpowers/plans/2026-09-22-dynamic-lab-validation-release.md`

Depois da Task 2, agentes podem construir módulos novos, fixtures e testes em worktrees isoladas. Commits que toquem `aether_re/contracts.py`, `aether_re/models.py`, `aether_re/pipeline.py`, `megazord.py` ou `README.md` não rodam em paralelo no mesmo worktree: integram sequencialmente na ordem Kernel → Perfis Estáticos → Laboratório/Validação → Pipeline Universal, sempre com regressão focal entre merges. A frente dinâmica pode preparar corpus e probes em paralelo, mas não pode promover execução antes do contrato e do gate de VM.

### Task 1: Congelar baseline e impedir contaminação de escopo

**Files:**
- Create: `tools/f00_program_baseline.py`
- Create: `tests/test_program_baseline.py`
- Create: `docs/evidence/program-baseline.schema.json`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: raiz `Path`, `git status --porcelain=v1`, suite JUnit e inventário de arquivos.
- Produces: `capture_program_baseline(root: Path, output: Path) -> dict[str, Any]` com schema `program-baseline.v1`.

- [ ] **Step 1: Escrever teste RED para escopo, hashes e Rotor fora do denominador**

```python
def test_baseline_hashes_project_and_rejects_rotor_scope(tmp_path: Path) -> None:
    root = tmp_path / "RE"
    root.mkdir()
    (root / "aether_re").mkdir()
    (root / "aether_re" / "core.py").write_text("x = 1\n", encoding="utf-8")
    (root / "replay_rotor_static_audit.py").write_text("legacy\n", encoding="utf-8")
    report = capture_program_baseline(root, tmp_path / "baseline.json")
    assert report["schema"] == "program-baseline.v1"
    assert report["scope"]["included_count"] == 1
    assert report["scope"]["excluded"] == ["replay_rotor_static_audit.py"]
    assert len(report["files"][0]["sha256"]) == 64
```

- [ ] **Step 2: Confirmar falha antes da implementação**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/test_program_baseline.py -q`  
Expected: FAIL com `ModuleNotFoundError` ou `cannot import name capture_program_baseline`.

- [ ] **Step 3: Implementar captura determinística e exclusões explícitas**

```python
def capture_program_baseline(root: Path, output: Path) -> dict[str, Any]:
    included, excluded = [], []
    for path in safe_iter_files(root):
        rel = path.relative_to(root).as_posix()
        if "rotor" in rel.casefold():
            excluded.append(rel)
            continue
        included.append({"path": rel, "sha256": sha256_file(path), "size": path.stat().st_size})
    report = {
        "schema": "program-baseline.v1",
        "scope": {"included_count": len(included), "excluded": sorted(excluded)},
        "files": sorted(included, key=lambda row: row["path"]),
    }
    atomic_write_json(output, report)
    return report
```

- [ ] **Step 4: Rodar teste focal e baseline real**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/test_program_baseline.py tests/test_project_snapshot.py -q`  
Expected: PASS. Depois executar `tools/f00_program_baseline.py --root D:\AetherRE_Megazord --output output\f00_program_baseline.json` e validar schema/hash.

- [ ] **Step 5: Commit isolado**

```powershell
git add -- tools/f00_program_baseline.py tests/test_program_baseline.py docs/evidence/program-baseline.schema.json .gitignore
git diff --cached --name-only
git commit -m "test: freeze RE_Megazord program baseline"
```

### Task 2: Congelar o contrato epistemológico compartilhado antes do paralelismo

**Files:**
- Create: `aether_re/kernel_contracts.py`
- Create: `tests/test_kernel_contracts.py`

**Interfaces:**
- Consumes: mappings JSON contendo autorização, budgets e metadados de derivação.
- Produces: `EpistemicState`, `AuthorizationPolicy`, `IntakeLimits`, `ArtifactRef`, `DerivationRecord`, `canonical_json()` e `sha256_canonical()`; estes nomes são canônicos para todos os demais planos.

- [ ] **Step 1: Escrever testes RED para enum, autorização e derivação comprovável**

```python
def test_inference_requires_parent_evidence_and_bounded_confidence() -> None:
    with pytest.raises(ContractError, match="parents_required"):
        DerivationRecord.from_dict({
            "derivation_id": "d1", "artifact_id": "a1",
            "epistemic_state": "PROBABILISTIC_INFERENCE",
            "confidence": 0.8, "parents": [], "losses": ["symbol names stripped"],
        })

def test_authorization_rejects_dynamic_execution_when_static_only() -> None:
    policy = AuthorizationPolicy.from_dict({"case_owner": "owner", "allow_static": True, "allow_dynamic": False})
    assert policy.allow_static is True
    assert policy.allow_dynamic is False
```

- [ ] **Step 2: Confirmar RED**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/test_kernel_contracts.py -q`  
Expected: FAIL porque os tipos ainda não existem.

- [ ] **Step 3: Implementar os tipos canônicos imutáveis e validação fail-closed**

```python
class EpistemicState(str, Enum):
    EXACT = "EXACT"
    VERIFIED_RECONSTRUCTION = "VERIFIED_RECONSTRUCTION"
    PROBABILISTIC_INFERENCE = "PROBABILISTIC_INFERENCE"
    HYPOTHESIS = "HYPOTHESIS"
    UNKNOWN = "UNKNOWN"

@dataclass(frozen=True)
class DerivationRecord:
    derivation_id: str
    artifact_id: str
    epistemic_state: EpistemicState
    confidence: float | None
    parents: tuple[str, ...]
    losses: tuple[str, ...]

    def validate(self) -> None:
        if self.epistemic_state not in {EpistemicState.EXACT, EpistemicState.UNKNOWN} and not self.parents:
            raise ContractError("parents_required")
        if self.epistemic_state is EpistemicState.PROBABILISTIC_INFERENCE and self.confidence is None:
            raise ContractError("confidence_required")
```

- [ ] **Step 4: Rodar contratos antigos e novos**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/test_kernel_contracts.py tests/test_contracts.py tests/test_evidence_contract.py -q`  
Expected: PASS e serialização canônica idêntica em duas execuções.

- [ ] **Step 5: Commit isolado e liberação das três frentes**

```powershell
git add -- aether_re/kernel_contracts.py tests/test_kernel_contracts.py
git diff --cached --name-only
git commit -m "feat: freeze forensic kernel contracts"
```

### Task 3: Executar plano de Evidence Kernel e Intake

**Files:**
- Follow: `docs/superpowers/plans/2026-09-22-evidence-kernel-intake.md`
- Test: testes enumerados no plano da frente.

**Interfaces:**
- Consumes: contratos da Task 2.
- Produces: manifesto de caso, journal encadeado, derivação, intake seguro, profile router e worker protocol.

No plano da frente, a Task 1 corresponde aos contratos já concluídos pela Task 2 deste programa; o executor verifica o commit e começa na Task 2 do subplano, sem recriar arquivos.

- [ ] **Step 1: Criar agente implementador com ownership exclusivo dos arquivos do plano**

```text
Leia a spec, o plano Evidence Kernel/Intake e o commit dos contratos. Execute uma task por vez em TDD. Não altere adapters de perfil nem o laboratório dinâmico. Após cada task, rode os testes focais e faça commit apenas dos arquivos listados.
```

- [ ] **Step 2: Para cada task, obter revisão de conformidade e qualidade antes da próxima**

```text
Revisor: compare diff, spec e task. Rejeite perda de proveniência, escrita não atômica, path escape, publicação após cancelamento, schema permissivo ou teste que não observa o efeito. Informe PASS ou correções por arquivo/linha.
```

- [ ] **Step 3: Rodar gate integrado da frente**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/test_evidence_contract.py tests/test_custody.py tests/test_safe_walk.py tests/test_checkpoint.py tests/test_process.py tests/test_process_cleanup.py tests/test_intake.py tests/test_profile_router.py -q`  
Expected: todos PASS; testes inexistentes neste momento serão criados pelo plano da frente.

- [ ] **Step 4: Verificar artefatos de caos e replay**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' tools/f02_fault_campaign.py` e `tools/f02_commit_crash_campaign.py`.  
Expected: journal íntegro ou falha fechada; nenhuma evidência órfã promovida.

- [ ] **Step 5: Registrar integração**

```powershell
git status --short
git log --oneline --max-count=12
```

Expected: commits da frente pequenos e nenhum arquivo de outra frente incluído.

### Task 4: Executar plano de Perfis Estáticos e Reconstrução

**Files:**
- Follow: `docs/superpowers/plans/2026-09-22-static-profiles-and-reconstruction.md`
- Test: testes enumerados no plano da frente.

**Interfaces:**
- Consumes: contratos da Task 2 e protocolo de worker da Task 3.
- Produces: IR/grafo, adapters nativos/managed/mobile/WASM e reconstrução diferencial.

- [ ] **Step 1: Criar agente implementador com ownership dos adapters e IR**

```text
Execute o plano de perfis estáticos em TDD. Trate outputs externos como hostis, preserve evidence_refs/losses e não certifique ferramentas indisponíveis. Não modifique journal, intake nem política de VM sem handoff explícito.
```

- [ ] **Step 2: Exigir revisão independente por perfil**

```text
Valide cada perfil contra golden fixture e backend alternativo. Rejeite sucesso baseado só em exit code, pseudocódigo chamado de fonte original, entidade sem endereço/proveniência ou licença ausente.
```

- [ ] **Step 3: Rodar regressão native antes de promover novos perfis**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/test_pe_structure.py tests/test_elf_structure.py tests/test_ensemble.py tests/test_differential.py tests/test_pipeline_guards.py -q`  
Expected: PASS e métricas não inferiores ao baseline da Task 1.

- [ ] **Step 4: Rodar matriz managed/mobile/WASM por disponibilidade**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/profiles -q`  
Expected: fixture suportada PASS; dependência ausente produz `unavailable`, nunca falso `succeeded`.

- [ ] **Step 5: Registrar integração e outputs diferenciais**

```powershell
Get-ChildItem output\profile-certificates -File | Get-FileHash -Algorithm SHA256
git log --oneline --max-count=20
```

Expected: certificado separado por perfil, corpus e versão de ferramenta.

### Task 5: Executar plano de Laboratório, Validação e Release

**Files:**
- Follow: `docs/superpowers/plans/2026-09-22-dynamic-lab-validation-release.md`
- Test: testes enumerados no plano da frente.

**Interfaces:**
- Consumes: manifesto/journal, contratos de perfil, IR e certificados estáticos.
- Produces: capability proof de VM, traces, splits selados, métricas cegas, red team e gate F00–F12.

- [ ] **Step 1: Executar tarefas não dinâmicas em paralelo**

```text
Prepare corpus, split contract, métricas, red team e clean-install harness. Não execute amostra. Trate WSL, Windows Sandbox desabilitado ou hypervisor sem firmware como incapacidade, não como VM aprovada.
```

- [ ] **Step 2: Fazer probe real e bloquear dinâmica se faltar isolamento**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' tools/f08_lab_capability_probe.py`  
Expected: `approved=true` somente com VM, snapshot, rollback e capture probes comprovados; caso contrário `NAO_COMPROVADA`.

- [ ] **Step 3: Rodar split e métricas sem abrir holdout prematuramente**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' tools/tri_split_ci.py`  
Expected: development/calibration verdes e holdout selado.

- [ ] **Step 4: Rodar adversarial e chaos**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' tools/f11_adversarial_cli_campaign.py`  
Expected: zero path escape, zero comando de prompt injection executado e zero claim promovido sem citação válida.

- [ ] **Step 5: Registrar status honesto da frente**

```text
Publique por gate: evidência, denominador, resultado, limitações e dívida. Se a VM continuar bloqueada pelo host, F08/F09/F12 permanecem não quitados sem impedir o fechamento das capacidades estáticas comprovadas.
```

### Task 6: Integrar as três frentes sem regressão

**Files:**
- Modify: `aether_re/pipeline.py`
- Modify: `megazord.py`
- Create: `tests/test_universal_pipeline.py`
- Create: `docs/architecture/UNIVERSAL_PIPELINE.md`

**Interfaces:**
- Consumes: `prepare_case()` e `route_case()` do plano Kernel; `detect_static_profiles()`, `run_static_worker()`, `project_ir()`, `build_reconstruction()` e `certify_static_profile()` do plano de perfis; `run_dynamic_case()` somente quando a política e a atestação de VM forem válidas.
- Produces: `CasePolicy`, `CaseReport`, `run_profile_workers()`, `normalize_observations()`, `verify_reconstruction()`, `certify_case()`, `run_universal_case(target: Path, out_dir: Path, policy: CasePolicy) -> CaseReport` e CLI `megazord universal`.

- [ ] **Step 1: Escrever E2E RED para roteamento, evidência e abstinência**

```python
def test_universal_case_routes_fixture_and_preserves_unknown(tmp_path: Path) -> None:
    target = tmp_path / "sample.wasm"
    target.write_bytes(b"\x00asm\x01\x00\x00\x00")
    report = run_universal_case(target, tmp_path / "out", CasePolicy.static_only())
    assert report.profile == "wasm"
    assert report.target_sha256
    assert all(item.evidence_refs for item in report.observations if item.epistemic_state != EpistemicState.UNKNOWN)
    assert report.dynamic_status == "not_requested"
    assert report.original_source_recovered is False
```

- [ ] **Step 2: Confirmar RED**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/test_universal_pipeline.py -q`  
Expected: FAIL porque o orquestrador ainda não existe.

- [ ] **Step 3: Implementar orquestração fina, sem duplicar engines**

```python
def run_universal_case(target: Path, out_dir: Path, policy: CasePolicy) -> CaseReport:
    intake = prepare_case(IntakeRequest(target, out_dir / "intake", policy.authorization, policy.intake_limits))
    store = EvidenceStore(intake.manifest_path.parent)
    decision = route_case(intake, store)
    observations = run_profile_workers(intake, decision, policy)
    graph = normalize_observations(intake, observations)
    reconstruction = verify_reconstruction(intake, graph, policy)
    return certify_case(intake, decision, graph, reconstruction, policy)
```

- [ ] **Step 4: Rodar E2E e regressão completa**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/test_universal_pipeline.py -q` e depois `-m pytest -q --junitxml=output/final_full_suite_20260922_v2.junit.xml`.  
Expected: zero falhas/erros; skips apenas por dependências ou hypervisor claramente registrados.

- [ ] **Step 5: Commit isolado**

```powershell
git add -- aether_re/pipeline.py megazord.py tests/test_universal_pipeline.py docs/architecture/UNIVERSAL_PIPELINE.md
git diff --cached --name-only
git commit -m "feat: integrate universal forensic case pipeline"
```

### Task 7: Clean install, campanha final e veredito

**Files:**
- Create: `tools/f12_universal_release.py`
- Create: `tests/test_universal_release.py`
- Create: `docs/operations/CLEAN_INSTALL_AND_REPLAY.md`
- Output: `output/f12_universal_release.json`

**Interfaces:**
- Consumes: baseline, certificados por perfil, JUnit, chaos reports, VM proof e manifests.
- Produces: `evaluate_universal_release(root: Path, evidence: Sequence[Path]) -> dict[str, Any]`.

- [ ] **Step 1: Escrever teste RED que impede overclaim final**

```python
def test_release_stays_partial_when_vm_gate_is_unproved(tmp_path: Path) -> None:
    report = evaluate_universal_release_from_rows([
        {"gate": "F00", "status": "QUITADA", "evidence_valid": True},
        {"gate": "F08", "status": "NAO_COMPROVADA", "evidence_valid": True},
    ])
    assert report["gate_passed"] is False
    assert report["status"] == "PARCIALMENTE_QUITADA"
    assert "F08" in report["remaining_debt"]
```

- [ ] **Step 2: Confirmar RED**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest tests/test_universal_release.py -q`  
Expected: FAIL porque o agregador universal ainda não existe.

- [ ] **Step 3: Implementar agregação fail-closed dos treze gates**

```python
def evaluate_universal_release_from_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_gate = {row["gate"]: row for row in rows}
    required = [f"F{i:02d}" for i in range(13)]
    debt = [gate for gate in required if by_gate.get(gate, {}).get("status") != "QUITADA" or not by_gate.get(gate, {}).get("evidence_valid")]
    return {
        "schema": "universal-release.v1",
        "gate_passed": not debt,
        "status": "QUITADA" if not debt else "PARCIALMENTE_QUITADA",
        "remaining_debt": debt,
    }
```

- [ ] **Step 4: Executar suite, clean replay e release**

Run: `& 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe' -m pytest -q --junitxml=output/f12_final.junit.xml`; executar `tools/f00_clean_replay_v2.py`; por fim `tools/f12_universal_release.py --output output/f12_universal_release.json`.  
Expected: relatório determinístico, hashes válidos e nenhum gate ausente convertido em sucesso.

- [ ] **Step 5: Revisão independente e commit final**

```text
Um revisor sem participação nas implementações deve reproduzir instalação, selecionar amostras aleatórias por perfil, validar pelo menos um achado e uma abstinência, recalcular hashes e contestar o status de cada gate. Divergência bloqueia QUITADA.
```

```powershell
git add -- tools/f12_universal_release.py tests/test_universal_release.py docs/operations/CLEAN_INSTALL_AND_REPLAY.md
git diff --cached --name-only
git commit -m "test: add universal F00-F12 release gate"
```

## Critério de parada

A execução não para por uma suite verde isolada. Ela para quando o relatório `universal-release.v1` listar F00–F12, todos com evidência válida e `QUITADA`; ou quando um bloqueio físico externo for comprovado, caso em que o status permanece parcial e a dívida é registrada sem falsificação. A ausência de ferramenta, licença, corpus, autorização ou VM jamais é convertida em aprovação.
