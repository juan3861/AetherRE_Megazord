# ⚠️ LEIA ANTES DE TRABALHAR NESTE REPO

Você está no **projeto 4 de 4** do Juan: **AetherRE Megazord** (engenharia reversa
e forense de binários).

## 📖 Fonte da verdade

**Hub central:** `D:\AetherMind_HUB\` — vault Obsidian com os 4 projetos,
plantas-mãe, links de acesso e estado datado.

**Leia primeiro:** `D:\AetherMind_HUB\AGENTS.md` (regras completas, válidas para
qualquer agente e qualquer ferramenta).

| Documento | Onde |
|---|---|
| Nota completa deste projeto | `D:\AetherMind_HUB\Projetos\04 - Engenharia Reversa (AetherRE).md` |
| Planta-mãe | `docs\PLANO_MESTRE_ENGENHARIA_FORENSE_2026-09-15.md` |
| Ledger vivo (onde paramos) | `.superpowers\sdd\2026-09-24-economic-ceiling-plan\progress.md` |
| Kernel de evidência | `docs\EVIDENCE_KERNEL.md` |
| Custódia (satélite) | `E:\AetherRE_Evidence` |
| Toolchain / wheels (satélite) | `E:\AetherRE_Toolchain` |

> Os diretórios em `E:\` **NÃO são o projeto** — são evidência de custódia e
> wheelhouses/venvs, por design. Todo o código está em `D:\AetherRE_Megazord`.

## 🟠 Estado em 25/09/2026 — sessão Codex de 24/09 20:34

**Release: `PARCIALMENTE QUITADA`** — não existe `gate_passed: true` cobrindo F00–F12.

**Quitadas:** Task 1 (custódia, 508/508 testes) · Task 2 (gates, 69 testes) ·
Task 3 v8 (guest dinâmico, 8/8, Ed25519) · Task 5 (precisão ELF/PE/PDB 1.0) ·
Task 6 (replay hermético, **533 passed, 0 failed**, hash idêntico entre A e B).

**Pendências:**
- **F08/F09 só PARCIAIS** — Windows Sandbox não é prova de snapshot/rollback de VM real
- **Ghidra fora do lock de toolchain**
- 3 testes ignorados (fixtures externos ausentes)
- **Nenhuma atestação Hyper-V** com snapshot/rollback
- **Revisão independente por terceiro INEXISTENTE** — o autor não pode certificar a própria obra

## 🚫 Regras que valem SEMPRE aqui

1. **Nunca autoautorize.** Não emitir atestado, certificado ou gate passed por conta própria.
2. **Nunca reinvente evidência.** Custódia é hash-verificada. Sem hash real, é pendência.
3. **Cuidado com o worktree — 175+ caminhos alterados ou não rastreados.**
   `git clean`, `git reset --hard` e `git checkout .` **APAGAM TRABALHO REAL**.
4. **Antes de reportar status, leia** o `progress.md` do ledger. Não deduza pelo mtime.
5. **"pseudo-fonte ≠ código-fonte original"** — mantenha o disclaimer explícito.
6. **Nunca reporte "pronto" sem** revisão independente.

## ▶️ Comandos

```powershell
cd D:\AetherRE_Megazord
py -3.13 -m pip install -r requirements.txt
py -3.13 megazord.py status
py -3.13 megazord.py selftest
py -3.13 megazord.py analyze C:\Windows\System32\notepad.exe
```
Testes: `pytest` (config em `pytest.ini`, `testpaths=tests`)

## ⚠️ Disco

`D:` tem 5,8 GB livres (99%). Não gere artefato pesado aqui. **Só a E: tem espaço real.**

---

*Este arquivo foi adicionado em 25/09/2026 pelo Claude Code, a pedido do dono.
Ele é um ponteiro — não é fonte de verdade e não substitui a planta-mãe.*
