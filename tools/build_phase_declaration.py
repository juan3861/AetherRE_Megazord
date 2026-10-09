"""Executa a suite POR FASE e constroi a declaracao de gates com contagens reais.

Honestidade por desenho:
- ``reviewed`` permanece **false** em todas as fases: revisao independente e ato de
  terceiro e nao pode ser auto-declarada. Este script NUNCA escreve ``true`` ali.
- ``implementation``/``integration`` sao preservados como ja declarados (true);
  o script nao os promove.
- cada fase recebe o JUnit da sua propria execucao, com SHA-256 calculado.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PHASES = tuple(f"F{index:02d}" for index in range(13))
GATES = {phase: f"G{phase[1:]}" for phase in PHASES}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def junit_counts(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    skipped = 0
    failed = 0
    errors = 0
    for case in cases:
        if case.find("skipped") is not None:
            skipped += 1
        elif case.find("failure") is not None:
            failed += 1
        elif case.find("error") is not None:
            errors += 1
    passed = len(cases) - skipped - failed - errors
    return {"total": len(cases), "passed": passed, "failed": failed,
            "errors": errors, "skipped": skipped}


def run_phase(phase: str, files: list[str], root: Path, out_dir: Path,
              python: str) -> dict[str, object]:
    junit = out_dir / f"phase-{phase}.junit.xml"
    if junit.exists():
        junit.unlink()
    cmd = [python, "-m", "pytest", "-q", f"--junitxml={junit}", *files]
    completed = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    tail = (completed.stdout or "").strip().splitlines()[-1:] or [""]
    counts = junit_counts(junit) if junit.exists() else {
        "total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    return {
        "phase": phase,
        "files": files,
        "file_count": len(files),
        "exit_code": completed.returncode,
        "stdout_tail": tail[0][:400],
        "junit": junit.name,
        "junit_sha256": sha256_file(junit) if junit.exists() else None,
        **counts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--map", required=True)
    parser.add_argument("--out-dir", required=True,
                        help="diretorio de evidencia (JUnit por fase)")
    parser.add_argument("--declaration-out", required=True)
    parser.add_argument("--report-out", required=True)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    mapping = json.loads(Path(args.map).read_text(encoding="utf-8"))
    phases_map: dict[str, list[str]] = mapping["phases"]

    results = []
    for phase in PHASES:
        files = phases_map.get(phase, [])
        if not files:
            results.append({"phase": phase, "files": [], "file_count": 0,
                            "exit_code": None, "stdout_tail": "sem arquivos",
                            "junit": None, "junit_sha256": None, "total": 0,
                            "passed": 0, "failed": 0, "errors": 0, "skipped": 0})
            continue
        outcome = run_phase(phase, files, root, out_dir, args.python)
        results.append(outcome)
        print(f"{phase}: {outcome['passed']} passed, {outcome['failed']} failed, "
              f"{outcome['skipped']} skipped ({outcome['file_count']} arquivos)",
              flush=True)

    declaration_phases = []
    for outcome in results:
        phase = outcome["phase"]
        evidence = []
        if outcome["junit"] and outcome["junit_sha256"]:
            evidence.append({"path": f"phases/{outcome['junit']}",
                             "sha256": outcome["junit_sha256"]})
        # reviewed permanece false: nao ha revisor independente. Nunca true aqui.
        declaration_phases.append({
            "phase_id": phase,
            "implementation": True,
            "integration": True,
            "reviewed": False,
            "tests": {"passed": outcome["passed"], "failed": outcome["failed"],
                      "skipped": outcome["skipped"]},
            "evidence": evidence,
            "gaps": ["revisao independente por terceiro ausente (reviewed=false por regra)"],
        })

    declaration = {
        "schema": "phase-gate-declaration.v1",
        "scope": "current-candidate-local-evidence-only",
        "assessment": "phase-test-map v1; contagens medidas por execucao por fase",
        "honesty_note": (
            "reviewed=false em todas as fases: revisao independente e ato de terceiro. "
            "implementation/integration preservados como ja declarados; nada foi promovido."
        ),
        "phases": declaration_phases,
    }
    Path(args.declaration_out).write_text(
        json.dumps(declaration, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")

    report = {
        "schema": "phase-test-execution.v1",
        "python": args.python,
        "env": {key: os.environ.get(key) for key in
                ("GHIDRA_HOME", "MEGAZORD_MSVC_PE_FIXTURE",
                 "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTHONDONTWRITEBYTECODE")},
        "results": results,
        "totals": {
            "passed": sum(item["passed"] for item in results),
            "failed": sum(item["failed"] for item in results),
            "skipped": sum(item["skipped"] for item in results),
            "phases_with_zero_passed": [item["phase"] for item in results if item["passed"] == 0],
            "phases_with_failures": [item["phase"] for item in results if item["failed"]],
            "phases_with_skips": [item["phase"] for item in results if item["skipped"]],
        },
        "limitations": [
            "contagens somam execucoes por fase; arquivos mapeados em varias fases contam mais de uma vez",
            "reviewed permanece false; este relatorio nao certifica gate algum",
        ],
    }
    Path(args.report_out).write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")
    print(json.dumps(report["totals"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
