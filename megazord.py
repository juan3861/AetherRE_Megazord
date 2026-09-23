#!/usr/bin/env python3
"""
AetherRE MEGAZORD — CLI
Uso:
  py -3.13 megazord.py analyze CAMINHO\\para\\binario.exe
  py -3.13 megazord.py status
  py -3.13 megazord.py selftest
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# garantir imports locais
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aether_re import __version__, __codename__
from aether_re.pipeline import CasePolicy, adapters_status, run_megazord, run_universal_case


def cmd_status(_: argparse.Namespace) -> int:
    print(f"AetherRE {__codename__} v{__version__}")
    print("Adapters:")
    for s in adapters_status():
        flag = "OK" if s["available"] else "—"
        print(f"  [{flag}] {s['name']}")
    # engines nativos
    print("Engines nativos: triage, structure, strings_decode, disasm, reconstruct")
    try:
        import pefile  # noqa: F401

        print("  pefile: OK")
    except ImportError:
        print("  pefile: MISSING")
    try:
        import capstone  # noqa: F401

        print("  capstone: OK")
    except ImportError:
        print("  capstone: MISSING (disasm limitado)")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    target = Path(args.target)
    out = Path(args.out) if args.out else None
    report = run_megazord(
        target,
        out_dir=out,
        use_adapters=not args.no_adapters,
        deep=not args.shallow,
    )
    out_dir = report.adapter_results.get("_output_dir", "")
    print("=" * 60)
    print(f"MEGAZORD v{__version__} — análise completa")
    print("=" * 60)
    print(f"Target : {report.target}")
    print(f"SHA256 : {report.target_sha256}")
    print(f"Type   : {report.file_type} | size={report.size_bytes} | H={report.entropy:.3f}")
    print(f"Conf   : {report.overall_confidence:.2f}")
    print(f"Imports: {len(report.imports)} | Exports: {len(report.exports)} | Strings: {len(report.strings)}")
    print(f"Findings: {len(report.findings)}")
    print(f"Output : {out_dir}")
    print("-" * 60)
    for f in report.findings[:12]:
        print(f"[{f.severity}] {f.title}")
    if len(report.findings) > 12:
        print(f"... +{len(report.findings) - 12} findings (ver findings.md)")
    print("-" * 60)
    print("Ficheiros: report.json | pseudo_source.c | findings.md | strings.txt")
    return 0


def cmd_selftest(_: argparse.Namespace) -> int:
    """Gera um mini PE-like payload sintético? Melhor: analisa o próprio python.exe."""
    candidates = [
        Path(sys.executable),
        Path(r"C:\Windows\System32\notepad.exe"),
        Path(r"C:\Windows\System32\cmd.exe"),
    ]
    target = next((c for c in candidates if c.is_file()), None)
    if not target:
        print("Nenhum binário de teste encontrado")
        return 1
    print(f"Selftest target: {target}")
    args = argparse.Namespace(
        target=str(target),
        out=str(ROOT / "output" / "selftest"),
        no_adapters=True,
        shallow=False,
    )
    return cmd_analyze(args)


def cmd_universal(args: argparse.Namespace) -> int:
    """Run the default static-only universal pipeline."""
    report = run_universal_case(Path(args.target), Path(args.out), CasePolicy.static_only())
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="megazord",
        description="AetherRE Megazord — engenharia reversa / forense de binários",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    universal = sub.add_parser("universal", help="Pipeline universal fail-closed (estático por padrão)")
    universal.add_argument("target", help="Artefato alvo autorizado")
    universal.add_argument("--out", required=True, help="Diretório novo de saída")
    universal.set_defaults(func=cmd_universal)

    s = sub.add_parser("status", help="Estado dos motores e adapters")
    s.set_defaults(func=cmd_status)

    a = sub.add_parser("analyze", help="Analisar um binário/artefacto")
    a.add_argument("target", help="Caminho do ficheiro alvo")
    a.add_argument("--out", help="Pasta de output")
    a.add_argument("--no-adapters", action="store_true", help="Só motores nativos")
    a.add_argument("--shallow", action="store_true", help="Sem disasm profundo")
    a.set_defaults(func=cmd_analyze)

    t = sub.add_parser("selftest", help="Teste rápido com notepad/python")
    t.set_defaults(func=cmd_selftest)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
