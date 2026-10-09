"""Gera um corpus sintético, autorizado e determinístico para F03.

O gerador não compila nem executa os projetos; produz fonte, oracle e receita
para que cada build/execução seja uma etapa explícita do laboratório.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


FAMILIES = (
    "constant",
    "branch",
    "callback",
    "cycle",
    "dead_code",
    "feature_flag",
    "mock_boundary",
    "indirect_call",
    "parser",
    "sanitizer",
)


def _python_source(family: str) -> str:
    if family == "cycle":
        body = "def cycle_a(value):\n    return cycle_b(value)\n\ndef cycle_b(value):\n    return cycle_a(value)\n"
    elif family == "callback":
        body = "def callback_helper(fn, value):\n    return fn(value)\n"
    elif family == "indirect_call":
        body = "def indirect_helper(value):\n    return value + 1\n\nDISPATCH = {'run': indirect_helper}\n"
    elif family == "dead_code":
        body = "def dead_helper(value):\n    return value * 99\n"
    else:
        body = f"def {family}_helper(value):\n    return value\n"
    if family == "callback":
        main_body = "    return callback_helper(lambda item: item, value)\n"
    elif family in {"dead_code", "cycle"}:
        main_body = "    return value\n"
    elif family == "indirect_call":
        main_body = "    return DISPATCH['run'](value)\n"
    elif family == "feature_flag":
        main_body = "    if ENABLED:\n        return feature_flag_helper(value)\n    return value\n"
    else:
        main_body = f"    return {family}_helper(value)\n"
    return f"# synthetic owned fixture: {family}\n{body}\ndef main(value=0):\n{main_body}\nif __name__ == '__main__':\n    print(main())\n"


def _c_source(family: str) -> str:
    if family == "cycle":
        body = "int cycle_b(int value);\nint cycle_a(int value) { return cycle_b(value); }\nint cycle_b(int value) { return cycle_a(value); }\n"
    elif family == "callback":
        body = "int callback_helper(int (*fn)(int), int value) { return fn(value); }\n"
    elif family == "indirect_call":
        body = "int indirect_helper(int value) { return value + 1; }\nint (*dispatch)(int) = indirect_helper;\n"
    elif family == "dead_code":
        body = "int dead_helper(int value) { return value * 99; }\n"
    else:
        body = f"int {family}_helper(int value) {{ return value; }}\n"
    if family == "callback":
        main_body = "return callback_helper(0, value);"
    elif family in {"dead_code", "cycle"}:
        main_body = "return 0;"
    elif family == "indirect_call":
        main_body = "return dispatch(value);"
    else:
        main_body = f"return {family}_helper(value);"
    return f"/* synthetic owned fixture: {family} */\n{body}\nint main(void) {{ int value = 0; {main_body} }}\n"


def _oracle(family: str, language: str) -> dict[str, Any]:
    helper = f"{family}_helper"
    relations = [["main", helper]] if family not in {"cycle", "indirect_call", "dead_code"} else []
    if family == "cycle":
        relations = [["cycle_a", "cycle_b"], ["cycle_b", "cycle_a"]]
    indirect_relations = [["dispatch", "indirect_helper"]] if family == "indirect_call" else []
    expected_symbols = ["main", helper]
    if family == "cycle":
        expected_symbols = ["main", "cycle_a", "cycle_b"]
    elif family == "indirect_call":
        expected_symbols = ["main", "indirect_helper"]
    elif family == "dead_code":
        expected_symbols = ["main", "dead_helper"]
    return {
        "oracle_schema": "re-megazord-oracle.v1",
        "language": language,
        "family": family,
        "expected_symbols": expected_symbols,
        "expected_relations": relations,
        "expected_indirect_relations": indirect_relations,
        "known_limits": ["synthetic fixture", "source oracle does not prove binary equivalence"],
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_corpus(out_dir: Path) -> dict[str, Any]:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FileExistsError(f"corpus_output_not_empty:{out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for index, family in enumerate(FAMILIES):
        split = "development" if index < 6 else "calibration" if index < 8 else "holdout"
        for language in ("python", "c"):
            project_id = f"f03_{index + 1:02d}_{language}"
            project_dir = out_dir / project_id
            source_dir = project_dir / "src"
            source_dir.mkdir(parents=True)
            source = source_dir / ("main.py" if language == "python" else "main.c")
            source.write_text(_python_source(family) if language == "python" else _c_source(family), encoding="utf-8", newline="\n")
            oracle = project_dir / "oracle.json"
            oracle.write_text(json.dumps(_oracle(family, language), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
            entries.append(
                {
                    "id": project_id,
                    "family": family,
                    "language": language,
                    "split": split,
                    "authorization": "owned_synthetic",
                    "source": source.relative_to(out_dir).as_posix(),
                    "source_sha256": _sha256(source),
                    "oracle": oracle.relative_to(out_dir).as_posix(),
                    "oracle_sha256": _sha256(oracle),
                    "build_recipe": "python -m py_compile src/main.py" if language == "python" else "cc -std=c11 -O0 -g src/main.c -o build/program",
                    "execution": "not_run_by_bootstrap",
                }
            )
    manifest = {
        "schema": "re-megazord-corpus.v1",
        "generator": "tools/bootstrap_corpus.py",
        "authorization": "owned_synthetic",
        "count": len(entries),
        "split_group": "family",
        "projects": entries,
        "limits": ["synthetic only", "no external dataset", "build and behavior still require separate tests"],
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("corpus/bootstrap_v1"))
    args = parser.parse_args()
    manifest = generate_corpus(args.out)
    print(f"generated={manifest['count']} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
