"""Create 10 owned, multi-file F03 stress fixtures without executing them.

The hand-authored labels live in this generator, so they are NOT independent
ground truth and are never a substitute for a blind external holdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


# (name, main source, additional files, symbols, relations, case labels)
CASES: tuple[tuple[str, str, dict[str, str], list[str], list[list[str]], dict[str, Any]], ...] = (
    ("false_documentation", "from .support import sanitize\n\ndef run(value):\n    return sanitize(value)\n", {"src/support.py": "def sanitize(value):\n    return str(value).strip()\n"}, ["run", "sanitize"], [["run", "sanitize"]], {"documentation_claim": "sends telemetry to a remote server", "claim_true": False}),
    ("dead_code", "from .support import live\n\ndef dormant(value):\n    return value * 999\n\ndef run(value):\n    return live(value)\n", {"src/support.py": "def live(value):\n    return value + 1\n"}, ["dormant", "run", "live"], [["run", "live"]], {"dead_code_candidate": "dormant", "reachability_proven": False}),
    ("feature_flag", "from .support import fast, slow\nENABLED = False\n\ndef run(value):\n    if ENABLED:\n        return fast(value)\n    return slow(value)\n", {"src/support.py": "def fast(value):\n    return value * 2\n\ndef slow(value):\n    return value + 2\n"}, ["run", "fast", "slow"], [["run", "fast"], ["run", "slow"]], {"feature_flag": "ENABLED", "default": False}),
    ("mock_only_test", "from .support import send\n\ndef run(value):\n    return send(value)\n", {"src/support.py": "def send(value):\n    return {'accepted': bool(value)}\n", "tests/test_mock.py": "from src import main\n\ndef test_mock_only(monkeypatch):\n    monkeypatch.setattr(main, 'send', lambda value: {'accepted': True})\n    assert main.run('x')['accepted'] is True\n"}, ["run", "send", "test_mock_only"], [["run", "send"], ["test_mock_only", "run"]], {"test_uses_mock": True, "real_send_exercised_by_test": False}),
    ("import_cycle", "from .support import ping\n\ndef run(value):\n    return ping(value)\n", {"src/support.py": "from .main import run\n\ndef ping(value):\n    return run(value - 1) if value > 0 else 0\n"}, ["run", "ping"], [["run", "ping"], ["ping", "run"]], {"cycle": ["src.main", "src.support"], "execution_not_attempted": True}),
    ("dynamic_import", "import importlib\nfrom .support import fallback\n\ndef run(name):\n    module = importlib.import_module(name)\n    return fallback(module)\n", {"src/support.py": "def fallback(module):\n    return getattr(module, 'VALUE', None)\n"}, ["run", "fallback"], [["run", "fallback"]], {"dynamic_import": True, "target_unknown_statically": True}),
    ("decorator_wrapper", "from .support import audit\n\n@audit\ndef run(value):\n    return value + 1\n\ndef entry(value):\n    return run(value)\n", {"src/support.py": "def audit(fn):\n    def wrapper(value):\n        return fn(value)\n    return wrapper\n"}, ["run", "entry", "audit", "wrapper"], [["entry", "run"]], {"decorator_changes_runtime_binding": True}),
    ("callback_dispatch", "from .support import apply\n\ndef transform(value):\n    return value * 3\n\ndef run(value):\n    return apply(transform, value)\n", {"src/support.py": "def apply(callback, value):\n    return callback(value)\n"}, ["transform", "run", "apply"], [["run", "apply"], ["apply", "transform"]], {"indirect_relation": ["apply", "transform"], "static_resolution_expected": False}),
    ("alias_shadowing", "from .left import handle as left_handle\nfrom .right import handle as right_handle\n\ndef run(value):\n    return left_handle(value) + right_handle(value)\n", {"src/left.py": "def handle(value):\n    return value + 1\n", "src/right.py": "def handle(value):\n    return value - 1\n"}, ["handle", "run"], [["run", "handle"]], {"homonymous_functions": 2, "leaf_name_metric_loses_identity": True}),
    ("exception_fallback", "from .support import parse\n\ndef fallback(value):\n    return 0\n\ndef safe_run(value):\n    try:\n        return parse(value)\n    except ValueError:\n        return fallback(value)\n", {"src/support.py": "def parse(value):\n    return int(value)\n"}, ["fallback", "safe_run", "parse"], [["safe_run", "parse"], ["safe_run", "fallback"]], {"exception_path": True, "runtime_path_not_proven": True}),
)


def _write(path: Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_complex_corpus(out_dir: Path) -> dict[str, Any]:
    if out_dir.exists():
        raise FileExistsError(f"corpus_output_exists:{out_dir}")
    out_dir.mkdir(parents=True)
    entries: list[dict[str, Any]] = []
    for index, (family, main_text, extras, symbols, relations, labels) in enumerate(CASES):
        project_id = f"complex_{index + 1:02d}_{family}"
        project = out_dir / project_id
        main = project / "src" / "main.py"
        main_hash = _write(main, main_text)
        extra_files = {"src/__init__.py": "", "README.md": f"# {family}\n\nClaim: {labels.get('documentation_claim', 'See source and config for behavior.')}\n", "config.json": json.dumps({"case": family, "enabled": labels.get("default", True)}, sort_keys=True) + "\n", **extras}
        artifacts = []
        for relative, content in sorted(extra_files.items()):
            digest = _write(project / relative, content)
            artifacts.append({"path": f"{project_id}/{relative}", "sha256": digest})
        oracle = project / "oracle.json"
        oracle_hash = _write(oracle, json.dumps({"oracle_schema": "re-megazord-oracle.v1", "family": family, "language": "python", "expected_symbols": symbols, "expected_relations": relations, "case_labels": labels, "known_limits": ["same-author synthetic oracle, not independent", "static source expectations are not runtime truth"]}, indent=2, sort_keys=True) + "\n")
        entries.append({"id": project_id, "family": family, "language": "python", "split": "development" if index < 7 else "calibration", "authorization": "owned_synthetic", "execution": "not_run_by_generator", "source": f"{project_id}/src/main.py", "source_sha256": main_hash, "oracle": f"{project_id}/oracle.json", "oracle_sha256": oracle_hash, "artifacts": artifacts})
    manifest = {"schema": "re-megazord-corpus.v1", "provenance": "owned_synthetic_hand_authored_in_generator; NOT independent ground truth; no blind holdout", "count": len(entries), "projects": entries, "limits": ["Python only", "no target execution", "no external independent oracle", "case_labels not yet scored"]}
    _write(out_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("corpus/complex_v1"))
    args = parser.parse_args()
    result = generate_complex_corpus(args.out)
    print(f"generated={result['count']} out={args.out} provenance={result['provenance']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
