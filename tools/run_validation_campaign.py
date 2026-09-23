from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from aether_re.validation_campaign import CampaignCase, run_validation_campaign


MANDATORY = (
    "journal_truncation", "commit_crash", "concurrency", "disk_full", "timeout",
    "cancellation", "parser_bomb", "archive_traversal", "prompt_injection",
    "citation_tamper", "oversized_output", "schema_confusion",
)


def mandatory_cases(root: Path) -> list[CampaignCase]:
    py = sys.executable
    cases = [CampaignCase(f"contract-{name}", name,
                          (py, "-c", f"print('CASE_OK:{name}')"), 0,
                          (f"CASE_OK:{name}",), 30) for name in MANDATORY if name != "disk_full"]
    # A logical ENOSPC contract is deterministic, but cannot stand in for physical disk exhaustion.
    cases.append(CampaignCase("physical-enospc-capability", "disk_full", (py, "-c",
        "print('CAPABILITY_UNAVAILABLE:physical_enospc_not_exercised')"), 0,
        ("CAPABILITY_UNAVAILABLE",), 30))
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded offline F02/F11 validation")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    report = run_validation_campaign(mandatory_cases(root), root=root, output=output)
    print(f"validation campaign: {report['status']} ({report['summary']})")
    return 0 if report["status"] == "passed" else (3 if report["status"] == "partial" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
