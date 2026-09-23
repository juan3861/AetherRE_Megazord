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
    # Unbound classes are explicit debt, never synthetic passes. The integrated suites
    # below provide assertion-bearing coverage for the classes they actually exercise.
    cases = [CampaignCase(f"not-exercised-{name}", name,
                          (py, "-c", f"print('CAPABILITY_UNAVAILABLE:{name}_not_bound')"), 0,
                          ("CAPABILITY_UNAVAILABLE", name), 30, capability_optional=True)
             for name in MANDATORY]
    scripts = [root / "tools" / name for name in (
        "f02_fault_campaign.py", "f11_adversarial_campaign.py", "f11_adversarial_cli_campaign.py")]
    if not all(path.is_file() for path in scripts):
        for label, category in (("f02-suite", "tamper"), ("f11-suite", "prompt_injection"),
                                ("f11-cli-suite", "cli_encoding")):
            cases.append(CampaignCase(f"not-exercised-{label}", category,
                (py, "-c", f"print('CAPABILITY_UNAVAILABLE:{label}_script_absent')"),
                0, ("CAPABILITY_UNAVAILABLE", label), 30, capability_optional=True))
        return cases
    cases.extend([
        CampaignCase("f02-local-fault-suite", "tamper",
                     (py, str(root / "tools" / "f02_fault_campaign.py"),
                      "--out", str(root / "output" / "f02_local_fault_campaign.json")),
                     0, ("status=complete_for_injected_local_profile",), 180,
                     evidence_files=("output/f02_local_fault_campaign.json",),
                     evidence_schema="f02-local-fault-campaign.v1",
                     evidence_status="complete_for_injected_local_profile", minimum_evidence_cases=8),
        CampaignCase("f11-adversarial-suite", "prompt_injection",
                     (py, str(root / "tools" / "f11_adversarial_campaign.py")),
                     0, ('"status": "complete"',), 180,
                     evidence_files=("output/f11_adversarial_campaign_20260918.json",),
                     evidence_schema="f11-adversarial-campaign.v1", evidence_status="complete",
                     minimum_evidence_cases=9),
        CampaignCase("f11-cli-adversarial-suite", "cli_encoding",
                     (py, str(root / "tools" / "f11_adversarial_cli_campaign.py")),
                     0, ('"status": "complete"',), 180,
                     evidence_files=("output/f11_adversarial_cli_campaign_20260918.json",),
                     evidence_schema="f11-adversarial-cli-campaign.v1", evidence_status="complete",
                     minimum_evidence_cases=2),
    ])
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
