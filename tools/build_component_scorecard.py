import csv
from pathlib import Path

GEARS = [
    {
        "gear_id": "GEAR-01",
        "gear_name": "FindCrypt / Crypto Signature & S-Box Scanner",
        "source_candidates": "CAN-074 (FindCrypt-Ghidra), CAN-075 (findcrypt-yara), CAN-077 (signsrch)",
        "source_license": "MIT / Public Domain",
        "target_gap": "GAP-01 (Automated Cryptographic Constant Detection)",
        "target_file": "aether_re/crypto_detect.py",
        "gap_coverage": 40,
        "adherence": 30,
        "impact": 20,
        "modularity": 10,
        "relevance_score": 100,
        "compatibility": 30,
        "maturity": 20,
        "integration_cost": 19,
        "evidence_of_gain": 20,
        "reversibility": 10,
        "readiness_score": 99,
        "confidence": "HIGH",
        "threshold_status": "QUALIFIED_STAGING (>=80)",
        "decision": "SELECTED_FOR_INTEGRATION"
    },
    {
        "gear_id": "GEAR-02",
        "gear_name": "Go pclntab & Type Descriptor Recovery Engine",
        "source_candidates": "CAN-019 (GoReSym), CAN-095 (redress)",
        "source_license": "Apache-2.0",
        "target_gap": "GAP-02 (Golang Stripped Symbol Extraction)",
        "target_file": "aether_re/golang_recover.py",
        "gap_coverage": 38,
        "adherence": 28,
        "impact": 18,
        "modularity": 9,
        "relevance_score": 93,
        "compatibility": 25,
        "maturity": 18,
        "integration_cost": 14,
        "evidence_of_gain": 18,
        "reversibility": 9,
        "readiness_score": 84,
        "confidence": "HIGH",
        "threshold_status": "QUALIFIED_RESERVE (>=80)",
        "decision": "RESERVE_CANDIDATE"
    },
    {
        "gear_id": "GEAR-03",
        "gear_name": "PE Authenticode & Digital Certificate Forensics",
        "source_candidates": "CAN-041 (LIEF), CAN-099 (osslsigncode)",
        "source_license": "Apache-2.0 / GPL-3.0",
        "target_gap": "GAP-03 (PE Authenticode Security & PKCS#7)",
        "target_file": "aether_re/authenticode_audit.py",
        "gap_coverage": 32,
        "adherence": 25,
        "impact": 15,
        "modularity": 8,
        "relevance_score": 80,
        "compatibility": 24,
        "maturity": 17,
        "integration_cost": 16,
        "evidence_of_gain": 15,
        "reversibility": 8,
        "readiness_score": 80,
        "confidence": "MEDIUM",
        "threshold_status": "QUALIFIED_RESERVE (>=80)",
        "decision": "RESERVE_CANDIDATE"
    },
    {
        "gear_id": "GEAR-04",
        "gear_name": "Pure Python DWARF & Type Extractor",
        "source_candidates": "CAN-098 (pyelftools)",
        "source_license": "Public Domain",
        "target_gap": "GAP-04 (DWARF / PDB Symbol Table Binding)",
        "target_file": "aether_re/dwarf_types.py",
        "gap_coverage": 30,
        "adherence": 22,
        "impact": 14,
        "modularity": 9,
        "relevance_score": 75,
        "compatibility": 26,
        "maturity": 20,
        "integration_cost": 12,
        "evidence_of_gain": 14,
        "reversibility": 8,
        "readiness_score": 80,
        "confidence": "MEDIUM",
        "threshold_status": "ARCHIVED (<80)",
        "decision": "ARCHIVE"
    }
]

def main():
    out_csv = Path("D:/AetherRE_Megazord/engineering_evidence/COMPONENT_SCORECARD.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Gear_ID",
            "Gear_Name",
            "Source_Candidates",
            "Source_License",
            "Target_Gap",
            "Target_File",
            "Gap_Coverage_40",
            "Adherence_30",
            "Impact_20",
            "Modularity_10",
            "Relevance_Score",
            "Compatibility_30",
            "Maturity_20",
            "Integration_Cost_20",
            "Evidence_Of_Gain_20",
            "Reversibility_10",
            "Readiness_Score",
            "Confidence",
            "Threshold_Status",
            "Decision"
        ])
        for g in GEARS:
            writer.writerow([
                g["gear_id"],
                g["gear_name"],
                g["source_candidates"],
                g["source_license"],
                g["target_gap"],
                g["target_file"],
                g["gap_coverage"],
                g["adherence"],
                g["impact"],
                g["modularity"],
                g["relevance_score"],
                g["compatibility"],
                g["maturity"],
                g["integration_cost"],
                g["evidence_of_gain"],
                g["reversibility"],
                g["readiness_score"],
                g["confidence"],
                g["threshold_status"],
                g["decision"]
            ])
    print(f"Successfully generated {out_csv}")

if __name__ == "__main__":
    main()
