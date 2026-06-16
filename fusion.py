import json
from datetime import datetime

# Read Static Report

with open(
    "C:/VSCODE/HYBRID_IDS/reports/static_report.json",
    "r"
) as f:

    static_result = json.load(f)

# Read AI Report

with open(
    "C:/VSCODE/HYBRID_IDS/reports/ai_report.json",
    "r"
) as f:

    ai_data = json.load(f)

# Confidence

malware_probability = ai_data["malware_probability"]

if malware_probability >= 90:

    confidence = "Very High"

elif malware_probability >= 70:

    confidence = "High"

elif malware_probability >= 50:

    confidence = "Medium"

else:

    confidence = "Low"

# Fusion Logic

final_verdict = "Benign"

if (
    malware_probability >= 80
    or static_result["status"] == "Malware"
):

    final_verdict = "Malware"

elif (
    malware_probability >= 50
    or static_result["status"] == "Suspicious"
):

    final_verdict = "Suspicious"

# Final Report

final_report = {

    "filename":
        static_result["filename"],

    "scan_time":
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

    "static_status":
        static_result["status"],

    "heuristic_score":
        static_result["heuristic_score"],

    "entropy":
        static_result["entropy"],

    "matched_keywords":
        static_result["matched_keywords"],

    "matched_rules":
        static_result["matched_rules"],

    "quarantined":
        static_result["quarantined"],

    "ai_verdict":
        ai_data["verdict"],

    "malware_probability":
        malware_probability,

    "benign_probability":
        ai_data["benign_probability"],

    "confidence":
        confidence,

    "final_verdict":
        final_verdict
}

# Save

with open(
    "C:/VSCODE/HYBRID_IDS/reports/final_report.json",
    "w"
) as f:

    json.dump(
        final_report,
        f,
        indent=4
    )

print("\nFINAL VERDICT")
print("=" * 40)

print(
    final_report["final_verdict"]
)

print(
    f"Confidence: {confidence}"
)