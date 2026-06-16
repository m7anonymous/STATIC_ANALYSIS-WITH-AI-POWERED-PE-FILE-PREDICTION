from signature_scan import signature_scan
from heuristic_scan import heuristic_scan

from analyzer.quarantine import quarantine_file
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
from analyzer.entropy import calculate_entropy
from analyzer.xml_logger import save_scan_result

import json
import os

print("\n[+] Starting Scan...\n")

# ==========================
# USER INPUT
# ==========================
def run_static_scan(file_path):

    file_path = input(
        "\nEnter file path: "
    ).strip()

    if not os.path.exists(file_path):

        print("\n[ERROR] File not found.")
        exit()

    file = os.path.basename(file_path)

# ==========================
# SIGNATURE SCAN
# ==========================

    matches = signature_scan(file_path)

    yara_detected = False
    matched_rules = []

    if matches:

        yara_detected = True

        for match in matches:

            matched_rules.append(
                match.rule
            )

# ==========================
# HEURISTIC SCAN
# ==========================

    matched_keywords, heuristic_score = heuristic_scan(
        file_path
    )

    if matched_keywords:

        print(
            "\n[HEURISTIC] Suspicious keywords found:"
        )

        for item in matched_keywords:

            print(
                f"   -> {item['text']} (+{item['score']})"
            )

    print(
        f"\n[HEURISTIC SCORE] {heuristic_score}"
    )

# ==========================
# ENTROPY
# ==========================

    entropy = calculate_entropy(
        file_path
    )

    print(
        f"[INFO] Entropy: {entropy:.2f}"
    )

# ==========================
# THREAT SCORE
# ==========================

    final_score = 0

    if yara_detected:

        final_score += 70

    final_score += heuristic_score

    if entropy >= 7:

        final_score += 20

    print(
        f"[FINAL THREAT SCORE] {final_score}"
    )

# ==========================
# DECISION LOGIC
# ==========================

    status = "Clean"
    quarantined = False

    if yara_detected:

        status = "Malware"

        print(
            f"\n[!] MALWARE DETECTED: {file}"
        )

        for rule in matched_rules:

            print(
                f"   Rule Matched: {rule}"
            )

        quarantine_file(
            file_path
        )

        quarantined = True

    elif heuristic_score >= 50:

        status = "Suspicious"

        print(
            f"\n[!] SUSPICIOUS FILE DETECTED: {file}"
        )

        quarantine_file(
            file_path
        )

        quarantined = True

    else:

        print(
            f"\n[OK] CLEAN FILE: {file}"
        )

# ==========================
# KEYWORDS
# ==========================

    keyword_list = []

    for item in matched_keywords:

        keyword_list.append(
            item["text"]
        )

# ==========================
# REPORT
# ==========================

    scan_result = {

        "filename":
            file,

        "heuristic_score":
            heuristic_score,

        "entropy":
            round(entropy, 2),

        "matched_keywords":
            keyword_list,

        "matched_rules":
            matched_rules,

        "status":
            status,

        "quarantined":
            quarantined,

        "final_score":
            final_score
    }

# ==========================
# XML LOG
# ==========================

    save_scan_result(
        scan_result
    )

# ==========================
# JSON REPORT
# ==========================

    with open(
        "/media/sf_reports/static_report.json",
        "w"
    ) as f: 

        json.dump(
            scan_result,
            f,
            indent=4
        )

    print(
        "\n[DEBUG] JSON SAVED"
    )

# ==========================
# SUMMARY
# ==========================

    print(
        "\n[+] FINAL SCAN SUMMARY"
    )

    print(
        "=" * 50
    )

    print(
        json.dumps(
            scan_result,
            indent=4
        )
    )
 
    return scan_result
