import joblib
import pandas as pd
import json

from feature_extractor import extract_features

model = joblib.load("rf_model.pkl")
columns = joblib.load("columns.pkl")

def run_ai_scan(file_path):

    features = extract_features(file_path)

    features_df = pd.DataFrame([features])

    features_df = features_df.reindex(
        columns=columns,
        fill_value=0
    )

    prediction = model.predict(features_df)

    probability = model.predict_proba(
        features_df
    )

    print("\nFEATURE VECTOR")
    print("=" * 60)

    for i, (feature, value) in enumerate(
        features.items(),
        start=1
    ):
        print(f"{i}. {feature}: {value}")
    
    ai_report = {

        "malware_probability":
            round(probability[0][1] * 100, 2),

        "benign_probability":
            round(probability[0][0] * 100, 2),

        "verdict":
            "Malware" if prediction[0] == 1
            else "Benign"
    }

    with open(
        r"C:\VSCODE\HYBRID_IDS\reports\ai_report.json",
        "w"
    ) as f:

        json.dump(
            ai_report,
            f,
            indent=4
        )

    print("\n[+] ai_report.json created")
    return ai_report