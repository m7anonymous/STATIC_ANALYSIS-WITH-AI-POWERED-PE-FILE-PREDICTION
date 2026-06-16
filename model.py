import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ==========================
# LOAD DATASET
# ==========================

df = pd.read_csv("ClaMP_Raw-5184.csv")

print("Dataset Shape:")
print(df.shape)

print("\nObject Columns:")
print(df.select_dtypes(include='object').columns)

# ==========================
# HANDLE MISSING VALUES
# ==========================

df = df.fillna(0)

# ==========================
# CONVERT TEXT COLUMNS
# ==========================

object_cols = df.select_dtypes(include='object').columns

for col in object_cols:
    df[col] = df[col].astype('category').cat.codes

# ==========================
# FEATURES AND LABEL
# ==========================

X = df.drop("class", axis=1)
y = df["class"]

# ==========================
# TRAIN TEST SPLIT
# ==========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.3,
    random_state=42,
    stratify=y
)

# ==========================
# RANDOM FOREST
# ==========================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# ==========================
# TRAIN
# ==========================

model.fit(X_train, y_train)

# ==========================
# PREDICT
# ==========================

y_pred = model.predict(X_test)

# ==========================
# RESULTS
# ==========================

print("\n===================")
print("ACCURACY")
print("===================")

print(accuracy_score(y_test, y_pred))

print("\n===================")
print("CONFUSION MATRIX")
print("===================")

print(confusion_matrix(y_test, y_pred))

print("\n===================")
print("CLASSIFICATION REPORT")
print("===================")

print(classification_report(y_test, y_pred))

print("Accuracy :", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall   :", recall_score(y_test, y_pred))
print("F1 Score :", f1_score(y_test, y_pred))

# ==========================
# FEATURE IMPORTANCE
# ==========================

feature_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print("\n===================")
print("TOP 20 FEATURES")
print("===================")

print(feature_importance.head(20))

# ==========================
# SAVE TO CSV
# ==========================

feature_importance["Rank"] = range(
    1,
    len(feature_importance) + 1
)

feature_importance.to_csv(
    "feature_importance.csv",
    index=False
)

print("\nSaved feature_importance.csv")

# ==========================
# SAVE MODEL
# ==========================

joblib.dump(
    model,
    "rf_model.pkl"
)

joblib.dump(
    X.columns.tolist(),
    "columns.pkl"
)

print("\n===================")
print("MODEL SAVED")
print("===================")

print("Saved rf_model.pkl")
print("Saved columns.pkl")