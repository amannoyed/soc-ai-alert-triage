import pandas as pd
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report
import sys

sys.path.append(os.path.dirname(__file__))
from preprocess import load_data

base_path = os.path.dirname(os.path.dirname(__file__))
model_dir = os.path.join(base_path, "model")
model_path = os.path.join(model_dir, "model.pkl")


def train():
    df = load_data()

    # --- Defensive checks ---
    print(f"Dataset shape: {df.shape}")
    print(f"Label NaN count: {df['label'].isna().sum()}")
    print(f"Label value counts:\n{df['label'].value_counts(dropna=False)}")

    # Drop rows with missing labels
    df = df.dropna(subset=["label"])

    # Drop rows with any NaN in features (optional but safe)
    df = df.dropna()

    if df.empty:
        raise ValueError("No valid training data after dropping NaN rows. Check your preprocess.py / data source.")

    # Check each class has enough samples for stratified split
    min_class_count = df["label"].value_counts().min()
    if min_class_count < 2:
        raise ValueError(
            f"At least one label class has fewer than 2 samples (min={min_class_count}). "
            "Cannot use stratify. Either get more data or remove stratify=y."
        )
    # --- End defensive checks ---

    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.1,
        max_depth=4,
        random_state=42
    )
    model.fit(X_train, y_train)

    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(model, model_path)

    print("Model trained and saved!")
    print(classification_report(y_test, model.predict(X_test)))

    return model


if __name__ == "__main__":
    train()