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