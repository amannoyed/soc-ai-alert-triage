import pandas as pd
import os


def load_data():
    base_path = os.path.dirname(os.path.dirname(__file__))
    file_path = os.path.join(base_path, "data", "sample_logs.csv")

    df = pd.read_csv(file_path)

    # Drop non-feature columns
    df = df.drop(columns=["timestamp", "source_ip"], errors="ignore")

    # One-hot encode categorical columns
    df = pd.get_dummies(df, columns=["location", "device", "alert_type"])

    return df