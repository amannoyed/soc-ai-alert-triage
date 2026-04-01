import pandas as pd
import os

def load_data():
    base_path = os.path.dirname(os.path.dirname(__file__))
    file_path = os.path.join(base_path, "data", "sample_logs.csv")

    df = pd.read_csv(file_path)

    df = pd.get_dummies(df, columns=["location", "device", "alert_type"])

    df = df.drop(columns=["timestamp", "source_ip"])

    return df