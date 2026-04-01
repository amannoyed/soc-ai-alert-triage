import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# 🔥 FIXED PATHS
base_path = os.path.dirname(os.path.dirname(__file__))

data_path = os.path.join(base_path, "data", "sample_logs.csv")
model_dir = os.path.join(base_path, "model")
model_path = os.path.join(model_dir, "model.pkl")

# Load data
df = pd.read_csv(data_path)

# Features & labels
X = df.drop("label", axis=1)
y = df["label"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save model
os.makedirs(model_dir, exist_ok=True)
joblib.dump(model, model_path)

print("Model trained and saved successfully!")