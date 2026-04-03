import pandas as pd
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier

base_path = os.path.dirname(os.path.dirname(__file__))
data_path = os.path.join(base_path, "data", "sample_logs.csv")
model_path = os.path.join(base_path, "model", "model.pkl")

# 🔥 Load data
df = pd.read_csv(data_path)

# 🔥 One-hot encoding
df = pd.get_dummies(df)

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# 🔥 Better model
model = GradientBoostingClassifier()
model.fit(X_train, y_train)

# 🔥 Ensure model folder exists
os.makedirs(os.path.dirname(model_path), exist_ok=True)

# 🔥 Save model
joblib.dump(model, model_path)

print("Model trained and saved!")