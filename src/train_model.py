from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from preprocess import load_data

df = load_data()

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier()
model.fit(X_train, y_train)

# 🔥 FIXED PATH
base_path = os.path.dirname(os.path.dirname(__file__))
model_dir = os.path.join(base_path, "model")

os.makedirs(model_dir, exist_ok=True)

model_path = os.path.join(model_dir, "model.pkl")
joblib.dump(model, model_path)

print("Model trained and saved!")