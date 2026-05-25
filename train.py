import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib
import json

df = pd.DataFrame(pd.read_csv("network_traffic.csv"))
X = df[['duration', 'packet_count', 'byte_count', 'port', 'protocol']]
y = df['attack_type']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred).tolist()

joblib.dump(model, "cyber_model.pkl")

metrics = {
    "accuracy": acc,
    "confusion_matrix": cm
}
with open("metrics.json", "w") as f:
    json.dump(metrics, f)

print(f"ახალი მოდელი გაიწვრთნა! სიზუსტე: {acc*100:.2f}%")