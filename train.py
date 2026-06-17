import pandas as pd # შეცდომა გასწორდა: დაემატა Pandas ბიბლიოთეკის იმპორტი
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib
import json
import os

# CSV ფაილის შემოწმება
if not os.path.exists("network_traffic.csv"):
    print("შეცდომა: network_traffic.csv ვერ მოიძებნა!")
    exit()

# მონაცემების ჩატვირთვა
df = pd.read_csv("network_traffic.csv")

# შემოწმება ცარიელია თუ არა
if df.empty:
    print("შეცდომა: network_traffic.csv ცარიელია!")
    print("ჯერ გაუშვი generate_data.py")
    exit()

print(f"ჩაიტვირთა {len(df)} ჩანაწერი")

# Feature-ები და Target
X = df[['duration', 'packet_count', 'byte_count', 'port', 'protocol']]
y = df['attack_type']


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# მოდელის შექმნა
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# სწავლება
model.fit(X_train, y_train)

# პროგნოზი
y_pred = model.predict(X_test)

# მეტრიკები
acc = accuracy_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred).tolist()

# მოდელის შენახვა
joblib.dump(model, "cyber_model.pkl")

metrics = {
    "accuracy": float(acc),
    "confusion_matrix": cm
}

with open("metrics.json", "w") as f:
    json.dump(metrics, f, indent=4)

print(f"მოდელი წარმატებით გაიწვრთნა!")
print(f"Accuracy: {acc * 100:.2f}%")
print("შეიქმნა ახალი ფაილები: cyber_model.pkl და metrics.json")