import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


# Load dataset
data = pd.read_csv("behaviour_data.csv")

# Features used by the ML model
features = [
    "device_trusted",
    "device_secure",
    "location_known",
    "access_frequency",
    "failed_attempts",
    "resource_sensitivity",
    "behaviour_anomaly"
]

X = data[features]
y = data["label"]

# Split data into training and testing
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# Create ML model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# Train model
model.fit(X_train, y_train)

# Test model
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("===================================")
print("Behaviour Detection ML Model")
print("===================================")
print(f"Accuracy: {accuracy * 100:.2f}%")
print()
print("Classification Report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Normal", "Anomalous"]
))

# Save trained model
joblib.dump(model, "behaviour_model.pkl")

print("===================================")
print("Model saved as behaviour_model.pkl")
print("===================================")