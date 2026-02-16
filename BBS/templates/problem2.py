import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, confusion_matrix

# ----------------------------------
# Step 1: Load Dataset
# ----------------------------------
data = pd.read_csv("data.csv")

# IP addresses (for reference)
ips = data["IP_Address"]

# Numeric features for model
features = data[["Login_Attempts", "Bytes_Sent", "Port_Number"]]

# Actual labels
# 0 = Normal, 1 = Attack
actual_labels = data["Label"]

# ----------------------------------
# Step 2: Train Isolation Forest
# ----------------------------------
model = IsolationForest(contamination=0.2, random_state=42)
model.fit(features)

# ----------------------------------
# Step 3: Predict Anomalies
# ----------------------------------
predictions = model.predict(features)

# Convert Isolation Forest output to labels
# -1 → Attack (1)
#  1 → Normal (0)
predicted_labels = [1 if p == -1 else 0 for p in predictions]

# ----------------------------------
# Step 4: Accuracy Calculation
# ----------------------------------
accuracy = accuracy_score(actual_labels, predicted_labels)

# ----------------------------------
# Step 5: Confusion Matrix
# ----------------------------------
cm = confusion_matrix(actual_labels, predicted_labels)

# ----------------------------------
# Step 6: Output Results
# ----------------------------------
print("------ PROBLEM STATEMENT 2 OUTPUT ------\n")

print("Accuracy of the Model:", accuracy)

print("\nConfusion Matrix:")
print(cm)