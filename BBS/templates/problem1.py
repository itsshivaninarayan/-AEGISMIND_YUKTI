import pandas as pd
from sklearn.ensemble import IsolationForest

# ----------------------------
# Step 1: Load Dataset
# ----------------------------
data = pd.read_csv("network_data.csv")

# Store IP addresses
ips = data["IP_Address"]

# ----------------------------
# Step 2: Select Features
# ----------------------------
features = data[["Login_Attempts", "Bytes_Sent", "Port_Number"]]

# ----------------------------
# Step 3: Train Isolation Forest
# ----------------------------
model = IsolationForest(contamination=0.2, random_state=42)
model.fit(features)

# ----------------------------
# Step 4: Predict Anomalies
# ----------------------------
predictions = model.predict(features)

# ----------------------------
# Step 5: Display Results
# ----------------------------
print("---- Suspicious IP Detection Report ----\n")

for i in range(len(predictions)):
    status = "Suspicious" if predictions[i] == -1 else "Normal"
    print(f"IP Address : {ips[i]}")
    print(f"Status     : {status}")
    print("--------------------------------------")