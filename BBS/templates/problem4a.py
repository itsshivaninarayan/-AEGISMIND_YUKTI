import pandas as pd
from sklearn.ensemble import IsolationForest
import streamlit as st

# ----------------------------
# Load Dataset
# ----------------------------
data = pd.read_csv("network_data.csv")

# Save IP column
ip_addresses = data["IP_Address"]

# Select numeric features
features = data[["Login_Attempts", "Bytes_Sent", "Port_Number"]]

# ----------------------------
# Train Isolation Forest Model
# ----------------------------
model = IsolationForest(contamination=0.2, random_state=42)
model.fit(features)

# Predict anomalies
predictions = model.predict(features)

# Convert predictions to labels
data["Status"] = ["Suspicious" if x == -1 else "Normal" for x in predictions]

# ----------------------------
# Option A: Quarantine List
# ----------------------------
quarantine_list = data[data["Status"] == "Suspicious"]["IP_Address"]

# ----------------------------
# Streamlit Dashboard
# ----------------------------
st.title("🚨 Suspicious IP Detection Dashboard")

st.write("### 📊 Summary")
st.write("Total Records:", len(data))
st.write("Suspicious Records:", len(quarantine_list))

st.write("### ⚠️ Quarantine List (Suspicious IPs)")
st.table(quarantine_list.reset_index(drop=True))