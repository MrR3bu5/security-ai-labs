# Authentication Log Anomaly Detection (PoC)

This project is a **small proof-of-concept** exploring how unsupervised machine learning can assist security analysts by identifying anomalous authentication behavior in log data.

The goal is not to build a production detection system, but to demonstrate:
- realistic security data handling
- simple, explainable ML techniques
- analyst-aligned outputs

---

## Problem Statement

Authentication logs are high-volume and noisy.  
Security teams often need to identify subtle indicators such as:
- off-hours access
- unusual geolocation changes
- rare source IPs
- brute-force patterns followed by success

This PoC explores whether lightweight ML techniques can help **surface suspicious activity for analyst review**, rather than generating hard “alerts.”

---

## Approach

This project uses an **unsupervised anomaly detection** approach:

1. Ingest authentication logs (synthetic, lab-generated)
2. Extract basic behavioral features
3. Train an anomaly detection model on baseline behavior
4. Score events based on how much they deviate from normal patterns

The model flags *outliers*, leaving the final decision to the analyst.

---

## Dataset

The dataset used in this PoC is **fully synthetic** and safe for public sharing.

### Example Fields

- `timestamp_utc`
- `username`
- `event_source`
- `auth_type`
- `source_ip`
- `country`
- `result`
- `failure_reason`

The generator also injects a small number of **known anomalous patterns** (e.g., impossible travel, brute-force attempts) to support evaluation.

📁 `data/sample_auth_logs.csv`

---

## Model Choice

This PoC uses simple, well-understood models such as:
- Isolation Forest
- Local Outlier Factor (LOF)

These models were selected because they:
- do not require labeled data
- are commonly used for anomaly detection
- are easier to reason about and explain

---

## Project Structure
```text
poc-auth-anomaly/
├── README.md
├── data/
│ └── sample_auth_logs.csv
├── notebook/
│ └── anomaly_detection.ipynb
├── src/
│ ├── generate_synthetic_auth_logs.py
│ ├── preprocess.py
│ ├── train.py
│ └── detect.py
└── requirements.txt
```


---

## Usage (High-Level)

1. Generate or load authentication logs
2. Preprocess and extract features
3. Train an anomaly detection model
4. Review high-scoring anomalous events

Detailed steps are documented in the Jupyter notebook.

---

## Limitations

This project intentionally has several limitations:
- Small dataset size
- No real-world enterprise telemetry
- No tuning for false positive reduction
- No alerting or response automation

These constraints keep the PoC focused and explainable.

---

## Future Enhancements

Possible next steps include:
- Live log ingestion from lab systems
- Feature enrichment (ASN, device fingerprinting, MFA context)
- Scoring thresholds and prioritization
- Mapping anomalies to MITRE ATT&CK techniques
- Forwarding flagged events to a SIEM

---

## Disclaimer

All data in this project is **synthetic and lab-generated**.  
No production systems, credentials, or sensitive information are involved.

---
