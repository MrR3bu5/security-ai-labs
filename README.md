# Security AI Labs

This repository contains **small, security-focused AI proof-of-concepts** designed to explore how machine learning can *assist* security operations, not replace them.

The projects here intentionally prioritize:
- realistic security problems
- simple, explainable approaches
- hands-on experimentation over theoretical perfection

This lab complements traditional security tooling (SIEM, detection engineering, incident response) by exploring where lightweight AI techniques can add value.

---

## Philosophy

Security teams are already overloaded with alerts, logs, and telemetry.  
The goal of this lab is to explore how **AI can help prioritize, highlight, and support decision-making**, rather than act as a black-box detection system.

Key principles:
- Security-first thinking
- Explainable results
- Small, incremental proof-of-concepts
- Built to expand, but scoped to finish

---

## Current Projects

### 🔍 Authentication Log Anomaly Detection (PoC)

A minimal proof-of-concept that uses **unsupervised machine learning** to identify anomalous authentication behavior from log data.

**Focus areas:**
- Log feature extraction
- Behavioral baselining
- Anomaly detection using lightweight ML models
- Analyst-friendly outputs

This project is intentionally small and self-contained, serving as a foundation for future security AI experiments.

📁 `poc-auth-anomaly/`

---

## What This Repository Is (and Is Not)

**This repository is:**
- A learning and experimentation lab
- A showcase of security-minded AI workflows
- A place to iterate on small, focused ideas

**This repository is not:**
- A production-ready detection platform
- A replacement for SIEM or SOC workflows
- A large-scale AI system trained on enterprise data

---

## Tooling & Techniques

Projects in this repository may include:
- Python
- Pandas / NumPy
- Scikit-learn
- Jupyter notebooks
- Synthetic or lab-generated security data

Infrastructure, orchestration, and deployment are intentionally out of scope for early PoCs but may be introduced in later phases.

---

## Future Direction

Planned areas of exploration include:
- Integration with security logging pipelines
- Model comparison and evaluation
- Alert scoring and prioritization
- Mapping anomalies to ATT&CK-style techniques
- Feeding results into SIEM or SOAR-style workflows

---

## Disclaimer

All data used in this repository is either **synthetic or lab-generated**.  
No production, sensitive, or real-world organizational data is included.

---
