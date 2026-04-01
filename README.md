\# 🚨 AI-Powered SOC Alert Triage System



\## 📌 Overview

This project simulates a Security Operations Center (SOC) tool that uses machine learning to classify security alerts as malicious or benign.



It provides a real-time dashboard for analyzing login patterns, detecting attacks, and assisting analysts in decision-making.



\---



\## 🚀 Features

\- 🔍 AI-based alert classification

\- 🌐 Threat intelligence (IP reputation)

\- ⚠️ Severity scoring (Low → Critical)

\- 🧠 Explainable AI (why alert triggered)

\- 📊 Interactive dashboard (Streamlit)

\- 🌍 Multi-location support

\- 💻 Multi-OS support (Windows, Linux, MacOS, Android, iOS)



\---



\## 🛠️ Tech Stack

\- Python

\- Scikit-learn

\- Streamlit

\- Pandas

\- Matplotlib



\---



\## 📊 Use Case

Designed to simulate SOC workflows and reduce alert fatigue by automating initial triage of security alerts.



\---



\## ▶️ Run Locally



```bash

pip install -r requirements.txt

python src/train\_model.py

python -m streamlit run app/streamlit\_app.py

