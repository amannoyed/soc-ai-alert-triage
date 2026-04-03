# 🚨 AI-Powered SOC Alert Triage System

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-App-red)
![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-orange)
![Status](https://img.shields.io/badge/Status-Live-success)

---

## 🌐 Live Demo
👉 https://soc-ai-alert-triage-amanoyed.streamlit.app/

---

## 📌 Overview
This project simulates a Security Operations Center (SOC) tool that uses machine learning to classify alerts as malicious or benign.
⚡ Reduces alert fatigue by simulating AI-driven SOC triage workflows
It helps analysts:
- Reduce alert fatigue  
- Detect brute-force & suspicious logins  
- Understand threats with AI explanations  

---

## 🚀 Features

- 🔍 AI-based alert classification  
- ⚠️ Severity scoring (Low → Critical)  
- 🌐 IP reputation checking  
- 🧠 Explainable AI (why alert triggered)  
- 📊 Interactive dashboard  
- 🌍 Multi-location support  
- 💻 Multi-device / OS support  

---

## 🛠️ Tech Stack

- Python  
- Scikit-learn  
- Streamlit  
- Pandas  
- Matplotlib  

---

## 📊 How It Works

1. User inputs login behavior  
2. System analyzes:
   - Failed attempts  
   - Location  
   - Device  
   - Attack type  
3. ML model classifies:
   - Threat / Benign  
4. Outputs:
   - Severity level  
   - Explanation  
   - IP intelligence  

---

## ▶️ Run Locally

```bash
pip install -r requirements.txt
python -m streamlit run app/streamlit_app.py