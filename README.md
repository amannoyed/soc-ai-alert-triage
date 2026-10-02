# 🛡️ SOC AI Triage Console

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-App-red)
![ML](https://img.shields.io/badge/ML-IsolationForest%20%7C%20RandomForest-orange)

A real-time SOC alert triage console: stream Windows event logs through a
detection pipeline (rules + unsupervised ML + UEBA + correlation), work a
persistent alert queue, and let analyst triage decisions train a feedback
model that improves future prioritization.

**Live demo:** https://soc-ai-alert-triage-amanoyed.streamlit.app/

---

## How it works

```
EVTX / CSV ──► Parse ──► Detection ──► UEBA ──► Correlation ──► Scoring ──► Triage Queue
  │                        │              │           │              │
  │                        │              │           │              └─► SQLite (persistent)
  │                        │              │           └─► per-IP chains, bursts
  │                        │              └─► behavioral baselines per IP
  │                        └─► ① rules ② Isolation Forest ③ statistical baseline
  └─► watch folder (live) / demo simulator / file upload
```

**Detection, honestly.** The anomaly model is an Isolation Forest trained
*only* on benign baseline activity — it learns what "normal" looks like and
scores deviation. No labels, no label leakage, contamination 0.05, scores
calibrated on the baseline's own distribution (85 ≈ stranger than 99% of
normal). A transparent rules layer and a z-score/p95/p99 statistical layer
fuse with it. Analysts' true/false-positive decisions train a separate
RandomForest that adjusts prioritization (±8) — the only supervised model
here, and its labels are real analyst decisions.

---

## Quickstart

```bash
git clone https://github.com/amannoyed/soc-ai-alert-triage.git
cd soc-ai-alert-triage
pip install -r requirements.txt

# Headless regression suite (20 checks, ~30s)
python scripts/smoke_test.py

# Launch the console
streamlit run app/streamlit_app.py
```

Generate the benign training baseline (synthetic demo data, documented):

```bash
python scripts/generate_baseline.py --n 2000   # → data/baseline_benign.csv
```

## Using it

| Tab | What it does |
|---|---|
| 🔴 Live Monitor | Stream the demo attack simulator **(labeled SIMULATED)** or point the watch folder at real `.evtx`/`.csv` logs; events flow through the pipeline into the queue |
| 🔧 Scenario Simulator | Describe a *raw* event (event ID, hour, IP, failed count…) — the pipeline derives the category and scores it |
| 📂 Log Investigation | Upload an `.evtx`; full pipeline: investigation report, correlation, MITRE, timeline, IOCs |
| 📊 Threat Intel | AbuseIPDB lookup (needs `ABUSEIPDB_API_KEY` in secrets/env) |
| 📋 Triage Queue | Persistent SQLite queue: investigate → confirm threat / false positive / suppress; decisions train the feedback model |

## Project structure

```
app/streamlit_app.py      analyst console
src/
  soc_pipeline.py         orchestration (parse → score → queue)
  log_parser.py           EVTX parsing, real SystemTime, honest counts
  features.py             observable-only feature vectors (no label leakage)
  anomaly_model.py        IsolationForest on benign baselines
  detection_engine.py     rules + anomaly + statistical baseline fusion
  ueba_engine.py          per-IP behavioral profiles & anomaly detectors
  correlation_engine.py   per-IP burst / slow-bf / chain detection
  scoring_engine.py       weighted fusion + explainable overrides
  investigation_engine.py analyst-style reasoning & recommendations
  timeline_engine.py      MITRE-stage attack timeline
  mitre.py                single source of truth for ATT&CK mappings
  triage_store.py         SQLite alert queue + analyst workflow
  feedback_model.py       RandomForest on analyst TP/FP decisions
  ingest.py               watch-folder tailing (.csv/.evtx)
  simulator.py            explicitly-synthetic demo attack scenarios
  predict.py              AbuseIPDB intel lookups
scripts/
  smoke_test.py           headless regression suite (20 checks)
  generate_baseline.py    synthetic benign baseline generator
data/baseline_benign.csv documented synthetic benign training data
logs/UACME_59_Sysmon.evtx real Sysmon capture (UACMe test) for testing
```

## Honest limitations

- The benign baseline is **synthetic demo data** — replace it with your own
  historical logs for production use (`scripts/generate_baseline.py`
  documents the schema).
- The feedback model cold-starts: it needs ≥20 analyst triage decisions
  before training.
- "Real time" = poll-based streaming into a console, not a production SIEM.
- Threat intel needs an AbuseIPDB key; without one, IPs are reported
  clean-by-default and the UI says so.
- On Streamlit Cloud, the SQLite queue and learned profiles are ephemeral
  (they regenerate); run locally or attach storage for persistence.

## Why this design

Most portfolio "AI SOC" projects train a classifier on labels that are a
function of the input category — the model "detects" what it was told.
This project was rebuilt to avoid that: unsupervised anomaly detection on
behavioral baselines, per-entity correlation with evidence-based
confidence, no fabricated events on parse failure, and a supervised model
whose labels are genuine analyst decisions. Every shortcut the old version
took is documented in the git history, not hidden.
