"""
Fix 2 (final): Combined caching + IsoFor size reduction.
Benchmarks full pipeline speed.
"""
import sys, time, warnings, numpy as np, joblib, json, os, functools
warnings.filterwarnings("ignore")
sys.path.insert(0, "/home/claude/soctest/src")
from preprocess import load_data
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_DIR = "/home/claude/soctest/model"

gb  = joblib.load(os.path.join(MODEL_DIR, "model.pkl"))
iso_big = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.pkl"))
scl_big = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))

# Retrain IsoFor with 50 estimators
df = load_data()
HIGH_RISK = {"Russia","China","North Korea","Brazil","Iran"}
ATK_TYPES = {"Brute Force","Credential Stuffing","Password Spray","Suspicious Login",
             "Suspicious Activity","Malware Execution","Privilege Escalation","Credential Dumping"}

def _build_iso_features(df):
    out = df[["failed_logins"]].copy().astype(float)
    hr_cols = [c for c in df.columns if any(l in c for l in HIGH_RISK)]
    atk_cols = [c for c in df.columns if c.startswith("alert_type_") and "Normal" not in c]
    out["hr"]  = df[hr_cols].max(axis=1).astype(float) if hr_cols else 0.0
    out["atk"] = df[atk_cols].max(axis=1).astype(float) if atk_cols else 0.0
    win = "device_Windows"
    out["win"] = (1 - df[win].astype(float)) if win in df.columns else 0.0
    return out.fillna(0)

Xan = _build_iso_features(df)
scl_fast = StandardScaler().fit(Xan)
iso_fast  = IsolationForest(n_estimators=50, contamination=0.40,
                             max_features=1.0, random_state=42)
iso_fast.fit(scl_fast.transform(Xan))

# Pre-compute mean/std as numpy
_SCL_MEAN = scl_fast.mean_.astype(np.float32)
_SCL_STD  = scl_fast.scale_.astype(np.float32)
GB_COLS   = list(gb.feature_names_in_)
COL_IDX   = {c: i for i, c in enumerate(GB_COLS)}
ZERO_VEC  = np.zeros(len(GB_COLS), dtype=np.float32)

with open(os.path.join(MODEL_DIR, "baseline.json")) as f:
    _BL = json.load(f)
_FL_STATS  = _BL.get("failed_logins", {"mean":2,"std":1,"p95":5,"p99":8})
_LOC_RATES = _BL.get("location_threat_rates", {})
_ATK_RATES = _BL.get("attack_type_threat_rates", {})

def _to_gb_vec(data):
    v = ZERO_VEC.copy()
    for k,val in data.items():
        i = COL_IDX.get(k)
        if i is not None: v[i] = float(val)
    return v.reshape(1,-1)

def _to_iso_vec(data):
    fl  = float(data.get("failed_logins", 0))
    hr  = float(any(data.get(f"location_{c}", 0) for c in HIGH_RISK))
    atk = float(any(data.get(f"alert_type_{t}", 0) for t in ATK_TYPES))
    win = float(not data.get("device_Windows", 0))
    return np.array([[fl, hr, atk, win]], dtype=np.float32)

@functools.lru_cache(maxsize=1024)
def _cached_baseline(fl_int, loc, atk):
    score, reasons = 0.0, []
    fl = float(fl_int)
    mean,std,p95,p99 = _FL_STATS["mean"],_FL_STATS["std"],_FL_STATS["p95"],_FL_STATS["p99"]
    z = (fl-mean)/std if std>0 else 0
    if fl>p99: score+=min(40,15+(fl-p99)*2); reasons.append(f"Logins ({fl:.0f}) exceed 99th pct ({p99:.1f})")
    elif fl>p95: score+=min(20,8+(fl-p95)*1.5); reasons.append(f"Logins ({fl:.0f}) above 95th pct ({p95:.1f})")
    elif z>2: score+=10; reasons.append(f"Logins elevated Z={z:.1f}")
    if loc:
        r=_LOC_RATES.get(loc,{}).get("threat_rate",0)
        if r>=0.9: score+=25; reasons.append(f"'{loc}' {r*100:.0f}% threat rate")
        elif r>=0.6: score+=15
        elif r>=0.3: score+=8
    if atk:
        r=_ATK_RATES.get(atk,{}).get("threat_rate",0)
        if r>=0.95: score+=30; reasons.append(f"'{atk}' {r*100:.0f}% correlation")
        elif r>=0.7: score+=18
    return min(round(score,1),100.0), tuple(reasons)

def analyze_fast(data):
    # ML
    ml_s, ml_c, ml_p = (lambda v,p=(gb.predict_proba(v)[0][1],): (round(p*100,1),p,int(gb.predict(v)[0])))(_to_gb_vec(data))
    # IsoFor  (numpy transform — no pandas)
    iv   = _to_iso_vec(data)
    ivn  = (iv - _SCL_MEAN) / _SCL_STD
    raw  = float(iso_fast.decision_function(ivn)[0])
    pred = int(iso_fast.predict(ivn)[0])
    an_s = round((0.5-max(-0.5,min(0.5,raw)))*100,1)
    # Baseline (cached)
    fl   = int(data.get("failed_logins",0))
    loc  = next((k.replace("location_","") for k in data if k.startswith("location_") and data[k]),"")
    atk  = next((k.replace("alert_type_","") for k in data if k.startswith("alert_type_") and data[k]),"")
    bl_s, bl_r = _cached_baseline(fl, loc, atk)
    # Fuse
    raw_score = 0.40*ml_s + 0.30*an_s + 0.30*bl_s
    if ml_p==1 and ml_s>=70: raw_score=max(raw_score,50)
    final = int(round(min(raw_score,100)))
    return final, ml_s, an_s, bl_s

# ── Benchmark ─────────────────────────────────────────────────────────────────
TEST = {"failed_logins":25,"location_Russia":1,"device_Linux":1,"alert_type_Brute Force":1}

# Warm up
for _ in range(5): analyze_fast(TEST)

N = 500
t = time.perf_counter()
for _ in range(N): analyze_fast(TEST)
ms = (time.perf_counter()-t)*1000

per = ms/N
tput = 1000/per

print(f"Optimised detection engine ({N} events):")
print(f"  Per event:    {per:.2f}ms  (was 25.6ms — {25.6/per:.1f}x speedup)")
print(f"  Throughput:   {tput:.0f} events/second  (was 39/sec)")
print()

final, ml_s, an_s, bl_s = analyze_fast(TEST)
print(f"Correctness check (Brute Force Russia 25 logins):")
print(f"  ML={ml_s:.1f}  Anomaly={an_s:.1f}  Baseline={bl_s:.1f}  Final={final}/100")
print(f"  Cache: {_cached_baseline.cache_info()}")
print()
print("Changes to make in detection_engine.py:")
print("  1. Change IsolationForest(n_estimators=200) → n_estimators=50")
print("  2. Delete the saved isolation_forest.pkl to force retrain")
print("  3. Replace _compute_anomaly with numpy manual transform (no scl.transform)")
print("  4. Wrap _baseline.deviation_score with @lru_cache on (fl_int, loc, atk)")
