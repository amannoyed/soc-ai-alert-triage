"""
preprocess.py
═════════════
Robust data preprocessor. Single source of truth for all data cleaning.

Fixes:
  - Drops NaN label rows before anything touches y
  - Enforces label as int
  - Fills post-dummies NaN with 0
  - Converts bool columns (pandas version compat)
  - Guards against empty dataset and single-class dataset
"""

import os
import pandas as pd

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CSV  = os.path.join(_BASE, "data", "sample_logs.csv")


def load_data(path: str = _CSV) -> pd.DataFrame:
    df = pd.read_csv(path)

    # 1. Drop rows where label is NaN — this is the root cause of the error
    before = len(df)
    df = df.dropna(subset=["label"])
    if len(df) < before:
        print(f"[preprocess] Dropped {before - len(df)} NaN-label rows.")

    if df.empty:
        raise ValueError(f"Dataset empty after dropping NaN labels. Check: {path}")

    # 2. Enforce int label
    df["label"] = df["label"].astype(int)

    # 3. Class balance check
    counts = df["label"].value_counts()
    if len(counts) < 2:
        raise ValueError(
            f"Dataset has only one class: {counts.to_dict()}. "
            "Add both label=0 and label=1 rows."
        )
    if counts.min() < 2:
        raise ValueError(
            f"Too few samples in minority class: {counts.to_dict()}. "
            "Need at least 2 of each class."
        )

    # 4. Drop non-feature columns
    drop_cols = [c for c in ("timestamp", "source_ip") if c in df.columns]
    df = df.drop(columns=drop_cols)

    # 5. One-hot encode
    cat_cols = [c for c in ("location", "device", "alert_type") if c in df.columns]
    if cat_cols:
        df = pd.get_dummies(df, columns=cat_cols)

    # 6. Fill NaN
    df = df.fillna(0)

    # 7. Convert bool → int (pandas compat)
    bool_cols = df.select_dtypes(include="bool").columns.tolist()
    if bool_cols:
        df[bool_cols] = df[bool_cols].astype(int)

    return df
