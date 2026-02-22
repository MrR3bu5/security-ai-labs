from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable, Tuple

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


REQUIRED_COLUMNS = [
    "timestamp_utc",
    "username",
    "event_source",
    "auth_type",
    "source_ip",
    "country",
    "result",
    "failure_reason",
]


@dataclass(frozen=True)
class FeatureConfig:
    """
    Configuration for feature extraction.

    Notes:
    - keep it simple and explainable
    - avoid leaking labels (we won't use is_injected_anomaly as a feature)
    """
    drop_columns: Tuple[str, ...] = ("is_injected_anomaly",)
    one_hot_min_frequency: int = 5  # helps reduce sparse noise for rare categories


def load_logs(csv_path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    # Parse timestamp
    df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], utc=True, errors="coerce")
    if df["timestamp_utc"].isna().any():
        bad = df[df["timestamp_utc"].isna()].head(5)
        raise ValueError(f"Found unparsable timestamps. Examples:\n{bad}")

    # Normalize strings
    for col in ["username", "event_source", "auth_type", "source_ip", "country", "result", "failure_reason"]:
        df[col] = df[col].fillna("").astype(str).str.strip()

    return df


def _ip_is_private(ip_str: str) -> int:
    try:
        return int(ip_address(ip_str).is_private)
    except Exception:
        return 0


def _ip_is_reserved(ip_str: str) -> int:
    # reserved / special-use / unroutable can be interesting
    try:
        ip = ip_address(ip_str)
        return int(ip.is_reserved or ip.is_loopback or ip.is_multicast or ip.is_unspecified)
    except Exception:
        return 0


def _ip_prefix24(ip_str: str) -> str:
    """
    Very lightweight “bucketing” so the model can learn that
    a /24 is common vs rare without storing exact addresses.

    If parsing fails, return 'unknown'.
    """
    try:
        ip = ip_address(ip_str)
        if ip.version == 4:
            parts = ip_str.split(".")
            return ".".join(parts[:3]) + ".0/24"
        # For IPv6, keep a coarse prefix
        return ip.exploded[:9] + "::/32"
    except Exception:
        return "unknown"


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    # Time features (UTC)
    out["hour"] = out["timestamp_utc"].dt.hour.astype(int)
    out["day_of_week"] = out["timestamp_utc"].dt.dayofweek.astype(int)  # Mon=0
    out["is_weekend"] = (out["day_of_week"] >= 5).astype(int)

    # Simple “off-hours” heuristic (tune later)
    # Treat 7am-7pm as normal for most humans; service accounts will still look different.
    out["is_offhours"] = ((out["hour"] < 7) | (out["hour"] > 19)).astype(int)

    # Result as binary
    out["is_failure"] = (out["result"].str.upper() != "SUCCESS").astype(int)

    # IP features
    out["ip_is_private"] = out["source_ip"].apply(_ip_is_private).astype(int)
    out["ip_is_reserved"] = out["source_ip"].apply(_ip_is_reserved).astype(int)
    out["ip_prefix"] = out["source_ip"].apply(_ip_prefix24)

    # Optional: keep an event “burstiness” proxy by counting failures per user in rolling window later
    # (leave out for v1 - keep simple)

    return out


def build_preprocessor(cfg: FeatureConfig | None = None) -> ColumnTransformer:
    cfg = cfg or FeatureConfig()

    numeric_features = [
        "hour",
        "day_of_week",
        "is_weekend",
        "is_offhours",
        "is_failure",
        "ip_is_private",
        "ip_is_reserved",
    ]

    categorical_features = [
        "username",
        "event_source",
        "auth_type",
        "country",
        "failure_reason",
        "ip_prefix",
    ]

    # OneHotEncoder with min_frequency keeps the matrix smaller and more stable
    cat = OneHotEncoder(
        handle_unknown="infrequent_if_exist",
        min_frequency=cfg.one_hot_min_frequency,
        sparse_output=True,
    )

    num = Pipeline(
        steps=[
            ("scaler", StandardScaler(with_mean=False)),  # safe for sparse combos
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", num, numeric_features),
            ("cat", cat, categorical_features),
        ],
        remainder="drop",
        sparse_threshold=0.3,
    )

    return preprocessor


def make_xy(
    df: pd.DataFrame,
    cfg: FeatureConfig | None = None,
) -> Tuple[pd.DataFrame, pd.Series | None]:
    """
    Returns:
      X_df: dataframe containing derived features + original columns
      y: optional injected label (only for evaluation). Not used in training.
    """
    cfg = cfg or FeatureConfig()

    work = df.copy()
    y = None
    if "is_injected_anomaly" in work.columns:
        y = work["is_injected_anomaly"].astype(str).str.lower().eq("true")

    # drop columns we never want as features
    for c in cfg.drop_columns:
        if c in work.columns:
            work = work.drop(columns=[c])

    X_df = add_derived_features(work)
    return X_df, y
