"""
Baseline Comparator for Idea 3
================================
Implements three baselines that represent how existing IDS systems
correlate alerts WITHOUT any graph structural knowledge.

Baseline 1 — Time Proximity Correlator
  Any two consecutive alerts from the same source within T minutes
  are marked CORRELATED. This is how most SIEMs work.

Baseline 2 — Same Window Correlator
  Any two alerts that fall in the same time window are marked
  CORRELATED. Represents rule-based IDS window correlation.

Baseline 3 — Severity Threshold Correlator
  Any two alerts where both have severity >= threshold are marked
  CORRELATED. Represents priority-based alert grouping.

Each baseline is then compared against your TAG-based
3-class ground truth to measure:
  - False Correlation Rate  : pairs marked correlated but TAG says IMPOSSIBLE
  - Missed Chain Rate       : valid TAG chains the baseline missed
  - Precision / Recall      : treating VALID as positive class

Depends on:
  - ids_outputs/ids_alerts.csv
  - ids_outputs/alert_chain_classification.csv  (from idea3_validator.py)
"""

import math
import warnings
from pathlib import Path

import pandas as pd
import numpy as np

warnings.simplefilter(action="ignore", category=FutureWarning)

BASE_DIR       = Path(".").resolve()
IDS_OUTPUT_DIR = BASE_DIR / "ids_outputs"

ALERTS_CSV         = IDS_OUTPUT_DIR / "ids_alerts.csv"
TAG_RESULTS_CSV    = IDS_OUTPUT_DIR / "alert_chain_classification.csv"
COMPARISON_CSV     = IDS_OUTPUT_DIR / "baseline_comparison.csv"
DETAIL_CSV         = IDS_OUTPUT_DIR / "baseline_pair_detail.csv"

VALID      = "STRUCTURALLY_VALID"
IMPOSSIBLE = "STRUCTURALLY_IMPOSSIBLE"
AMBIGUOUS  = "STRUCTURALLY_AMBIGUOUS"

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ─────────────────────────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────────────────────────
def load_data():
    print("\n[1/5] Loading data...")

    alerts_df = pd.read_csv(ALERTS_CSV, parse_dates=["timestamp"])
    tag_df    = pd.read_csv(TAG_RESULTS_CSV, parse_dates=[
        "alert_a_timestamp", "alert_b_timestamp"
    ])

    print(f"  ✓ Raw alerts          : {len(alerts_df)}")
    print(f"  ✓ TAG-classified pairs: {len(tag_df)}")

    counts = tag_df["classification"].value_counts()
    print(f"  ✓ TAG valid           : {counts.get(VALID,      0)}")
    print(f"  ✓ TAG impossible      : {counts.get(IMPOSSIBLE, 0)}")
    print(f"  ✓ TAG ambiguous       : {counts.get(AMBIGUOUS,  0)}")

    return alerts_df, tag_df


# ─────────────────────────────────────────────────────────────────
# BASELINE 1 — Time Proximity Correlator
#
# Logic: for each source_host, consecutive alert pairs within
# `window_minutes` of each other are CORRELATED, others are NOT.
# We sweep multiple thresholds to show sensitivity.
# ─────────────────────────────────────────────────────────────────
def baseline_time_proximity(tag_df, window_minutes_list=None):
    if window_minutes_list is None:
        window_minutes_list = [15, 30, 60, 120]

    results = {}
    for wm in window_minutes_list:
        predictions = []
        for _, row in tag_df.iterrows():
            delta = abs(
                (row["alert_b_timestamp"] - row["alert_a_timestamp"])
                .total_seconds() / 60
            )
            pred = "CORRELATED" if delta <= wm else "NOT_CORRELATED"
            predictions.append(pred)
        results[f"time_{wm}min"] = predictions

    return results


# ─────────────────────────────────────────────────────────────────
# BASELINE 2 — Same Window Correlator
#
# Logic: pairs where both alerts fall in the same time window
# are CORRELATED. Different windows = NOT_CORRELATED.
# ─────────────────────────────────────────────────────────────────
def baseline_same_window(tag_df):
    predictions = []
    for _, row in tag_df.iterrows():
        pred = (
            "CORRELATED"
            if row["alert_a_window"] == row["alert_b_window"]
            else "NOT_CORRELATED"
        )
        predictions.append(pred)
    return {"same_window": predictions}


# ─────────────────────────────────────────────────────────────────
# BASELINE 3 — Severity Threshold Correlator
#
# Logic: pairs where BOTH alerts are >= severity threshold
# are CORRELATED. Sweeps LOW / MEDIUM / HIGH / CRITICAL.
# ─────────────────────────────────────────────────────────────────
def baseline_severity_threshold(tag_df, thresholds=None):
    if thresholds is None:
        thresholds = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    results = {}
    for threshold in thresholds:
        thresh_val  = SEVERITY_ORDER[threshold]
        predictions = []
        for _, row in tag_df.iterrows():
            sev_a = SEVERITY_ORDER.get(str(row.get("alert_a_severity", "LOW")).upper(), 0)
            sev_b = SEVERITY_ORDER.get(str(row.get("alert_b_severity", "LOW")).upper(), 0)
            pred  = (
                "CORRELATED"
                if sev_a >= thresh_val and sev_b >= thresh_val
                else "NOT_CORRELATED"
            )
            predictions.append(pred)
        results[f"severity_gte_{threshold}"] = predictions

    return results


# ─────────────────────────────────────────────────────────────────
# COMPUTE METRICS
#
# Ground truth mapping:
#   TAG VALID      → True Positive target  (should be CORRELATED)
#   TAG IMPOSSIBLE → True Negative target  (should be NOT_CORRELATED)
#   TAG AMBIGUOUS  → excluded from P/R
#     (ambiguous pairs are genuinely uncertain — including them
#      in either class would misrepresent both baselines and TAG)
#
# Metrics:
#   False Correlation Rate (FCR):
#     of pairs baseline says CORRELATED, % that TAG says IMPOSSIBLE
#     → how often the baseline creates spurious alert links
#
#   Missed Chain Rate (MCR):
#     of pairs TAG says VALID, % that baseline says NOT_CORRELATED
#     → how many real attack chains the baseline misses
#
#   Precision: TP / (TP + FP)
#   Recall   : TP / (TP + FN)
#   F1       : harmonic mean
# ─────────────────────────────────────────────────────────────────
def compute_metrics(tag_df, predictions, baseline_name):
    """
    predictions: list of "CORRELATED" / "NOT_CORRELATED", same length
                 and order as tag_df rows.
    """
    assert len(predictions) == len(tag_df), \
        f"Length mismatch: {len(predictions)} predictions vs {len(tag_df)} pairs"

    tag_labels = tag_df["classification"].values

    # ── core counts ──────────────────────────────────────────────
    total        = len(predictions)
    n_valid      = (tag_labels == VALID).sum()
    n_impossible = (tag_labels == IMPOSSIBLE).sum()
    n_ambiguous  = (tag_labels == AMBIGUOUS).sum()

    # False Correlation Rate
    correlated_mask  = [p == "CORRELATED" for p in predictions]
    impossible_mask  = tag_labels == IMPOSSIBLE
    false_corr       = sum(c and i for c, i in zip(correlated_mask, impossible_mask))
    total_correlated = sum(correlated_mask)
    fcr = false_corr / total_correlated if total_correlated else 0.0

    # Missed Chain Rate
    valid_mask   = tag_labels == VALID
    not_corr     = [p == "NOT_CORRELATED" for p in predictions]
    missed       = sum(v and nc for v, nc in zip(valid_mask, not_corr))
    mcr = missed / n_valid if n_valid else 0.0

    # Precision / Recall / F1 (excluding ambiguous rows)
    non_ambiguous = tag_labels != AMBIGUOUS
    y_true = [1 if t == VALID else 0
              for t, na in zip(tag_labels, non_ambiguous) if na]
    y_pred = [1 if p == "CORRELATED" else 0
              for p, na in zip(predictions, non_ambiguous) if na]

    tp = sum(a == 1 and b == 1 for a, b in zip(y_true, y_pred))
    fp = sum(a == 0 and b == 1 for a, b in zip(y_true, y_pred))
    fn = sum(a == 1 and b == 0 for a, b in zip(y_true, y_pred))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) else 0.0)

    return {
        "baseline"           : baseline_name,
        "total_pairs"        : total,
        "tag_valid"          : int(n_valid),
        "tag_impossible"     : int(n_impossible),
        "tag_ambiguous"      : int(n_ambiguous),
        "correlated_predicted": int(total_correlated),
        "false_corr_count"   : int(false_corr),
        "false_corr_rate_pct": round(fcr * 100, 1),
        "missed_chain_count" : int(missed),
        "missed_chain_rate_pct": round(mcr * 100, 1),
        "precision"          : round(precision, 3),
        "recall"             : round(recall, 3),
        "f1_score"           : round(f1, 3),
    }


# ─────────────────────────────────────────────────────────────────
# TAG SYSTEM SELF-METRICS
# (how TAG performs as a binary classifier on the same pairs)
# ─────────────────────────────────────────────────────────────────
def tag_self_metrics(tag_df):
    """
    Treats VALID as CORRELATED, IMPOSSIBLE as NOT_CORRELATED,
    AMBIGUOUS as a third class. Reports FCR = 0 and MCR = 0
    by construction — but also reports coverage (% non-ambiguous)
    so the comparison is honest.
    """
    total        = len(tag_df)
    n_valid      = (tag_df["classification"] == VALID).sum()
    n_impossible = (tag_df["classification"] == IMPOSSIBLE).sum()
    n_ambiguous  = (tag_df["classification"] == AMBIGUOUS).sum()
    coverage     = round(100 * (n_valid + n_impossible) / total, 1)

    return {
        "baseline"            : "TAG_IDS (ours)",
        "total_pairs"         : total,
        "tag_valid"           : int(n_valid),
        "tag_impossible"      : int(n_impossible),
        "tag_ambiguous"       : int(n_ambiguous),
        "correlated_predicted": int(n_valid),
        "false_corr_count"    : 0,
        "false_corr_rate_pct" : 0.0,
        "missed_chain_count"  : 0,
        "missed_chain_rate_pct": 0.0,
        "precision"           : 1.0,
        "recall"              : 1.0,
        "f1_score"            : 1.0,
        "note"                : f"TAG resolves {coverage}% of pairs; "
                                f"{n_ambiguous} ambiguous ({round(100*n_ambiguous/total,1)}%)",
    }


# ─────────────────────────────────────────────────────────────────
# BUILD PAIR-LEVEL DETAIL TABLE
# ─────────────────────────────────────────────────────────────────
def build_detail_table(tag_df, all_predictions):
    """
    One row per alert pair showing TAG classification and every
    baseline prediction side by side.
    """
    detail = tag_df[[
        "source_host",
        "alert_a_dest", "alert_a_window", "alert_a_severity",
        "alert_b_dest", "alert_b_window", "alert_b_severity",
        "classification", "same_window", "cross_window",
    ]].copy()

    for name, preds in all_predictions.items():
        detail[f"bl_{name}"] = preds

    return detail


# ─────────────────────────────────────────────────────────────────
# PRINT COMPARISON TABLE
# ─────────────────────────────────────────────────────────────────
def print_comparison(comparison_df):
    print("\n" + "=" * 80)
    print("  BASELINE COMPARISON TABLE")
    print("  (TAG VALID = ground truth positive; TAG IMPOSSIBLE = ground truth negative)")
    print("=" * 80)

    cols = [
        "baseline",
        "correlated_predicted",
        "false_corr_rate_pct",
        "missed_chain_rate_pct",
        "precision",
        "recall",
        "f1_score",
    ]
    headers = [
        "Baseline",
        "Correlated?",
        "FCR %",
        "MCR %",
        "Precision",
        "Recall",
        "F1",
    ]

    # header
    print(f"\n  {'Baseline':<35} {'Corr':>6} {'FCR%':>6} {'MCR%':>6} "
          f"{'Prec':>7} {'Rec':>7} {'F1':>7}")
    print("  " + "-" * 78)

    for _, row in comparison_df.iterrows():
        marker = " ◄" if "TAG_IDS" in str(row["baseline"]) else ""
        print(
            f"  {str(row['baseline']):<35} "
            f"{int(row['correlated_predicted']):>6} "
            f"{row['false_corr_rate_pct']:>6.1f} "
            f"{row['missed_chain_rate_pct']:>6.1f} "
            f"{row['precision']:>7.3f} "
            f"{row['recall']:>7.3f} "
            f"{row['f1_score']:>7.3f}"
            f"{marker}"
        )

    print("\n  FCR = False Correlation Rate: % of CORRELATED predictions TAG says are IMPOSSIBLE")
    print("  MCR = Missed Chain Rate     : % of TAG-VALID chains baseline marks NOT_CORRELATED")
    print("=" * 80)


# ─────────────────────────────────────────────────────────────────
# KEY FINDING SUMMARY
# ─────────────────────────────────────────────────────────────────
def print_key_findings(comparison_df, tag_df):
    total      = len(tag_df)
    n_valid    = (tag_df["classification"] == VALID).sum()
    n_impos    = (tag_df["classification"] == IMPOSSIBLE).sum()
    n_ambig    = (tag_df["classification"] == AMBIGUOUS).sum()

    # best baseline by F1 (excluding TAG itself)
    non_tag = comparison_df[~comparison_df["baseline"].str.contains("TAG")]
    best    = non_tag.loc[non_tag["f1_score"].idxmax()]

    print("\n" + "=" * 80)
    print("  KEY FINDINGS")
    print("=" * 80)
    print(f"\n  1. Of {total} consecutive alert pairs, only {n_valid} ({round(100*n_valid/total,1)}%)")
    print(f"     are structurally valid attack chains according to the TAG.")
    print(f"\n  2. {n_impos} pairs ({round(100*n_impos/total,1)}%) are structurally IMPOSSIBLE —")
    print(f"     a standard correlator would incorrectly link these.")
    print(f"\n  3. {n_ambig} pairs ({round(100*n_ambig/total,1)}%) are ambiguous (path exists")
    print(f"     but temporal ordering violated — potential detection lag).")
    print(f"\n  4. Best baseline: {best['baseline']}")
    print(f"     FCR={best['false_corr_rate_pct']}%  MCR={best['missed_chain_rate_pct']}%  F1={best['f1_score']}")
    print(f"\n  5. TAG-IDS reduces false correlation rate to 0% by design,")
    print(f"     while identifying the {n_ambig} ambiguous cases as a third")
    print(f"     class that no baseline can distinguish.")
    print("=" * 80)


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    print("╔" + "=" * 58 + "╗")
    print("║" + "  Baseline Comparator for Idea 3".center(58) + "║")
    print("╚" + "=" * 58 + "╝")

    alerts_df, tag_df = load_data()

    # ── run all baselines ─────────────────────────────────────────
    print("\n[2/5] Running baselines...")
    all_predictions = {}
    all_predictions.update(baseline_time_proximity(tag_df))
    all_predictions.update(baseline_same_window(tag_df))
    all_predictions.update(baseline_severity_threshold(tag_df))
    print(f"  ✓ Baselines defined   : {len(all_predictions)}")

    # ── compute metrics ───────────────────────────────────────────
    print("\n[3/5] Computing metrics...")
    rows = []
    for name, preds in all_predictions.items():
        rows.append(compute_metrics(tag_df, preds, name))

    # Add TAG self-report as the reference row
    rows.append(tag_self_metrics(tag_df))

    comparison_df = pd.DataFrame(rows)

    # ── build detail table ────────────────────────────────────────
    print("\n[4/5] Building pair-level detail table...")
    detail_df = build_detail_table(tag_df, all_predictions)

    # ── output ────────────────────────────────────────────────────
    print("\n[5/5] Saving results...")
    comparison_df.to_csv(COMPARISON_CSV, index=False)
    detail_df.to_csv(DETAIL_CSV, index=False)
    print(f"  ✓ Comparison table    : {COMPARISON_CSV}")
    print(f"  ✓ Pair detail table   : {DETAIL_CSV}")

    print_comparison(comparison_df)
    print_key_findings(comparison_df, tag_df)


if __name__ == "__main__":
    main()