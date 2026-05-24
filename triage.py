"""
Structural Alert Triage Score
==============================
Every existing IDS triages alerts by CVSS severity alone.
This module computes a composite triage score that combines:

  Component 1 — CVE Severity Score      (what every IDS already uses)
  Component 2 — Node Betweenness        (how central is this node in the TAG)
  Component 3 — Path Criticality        (does this node sit on a valid attack path)
  Component 4 — Temporal Persistence    (how many windows has this node been active)
  Component 5 — Blind Spot Penalty      (is this node currently unmonitored)

Formula:
  STS = w1*severity + w2*betweenness + w3*path_critical + w4*persistence - w5*blind_spot

All components normalized to [0,1] before weighting.

The key claim: a MEDIUM CVE on a high-betweenness path-critical node
scores higher than a CRITICAL CVE on a leaf node with no onward paths.

Depends on:
  - ids_outputs/ids_alerts.csv
  - ids_outputs/host_cves_mapping.json
  - ids_outputs/blind_spot_nodes.csv          (from blind_spot_quantifier.py)
  - VERTICES_T*.CSV  and  ARCS_T*.CSV

Outputs:
  - ids_outputs/structural_triage_scores.csv  one row per alert
  - ids_outputs/triage_comparison.csv         STS rank vs CVSS rank per alert
  - ids_outputs/triage_summary.csv            aggregate findings
"""

import re
import json
import math
import warnings
from pathlib import Path
from collections import defaultdict, deque

import pandas as pd
import numpy as np
import networkx as nx

warnings.simplefilter(action="ignore", category=FutureWarning)

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────
BASE_DIR       = Path(".").resolve()
IDS_OUTPUT_DIR = BASE_DIR / "ids_outputs"

ALERTS_CSV      = IDS_OUTPUT_DIR / "ids_alerts.csv"
CVE_MAP_JSON    = IDS_OUTPUT_DIR / "host_cves_mapping.json"
BLIND_SPOT_CSV  = IDS_OUTPUT_DIR / "blind_spot_nodes.csv"

OUT_SCORES      = IDS_OUTPUT_DIR / "structural_triage_scores.csv"
OUT_COMPARISON  = IDS_OUTPUT_DIR / "triage_comparison.csv"
OUT_SUMMARY     = IDS_OUTPUT_DIR / "triage_summary.csv"

# Component weights — must sum to 1.0
# Tunable; these defaults give graph structure 60% of the score
WEIGHTS = {
    "severity"    : 0.25,   # CVE severity         (what CVSS uses alone)
    "betweenness" : 0.25,   # node betweenness centrality in TAG
    "path_critical": 0.20,  # binary: on a valid attack path
    "persistence" : 0.15,   # windows node has been continuously active
    "blind_spot"  : 0.15,   # penalty: currently unmonitored (negative)
}

SEVERITY_MAP = {"LOW": 0.25, "MEDIUM": 0.50, "HIGH": 0.75, "CRITICAL": 1.00}


# ─────────────────────────────────────────────────────────────────
# STEP 1 — Load all data
# ─────────────────────────────────────────────────────────────────
def load_all_data():
    print("\n[1/7] Loading data...")

    alerts_df = pd.read_csv(ALERTS_CSV, parse_dates=["timestamp"])
    with open(CVE_MAP_JSON) as f:
        host_cves_map = json.load(f)

    # blind spot nodes from Idea 2 output
    if BLIND_SPOT_CSV.exists():
        blind_df = pd.read_csv(BLIND_SPOT_CSV)
        print(f"  ✓ Blind spot nodes    : {len(blind_df)}")
    else:
        blind_df = pd.DataFrame(columns=["window","node_id","host","status"])
        print("  ⚠ blind_spot_nodes.csv not found — run blind_spot_quantifier.py first")
        print("    Continuing without blind spot penalty component...")

    print(f"  ✓ Alerts loaded       : {len(alerts_df)}")
    print(f"  ✓ Hosts with CVEs     : {len(host_cves_map)}")
    return alerts_df, host_cves_map, blind_df


# ─────────────────────────────────────────────────────────────────
# STEP 2 — Recover time windows from timestamps
# ─────────────────────────────────────────────────────────────────
def assign_time_windows(alerts_df):
    print("\n[2/7] Recovering time windows...")
    base_time = alerts_df["timestamp"].min()
    df = alerts_df.copy()
    df["hour_offset"] = (
        (df["timestamp"] - base_time)
        .dt.total_seconds()
        .div(3600)
        .apply(math.floor)
    )
    sorted_offsets   = sorted(df["hour_offset"].unique())
    offset_to_window = {off: f"T{i+1}" for i, off in enumerate(sorted_offsets)}
    df["time_window"] = df["hour_offset"].map(offset_to_window)
    print(f"  ✓ Windows             : {list(offset_to_window.values())}")
    return df


# ─────────────────────────────────────────────────────────────────
# STEP 3 — Build TAG graphs per window and compute node features
# ─────────────────────────────────────────────────────────────────
def build_tag_graphs():
    print("\n[3/7] Building TAG graphs per window...")
    graphs   = {}
    registry = {}   # (host, window) → node_id
    node_host= {}   # node_id → host (global)

    vertex_files = sorted(BASE_DIR.glob("VERTICES_T*.CSV"))
    arc_files    = sorted(BASE_DIR.glob("ARCS_T*.CSV"))

    if not vertex_files:
        raise FileNotFoundError("No VERTICES_T*.CSV found. Run Cell 1 first.")

    # load vertices
    for vf in vertex_files:
        window = vf.stem.replace("VERTICES_", "")
        vdf    = pd.read_csv(vf, header=None,
                             names=["node_id","label","type","value"])
        registry[window] = {}
        for _, row in vdf.iterrows():
            nid   = int(row["node_id"])
            hosts = re.findall(r"\b(h\d+)\b", str(row["label"]))
            host  = hosts[0] if hosts else f"node_{nid}"
            registry[window][nid] = host
            node_host[nid] = host

    # load arcs into per-window DiGraph
    for af in arc_files:
        window = af.stem.replace("ARCS_", "")
        adf    = pd.read_csv(af, header=None)
        G      = nx.DiGraph()
        # add all nodes for this window first
        for nid in registry.get(window, {}).keys():
            G.add_node(nid)
        for _, row in adf.iterrows():
            try:
                G.add_edge(int(row.iloc[1]), int(row.iloc[0]))  # source → target
            except (ValueError, IndexError):
                continue
        graphs[window] = G
        print(f"  ✓ {window}: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    return graphs, registry, node_host


# ─────────────────────────────────────────────────────────────────
# STEP 4 — Compute betweenness centrality per window
#          Uses your existing Brandes algorithm from Cell 3
# ─────────────────────────────────────────────────────────────────
def compute_betweenness_per_window(graphs):
    print("\n[4/7] Computing betweenness centrality per window...")
    bc_per_window = {}   # window → {node_id: bc_score}

    for window, G in graphs.items():
        if G.number_of_nodes() < 2:
            bc_per_window[window] = {n: 0.0 for n in G.nodes()}
            continue

        # Brandes algorithm (same as your Cell 3)
        BC    = {v: 0.0 for v in G}
        nodes = list(G.nodes())

        for s in nodes:
            stack = []
            P     = {v: [] for v in G}
            sigma = {v: 0 for v in G}
            dist  = {v: -1 for v in G}
            sigma[s] = 1
            dist[s]  = 0
            Q = deque([s])

            while Q:
                v = Q.popleft()
                stack.append(v)
                for w in G.successors(v):
                    if dist[w] < 0:
                        Q.append(w)
                        dist[w] = dist[v] + 1
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        P[w].append(v)

            delta = {v: 0.0 for v in G}
            while stack:
                w = stack.pop()
                for v in P[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                if w != s:
                    BC[w] += delta[w]

        N = G.number_of_nodes()
        denom = (N - 1) * (N - 2) if N > 2 else 1
        for v in BC:
            BC[v] /= denom

        # normalize to [0,1]
        max_bc = max(BC.values()) if BC else 1.0
        if max_bc > 0:
            BC = {v: s / max_bc for v, s in BC.items()}

        bc_per_window[window] = BC
        print(f"  ✓ {window}: computed for {len(BC)} nodes")

    return bc_per_window


# ─────────────────────────────────────────────────────────────────
# STEP 5 — Compute path criticality and persistence per node
# ─────────────────────────────────────────────────────────────────
def compute_node_features(graphs, registry):
    print("\n[5/7] Computing path criticality and persistence...")
    all_windows = sorted(graphs.keys())

    # Combined graph for path finding
    combined = nx.compose_all(list(graphs.values())) if graphs else nx.DiGraph()

    # path-critical nodes: on at least one path between any two nodes
    path_critical_nodes = set()
    nodes_list = list(combined.nodes())
    for src in nodes_list:
        for dst in nodes_list:
            if src == dst:
                continue
            if nx.has_path(combined, src, dst):
                try:
                    path = nx.shortest_path(combined, src, dst)
                    if len(path) > 2:    # intermediate nodes only
                        path_critical_nodes.update(path[1:-1])
                    elif len(path) == 2:
                        path_critical_nodes.update(path)
                except nx.NetworkXNoPath:
                    continue

    print(f"  ✓ Path-critical nodes : {len(path_critical_nodes)}")

    # persistence: how many windows each node appears in
    node_window_count = defaultdict(int)
    for window, nodes in registry.items():
        for nid in nodes:
            node_window_count[nid] += 1

    max_persistence = max(node_window_count.values()) if node_window_count else 1

    return path_critical_nodes, node_window_count, max_persistence


# ─────────────────────────────────────────────────────────────────
# STEP 6 — Build blind spot lookup from Idea 2 output
# ─────────────────────────────────────────────────────────────────
def build_blind_spot_lookup(blind_df):
    """Returns set of (node_id, window) that are blind spots."""
    blind_set = set()
    if blind_df.empty:
        return blind_set
    for _, row in blind_df.iterrows():
        if row["status"] != "MONITORED":
            blind_set.add((int(row["node_id"]), str(row["window"])))
    return blind_set


# ─────────────────────────────────────────────────────────────────
# STEP 7 — Compute STS for every alert
# ─────────────────────────────────────────────────────────────────
def compute_sts(alerts_df, registry, bc_per_window,
                path_critical_nodes, node_window_count,
                max_persistence, blind_spot_set):
    print("\n[6/7] Computing Structural Triage Scores...")

    # build (host, window) → node_id lookup
    host_index = {}
    for window, nodes in registry.items():
        for nid, host in nodes.items():
            host_index[(host, window)] = nid

    scored_rows = []

    for _, row in alerts_df.iterrows():
        dest    = row["dest_host"]
        window  = row.get("time_window", "T1")
        sev_raw = str(row.get("severity", "HIGH")).upper()

        # ── map alert to TAG node ──────────────────────────────
        nid = host_index.get((dest, window))
        if nid is None:
            tw_num = int(re.sub(r"\D", "", window)) if window else 1
            for delta in [1, -1, 2, -2]:
                nid = host_index.get((dest, f"T{tw_num + delta}"))
                if nid:
                    break

        # ── Component 1: Severity ──────────────────────────────
        c_severity = SEVERITY_MAP.get(sev_raw, 0.75)

        if nid is not None:
            # ── Component 2: Betweenness ───────────────────────
            bc_dict  = bc_per_window.get(window, {})
            c_betw   = bc_dict.get(nid, 0.0)

            # ── Component 3: Path Criticality ─────────────────
            c_path   = 1.0 if nid in path_critical_nodes else 0.0

            # ── Component 4: Persistence ──────────────────────
            c_persist = node_window_count.get(nid, 1) / max_persistence

            # ── Component 5: Blind Spot Penalty ───────────────
            c_blind  = 1.0 if (nid, window) in blind_spot_set else 0.0

        else:
            # unmapped alert — only severity known
            c_betw    = 0.0
            c_path    = 0.0
            c_persist = 0.0
            c_blind   = 0.0

        # ── Composite STS ─────────────────────────────────────
        sts = (
            WEIGHTS["severity"]     * c_severity
            + WEIGHTS["betweenness"]  * c_betw
            + WEIGHTS["path_critical"]* c_path
            + WEIGHTS["persistence"]  * c_persist
            - WEIGHTS["blind_spot"]   * c_blind   # penalty
        )
        sts = round(max(0.0, min(1.0, sts)), 4)

        # CVSS-only score for comparison
        cvss_only = round(c_severity, 4)

        scored_rows.append({
            **row.to_dict(),
            "tag_node_id"       : nid,
            "c_severity"        : round(c_severity, 3),
            "c_betweenness"     : round(c_betw,     3),
            "c_path_critical"   : round(c_path,     3),
            "c_persistence"     : round(c_persist,  3),
            "c_blind_spot"      : round(c_blind,    3),
            "structural_triage_score": sts,
            "cvss_only_score"   : cvss_only,
        })

    scored_df = pd.DataFrame(scored_rows)
    print(f"  ✓ Scored alerts       : {len(scored_df)}")
    return scored_df


# ─────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────
def build_comparison(scored_df):
    """
    For each alert, compute rank by CVSS-only vs rank by STS.
    Rank inversion = alerts that CVSS ranks low but STS ranks high
    (or vice versa). These are your key examples for the paper.
    """
    df = scored_df.copy().reset_index(drop=True)

    df["cvss_rank"] = df["cvss_only_score"].rank(
        ascending=False, method="min"
    ).astype(int)
    df["sts_rank"]  = df["structural_triage_score"].rank(
        ascending=False, method="min"
    ).astype(int)
    df["rank_delta"] = df["cvss_rank"] - df["sts_rank"]

    # positive rank_delta = STS promotes this alert vs CVSS
    # negative rank_delta = STS demotes this alert vs CVSS

    return df


def print_report(comparison_df):
    print("\n" + "=" * 68)
    print("  STRUCTURAL TRIAGE SCORE REPORT")
    print("=" * 68)

    total = len(comparison_df)

    # rank inversions
    promoted  = (comparison_df["rank_delta"] > 5).sum()
    demoted   = (comparison_df["rank_delta"] < -5).sum()
    unchanged = total - promoted - demoted

    print(f"\n  Total alerts scored         : {total}")
    print(f"  Promoted by STS (rank +>5)  : {promoted}  "
          f"({round(100*promoted/total,1)}%)")
    print(f"  Demoted by STS  (rank -<5)  : {demoted}  "
          f"({round(100*demoted/total,1)}%)")
    print(f"  Rank stable (within ±5)     : {unchanged}  "
          f"({round(100*unchanged/total,1)}%)")

    # show top promoted alerts — MEDIUM/LOW severity but high STS
    print(f"\n  Top 5 alerts PROMOTED by structural context:")
    print(f"  (Low CVSS severity but high structural importance)")
    top_prom = comparison_df.nlargest(5, "rank_delta")[
        ["dest_host","severity","cve_id","time_window",
         "cvss_only_score","structural_triage_score",
         "cvss_rank","sts_rank","rank_delta",
         "c_betweenness","c_path_critical","c_persistence"]
    ]
    print(top_prom.to_string(index=False))

    # show top demoted alerts — CRITICAL severity but low STS
    print(f"\n  Top 5 alerts DEMOTED by structural context:")
    print(f"  (High CVSS severity but low structural importance)")
    top_dem = comparison_df.nsmallest(5, "rank_delta")[
        ["dest_host","severity","cve_id","time_window",
         "cvss_only_score","structural_triage_score",
         "cvss_rank","sts_rank","rank_delta",
         "c_betweenness","c_path_critical","c_persistence"]
    ]
    print(top_dem.to_string(index=False))

    # score distribution by severity
    print(f"\n  Mean STS vs CVSS-only by severity:")
    print(f"  {'Severity':<10} {'Count':>6} {'CVSS-only':>10} "
          f"{'STS mean':>10} {'STS > CVSS':>12}")
    print("  " + "-" * 52)
    for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        sub = comparison_df[
            comparison_df["severity"].str.upper() == sev
        ]
        if sub.empty:
            continue
        mean_cvss = sub["cvss_only_score"].mean()
        mean_sts  = sub["structural_triage_score"].mean()
        promoted_pct = round(
            100 * (sub["structural_triage_score"] > sub["cvss_only_score"]).mean(),
            1
        )
        print(f"  {sev:<10} {len(sub):>6} {mean_cvss:>10.3f} "
              f"{mean_sts:>10.3f} {promoted_pct:>11.1f}%")

    print("=" * 68)


def print_key_findings(comparison_df):
    total     = len(comparison_df)
    promoted  = (comparison_df["rank_delta"] > 5).sum()
    demoted   = (comparison_df["rank_delta"] < -5).sum()

    # find the clearest example: MEDIUM CVE, high STS
    medium_high_sts = comparison_df[
        (comparison_df["severity"].str.upper().isin(["MEDIUM","LOW"]))
        & (comparison_df["structural_triage_score"] > 0.6)
    ]
    # find clearest counter: CRITICAL CVE, low STS
    critical_low_sts = comparison_df[
        (comparison_df["severity"].str.upper() == "CRITICAL")
        & (comparison_df["structural_triage_score"] < 0.4)
    ]

    corr = comparison_df["cvss_only_score"].corr(
        comparison_df["structural_triage_score"]
    )

    print("\n" + "=" * 68)
    print("  KEY FINDINGS FOR PAPER")
    print("=" * 68)
    print(f"\n  1. {promoted} alerts ({round(100*promoted/total,1)}%) are ranked")
    print(f"     significantly HIGHER by STS than by CVSS alone.")
    print(f"     These are alerts CVSS would deprioritize but the TAG")
    print(f"     identifies as structurally dangerous.")
    print(f"\n  2. {demoted} alerts ({round(100*demoted/total,1)}%) are ranked")
    print(f"     significantly LOWER by STS than by CVSS alone.")
    print(f"     These are high-severity alerts on structurally dead-end")
    print(f"     nodes — CVSS overprioritizes them.")
    print(f"\n  3. Pearson correlation (CVSS vs STS): {corr:.3f}")
    if abs(corr) < 0.7:
        print(f"     Low correlation confirms STS captures information")
        print(f"     that severity alone does not.")
    else:
        print(f"     Moderate/high correlation — structural components")
        print(f"     refine but do not fully diverge from severity.")
    if not medium_high_sts.empty:
        ex = medium_high_sts.iloc[0]
        print(f"\n  4. Example promotion:")
        print(f"     Host {ex['dest_host']} | Severity: {ex['severity']}")
        print(f"     CVSS score: {ex['cvss_only_score']:.3f}  →  "
              f"STS: {ex['structural_triage_score']:.3f}")
        print(f"     Betweenness: {ex['c_betweenness']:.3f}  "
              f"Path-critical: {ex['c_path_critical']:.0f}  "
              f"Persistence: {ex['c_persistence']:.3f}")
    if not critical_low_sts.empty:
        ex = critical_low_sts.iloc[0]
        print(f"\n  5. Example demotion:")
        print(f"     Host {ex['dest_host']} | Severity: {ex['severity']}")
        print(f"     CVSS score: {ex['cvss_only_score']:.3f}  →  "
              f"STS: {ex['structural_triage_score']:.3f}")
        print(f"     Betweenness: {ex['c_betweenness']:.3f}  "
              f"Path-critical: {ex['c_path_critical']:.0f}  "
              f"Persistence: {ex['c_persistence']:.3f}")
    print("=" * 68)


def save_results(comparison_df):
    comparison_df.to_csv(OUT_SCORES, index=False)

    comparison_cols = [
        "dest_host","severity","cve_id","time_window",
        "cvss_only_score","structural_triage_score",
        "cvss_rank","sts_rank","rank_delta",
        "c_severity","c_betweenness","c_path_critical",
        "c_persistence","c_blind_spot",
    ]
    existing = [c for c in comparison_cols if c in comparison_df.columns]
    comparison_df[existing].to_csv(OUT_COMPARISON, index=False)

    summary = pd.DataFrame([{
        "total_alerts"              : len(comparison_df),
        "promoted_count"            : (comparison_df["rank_delta"] > 5).sum(),
        "demoted_count"             : (comparison_df["rank_delta"] < -5).sum(),
        "promoted_pct"              : round(
            100*(comparison_df["rank_delta"] > 5).mean(), 1),
        "demoted_pct"               : round(
            100*(comparison_df["rank_delta"] < -5).mean(), 1),
        "cvss_sts_correlation"      : round(
            comparison_df["cvss_only_score"].corr(
                comparison_df["structural_triage_score"]), 3),
        "mean_sts"                  : round(
            comparison_df["structural_triage_score"].mean(), 3),
        "mean_cvss"                 : round(
            comparison_df["cvss_only_score"].mean(), 3),
        "weight_severity"           : WEIGHTS["severity"],
        "weight_betweenness"        : WEIGHTS["betweenness"],
        "weight_path_critical"      : WEIGHTS["path_critical"],
        "weight_persistence"        : WEIGHTS["persistence"],
        "weight_blind_spot_penalty" : WEIGHTS["blind_spot"],
    }])
    summary.to_csv(OUT_SUMMARY, index=False)

    print(f"\n  ✓ Scored alerts       : {OUT_SCORES}")
    print(f"  ✓ Rank comparison     : {OUT_COMPARISON}")
    print(f"  ✓ Summary             : {OUT_SUMMARY}")


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    print("╔" + "=" * 58 + "╗")
    print("║" + "  Structural Alert Triage Score".center(58) + "║")
    print("╚" + "=" * 58 + "╝")

    alerts_df, host_cves_map, blind_df = load_all_data()
    alerts_df = assign_time_windows(alerts_df)

    graphs, registry, node_host        = build_tag_graphs()
    bc_per_window                      = compute_betweenness_per_window(graphs)
    path_critical_nodes, node_window_count, max_persistence = \
        compute_node_features(graphs, registry)
    blind_spot_set = build_blind_spot_lookup(blind_df)

    scored_df    = compute_sts(
        alerts_df, registry, bc_per_window,
        path_critical_nodes, node_window_count,
        max_persistence, blind_spot_set,
    )
    comparison_df = build_comparison(scored_df)

    save_results(comparison_df)
    print_report(comparison_df)
    print_key_findings(comparison_df)


if __name__ == "__main__":
    main()