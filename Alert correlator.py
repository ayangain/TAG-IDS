"""
Idea 3 Validator: Alert Chain Validity via Temporal Path Constraints
=====================================================================
Classifies every consecutive IDS alert pair as:
  - STRUCTURALLY_VALID     : temporal path exists between mapped nodes
                             in correct window order
  - STRUCTURALLY_IMPOSSIBLE: no temporal path exists between the nodes
  - STRUCTURALLY_AMBIGUOUS : path exists but window ordering is violated

Depends on:
  - ids_outputs/ids_alerts.csv
  - ids_outputs/host_cves_mapping.json
  - VERTICES_T*.CSV  and  ARCS_T*.CSV
  - Running Neo4j instance with TAG already loaded (run Cell 3 first)
"""

import os
import re
import json
import math
import warnings
from pathlib import Path

import pandas as pd
import numpy as np
import networkx as nx
from neo4j import GraphDatabase

warnings.simplefilter(action="ignore", category=FutureWarning)

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────
NEO4J_URI      = "bolt://localhost:7687"
NEO4J_USER     = "neo4j"
NEO4J_PASSWORD = "12345678"

BASE_DIR       = Path(".").resolve()
IDS_OUTPUT_DIR = BASE_DIR / "ids_outputs"
ALERTS_CSV     = IDS_OUTPUT_DIR / "ids_alerts.csv"
CVE_MAP_JSON   = IDS_OUTPUT_DIR / "host_cves_mapping.json"
RESULTS_CSV    = IDS_OUTPUT_DIR / "alert_chain_classification.csv"
SUMMARY_CSV    = IDS_OUTPUT_DIR / "alert_chain_summary.csv"

VALID      = "STRUCTURALLY_VALID"
IMPOSSIBLE = "STRUCTURALLY_IMPOSSIBLE"
AMBIGUOUS  = "STRUCTURALLY_AMBIGUOUS"


# ─────────────────────────────────────────────────────────────────
# STEP 1 — Load raw data
# ─────────────────────────────────────────────────────────────────
def load_data():
    print("\n[1/6] Loading raw data...")
    alerts_df = pd.read_csv(ALERTS_CSV, parse_dates=["timestamp"])
    with open(CVE_MAP_JSON) as f:
        host_cves_map = json.load(f)
    print(f"  ✓ Alerts loaded       : {len(alerts_df)}")
    print(f"  ✓ Hosts with CVEs     : {len(host_cves_map)}")
    return alerts_df, host_cves_map


# ─────────────────────────────────────────────────────────────────
# STEP 2 — Recover time window label per alert from timestamp
# ─────────────────────────────────────────────────────────────────
def assign_time_windows(alerts_df):
    print("\n[2/6] Recovering time windows from timestamps...")
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
    print(f"  ✓ Windows detected    : {list(offset_to_window.values())}")
    print(f"  ✓ Alerts per window   :\n{df['time_window'].value_counts().sort_index().to_string()}")
    return df


# ─────────────────────────────────────────────────────────────────
# STEP 3 — Build (host, window) → node_id index from VERTICES CSVs
# ─────────────────────────────────────────────────────────────────
def build_host_node_index():
    print("\n[3/6] Building host→node_id index from VERTICES CSVs...")
    index = {}
    vertex_files = sorted(BASE_DIR.glob("VERTICES_T*.CSV"))
    if not vertex_files:
        raise FileNotFoundError("No VERTICES_T*.CSV files found. Run Cell 1 first.")

    for vf in vertex_files:
        window = vf.stem.replace("VERTICES_", "")   # "T1", "T2", ...
        df = pd.read_csv(vf, header=None,
                         names=["node_id", "label", "type", "value"])
        for _, row in df.iterrows():
            node_id = int(row["node_id"])
            label   = str(row["label"])
            hosts   = re.findall(r"\b(h\d+)\b", label)
            if hosts:
                index[(hosts[0], window)] = node_id

    print(f"  ✓ Index entries built : {len(index)}")
    # Debug: show a few entries so we can verify
    sample = list(index.items())[:5]
    for k, v in sample:
        print(f"    {k} → node_id {v}")
    return index


# ─────────────────────────────────────────────────────────────────
# STEP 4 — Map each alert to its TAG node_id
# ─────────────────────────────────────────────────────────────────
def map_alerts_to_nodes(alerts_df, host_node_index):
    print("\n[4/6] Mapping alerts to TAG nodes...")
    mapped, unmapped = [], []

    for _, row in alerts_df.iterrows():
        dest    = row["dest_host"]
        window  = row["time_window"]
        node_id = host_node_index.get((dest, window))
        entry   = row.to_dict()

        if node_id is None:
            # Try adjacent windows as fallback
            tw_num = int(re.sub(r"\D", "", window))
            for delta in [1, -1, 2, -2]:
                fb_key = (dest, f"T{tw_num + delta}")
                if fb_key in host_node_index:
                    node_id = host_node_index[fb_key]
                    window  = fb_key[1]
                    break

        entry["tag_node_id"]     = node_id
        entry["tag_time_window"] = window if node_id is not None else None
        entry["mapped"]          = node_id is not None
        (mapped if entry["mapped"] else unmapped).append(entry)

    mapped_df   = pd.DataFrame(mapped)
    unmapped_df = pd.DataFrame(unmapped)
    pct = 100 * len(mapped_df) / len(alerts_df)
    print(f"  ✓ Mapped              : {len(mapped_df)} ({pct:.1f}%)")
    print(f"  ✗ Unmapped            : {len(unmapped_df)}")
    return mapped_df, unmapped_df


# ─────────────────────────────────────────────────────────────────
# STEP 5 — Load temporal paths from Neo4j
#
# ROOT CAUSE OF THE ORIGINAL BUG:
# The previous version queried DISTINCT LABELS(a) which returned
# ['TAG'] — the node label — not the relationship types.
# The APOC relationshipFilter needs relationship type names
# (T1, T2, T3 ...), not node labels.
# Fix: query DISTINCT type(r) from relationships instead.
# ─────────────────────────────────────────────────────────────────
def load_temporal_paths_from_neo4j(driver):
    print("\n[5/6] Loading temporal paths from Neo4j...")

    with driver.session() as session:

        # ── FIX: get relationship types, not node labels ──────────
        rel_types = session.run(
            "MATCH ()-[r]->() RETURN DISTINCT type(r) AS relType ORDER BY relType"
        ).value()

        if not rel_types:
            raise RuntimeError(
                "No relationships found in Neo4j. "
                "Ensure create_TAG() was called first (Cell 3)."
            )

        print(f"  ✓ Relationship types  : {rel_types}")

        # Build APOC direction filter: "T1>|T2>|T3>|T4>"
        direction = "|".join(f"{rt}>" for rt in sorted(rel_types))
        print(f"  ✓ APOC direction      : {direction}")

        query = (
            "MATCH (a:TAG) "
            "CALL apoc.path.expandConfig(a, {"
            "  relationshipFilter: '" + direction + "', "
            "  labelFilter: 'TAG', "
            "  minLevel: 1 "
            "}) YIELD path "
            "WITH DISTINCT "
            "  [node IN nodes(path) | node.name] AS nodesOnPath, "
            "  [rel  IN relationships(path) | type(rel)] AS relsOnPath "
            "WHERE size(nodesOnPath) >= 2 "
            "  AND all(i IN range(0, size(relsOnPath)-2) "
            "          WHERE relsOnPath[i] <= relsOnPath[i+1]) "
            "RETURN nodesOnPath, relsOnPath"
        )

        result = session.run(query).to_df()

    print(f"  ✓ Temporal paths found: {len(result)}")

    # Debug: show a few paths
    if not result.empty:
        print("  Sample paths:")
        for _, row in result.head(3).iterrows():
            print(f"    nodes={row['nodesOnPath']}  rels={row['relsOnPath']}")

    return result, sorted(rel_types)


# ─────────────────────────────────────────────────────────────────
# Build fast lookup: (src_node_name, dst_node_name) → earliest
# arrival window.
#
# NOTE: Neo4j TAG nodes store name as integers (the original
# node_id). We keep them as-is from the query and cast to int
# when matching against alert node_ids.
# ─────────────────────────────────────────────────────────────────
def build_path_lookup(paths_df):
    lookup = {}
    for _, row in paths_df.iterrows():
        nodes = row["nodesOnPath"]
        rels  = row["relsOnPath"]
        if len(nodes) < 2:
            continue

        src = nodes[0]
        dst = nodes[-1]
        arrival = rels[-1]
        key = (src, dst)
        if key not in lookup or arrival < lookup[key]:
            lookup[key] = arrival

    print(f"  ✓ Path lookup entries : {len(lookup)}")
    return lookup


# ─────────────────────────────────────────────────────────────────
# STEP 6 — Classify every consecutive alert pair
# ─────────────────────────────────────────────────────────────────
def classify_alert_pair(node_a, window_a, node_b, window_b, path_lookup):
    """
    node_a / node_b are integers (TAG node_ids).
    path_lookup keys are whatever type node.name returns from Neo4j.
    We try both int and the raw type.
    """
    def try_key(src, dst):
        for s, d in [(src, dst), (int(src), int(dst)),
                     (str(src), str(dst))]:
            if (s, d) in path_lookup:
                return path_lookup[(s, d)]
        return None

    arrival = try_key(node_a, node_b)
    if arrival is not None:
        if window_b >= window_a:
            return VALID, arrival
        else:
            return AMBIGUOUS, arrival

    rev_arrival = try_key(node_b, node_a)
    if rev_arrival is not None:
        return AMBIGUOUS, rev_arrival

    return IMPOSSIBLE, None


def classify_all_pairs(mapped_df, path_lookup):
    print("\n[6/6] Classifying alert pairs...")
    df = mapped_df.sort_values("timestamp").reset_index(drop=True)
    results = []

    for src_host, group in df.groupby("source_host"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        for i in range(len(group) - 1):
            a = group.iloc[i]
            b = group.iloc[i + 1]

            if pd.isna(a["tag_node_id"]) or pd.isna(b["tag_node_id"]):
                continue
            if a["tag_node_id"] == b["tag_node_id"]:
                continue

            clf, arrival = classify_alert_pair(
                a["tag_node_id"], a["tag_time_window"],
                b["tag_node_id"], b["tag_time_window"],
                path_lookup,
            )

            results.append({
                "source_host"         : src_host,
                "alert_a_dest"        : a["dest_host"],
                "alert_a_cve"         : a.get("cve_id"),
                "alert_a_severity"    : a.get("severity"),
                "alert_a_window"      : a["tag_time_window"],
                "alert_a_node_id"     : a["tag_node_id"],
                "alert_a_timestamp"   : a["timestamp"],
                "alert_a_attack_type" : a.get("attack_type"),
                "alert_b_dest"        : b["dest_host"],
                "alert_b_cve"         : b.get("cve_id"),
                "alert_b_severity"    : b.get("severity"),
                "alert_b_window"      : b["tag_time_window"],
                "alert_b_node_id"     : b["tag_node_id"],
                "alert_b_timestamp"   : b["timestamp"],
                "alert_b_attack_type" : b.get("attack_type"),
                "classification"      : clf,
                "path_arrival_window" : arrival,
                "same_window"         : a["tag_time_window"] == b["tag_time_window"],
                "cross_window"        : a["tag_time_window"] != b["tag_time_window"],
            })

    results_df = pd.DataFrame(results)
    print(f"  ✓ Total pairs classified: {len(results_df)}")
    return results_df


# ─────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────
def print_report(results_df, unmapped_df, total_alerts):
    print("\n" + "=" * 60)
    print("  ALERT CHAIN CLASSIFICATION REPORT")
    print("=" * 60)

    total_pairs = len(results_df)
    counts      = results_df["classification"].value_counts()
    valid       = counts.get(VALID,      0)
    impossible  = counts.get(IMPOSSIBLE, 0)
    ambiguous   = counts.get(AMBIGUOUS,  0)

    print(f"\n  Total alerts          : {total_alerts}")
    print(f"  Unmapped alerts       : {len(unmapped_df)}")
    print(f"  Total pairs evaluated : {total_pairs}")
    print()
    print(f"  {VALID:<34}: {valid:>5}  ({100*valid/max(total_pairs,1):.1f}%)")
    print(f"  {IMPOSSIBLE:<34}: {impossible:>5}  ({100*impossible/max(total_pairs,1):.1f}%)")
    print(f"  {AMBIGUOUS:<34}: {ambiguous:>5}  ({100*ambiguous/max(total_pairs,1):.1f}%)")

    cross = results_df[results_df["cross_window"]]
    print(f"\n  Cross-window pairs    : {len(cross)}")
    if not cross.empty:
        for cls, cnt in cross["classification"].value_counts().items():
            print(f"    {cls:<34}: {cnt}")

    valid_df = results_df[results_df["classification"] == VALID]
    if not valid_df.empty:
        print(f"\n  Valid chain severity (alert A):")
        print(valid_df["alert_a_severity"].value_counts().to_string())
        print(f"\n  Top 5 valid transitions:")
        trans = (valid_df[["alert_a_attack_type","alert_b_attack_type"]]
                 .value_counts().head(5))
        print(trans.to_string())

    print("\n" + "=" * 60)


def save_results(results_df, unmapped_df, total_alerts):
    results_df.to_csv(RESULTS_CSV, index=False)
    print(f"  ✓ Full results        : {RESULTS_CSV}")

    total_pairs = len(results_df)
    counts      = results_df["classification"].value_counts()
    pd.DataFrame([{
        "total_alerts"    : total_alerts,
        "unmapped_alerts" : len(unmapped_df),
        "total_pairs"     : total_pairs,
        "valid_count"     : counts.get(VALID,      0),
        "impossible_count": counts.get(IMPOSSIBLE, 0),
        "ambiguous_count" : counts.get(AMBIGUOUS,  0),
        "valid_pct"       : round(100*counts.get(VALID,      0)/max(total_pairs,1), 2),
        "impossible_pct"  : round(100*counts.get(IMPOSSIBLE, 0)/max(total_pairs,1), 2),
        "ambiguous_pct"   : round(100*counts.get(AMBIGUOUS,  0)/max(total_pairs,1), 2),
    }]).to_csv(SUMMARY_CSV, index=False)
    print(f"  ✓ Summary             : {SUMMARY_CSV}")


# ─────────────────────────────────────────────────────────────────
# FALLBACK — local NetworkX when Neo4j is unavailable
# ─────────────────────────────────────────────────────────────────
def fallback_local_paths():
    print("  Building paths locally from ARCS/VERTICES CSVs...")
    arc_files = sorted(BASE_DIR.glob("ARCS_T*.CSV"))
    graphs    = {}

    for af in arc_files:
        window = af.stem.replace("ARCS_", "")
        df     = pd.read_csv(af, header=None)
        G      = nx.DiGraph()
        for _, row in df.iterrows():
            try:
                G.add_edge(int(row.iloc[1]), int(row.iloc[0]))  # source, target
            except (ValueError, IndexError):
                continue
        graphs[window] = G

    windows = sorted(graphs.keys())
    all_paths = []

    for i, wi in enumerate(windows):
        for wj in windows[i:]:
            combined = nx.compose(graphs[wi], graphs[wj])
            for src in combined.nodes():
                for dst in combined.nodes():
                    if src == dst:
                        continue
                    if nx.has_path(combined, src, dst):
                        try:
                            path = nx.shortest_path(combined, src, dst)
                            all_paths.append({
                                "nodesOnPath": path,
                                "relsOnPath" : [wj] * (len(path) - 1),
                            })
                        except nx.NetworkXNoPath:
                            continue

    df = pd.DataFrame(all_paths)
    print(f"  ✓ Local paths computed: {len(df)}")
    return df, windows


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    print("╔" + "=" * 58 + "╗")
    print("║" + "  Idea 3: Alert Chain Validity Validator".center(58) + "║")
    print("╚" + "=" * 58 + "╝")

    alerts_df, host_cves_map = load_data()
    alerts_df                = assign_time_windows(alerts_df)
    host_node_index          = build_host_node_index()
    mapped_df, unmapped_df   = map_alerts_to_nodes(alerts_df, host_node_index)

    if mapped_df.empty:
        print("\n✗ No alerts mapped. Check VERTICES_T*.CSV files exist.")
        return

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USER, NEO4J_PASSWORD),
        connection_timeout=300,
        max_connection_lifetime=3600,
        keep_alive=True,
    )
    try:
        paths_df, rel_types = load_temporal_paths_from_neo4j(driver)
    except Exception as e:
        print(f"\n  Neo4j error: {e}\n  Using local fallback...")
        paths_df, rel_types = fallback_local_paths()
    finally:
        driver.close()

    path_lookup = build_path_lookup(paths_df)

    if not path_lookup:
        print("\n  ⚠ Path lookup is empty after build.")
        print("    Possible causes:")
        print("    1. TAG nodes in Neo4j have no relationships")
        print("    2. create_TAG() was not called before this script")
        print("    3. APOC plugin not installed in Neo4j")
        print("    → Switching to local fallback...")
        paths_df, rel_types = fallback_local_paths()
        path_lookup = build_path_lookup(paths_df)

    results_df = classify_all_pairs(mapped_df, path_lookup)

    if results_df.empty:
        print("\n✗ No pairs classified. Check source_host overlap in alerts.")
        return

    print_report(results_df, unmapped_df, len(alerts_df))
    save_results(results_df, unmapped_df, len(alerts_df))


if __name__ == "__main__":
    main()