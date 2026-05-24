"""
Idea 2: Temporal Blind Spot Quantification
===========================================
Formally measures what fraction of a Temporal Attack Graph is
structurally invisible to an IDS across time windows.

Three blind spot classes:
  STATIC BLIND SPOT   : node exists in TAG window but receives zero
                        IDS alert coverage in that window
  PATH-CRITICAL       : static blind spot that sits on at least one
                        valid temporal attack path — most dangerous
  DYNAMIC BLIND SPOT  : node that transitions between monitored and
                        unmonitored state across consecutive windows
                        (monitored in T_i, unmonitored in T_{i+1},
                         or vice versa)

Depends on:
  - ids_outputs/ids_alerts.csv
  - ids_outputs/host_cves_mapping.json
  - VERTICES_T*.CSV  and  ARCS_T*.CSV
  - Running Neo4j with TAG loaded  (used for path-critical check)
    Falls back to local NetworkX if Neo4j unavailable.

Outputs:
  - ids_outputs/blind_spot_per_window.csv   per-window summary
  - ids_outputs/blind_spot_nodes.csv        every blind spot node
  - ids_outputs/dynamic_blind_spots.csv     nodes that churn
"""

import re
import json
import math
import warnings
from pathlib import Path
from collections import defaultdict

import pandas as pd
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

OUT_WINDOW  = IDS_OUTPUT_DIR / "blind_spot_per_window.csv"
OUT_NODES   = IDS_OUTPUT_DIR / "blind_spot_nodes.csv"
OUT_DYNAMIC = IDS_OUTPUT_DIR / "dynamic_blind_spots.csv"


# ─────────────────────────────────────────────────────────────────
# STEP 1 — Load alerts and recover time windows
# ─────────────────────────────────────────────────────────────────
def load_alerts():
    print("\n[1/6] Loading IDS alerts...")
    df = pd.read_csv(ALERTS_CSV, parse_dates=["timestamp"])

    base_time = df["timestamp"].min()
    df["hour_offset"] = (
        (df["timestamp"] - base_time)
        .dt.total_seconds()
        .div(3600)
        .apply(math.floor)
    )
    sorted_offsets   = sorted(df["hour_offset"].unique())
    offset_to_window = {off: f"T{i+1}" for i, off in enumerate(sorted_offsets)}
    df["time_window"] = df["hour_offset"].map(offset_to_window)

    print(f"  ✓ Alerts loaded       : {len(df)}")
    print(f"  ✓ Windows recovered   : {sorted(df['time_window'].unique())}")
    return df


# ─────────────────────────────────────────────────────────────────
# STEP 2 — Build TAG node registry per window
#          Returns: window → { node_id → host }
# ─────────────────────────────────────────────────────────────────
def build_tag_registry():
    print("\n[2/6] Building TAG node registry per window...")
    registry   = {}   # window → {node_id: host}
    host_index = {}   # (host, window) → node_id  (reused from validator)

    vertex_files = sorted(BASE_DIR.glob("VERTICES_T*.CSV"))
    if not vertex_files:
        raise FileNotFoundError("No VERTICES_T*.CSV found. Run Cell 1 first.")

    for vf in vertex_files:
        window = vf.stem.replace("VERTICES_", "")
        df     = pd.read_csv(vf, header=None,
                             names=["node_id", "label", "type", "value"])
        registry[window] = {}
        for _, row in df.iterrows():
            nid   = int(row["node_id"])
            hosts = re.findall(r"\b(h\d+)\b", str(row["label"]))
            host  = hosts[0] if hosts else None
            registry[window][nid] = host
            if host:
                host_index[(host, window)] = nid

    all_windows = sorted(registry.keys())
    for w in all_windows:
        print(f"  ✓ {w}: {len(registry[w])} nodes")

    return registry, host_index, all_windows


# ─────────────────────────────────────────────────────────────────
# STEP 3 — Compute alerted node sets per window
#          A node is "alerted" if at least one IDS alert targets
#          the host mapped to that node in that window.
# ─────────────────────────────────────────────────────────────────
def compute_alerted_nodes(alerts_df, host_index, all_windows):
    print("\n[3/6] Computing alerted node sets per window...")

    alerted = {w: set() for w in all_windows}

    for _, row in alerts_df.iterrows():
        dest   = row["dest_host"]
        window = row["time_window"]
        nid    = host_index.get((dest, window))

        if nid is None:
            # try adjacent windows
            tw_num = int(re.sub(r"\D", "", window)) if window else 0
            for delta in [1, -1, 2, -2]:
                fb = host_index.get((dest, f"T{tw_num + delta}"))
                if fb is not None:
                    # counts toward the window the node actually belongs to
                    for w in all_windows:
                        if host_index.get((dest, w)) == fb:
                            alerted[w].add(fb)
                    break
        else:
            if window in alerted:
                alerted[window].add(nid)

    for w in all_windows:
        print(f"  ✓ {w}: {len(alerted[w])} alerted nodes")

    return alerted


# ─────────────────────────────────────────────────────────────────
# STEP 4 — Load temporal paths (Neo4j or local fallback)
#          Returns set of (src_node_id, dst_node_id) on any valid path
#          AND set of node_ids that sit on at least one valid path
# ─────────────────────────────────────────────────────────────────
def load_path_nodes(all_windows):
    print("\n[4/6] Loading temporal paths for path-critical check...")

    path_nodes  = set()   # node_ids on at least one valid temporal path
    path_edges  = set()   # (src, dst) pairs

    try:
        driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD),
            connection_timeout=60,
        )
        with driver.session() as session:
            rel_types = session.run(
                "MATCH ()-[r]->() RETURN DISTINCT type(r) AS relType "
                "ORDER BY relType"
            ).value()

            if not rel_types:
                raise RuntimeError("No relationships in Neo4j.")

            direction = "|".join(f"{rt}>" for rt in sorted(rel_types))
            query = (
                "MATCH (a:TAG) "
                "CALL apoc.path.expandConfig(a, {"
                "  relationshipFilter: '" + direction + "', "
                "  labelFilter: 'TAG', minLevel: 1 "
                "}) YIELD path "
                "WITH [node IN nodes(path) | node.name] AS nodesOnPath, "
                "     [rel  IN relationships(path) | type(rel)] AS relsOnPath "
                "WHERE size(nodesOnPath) >= 2 "
                "  AND all(i IN range(0, size(relsOnPath)-2) "
                "          WHERE relsOnPath[i] <= relsOnPath[i+1]) "
                "RETURN nodesOnPath, relsOnPath"
            )
            result = session.run(query).to_df()
        driver.close()

        for _, row in result.iterrows():
            nodes = row["nodesOnPath"]
            for n in nodes:
                try:
                    path_nodes.add(int(n))
                except (ValueError, TypeError):
                    pass
            for i in range(len(nodes) - 1):
                try:
                    path_edges.add((int(nodes[i]), int(nodes[i + 1])))
                except (ValueError, TypeError):
                    pass

        print(f"  ✓ Source           : Neo4j")
        print(f"  ✓ Path nodes found : {len(path_nodes)}")

    except Exception as e:
        print(f"  ⚠ Neo4j unavailable ({e}), using local fallback...")
        path_nodes, path_edges = _local_path_nodes(all_windows)

    return path_nodes, path_edges


def _local_path_nodes(all_windows):
    """Fallback: build paths from ARCS CSVs via NetworkX."""
    graphs = {}
    for w in all_windows:
        af = BASE_DIR / f"ARCS_{w}.CSV"
        if not af.exists():
            continue
        df = pd.read_csv(af, header=None)
        G  = nx.DiGraph()
        for _, row in df.iterrows():
            try:
                G.add_edge(int(row.iloc[1]), int(row.iloc[0]))
            except (ValueError, IndexError):
                continue
        graphs[w] = G

    combined   = nx.compose_all(list(graphs.values())) if graphs else nx.DiGraph()
    path_nodes = set()
    path_edges = set()

    nodes = list(combined.nodes())
    for src in nodes:
        for dst in nodes:
            if src == dst:
                continue
            if nx.has_path(combined, src, dst):
                try:
                    path = nx.shortest_path(combined, src, dst)
                    path_nodes.update(path)
                    for i in range(len(path) - 1):
                        path_edges.add((path[i], path[i + 1]))
                except nx.NetworkXNoPath:
                    continue

    print(f"  ✓ Source           : local NetworkX fallback")
    print(f"  ✓ Path nodes found : {len(path_nodes)}")
    return path_nodes, path_edges


# ─────────────────────────────────────────────────────────────────
# STEP 5 — Classify every node in every window
# ─────────────────────────────────────────────────────────────────
MONITORED        = "MONITORED"
STATIC_BLIND     = "STATIC_BLIND_SPOT"
PATH_CRITICAL    = "PATH_CRITICAL_BLIND_SPOT"


def classify_nodes(registry, alerted, path_nodes, all_windows):
    print("\n[5/6] Classifying nodes per window...")

    node_records = []   # one row per (window, node)

    for w in all_windows:
        for nid, host in registry[w].items():
            is_alerted      = nid in alerted[w]
            is_on_path      = nid in path_nodes

            if is_alerted:
                status = MONITORED
            elif is_on_path:
                status = PATH_CRITICAL
            else:
                status = STATIC_BLIND

            node_records.append({
                "window"         : w,
                "node_id"        : nid,
                "host"           : host,
                "alerted"        : is_alerted,
                "on_valid_path"  : is_on_path,
                "status"         : status,
            })

    nodes_df = pd.DataFrame(node_records)

    for w in all_windows:
        wdf = nodes_df[nodes_df["window"] == w]
        print(f"  {w}: total={len(wdf)}  "
              f"monitored={( wdf['status']==MONITORED).sum()}  "
              f"static_blind={(wdf['status']==STATIC_BLIND).sum()}  "
              f"path_critical={(wdf['status']==PATH_CRITICAL).sum()}")

    return nodes_df


# ─────────────────────────────────────────────────────────────────
# STEP 6 — Compute per-window summary and dynamic blind spots
# ─────────────────────────────────────────────────────────────────
def compute_window_summary(nodes_df, all_windows):
    rows = []
    for w in all_windows:
        wdf   = nodes_df[nodes_df["window"] == w]
        total = len(wdf)
        mon   = (wdf["status"] == MONITORED).sum()
        sb    = (wdf["status"] == STATIC_BLIND).sum()
        pc    = (wdf["status"] == PATH_CRITICAL).sum()

        rows.append({
            "window"                    : w,
            "total_nodes"               : total,
            "monitored"                 : int(mon),
            "static_blind_spots"        : int(sb),
            "path_critical_blind_spots" : int(pc),
            "total_blind_spots"         : int(sb + pc),
            "blind_spot_ratio_pct"      : round(100 * (sb + pc) / total, 1) if total else 0,
            "path_critical_ratio_pct"   : round(100 * pc / total, 1) if total else 0,
            "coverage_pct"              : round(100 * mon / total, 1) if total else 0,
        })

    return pd.DataFrame(rows)


def compute_dynamic_blind_spots(nodes_df, all_windows):
    """
    A dynamic blind spot is a host that transitions between
    MONITORED and any blind spot status across consecutive windows.

    Types:
      EMERGED   : was monitored in T_i, became blind spot in T_{i+1}
      RESOLVED  : was blind spot in T_i, became monitored in T_{i+1}
      PERSISTED : blind spot in both T_i and T_{i+1}
      ESCALATED : static blind spot → path-critical blind spot
      DE-ESCALATED: path-critical → static blind spot
    """
    # pivot: host → window → status
    pivot = nodes_df.pivot_table(
        index="host", columns="window", values="status", aggfunc="first"
    )

    dynamic_records = []

    for i in range(len(all_windows) - 1):
        w_prev = all_windows[i]
        w_next = all_windows[i + 1]

        if w_prev not in pivot.columns or w_next not in pivot.columns:
            continue

        for host in pivot.index:
            s_prev = pivot.loc[host, w_prev] if host in pivot.index else None
            s_next = pivot.loc[host, w_next] if host in pivot.index else None

            if pd.isna(s_prev) or pd.isna(s_next):
                continue

            transition = None

            if s_prev == MONITORED and s_next in (STATIC_BLIND, PATH_CRITICAL):
                transition = "EMERGED"
            elif s_prev in (STATIC_BLIND, PATH_CRITICAL) and s_next == MONITORED:
                transition = "RESOLVED"
            elif s_prev == STATIC_BLIND and s_next == PATH_CRITICAL:
                transition = "ESCALATED"
            elif s_prev == PATH_CRITICAL and s_next == STATIC_BLIND:
                transition = "DE-ESCALATED"
            elif s_prev in (STATIC_BLIND, PATH_CRITICAL) and s_next in (STATIC_BLIND, PATH_CRITICAL):
                transition = "PERSISTED"

            if transition:
                dynamic_records.append({
                    "host"           : host,
                    "from_window"    : w_prev,
                    "to_window"      : w_next,
                    "from_status"    : s_prev,
                    "to_status"      : s_next,
                    "transition_type": transition,
                })

    return pd.DataFrame(dynamic_records)


# ─────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────
def print_report(window_summary, dynamic_df, nodes_df, all_windows):
    print("\n" + "=" * 65)
    print("  TEMPORAL BLIND SPOT QUANTIFICATION REPORT")
    print("=" * 65)

    # per-window table
    print(f"\n  {'Window':<8} {'Total':>6} {'Monitored':>10} "
          f"{'Static BS':>10} {'Path-Critical':>14} {'BS Ratio%':>10} {'Coverage%':>10}")
    print("  " + "-" * 63)
    for _, row in window_summary.iterrows():
        print(
            f"  {row['window']:<8} "
            f"{row['total_nodes']:>6} "
            f"{row['monitored']:>10} "
            f"{row['static_blind_spots']:>10} "
            f"{row['path_critical_blind_spots']:>14} "
            f"{row['blind_spot_ratio_pct']:>9.1f}% "
            f"{row['coverage_pct']:>9.1f}%"
        )

    # aggregate
    total_node_windows = len(nodes_df)
    total_blind        = (nodes_df["status"] != MONITORED).sum()
    total_pc           = (nodes_df["status"] == PATH_CRITICAL).sum()

    print(f"\n  Aggregate across all windows:")
    print(f"    Total node-window instances   : {total_node_windows}")
    print(f"    Blind spot instances          : {total_blind} "
          f"({round(100*total_blind/total_node_windows,1)}%)")
    print(f"    Path-critical blind spots     : {total_pc} "
          f"({round(100*total_pc/total_node_windows,1)}%)")

    # dynamic
    if not dynamic_df.empty:
        print(f"\n  Dynamic Blind Spot Transitions:")
        tc = dynamic_df["transition_type"].value_counts()
        for t, c in tc.items():
            print(f"    {t:<20}: {c}")

        emerged   = (dynamic_df["transition_type"] == "EMERGED").sum()
        resolved  = (dynamic_df["transition_type"] == "RESOLVED").sum()
        escalated = (dynamic_df["transition_type"] == "ESCALATED").sum()
        print(f"\n  Hosts that became blind spots   : {emerged}")
        print(f"  Hosts that recovered monitoring : {resolved}")
        print(f"  Blind spots that escalated      : {escalated}")

        # most dangerous: escalated to path-critical
        esc_df = dynamic_df[dynamic_df["transition_type"] == "ESCALATED"]
        if not esc_df.empty:
            print(f"\n  Escalated hosts (most dangerous):")
            for _, r in esc_df.iterrows():
                print(f"    {r['host']}  {r['from_window']}→{r['to_window']}")

    print("=" * 65)


def print_key_findings(window_summary, dynamic_df, nodes_df):
    avg_bs   = window_summary["blind_spot_ratio_pct"].mean()
    max_bs   = window_summary["blind_spot_ratio_pct"].max()
    max_w    = window_summary.loc[window_summary["blind_spot_ratio_pct"].idxmax(), "window"]
    avg_cov  = window_summary["coverage_pct"].mean()
    total_pc = (nodes_df["status"] == PATH_CRITICAL).sum()
    emerged  = (dynamic_df["transition_type"] == "EMERGED").sum() if not dynamic_df.empty else 0

    print("\n" + "=" * 65)
    print("  KEY FINDINGS FOR PAPER")
    print("=" * 65)
    print(f"\n  1. Average blind spot ratio across windows : {avg_bs:.1f}%")
    print(f"     Peak blind spot ratio                  : {max_bs:.1f}% ({max_w})")
    print(f"     Average IDS coverage                   : {avg_cov:.1f}%")
    print(f"\n  2. Path-critical blind spots (on attack paths): {total_pc}")
    print(f"     These are invisible to IDS but exploitable")
    print(f"\n  3. Dynamic blind spot emergences           : {emerged}")
    print(f"     Nodes monitored in one window but blind")
    print(f"     in the next — unique to temporal analysis")
    print(f"\n  → Static IDS tools cannot detect items 2 or 3")
    print(f"    because they have no temporal graph model.")
    print("=" * 65)


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    print("╔" + "=" * 58 + "╗")
    print("║" + "  Idea 2: Temporal Blind Spot Quantification".center(58) + "║")
    print("╚" + "=" * 58 + "╝")

    alerts_df                         = load_alerts()
    registry, host_index, all_windows = build_tag_registry()
    alerted                           = compute_alerted_nodes(alerts_df, host_index, all_windows)
    path_nodes, _                     = load_path_nodes(all_windows)
    nodes_df                          = classify_nodes(registry, alerted, path_nodes, all_windows)

    print("\n[6/6] Computing summaries and dynamic transitions...")
    window_summary = compute_window_summary(nodes_df, all_windows)
    dynamic_df     = compute_dynamic_blind_spots(nodes_df, all_windows)

    # save
    window_summary.to_csv(OUT_WINDOW,  index=False)
    nodes_df.to_csv(OUT_NODES,         index=False)
    dynamic_df.to_csv(OUT_DYNAMIC,     index=False)
    print(f"  ✓ Per-window summary  : {OUT_WINDOW}")
    print(f"  ✓ Node-level detail   : {OUT_NODES}")
    print(f"  ✓ Dynamic transitions : {OUT_DYNAMIC}")

    print_report(window_summary, dynamic_df, nodes_df, all_windows)
    print_key_findings(window_summary, dynamic_df, nodes_df)


if __name__ == "__main__":
    main()