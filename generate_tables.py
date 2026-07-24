import os
import re

runs = [20, 30, 40, 50, 60, 70, 80, 90, 100]

table2 = []
table3 = []
table4 = []
table5 = []

for n in runs:
    with open(f"/Users/ayangain/repos/TAG-IDS/ids_outputs/run_output{n}.txt", "r") as f:
        content = f.read()
        
    # Table 2: Avg. Coverage Avg. BSR Path-Critical %
    # Extract: - Blind spots: avg_blind_spot_ratio=36.8% avg_coverage=63.2%
    bs_match = re.search(r"avg_blind_spot_ratio=([0-9.]+)%\s+avg_coverage=([0-9.]+)%", content)
    bsr = bs_match.group(1)
    cov = bs_match.group(2)
    # path-critical is 100% in all
    table2.append(f"{n} & {cov}\\% & {bsr}\\% & 100\\% \\\\")
    
    # Table 3: Pairs Valid (%) Impossible (%) Ambiguous (%)
    # Extract: - Alert chains: total_pairs=69 valid=11 impossible=49 ambiguous=9
    chain_match = re.search(r"total_pairs=(\d+)\s+valid=(\d+)\s+impossible=(\d+)\s+ambiguous=(\d+)", content)
    tp = int(chain_match.group(1))
    v = int(chain_match.group(2))
    i = int(chain_match.group(3))
    a = int(chain_match.group(4))
    v_pct = (v/tp)*100
    i_pct = (i/tp)*100
    a_pct = (a/tp)*100
    table3.append(f"{n} & {tp} & {v} ({v_pct:.1f}) & {i} ({i_pct:.1f}) & {a} ({a_pct:.1f}) \\\\")
    
    # Table 4: Best Baseline Best-BL FCR Static FCR TAG-IDS FCR
    # Extract: - Baselines: lowest-FCR=time_15min F1=0.293 FCR=70.3% MCR=0.0%
    base_match = re.search(r"lowest-FCR=([^\s]+).*?FCR=([0-9.]+)%", content)
    best_bl = base_match.group(1).replace("_", "\\_")
    best_fcr = base_match.group(2)
    # Extract: Static TAG snapshot FCR  : 71.0%
    stat_match = re.search(r"Static TAG snapshot FCR\s*:\s*([0-9.]+)%", content)
    stat_fcr = stat_match.group(1)
    table4.append(f"{n} & {best_bl} & {best_fcr}\\% & {stat_fcr}\\% & 0\\% \\\\")
    
    # Table 5: Pairs Imposs. % Best-BL FCR Static FCR STS r2 Avg. BSR
    # Extract r2
    r2_match = re.search(r"Explained Variance \(r.\): ([0-9.]+)", content)
    r2 = float(r2_match.group(1)) * 100
    table5.append(f"{n} & {tp} & {i_pct:.1f}\\% & {best_fcr}\\% & {stat_fcr}\\% & {r2:.1f}\\% & {bsr}\\% \\\\")
    
print("--- TABLE 2 ---")
print("\n".join(table2))
print("\n--- TABLE 3 ---")
print("\n".join(table3))
print("\n--- TABLE 4 ---")
print("\n".join(table4))
print("\n--- TABLE 5 ---")
print("\n".join(table5))
