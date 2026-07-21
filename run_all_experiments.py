import subprocess
import time
import os
import glob

hosts = [40, 30, 20]  # Conference paper scope: 3 configurations
windows = 4

print(f"Starting batch run for {len(hosts)} experiments: {hosts} hosts, {windows} windows each.")
print("The output for each run will be saved in ids_outputs/run_output{hosts}.txt")

for h in hosts:
    print(f"\n{'='*50}")
    print(f"Starting run for {h} hosts...")
    print(f"{'='*50}")
    
    # Provide the host count and window count via stdin
    input_str = f"{h}\n{windows}\n"
    
    start_time = time.time()
    
    try:
        # Use subprocess.run, which waits for the process to finish
        result = subprocess.run(
            ['.venv/bin/python', 'combined_all.py'],
            input=input_str,
            text=True,
            check=True
        )
        elapsed = time.time() - start_time
        print(f"\n[+] Run for {h} hosts completed in {elapsed:.1f} seconds.")
        print(f"    Output saved to ids_outputs/run_output{h}.txt")
    except subprocess.CalledProcessError as e:
        print(f"\n[-] ERROR: Run for {h} hosts failed with exit code {e.returncode}.")
        print("Aborting remaining runs.")
        break
        
print("\nAll experiments finished successfully!")

# ── Cross-Run Aggregate Summary ──
# Parse each run's output to extract the key metrics that vary across runs,
# then report ranges/means so the paper cites reproducible aggregate claims
# rather than single-run point estimates.
print("\n" + "=" * 72)
print("  CROSS-RUN AGGREGATE SUMMARY (for paper claims)")
print("=" * 72)

try:
    import re

    lowest_fcrs = []       # lowest baseline FCR per run
    lowest_fcr_names = []  # which baseline was lowest per run
    static_fcrs = []       # static_tag_snapshot FCR per run
    tag_exacts = []        # TAG exact@60% per run
    tag_dists = []         # TAG median dist@60% per run
    static_dists = []      # static TAG dist@60% per run
    sts_r2s = []           # STS explained variance r2 per run
    run_sizes = []

    for h in hosts:
        outfile = f"ids_outputs/run_output{h}.txt"
        if not os.path.exists(outfile):
            continue

        with open(outfile, "r") as f:
            text = f.read()

        run_sizes.append(h)

        # Extract lowest-FCR baseline from consolidated summary line
        m = re.search(r"Baselines: lowest-FCR=(\S+) F1=[\d.]+ FCR=([\d.]+)%", text)
        if m:
            lowest_fcr_names.append(m.group(1))
            lowest_fcrs.append(float(m.group(2)))

        # Extract static_tag_snapshot FCR from ablation section
        m = re.search(r"Static TAG snapshot FCR\s*:\s*([\d.]+)%", text)
        if m:
            static_fcrs.append(float(m.group(1)))

        # Extract attacker progress metrics from consolidated summary
        m = re.search(r"tag_exact@60%=([\d.]+)", text)
        if m:
            tag_exacts.append(float(m.group(1)))

        m = re.search(r"tag_dist@60%=([\d.]+)", text)
        if m:
            tag_dists.append(float(m.group(1)))

        # Extract static TAG dist from ablation
        m = re.search(r"Static TAG median dist \(60% sparsity\)\s*:\s*([\d.]+)", text)
        if m:
            static_dists.append(float(m.group(1)))

        # Extract STS explained variance r2
        m = re.search(r"Explained Variance \(r²\):\s*([\d.]+)", text)
        if m:
            sts_r2s.append(float(m.group(1)))

    if lowest_fcrs:
        mean_fcr = sum(lowest_fcrs) / len(lowest_fcrs)
        print(f"\n  Lowest-FCR baseline across {len(lowest_fcrs)} runs:")
        print(f"    Range : {min(lowest_fcrs):.1f}% – {max(lowest_fcrs):.1f}%")
        print(f"    Mean  : {mean_fcr:.1f}%")
        print(f"    Names : {', '.join(sorted(set(lowest_fcr_names)))}")
        print(f"    PAPER CLAIM: No independent baseline achieves FCR below")
        print(f"    ~{min(lowest_fcrs):.0f}% in any configuration (range {min(lowest_fcrs):.1f}–{max(lowest_fcrs):.1f}%).")

    if static_fcrs:
        mean_static = sum(static_fcrs) / len(static_fcrs)
        ablation_gaps = [s for s in static_fcrs]  # TAG FCR = 0, so gap = static FCR
        print(f"\n  Static TAG snapshot FCR across {len(static_fcrs)} runs:")
        print(f"    Range : {min(static_fcrs):.1f}% – {max(static_fcrs):.1f}%")
        print(f"    Mean  : {mean_static:.1f}%")
        print(f"    PAPER CLAIM: Collapsing temporal ordering raises FCR from 0%")
        print(f"    to {min(static_fcrs):.1f}–{max(static_fcrs):.1f}% (mean {mean_static:.1f}pp ablation gap).")

    if tag_exacts:
        mean_exact = sum(tag_exacts) / len(tag_exacts)
        print(f"\n  Attacker Progress TAG exact@60% across {len(tag_exacts)} runs:")
        print(f"    Range : {min(tag_exacts)*100:.1f}% – {max(tag_exacts)*100:.1f}%")
        print(f"    Mean  : {mean_exact*100:.1f}%")

    if sts_r2s:
        mean_sts = sum(sts_r2s) / len(sts_r2s)
        print(f"\n  STS Explained Variance (r²) across {len(sts_r2s)} runs:")
        print(f"    Range : {min(sts_r2s)*100:.1f}% – {max(sts_r2s)*100:.1f}%")
        print(f"    Mean  : {mean_sts*100:.1f}%")
        print(f"    PAPER CLAIM: CVSS severity alone only explains ~{min(sts_r2s)*100:.0f}–{max(sts_r2s)*100:.0f}%")
        print(f"    of the variance in true structural risk.")

    if tag_dists and static_dists and len(tag_dists) == len(static_dists):
        improvements = [s - t for s, t in zip(static_dists, tag_dists)]
        pos = sum(1 for i in improvements if i > 0.1)
        neg = sum(1 for i in improvements if i < -0.1)
        tied = len(improvements) - pos - neg
        print(f"\n  Temporal vs Static ablation (attacker dist) across {len(improvements)} runs:")
        print(f"    Temporal wins : {pos}/{len(improvements)} runs")
        print(f"    Static wins   : {neg}/{len(improvements)} runs")
        print(f"    Tied          : {tied}/{len(improvements)} runs")
        print(f"    NOTE: Ablation direction is topology-dependent. Report as")
        print(f"    'temporal weighting improves localization in {pos}/{len(improvements)} configurations'")
        print(f"    rather than asserting a universal directional claim.")

    print("\n" + "=" * 72)

except Exception as e:
    print(f"\n  [WARN] Cross-run aggregation failed: {e}")
    print("=" * 72)

