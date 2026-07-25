import matplotlib.pyplot as plt
import numpy as np
import os

# ---------------------------------------------------------
# 1. Rebuild Figure 5 (Baseline FCR Comparison)
# Verified exact FCR data parsed from run_output20.txt, run_output30.txt, run_output40.txt
# ---------------------------------------------------------
fcr_data = {
    'sev_CRITICAL': (100.0 + 50.0 + 75.0) / 3.0,     # 75.0%
    'sev_MEDIUM':   (73.0 + 44.8 + 66.7) / 3.0,     # 61.5%
    'sev_HIGH':     (70.7 + 43.9 + 65.4) / 3.0,     # 60.0%
    'time_60min':   (71.6 + 44.7 + 62.1) / 3.0,     # 59.5%
    'sev_LOW':      (71.0 + 44.9 + 61.7) / 3.0,     # 59.2%
    'time_120min':  (71.6 + 44.9 + 61.0) / 3.0,     # 59.2%
    'Static Snapshot': (71.0 + 43.4 + 61.7) / 3.0,  # 58.7%
    'time_30min':   (70.3 + 42.3 + 61.5) / 3.0,     # 58.0%
    'time_15min':   (70.3 + 42.3 + 61.5) / 3.0,     # 58.0%
}

# Sort baselines by FCR descending
sorted_items = sorted(fcr_data.items(), key=lambda x: x[1])
labels = [item[0] for item in sorted_items]
values = [item[1] for item in sorted_items]

# Add TAG-IDS at the bottom
labels = ['TAG-IDS (Oracle)'] + labels
values = [0.0] + values

plt.figure(figsize=(8, 5.5), dpi=300)

# Colors: Coral/Red for baselines, SteelBlue with distinct hatch for TAG-IDS
colors = ['#1f77b4'] + ['#e74c3c'] * (len(labels) - 1)

bars = plt.barh(labels, values, color=colors, edgecolor='black', linewidth=0.8)
for i, bar in enumerate(bars):
    if i == 0:
        bar.set_hatch('///')
        plt.text(1.5, bar.get_y() + bar.get_height()/2.0, '0.0% (by construction)', 
                 va='center', ha='left', fontweight='bold', color='#1f77b4', fontsize=10)
    else:
        val = values[i]
        plt.text(val + 1.0, bar.get_y() + bar.get_height()/2.0, f'{val:.1f}%', 
                 va='center', ha='left', fontsize=9.5)

plt.xlabel('Mean False Correlation Rate (FCR %)', fontsize=11, fontweight='bold')
plt.ylabel('Correlation Baseline', fontsize=11, fontweight='bold')
plt.xlim(0, 88)
plt.title('Baseline False Correlation Rate (Mean across n=20, 30, 40)', fontsize=12, fontweight='bold', pad=12)
plt.grid(axis='x', linestyle='--', alpha=0.5)
plt.tight_layout()

os.makedirs('Figures', exist_ok=True)
plt.savefig('Figures/fig5_fcr_comparison.png', dpi=300)
plt.close()
print("Figure 5 successfully rebuilt with exact, verified mean FCR numbers!")

# ---------------------------------------------------------
# 2. Rebuild Figure 4 (BSR Trend across Windows)
# Exact per-window BSR% parsed from run_output20.txt, run_output30.txt, run_output40.txt
# ---------------------------------------------------------
windows = ['T1', 'T2', 'T3', 'T4']
bsr_20 = [37.5, 33.3, 42.9, 33.3]
bsr_30 = [35.7, 30.0, 33.3, 36.4]
bsr_40 = [38.9, 37.5, 44.4, 45.0]

plt.figure(figsize=(6.5, 4.5), dpi=300)
plt.plot(windows, bsr_20, marker='s', linewidth=2, color='#1f77b4', label='n = 20 hosts')
plt.plot(windows, bsr_30, marker='^', linewidth=2, linestyle='--', color='#e74c3c', label='n = 30 hosts')
plt.plot(windows, bsr_40, marker='D', linewidth=2, linestyle='-.', color='#2ca02c', label='n = 40 hosts')

plt.xlabel('Observation Window', fontsize=11, fontweight='bold')
plt.ylabel('Blind Spot Ratio (BSR %)', fontsize=11, fontweight='bold')
plt.ylim(25, 50)
plt.title('Temporal Variation of Blind Spot Ratio across Windows', fontsize=11, fontweight='bold', pad=10)
plt.legend(frameon=True, loc='upper left')
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()

plt.savefig('Figures/fig4_bsr_trend.png', dpi=300)
plt.close()
print("Figure 4 successfully rebuilt with exact empirical per-window BSR values!")
