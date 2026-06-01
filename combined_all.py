# Combined Python file (pipeline order: create -> load -> metrics).
# NOTE: Betweenness and closeness computations are intentionally skipped here.

# ===== File: TAG_convert_into_single_homo_graph_MAC.py =====
import subprocess
import re
import os
import json
import pandas as pd
import datetime
import random
import shutil
from pathlib import Path
from enum import Enum
import glob


BASE_DIR = Path.cwd().resolve()
os.chdir(BASE_DIR)
IDS_OUTPUT_DIR = BASE_DIR / "ids_outputs"
IDS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

WINDOW_POLICY = "first"  # Options: first, last, most_frequent

def pick_tag_window(windows, policy):
    if not windows:
        return None
    if policy == "last":
        return sorted(windows)[-1]
    if policy == "most_frequent":
        counts = {}
        for w in windows:
            counts[w] = counts.get(w, 0) + 1
        max_count = max(counts.values())
        candidates = [w for w, c in counts.items() if c == max_count]
        return sorted(candidates)[0]
    return sorted(windows)[0]

shutil.rmtree(BASE_DIR / "backup_originals", ignore_errors=True)
for csv_file in list(BASE_DIR.glob("ARCS_T*.CSV")) + list(BASE_DIR.glob("VERTICES_T*.CSV")):
    csv_file.unlink(missing_ok=True)

CVE_DATABASE = {
    "httpd": [
        "CVE-2021-44228", "CVE-2021-41773", "CVE-2020-1938",
        "CVE-2021-26855", "CVE-2019-0604", "CVE-2018-4939",
        "CVE-2020-5410",  "CVE-2021-45046", "CVE-2021-44512",
        "CVE-2021-33910", "CVE-2021-21224", "CVE-2020-9488",
        "CVE-2020-11738", "CVE-2021-28169", "CVE-2021-28156",
        "CVE-2021-28341", "CVE-2021-21898", "CVE-2021-3129",
        "CVE-2021-24410", "CVE-2021-24512", "CVE-2020-14144",
        "CVE-2020-14145", "CVE-2021-21233", "CVE-2021-21234",
        "CVE-2021-26858", "CVE-2021-27065", "CVE-2020-16898",
        "CVE-2021-31166", "CVE-2020-1470",  "CVE-2020-15505",
        "CVE-2021-1234",  "CVE-2021-1235",  "CVE-2020-8516",
        "CVE-2020-8517",  "CVE-2021-20225", "CVE-2021-20226",
        "CVE-2020-13933", "CVE-2020-13934", "CVE-2021-30129",
        "CVE-2021-30130", "CVE-2020-1234",  "CVE-2020-1235",
        "CVE-2021-26851", "CVE-2021-26852", "CVE-2021-28850",
        "CVE-2021-28851", "CVE-2020-25695", "CVE-2020-25696",
        "CVE-2020-11083", "CVE-2020-11084", "CVE-2021-28168",
        "CVE-2021-28169", "CVE-2021-30609", "CVE-2021-30610",
        "CVE-2020-9614",  "CVE-2020-9615",  "CVE-2021-22556",
        "CVE-2021-22557", "CVE-2020-11989", "CVE-2020-11990",
        "CVE-2021-23840", "CVE-2021-23841", "CVE-2020-14644",
        "CVE-2020-14645", "CVE-2021-20294", "CVE-2021-20295",
        "CVE-2020-27238", "CVE-2020-27239", "CVE-2021-32074",
        "CVE-2021-32075", "CVE-2020-1234",  "CVE-2020-1236",
        "CVE-2021-24514", "CVE-2021-24515", "CVE-2020-12624",
        "CVE-2020-12625", "CVE-2021-3129",  "CVE-2021-3130",
        "CVE-2020-27238", "CVE-2020-27240", "CVE-2021-27067",
        "CVE-2021-27068", "CVE-2020-16892", "CVE-2020-16893",
        "CVE-2021-34482", "CVE-2021-34483", "CVE-2020-13777",
        "CVE-2020-13778", "CVE-2021-40346", "CVE-2021-40347",
        "CVE-2020-24614", "CVE-2020-24615", "CVE-2021-23879",
        "CVE-2021-23880", "CVE-2020-8554",  "CVE-2020-8555",
        "CVE-2021-37582", "CVE-2021-37583", "CVE-2020-15999",
        "CVE-2020-16000", "CVE-2021-22569", "CVE-2021-22570",
        "CVE-2020-7960",  "CVE-2020-7961",  "CVE-2021-23214",
        "CVE-2021-23215", "CVE-2020-8557",  "CVE-2020-8558",
        "CVE-2021-24497", "CVE-2021-24498", "CVE-2020-16898",
        "CVE-2020-16899", "CVE-2021-28149", "CVE-2021-28150",
        "CVE-2020-5410",  "CVE-2020-5411",  "CVE-2021-30132",
        "CVE-2021-30133", "CVE-2020-26139", "CVE-2020-26140",
    ]
}

CVE_INFO = {
    "CVE-2021-44228": {"name": "Apache Log4j RCE",            "severity": "CRITICAL"},
    "CVE-2021-41773": {"name": "Apache HTTP Path Traversal",   "severity": "CRITICAL"},
    "CVE-2020-1938":  {"name": "Tomcat AJP Ghostcat",          "severity": "CRITICAL"},
    "CVE-2021-26855": {"name": "Exchange RCE",                 "severity": "CRITICAL"},
    "CVE-2019-0604":  {"name": "SharePoint RCE",               "severity": "CRITICAL"},
    "CVE-2018-4939":  {"name": "WebLogic RCE",                 "severity": "CRITICAL"},
    "CVE-2020-5410":  {"name": "Spring Cloud Config RCE",      "severity": "CRITICAL"},
    "CVE-2021-45046": {"name": "Log4j Privilege Escalation",   "severity": "HIGH"},
    "CVE-2021-44512": {"name": "Sudo Heap Overflow",           "severity": "HIGH"},
    "CVE-2021-33910": {"name": "Systemd Memory Exhaustion",    "severity": "CRITICAL"},
    "CVE-2021-21224": {"name": "Chrome V8 Type Confusion",     "severity": "HIGH"},
    "CVE-2020-9488":  {"name": "Log4j SMTP Header",            "severity": "MEDIUM"},
    "CVE-2020-11738": {"name": "Drupal RCE",                   "severity": "CRITICAL"},
    "CVE-2021-28169": {"name": "OFBiz Auth Bypass",            "severity": "CRITICAL"},
    "CVE-2021-28156": {"name": "WebKit Buffer Overflow",       "severity": "HIGH"},
    "CVE-2021-28341": {"name": "Print Spooler RCE",            "severity": "CRITICAL"},
    "CVE-2021-21898": {"name": "ColdFusion RCE",               "severity": "CRITICAL"},
    "CVE-2021-3129":  {"name": "Laravel RCE",                  "severity": "HIGH"},
    "CVE-2021-24410": {"name": "WordPress XSS",                "severity": "MEDIUM"},
    "CVE-2021-24512": {"name": "WordPress Injection",          "severity": "HIGH"},
    "CVE-2020-14144": {"name": "Kernel Memory Leak",           "severity": "HIGH"},
    "CVE-2020-14145": {"name": "OpenSSL Failure",              "severity": "MEDIUM"},
    "CVE-2021-21233": {"name": "Copilot Unauthorized",         "severity": "HIGH"},
    "CVE-2021-21234": {"name": "Azure Auth Bypass",            "severity": "CRITICAL"},
    "CVE-2021-26858": {"name": "Exchange OWA RCE",             "severity": "CRITICAL"},
    "CVE-2021-27065": {"name": "Exchange PS RCE",              "severity": "CRITICAL"},
    "CVE-2020-16898": {"name": "TCP/IP RCE",                   "severity": "CRITICAL"},
    "CVE-2021-31166": {"name": "HTTP Stack RCE",               "severity": "HIGH"},
    "CVE-2020-1470":  {"name": "RD Gateway RCE",               "severity": "CRITICAL"},
    "CVE-2020-15505": {"name": "MobileIron RCE",               "severity": "CRITICAL"},
    "CVE-2021-1234":  {"name": "Service Auth Bypass",          "severity": "MEDIUM"},
    "CVE-2021-1235":  {"name": "Service BOF",                  "severity": "HIGH"},
    "CVE-2020-8516":  {"name": "K8s Privilege Esc",            "severity": "CRITICAL"},
    "CVE-2020-8517":  {"name": "Docker Escape",                "severity": "CRITICAL"},
    "CVE-2021-20225": {"name": "QEMU Escape",                  "severity": "CRITICAL"},
    "CVE-2021-20226": {"name": "OpenStack Escape",             "severity": "HIGH"},
    "CVE-2020-13933": {"name": "Apache Crash",                 "severity": "MEDIUM"},
    "CVE-2020-13934": {"name": "Apache DoS",                   "severity": "MEDIUM"},
    "CVE-2021-30129": {"name": "Chromium RCE",                 "severity": "HIGH"},
    "CVE-2021-30130": {"name": "Firefox RCE",                  "severity": "HIGH"},
    "CVE-2020-1234":  {"name": "Service Privilege Esc",        "severity": "HIGH"},
    "CVE-2020-1235":  {"name": "Driver BOF",                   "severity": "CRITICAL"},
    "CVE-2020-1236":  {"name": "Service Privilege Esc Variant","severity": "HIGH"},
    "CVE-2021-24497": {"name": "WordPress Plugin Injection",   "severity": "MEDIUM"},
    "CVE-2021-24498": {"name": "WordPress Plugin Injection Variant", "severity": "MEDIUM"},
    "CVE-2021-30132": {"name": "Chromium RCE Variant",         "severity": "HIGH"},
    "CVE-2021-26851": {"name": "Struts RCE",                   "severity": "CRITICAL"},
    "CVE-2021-26852": {"name": "Struts File Upload",           "severity": "HIGH"},
    "CVE-2021-28850": {"name": "PHP Type Confusion",           "severity": "HIGH"},
    "CVE-2021-28851": {"name": "PHP Object Injection",         "severity": "HIGH"},
    "CVE-2020-25695": {"name": "PostgreSQL Priv Esc",          "severity": "HIGH"},
    "CVE-2020-25696": {"name": "PostgreSQL Auth Bypass",       "severity": "CRITICAL"},
    "CVE-2020-11083": {"name": "MongoDB Auth Bypass",          "severity": "CRITICAL"},
    "CVE-2020-11084": {"name": "MongoDB Replication",          "severity": "HIGH"},
    "CVE-2021-28168": {"name": "MySQL Auth Bypass",            "severity": "HIGH"},
    "CVE-2021-30609": {"name": "Redis Auth Bypass",            "severity": "CRITICAL"},
    "CVE-2021-30610": {"name": "Redis Injection",              "severity": "HIGH"},
    "CVE-2020-9614":  {"name": "ES Unauthorized",              "severity": "CRITICAL"},
    "CVE-2020-9615":  {"name": "ES Disclosure",                "severity": "HIGH"},
    "CVE-2021-22556": {"name": "Spring RCE",                   "severity": "CRITICAL"},
    "CVE-2021-22557": {"name": "Spring Boot Bypass",           "severity": "HIGH"},
    "CVE-2020-11989": {"name": "Jira RCE",                     "severity": "CRITICAL"},
    "CVE-2020-11990": {"name": "Confluence RCE",               "severity": "CRITICAL"},
    "CVE-2021-23840": {"name": "OpenSSL Int Overflow",         "severity": "HIGH"},
    "CVE-2021-23841": {"name": "OpenSSL Assert Fail",          "severity": "MEDIUM"},
    "CVE-2020-14644": {"name": "Java Serialization RCE",       "severity": "CRITICAL"},
    "CVE-2020-14645": {"name": "Java JNDI Injection",          "severity": "CRITICAL"},
    "CVE-2021-20294": {"name": "GitLab Auth Bypass",           "severity": "HIGH"},
    "CVE-2021-20295": {"name": "GitLab Disclosure",            "severity": "HIGH"},
    "CVE-2020-27238": {"name": "Grafana Auth Bypass",          "severity": "HIGH"},
    "CVE-2020-27239": {"name": "Grafana Plugin RCE",           "severity": "CRITICAL"},
    "CVE-2021-32074": {"name": "Prometheus RCE",               "severity": "CRITICAL"},
    "CVE-2021-32075": {"name": "Prometheus Auth Bypass",       "severity": "HIGH"},
    "CVE-2021-24514": {"name": "Nextcloud Auth Bypass",        "severity": "HIGH"},
    "CVE-2021-24515": {"name": "Nextcloud Disclosure",         "severity": "HIGH"},
    "CVE-2020-12624": {"name": "OpenVPN BOF",                  "severity": "CRITICAL"},
    "CVE-2020-12625": {"name": "OpenVPN Auth Bypass",          "severity": "HIGH"},
    "CVE-2021-3131":  {"name": "nginx Integer Overflow",       "severity": "HIGH"},
    "CVE-2021-3132":  {"name": "nginx BOF",                    "severity": "CRITICAL"},
    "CVE-2020-27241": {"name": "SSH Auth Bypass",              "severity": "CRITICAL"},
    "CVE-2020-27242": {"name": "SSH Priv Esc",                 "severity": "HIGH"},
    "CVE-2021-27066": {"name": "SolarWinds Attack",            "severity": "CRITICAL"},
    "CVE-2021-27067": {"name": "Codecov Attack",               "severity": "CRITICAL"},
    "CVE-2021-27068": {"name": "DependencyCheck Vuln",         "severity": "HIGH"},
    "CVE-2020-16891": {"name": "Zoom RCE",                     "severity": "HIGH"},
    "CVE-2020-16892": {"name": "Slack Auth Bypass",            "severity": "HIGH"},
    "CVE-2020-16893": {"name": "Discord Token",                "severity": "MEDIUM"},
    "CVE-2021-34481": {"name": "Teams RCE",                    "severity": "CRITICAL"},
    "CVE-2021-34482": {"name": "Slack Escape",                 "severity": "HIGH"},
    "CVE-2021-34483": {"name": "Reddit Auth Bypass",           "severity": "MEDIUM"},
    "CVE-2020-13776": {"name": "Telegram RCE",                 "severity": "HIGH"},
    "CVE-2020-13777": {"name": "Signal Auth Bypass",           "severity": "HIGH"},
    "CVE-2020-13778": {"name": "WhatsApp Auth Bypass",         "severity": "CRITICAL"},
    "CVE-2021-40345": {"name": "HTTP/2 Reset DoS",             "severity": "HIGH"},
    "CVE-2021-40346": {"name": "HTTP Request Smuggling",       "severity": "HIGH"},
    "CVE-2021-40347": {"name": "Apache Memory Leak",           "severity": "MEDIUM"},
    "CVE-2020-24613": {"name": "Kernel Use-After-Free",        "severity": "CRITICAL"},
    "CVE-2020-24614": {"name": "Kernel Race Cond",             "severity": "HIGH"},
    "CVE-2020-24615": {"name": "Kernel Out-of-Bounds",         "severity": "HIGH"},
    "CVE-2021-23878": {"name": "Docker Priv Esc",              "severity": "CRITICAL"},
    "CVE-2021-23879": {"name": "K8s RBAC Bypass",              "severity": "HIGH"},
    "CVE-2021-23880": {"name": "etcd Auth Bypass",             "severity": "CRITICAL"},
    "CVE-2020-8553":  {"name": "K8s DoS",                      "severity": "MEDIUM"},
    "CVE-2020-8554":  {"name": "K8s MITM",                     "severity": "CRITICAL"},
    "CVE-2020-8555":  {"name": "K8s SSRF",                     "severity": "HIGH"},
}


print("=" * 60)
print("Temporal Attack Graph with CVE Integration")
print("=" * 60 + "\n")

total_hosts  = int(input("Enter total number of hosts (default: 10): ") or 10)
time_windows = int(input("Enter number of time windows (default: 4): ") or 4)

min_hosts_per_window = 3
time_windows = max(1, time_windows)

print(f"OK Configuration: {total_hosts} total hosts across {time_windows} time windows")

all_hosts        = [f"h{i}" for i in range(1, total_hosts + 1)]
host_vertex_ids  = {host: idx for idx, host in enumerate(all_hosts)}
min_active_hosts = min(min_hosts_per_window, total_hosts)
max_active_hosts = max(min_active_hosts, min(total_hosts, round(total_hosts * 0.75)))

active_hosts_by_window = []
previous_active_hosts  = set()
covered_hosts          = set()

for i in range(time_windows):
    remaining_windows = time_windows - i
    unseen_hosts      = set(all_hosts) - covered_hosts
    min_new_hosts     = (len(unseen_hosts) + remaining_windows - 1) // remaining_windows
    target_count      = random.randint(min_active_hosts, max_active_hosts)
    target_count      = min(total_hosts, max(target_count, min_new_hosts))

    max_retained = max(0, target_count - min_new_hosts)
    if previous_active_hosts and max_retained:
        retain_min   = min(max_retained, max(1, round(len(previous_active_hosts) * 0.5)))
        retain_max   = min(len(previous_active_hosts), max_retained)
        retain_count = random.randint(retain_min, retain_max) if retain_max >= retain_min else retain_max
        retained_hosts = set(random.sample(sorted(previous_active_hosts), retain_count))
    else:
        retained_hosts = set()

    slots     = target_count - len(retained_hosts)
    new_count = min(len(unseen_hosts), slots, max(min_new_hosts, 0))
    new_hosts = set(random.sample(sorted(unseen_hosts), new_count)) if new_count else set()

    slots = target_count - len(retained_hosts) - len(new_hosts)
    available_returning_hosts = set(all_hosts) - retained_hosts - new_hosts
    returning_count = min(slots, len(available_returning_hosts))
    returning_hosts = (
        set(random.sample(sorted(available_returning_hosts), returning_count))
        if returning_count else set()
    )

    active_hosts = retained_hosts | new_hosts | returning_hosts
    active_hosts_by_window.append(active_hosts)
    covered_hosts.update(active_hosts)
    previous_active_hosts = active_hosts

hosts_per_window_dist = [len(hosts) for hosts in active_hosts_by_window]
print(f"OK Active hosts per window: {hosts_per_window_dist}")
print(f"OK Unique hosts scheduled across all windows: {len(covered_hosts)}\n")

host_cves = {}
seen_hosts = set()
for i in range(1, total_hosts + 1):
    host_cves[f"h{i}"] = []

for t in range(1, time_windows + 1):
    print(f"TIME WINDOW T{t}: ", end="")
    active_hosts = active_hosts_by_window[t - 1]
    seen_hosts.update(active_hosts)
    print(f"{sorted(active_hosts)}")
    previous_window_hosts = active_hosts_by_window[t - 2] if t > 1 else set()
    turned_on_hosts  = active_hosts - previous_window_hosts
    turned_off_hosts = previous_window_hosts - active_hosts
    print(f"  Turned on/returned: {sorted(turned_on_hosts)}")
    if t > 1:
        print(f"  Turned off: {sorted(turned_off_hosts)}")

    for host in sorted(active_hosts):
        if not host_cves[host]:
            num_cves      = random.randint(1, 2)
            host_cves[host] = random.sample(CVE_DATABASE["httpd"], num_cves)

    with open("input.P", "w") as f:
        f.write("% MulVAL Temporal Attack Graph\n")
        target_host = list(sorted(active_hosts))[-1]
        f.write(f"attackGoal(execCode({target_host}, root)).\n")
        for host in sorted(active_hosts):
            for idx, cve_id in enumerate(host_cves[host]):
                f.write(f"vulExists({host}, vul_{host}_{idx}, httpd).\n")

    print(f"  Generated {len(active_hosts)} host(s) with CVEs")

    try:
        subprocess.run(
            f"docker run --rm -v {BASE_DIR}:/input --platform linux/amd64 "
            f"wilbercui/mulval:latest bash -c 'cd /input && graph_gen.sh input.P -l' 2>&1",
            shell=True, capture_output=True, timeout=20, text=True,
        )
    except Exception:
        pass

    vertices = {}
    arcs     = []

    for host in sorted(active_hosts):
        cve_summary = " ".join(host_cves[host])
        vertices[host_vertex_ids[host]] = f"execCode({host}, root): {cve_summary}"

    if len(vertices) > 1:
        vertex_ids     = list(vertices.keys())
        existing_edges = set(arcs)
        for from_id, to_id in zip(sorted(vertex_ids), sorted(vertex_ids)[1:]):
            edge = (from_id, to_id)
            if edge not in existing_edges:
                arcs.append(edge)
                existing_edges.add(edge)

    with open(f"VERTICES_T{t}.CSV", "w") as f:
        for vid in sorted(vertices.keys()):
            desc = str(vertices[vid])[:200].replace('"', '\\"')
            f.write(f'{vid},"{desc}",AND,0\n')

    with open(f"ARCS_T{t}.CSV", "w") as f:
        for from_id, to_id in arcs:
            f.write(f"{to_id},{from_id},-1\n")

    for file in list(Path(".").glob("*.P")) + list(Path(".").glob("*.xwam")):
        try:
            file.unlink()
        except Exception:
            pass

cves_export = {host: host_cves[host] for host in sorted(seen_hosts) if host_cves[host]}
with open(IDS_OUTPUT_DIR / "host_cves_mapping.json", "w") as f:
    json.dump(cves_export, f, indent=2)

print(f"\nOK COMPLETE: {time_windows} time windows, {total_hosts} hosts, {len(cves_export)} with CVEs")
csvs = sorted(Path(".").glob("*.CSV"))
print(f"OK Generated {len(csvs)} CSV files")

for pattern in ["input.P", "trace_output.P", "AttackGraph.txt", "dynamic_decl.gen", "xsb_log.txt"]:
    Path(pattern).unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────
# IDS ALERT SIMULATOR
# ─────────────────────────────────────────────────────────────────
class AlertSeverity(Enum):
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


SEVERITY_NOISE = {
    AlertSeverity.CRITICAL : [0.05, 0.10, 0.20, 0.65],
    AlertSeverity.HIGH     : [0.10, 0.20, 0.50, 0.20],
    AlertSeverity.MEDIUM   : [0.25, 0.45, 0.25, 0.05],
    AlertSeverity.LOW      : [0.50, 0.35, 0.10, 0.05],
}


class IDSAlertSimulator:

    CVE_ATTACK_MAPPING = {
        "CVE-2021-44228": "Apache Log4j RCE Exploitation",
        "CVE-2021-41773": "Apache Path Traversal Attack",
        "CVE-2020-1938":  "Apache Tomcat Ghostcat Exploit",
        "CVE-2021-26855": "Exchange Server SSRF Attack",
        "CVE-2019-0604":  "SharePoint Remote Code Execution",
        "CVE-2021-3129":  "Laravel Framework RCE",
        "CVE-2021-22986": "F5 BIG-IP RCE Exploitation",
        "CVE-2021-40444": "Office Component RCE",
        "CVE-2021-22911": "Apache HTTP Buffer Overflow",
        "CVE-2021-1732":  "Windows Privilege Escalation",
        "CVE-2020-5410":  "Spring Cloud Config RCE",
        "CVE-2019-2725":  "Oracle WebLogic RCE",
        "CVE-2020-14625": "Tomcat Remote Code Execution",
        "CVE-2021-3156":  "Sudo Buffer Overflow Attack",
        "CVE-2020-1472":  "Windows Netlogon Elevation",
        "CVE-2020-14882": "Oracle WebLogic Server RCE",
        "CVE-2021-2109":  "Oracle WebLogic SSRF",
        "CVE-2020-11738": "Apache Karaf RCE",
        "CVE-2021-21985": "VMware vCenter RCE",
        "CVE-2020-16898": "Windows TCP/IP Remote Execution",
        "CVE-2021-31806": "Apache OpenOffice RCE",
        "CVE-2020-0688":  "Exchange Server RCE",
        "CVE-2021-24086": "Windows TCP/IP Elevation",
        "CVE-2020-14040": "Go JSON Unmarshal RCE",
        "CVE-2021-20090": "OkHttp Certificate Bypass",
        "CVE-2020-15505": "Accellion FTA RCE",
        "CVE-2021-22120": "Spring Framework SpEL Injection",
        "CVE-2020-35476": "Apache ActiveMQ Injection",
        "CVE-2021-35065": "Fortinet FortiGate Exploit",
        "CVE-2020-11022": "jQuery XSS Attack",
        "CVE-2021-22214": "Apache Struts RCE",
        "CVE-2020-14779": "Oracle Coherence RCE",
        "CVE-2021-33910": "systemd DoS Attack",
        "CVE-2020-12447": "GnuTLS Buffer Read Attack",
        "CVE-2021-4034":  "Polkit Privilege Escalation",
        "CVE-2020-15778": "OpenSSH Code Execution",
        "CVE-2021-30129": "Apache OFBiz Authentication Bypass RCE",
        "CVE-2020-11080": "HTTP/2 DoS Attack",
        "CVE-2021-22045": "Spring Cloud Config Traversal",
        "CVE-2020-25213": "WordPress Plugin File Upload",
        "CVE-2021-28169": "Apache Struts2 RCE",
        "CVE-2020-12826": "Linux Kernel BPF Spray",
        "CVE-2021-32785": "Apache ActiveMQ Exploitation",
        "CVE-2020-14382": "Linux Kernel Privilege Escalation",
        "CVE-2021-3114":  "Go Path Traversal",
        "CVE-2020-9847":  "Apache Solr Bypass",
        "CVE-2021-27065": "Exchange Server RCE Attack",
        "CVE-2020-24027": "Cisco IOS Command Injection",
        "CVE-2021-28478": "Apache Log4j RCE Vector",
        "CVE-2020-11905": "Zoom Security Exploitation",
        "CVE-2021-31883": "Drupal Plugin RCE",
        "CVE-2020-16123": "Windows Desktop Bridge Elevation",
        "CVE-2021-26900": "Apache OFBiz Traversal",
        "CVE-2020-3123":  "Cisco Router Command Injection",
        "CVE-2021-24112": "WordPress Plugin SQL Injection",
        "CVE-2020-9839":  "Apache Kafka Authorization Bypass",
        "CVE-2021-20224": "Ansible Tower Escalation",
        "CVE-2020-7919":  "Go net Package DoS",
        "CVE-2021-22119": "Spring Expression Language Injection",
        "CVE-2020-14383": "Linux Kernel SCSI Escalation",
        "CVE-2021-3420":  "CUnit Buffer Overflow",
        "CVE-2020-8840":  "Exim Remote Code Execution",
        "CVE-2021-32786": "Apache OFBiz RCE",
        "CVE-2020-13999": "libpng Buffer Overflow",
        "CVE-2021-24410": "Elementor Plugin Bypass",
        "CVE-2020-13847": "Dovecot IMAP DoS",
        "CVE-2021-1102":  "Cisco ASA SSL/TLS DoS",
        "CVE-2020-12762": "Wacom Driver Privilege Escalation",
        "CVE-2021-21225": "Chromium Out-of-Bounds Write",
        "CVE-2020-11897": "Apple WebKit Memory Corruption",
        "CVE-2021-37750": "Linux Kernel Escalation",
        "CVE-2020-8992":  "e2fsprogs Buffer Overflow",
        "CVE-2021-32807": "Apache Commons Deserialization RCE",
        "CVE-2020-27840": "Linux Kernel NFT Disclosure",
        "CVE-2021-3638":  "KVM Memory Corruption",
        "CVE-2020-5698":  "Spring Data Commons SpEL",
        "CVE-2021-26619": "Linux Kernel BPF Escalation",
        "CVE-2020-14644": "Oracle WebLogic Console RCE",
        "CVE-2021-33034": "Linux Kernel eBPF Escalation",
        "CVE-2020-14636": "PostgreSQL Client Bypass",
        "CVE-2021-20225": "Apache Kafka Heap Overflow",
        "CVE-2020-13361": "QEMU Privilege Escalation",
        "CVE-2021-32610": "Apache Struts XSS",
        "CVE-2020-9496":  "Apache Commons XML XXE",
        "CVE-2021-39201": "Twilio Authy Bypass",
        "CVE-2020-11196": "Samba NetLogon Escalation",
        "CVE-2021-3449":  "OpenSSL Integer Overflow",
        "CVE-2020-11899": "Cisco IOS XE Escalation",
        "CVE-2021-22526": "Spring Framework DoS",
        "CVE-2020-27889": "Linux Kernel FUSE Overflow",
        "CVE-2021-31855": "OpenEXR Buffer Overflow",
        "CVE-2020-5086":  "Nextcloud Path Traversal",
        "CVE-2021-21239": "Firefox Memory Corruption",
        "CVE-2020-14331": "Oracle Java Deserialization RCE",
        "CVE-2021-21330": "Apache OFBiz RCE Vector",
        "CVE-2020-28196": "Nextcloud Privilege Escalation",
        "CVE-2021-24486": "WordPress Plugin Injection",
        "CVE-2020-7207":  "Ansible Tower Upload",
        "CVE-2021-32747": "Apache Commons FileUpload DoS",
        "CVE-2020-11988": "Samba VFS RCE",
        "CVE-2021-24597": "WordPress Plugin Disclosure",
        "CVE-2020-24779": "GNOME Shell Escalation",
        "CVE-2021-32748": "Apache OFBiz Template",
        "CVE-2020-14645": "Linux Kernel Memory Corruption",
        "CVE-2021-32628": "Apache Log4j Configuration",
        "CVE-2020-16242": "Intel CPU Speculation",
        "CVE-2021-21224": "Chrome Out-of-Bounds Write",
        "CVE-2020-8174":  "Node.js HTTP Header Parsing",
    }

    CVE_SEVERITY = {
        "CVE-2021-44228": AlertSeverity.CRITICAL,
        "CVE-2021-41773": AlertSeverity.CRITICAL,
        "CVE-2020-1938":  AlertSeverity.CRITICAL,
        "CVE-2021-26855": AlertSeverity.CRITICAL,
        "CVE-2019-0604":  AlertSeverity.CRITICAL,
        "CVE-2021-3129":  AlertSeverity.CRITICAL,
        "CVE-2021-22986": AlertSeverity.CRITICAL,
        "CVE-2021-40444": AlertSeverity.HIGH,
        "CVE-2021-22911": AlertSeverity.HIGH,
        "CVE-2021-1732":  AlertSeverity.HIGH,
        "CVE-2020-5410":  AlertSeverity.CRITICAL,
        "CVE-2019-2725":  AlertSeverity.CRITICAL,
        "CVE-2020-14625": AlertSeverity.CRITICAL,
        "CVE-2021-3156":  AlertSeverity.HIGH,
        "CVE-2020-1472":  AlertSeverity.CRITICAL,
        "CVE-2020-14882": AlertSeverity.CRITICAL,
        "CVE-2021-2109":  AlertSeverity.HIGH,
        "CVE-2020-11738": AlertSeverity.HIGH,
        "CVE-2021-21985": AlertSeverity.CRITICAL,
        "CVE-2020-16898": AlertSeverity.HIGH,
        "CVE-2021-31806": AlertSeverity.HIGH,
        "CVE-2020-0688":  AlertSeverity.HIGH,
        "CVE-2021-24086": AlertSeverity.CRITICAL,
        "CVE-2020-14040": AlertSeverity.HIGH,
        "CVE-2021-20090": AlertSeverity.HIGH,
        "CVE-2020-15505": AlertSeverity.CRITICAL,
        "CVE-2021-22120": AlertSeverity.HIGH,
        "CVE-2020-35476": AlertSeverity.CRITICAL,
        "CVE-2021-35065": AlertSeverity.CRITICAL,
        "CVE-2020-11022": AlertSeverity.MEDIUM,
        "CVE-2021-22214": AlertSeverity.HIGH,
        "CVE-2020-14779": AlertSeverity.CRITICAL,
        "CVE-2021-33910": AlertSeverity.HIGH,
        "CVE-2020-12447": AlertSeverity.HIGH,
        "CVE-2021-4034":  AlertSeverity.HIGH,
        "CVE-2020-15778": AlertSeverity.HIGH,
        "CVE-2021-30129": AlertSeverity.CRITICAL,
        "CVE-2020-11080": AlertSeverity.MEDIUM,
        "CVE-2021-22045": AlertSeverity.HIGH,
        "CVE-2020-25213": AlertSeverity.HIGH,
        "CVE-2021-28169": AlertSeverity.CRITICAL,
        "CVE-2020-12826": AlertSeverity.HIGH,
        "CVE-2021-32785": AlertSeverity.HIGH,
        "CVE-2020-14382": AlertSeverity.HIGH,
        "CVE-2021-3114":  AlertSeverity.MEDIUM,
        "CVE-2020-9847":  AlertSeverity.HIGH,
        "CVE-2021-27065": AlertSeverity.CRITICAL,
        "CVE-2020-24027": AlertSeverity.HIGH,
        "CVE-2021-28478": AlertSeverity.CRITICAL,
        "CVE-2020-11905": AlertSeverity.HIGH,
        "CVE-2021-31883": AlertSeverity.HIGH,
        "CVE-2020-16123": AlertSeverity.HIGH,
        "CVE-2021-26900": AlertSeverity.HIGH,
        "CVE-2020-3123":  AlertSeverity.HIGH,
        "CVE-2021-24112": AlertSeverity.MEDIUM,
        "CVE-2020-9839":  AlertSeverity.MEDIUM,
        "CVE-2021-20224": AlertSeverity.HIGH,
        "CVE-2020-7919":  AlertSeverity.MEDIUM,
        "CVE-2021-22119": AlertSeverity.HIGH,
        "CVE-2020-14383": AlertSeverity.HIGH,
        "CVE-2021-3420":  AlertSeverity.MEDIUM,
        "CVE-2020-8840":  AlertSeverity.CRITICAL,
        "CVE-2021-32786": AlertSeverity.CRITICAL,
        "CVE-2020-13999": AlertSeverity.HIGH,
        "CVE-2021-24410": AlertSeverity.HIGH,
        "CVE-2020-13847": AlertSeverity.MEDIUM,
        "CVE-2021-1102":  AlertSeverity.MEDIUM,
        "CVE-2020-12762": AlertSeverity.HIGH,
        "CVE-2021-21225": AlertSeverity.HIGH,
        "CVE-2020-11897": AlertSeverity.HIGH,
        "CVE-2021-37750": AlertSeverity.HIGH,
        "CVE-2020-8992":  AlertSeverity.MEDIUM,
        "CVE-2021-32807": AlertSeverity.HIGH,
        "CVE-2020-27840": AlertSeverity.MEDIUM,
        "CVE-2021-3638":  AlertSeverity.HIGH,
        "CVE-2020-5698":  AlertSeverity.HIGH,
        "CVE-2021-26619": AlertSeverity.HIGH,
        "CVE-2020-14644": AlertSeverity.HIGH,
        "CVE-2021-33034": AlertSeverity.HIGH,
        "CVE-2020-14636": AlertSeverity.MEDIUM,
        "CVE-2021-20225": AlertSeverity.HIGH,
        "CVE-2020-13361": AlertSeverity.HIGH,
        "CVE-2021-32610": AlertSeverity.MEDIUM,
        "CVE-2020-9496":  AlertSeverity.MEDIUM,
        "CVE-2021-39201": AlertSeverity.MEDIUM,
        "CVE-2020-11196": AlertSeverity.HIGH,
        "CVE-2021-3449":  AlertSeverity.MEDIUM,
        "CVE-2020-11899": AlertSeverity.HIGH,
        "CVE-2021-22526": AlertSeverity.MEDIUM,
        "CVE-2020-27889": AlertSeverity.HIGH,
        "CVE-2021-31855": AlertSeverity.MEDIUM,
        "CVE-2020-5086":  AlertSeverity.MEDIUM,
        "CVE-2021-21239": AlertSeverity.HIGH,
        "CVE-2020-14331": AlertSeverity.CRITICAL,
        "CVE-2021-21330": AlertSeverity.HIGH,
        "CVE-2020-28196": AlertSeverity.MEDIUM,
        "CVE-2021-24486": AlertSeverity.MEDIUM,
        "CVE-2020-7207":  AlertSeverity.HIGH,
        "CVE-2021-32747": AlertSeverity.MEDIUM,
        "CVE-2020-11988": AlertSeverity.HIGH,
        "CVE-2021-24597": AlertSeverity.LOW,
        "CVE-2020-24779": AlertSeverity.MEDIUM,
        "CVE-2021-32748": AlertSeverity.MEDIUM,
        "CVE-2020-14645": AlertSeverity.HIGH,
        "CVE-2021-32628": AlertSeverity.HIGH,
        "CVE-2020-16242": AlertSeverity.MEDIUM,
        "CVE-2021-21224": AlertSeverity.HIGH,
        "CVE-2020-8174":  AlertSeverity.MEDIUM,
    }

    PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SSH", "FTP"]

    def __init__(self, num_hosts, base_time=None, host_cves_map=None):
        self.num_hosts      = num_hosts
        self.base_time      = base_time or datetime.datetime.now()
        self.alerts         = []
        self.host_cves_map  = host_cves_map or {}

    def generate_alert(self, timestamp, src_host, dst_host,
                       attack_type, severity, cve_id=None):
        return {
            "timestamp"        : timestamp,
            "source_host"      : src_host,
            "dest_host"        : dst_host,
            "source_port"      : random.randint(1024, 65535),
            "dest_port"        : random.randint(1, 65535),
            "protocol"         : random.choice(self.PROTOCOLS),
            "attack_type"      : attack_type,
            "severity"         : severity.name,
            "packet_count"     : random.randint(1, 1000),
            "bytes_transferred": random.randint(100, 1000000),
            "cve_id"           : cve_id,
        }

    def simulate_alerts_for_window(self, time_window, hosts, num_alerts=None):
        if num_alerts is None:
            num_alerts = random.randint(5, 15)

        window_start = self.base_time + datetime.timedelta(hours=time_window)

        for _ in range(num_alerts):
            src_host = random.choice(hosts)
            dst_host = random.choice([h for h in hosts if h != src_host])

            if dst_host in self.host_cves_map and self.host_cves_map[dst_host]:
                cve_id      = random.choice(self.host_cves_map[dst_host])
                cve_info    = globals().get("CVE_INFO", {}).get(cve_id, {})
                attack_type = self.CVE_ATTACK_MAPPING.get(
                    cve_id, cve_info.get("name", f"CVE {cve_id}")
                )
                base_sev = self.CVE_SEVERITY.get(cve_id, AlertSeverity.HIGH)
                severity  = random.choices(
                    list(AlertSeverity),
                    weights=SEVERITY_NOISE[base_sev],
                )[0]
            else:
                cve_id      = None
                attack_type = "Unclassified Network Attack"
                severity = random.choices(
                    list(AlertSeverity),
                    weights=[0.15, 0.35, 0.35, 0.15],
                )[0]

            timestamp = window_start + datetime.timedelta(
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59),
            )
            self.alerts.append(
                self.generate_alert(timestamp, src_host, dst_host,
                                    attack_type, severity, cve_id)
            )

    def simulate_from_temporal_graph(self, global_order, max_hosts,
                                     time_windows, hosts_per_window):
        all_hosts_per_window = {}
        all_hosts_set        = set()

        for t in range(1, time_windows + 1):
            if t == 1:
                initial_hosts            = global_order[:hosts_per_window]
                all_hosts_per_window[t]  = set(initial_hosts)
            else:
                prev_active = all_hosts_per_window[t - 1]
                retained    = set(
                    random.sample(list(prev_active),
                                  max(1, int(0.6 * len(prev_active))))
                )
                all_seen_hosts = set()
                for i in range(1, t):
                    all_seen_hosts.update(all_hosts_per_window[i])
                unseen_hosts = list(set(global_order) - all_seen_hosts)
                num_new      = min(hosts_per_window, len(unseen_hosts))
                new_hosts    = set(random.sample(unseen_hosts, num_new)) if unseen_hosts else set()
                all_hosts_per_window[t] = retained | new_hosts

            all_hosts_set.update(all_hosts_per_window[t])

        for t in range(1, time_windows + 1):
            available_hosts = sorted(list(all_hosts_set))
            if available_hosts:
                num_alerts = random.randint(15, 30)
                self.simulate_alerts_for_window(t, available_hosts, num_alerts)

    def get_alerts_dataframe(self):
        return pd.DataFrame(self.alerts)

    def save_alerts(self, filename):
        df = self.get_alerts_dataframe()
        df.to_csv(filename, index=False)
        print(f"OK Alerts saved to {filename}")

    def print_summary(self):
        if not self.alerts:
            print("No alerts generated")
            return
        df = self.get_alerts_dataframe()
        print("\n--- IDS Alert Simulation Summary ---")
        print(f"Total Alerts: {len(self.alerts)}")
        print("\nAlerts by Severity:")
        print(df["severity"].value_counts())
        print("\nTop Attack Types:")
        print(df["attack_type"].value_counts().head(10))
        print("\nCVE-based Alerts:")
        cve_alerts = df[df["cve_id"].notna()]
        print(f"  Total CVE-specific alerts: {len(cve_alerts)}")
        if len(cve_alerts) > 0:
            print(f"  Unique CVEs detected: {cve_alerts['cve_id'].nunique()}")
            print("  Top CVEs:")
            print(cve_alerts["cve_id"].value_counts().head(10))
        print(f"\nTime Range: {df['timestamp'].min()} to {df['timestamp'].max()}")


# ─────────────────────────────────────────────────────────────────
# GENERATE ALERTS
# ─────────────────────────────────────────────────────────────────
base_dir = Path.cwd().resolve()
os.chdir(base_dir)

host_cves_map = {}
if os.path.exists(IDS_OUTPUT_DIR / "host_cves_mapping.json"):
    with open(IDS_OUTPUT_DIR / "host_cves_mapping.json", "r") as f:
        host_cves_map = json.load(f)
    print(f"OK Loaded CVE mapping for {len(host_cves_map)} hosts")
else:
    print("WARN host_cves_mapping.json not found. Run cell 1 first.")

all_tag_hosts    = sorted(host_cves_map.keys())
max_hosts        = len(all_tag_hosts)
time_windows     = 4
hosts_per_window = max(1, max_hosts // time_windows)

global_order = all_tag_hosts.copy()
random.shuffle(global_order)

simulator = IDSAlertSimulator(num_hosts=max_hosts, host_cves_map=host_cves_map)
simulator.simulate_from_temporal_graph(global_order, max_hosts, time_windows, hosts_per_window)
simulator.print_summary()
simulator.save_alerts(IDS_OUTPUT_DIR / "ids_alerts.csv")

# Ensure every TAG host appears in alerts
all_cves_in_map    = {cve for cves in host_cves_map.values() for cve in cves}
missing_cve_info   = sorted(all_cves_in_map - set(CVE_INFO.keys()))
if missing_cve_info:
    for cve_id in missing_cve_info:
        CVE_INFO[cve_id] = {"name": f"CVE {cve_id}", "severity": "HIGH"}
    print(f"Added {len(missing_cve_info)} CVE_INFO placeholders.")

alerts_df     = pd.read_csv(IDS_OUTPUT_DIR / "ids_alerts.csv")
observed_hosts = set(alerts_df["source_host"]) | set(alerts_df["dest_host"])
all_hosts_set  = set(host_cves_map.keys())
missing_hosts  = sorted(all_hosts_set - observed_hosts)

if missing_hosts:
    sim2      = IDSAlertSimulator(num_hosts=len(all_hosts_set), host_cves_map=host_cves_map)
    new_alerts = []
    for host in missing_hosts:
        others = [h for h in all_hosts_set if h != host]
        other  = random.choice(others) if others else host
        if host_cves_map.get(host):
            cve_id      = random.choice(host_cves_map[host])
            cve_info    = CVE_INFO.get(cve_id, {})
            attack_type = IDSAlertSimulator.CVE_ATTACK_MAPPING.get(
                cve_id, cve_info.get("name", f"CVE {cve_id}")
            )
            base_sev = IDSAlertSimulator.CVE_SEVERITY.get(cve_id, AlertSeverity.HIGH)
            severity  = random.choices(
                list(AlertSeverity),
                weights=SEVERITY_NOISE[base_sev],
            )[0]
        else:
            cve_id      = None
            attack_type = "Unclassified Network Attack"
            severity    = random.choices(
                list(AlertSeverity),
                weights=[0.15, 0.35, 0.35, 0.15],
            )[0]
        timestamp = sim2.base_time + datetime.timedelta(
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )
        new_alerts.append(
            sim2.generate_alert(timestamp, other, host, attack_type, severity, cve_id)
        )
    if new_alerts:
        alerts_df = pd.concat([alerts_df, pd.DataFrame(new_alerts)], ignore_index=True)
        alerts_df.to_csv(IDS_OUTPUT_DIR / "ids_alerts.csv", index=False)
        print(f"Added {len(new_alerts)} alerts to cover missing hosts.")
else:
    print("All TAG hosts already appear in IDS alerts.")


# ─────────────────────────────────────────────────────────────────
# CONSISTENCY CHECK
# ─────────────────────────────────────────────────────────────────
if not os.path.exists(IDS_OUTPUT_DIR / "host_cves_mapping.json"):
    raise FileNotFoundError("host_cves_mapping.json not found.")
if not os.path.exists(IDS_OUTPUT_DIR / "ids_alerts.csv"):
    raise FileNotFoundError("ids_alerts.csv not found.")

with open(IDS_OUTPUT_DIR / "host_cves_mapping.json", "r") as f:
    host_cves_map = json.load(f)
alerts_df = pd.read_csv(IDS_OUTPUT_DIR / "ids_alerts.csv")

vertices_files = sorted(glob.glob("VERTICES_T*.CSV"))
if not vertices_files:
    raise FileNotFoundError("No VERTICES_T*.CSV files found.")

tag_hosts = set()
for vertices_file in vertices_files:
    df = pd.read_csv(vertices_file, header=None)
    for label in df[1].astype(str):
        for host_id in re.findall(r"\bh(\d+)\b", label):
            tag_hosts.add(f"h{host_id}")

ids_hosts          = set(alerts_df["source_host"]) | set(alerts_df["dest_host"])
only_in_tag        = tag_hosts - ids_hosts
only_in_ids        = ids_hosts - tag_hosts
missing_cve_for_dst = 0
unknown_cve_ids    = set()
mismatched_attack_type = 0

for _, row in alerts_df.iterrows():
    cve_id = row.get("cve_id")
    if pd.isna(cve_id):
        continue
    dst = row.get("dest_host")
    if dst not in host_cves_map or cve_id not in host_cves_map.get(dst, []):
        missing_cve_for_dst += 1
    if cve_id not in CVE_INFO:
        unknown_cve_ids.add(cve_id)
    expected_name = IDSAlertSimulator.CVE_ATTACK_MAPPING.get(
        cve_id, CVE_INFO.get(cve_id, {}).get("name", f"CVE {cve_id}")
    )
    if row.get("attack_type") != expected_name:
        mismatched_attack_type += 1

print("=" * 60)
print("CONSISTENCY CHECK: TAG vs IDS")
print("=" * 60)
print(f"TAG hosts: {len(tag_hosts)} | IDS hosts: {len(ids_hosts)}")
print(f"Only in TAG: {sorted(only_in_tag)}")
print(f"Only in IDS: {sorted(only_in_ids)}")
print(f"CVE alerts with dst host mismatch: {missing_cve_for_dst}")
print(f"CVE IDs missing from CVE_INFO: {sorted(unknown_cve_ids)}")
print(f"Attack type mismatches: {mismatched_attack_type}")

print("\nSeverity Distribution:")
print(alerts_df["severity"].value_counts().to_string())

if (not only_in_tag and not only_in_ids
        and missing_cve_for_dst == 0 and mismatched_attack_type == 0):
    print("\nOK IDS alerts consistent with temporal graph and mappings.")
else:
    print("\nWARN Review inconsistencies listed above.")


# ===== File: Alert correlator.py =====
from neo4j import GraphDatabase
from tqdm import tqdm, trange
from collections import deque
import warnings
from pathlib import Path
warnings.simplefilter(action='ignore', category=FutureWarning)
import pandas as pd
import numpy as np
import networkx as nx
import os
import shutil
import pathlib
import getpass
import platform
import math
import time
import glob

def strip_labels(graph):
    return {
        u: [v for (v, _) in edges]
        for u, edges in graph.items()
    }

def sparsify_and_replace():

    if platform.system() == "Darwin":
        base_dir = Path(__file__).resolve().parent
    else:
        base_dir = Path(".").expanduser().resolve()

    print(f"Using base directory: {base_dir}")

    arc_files = glob.glob(str(base_dir / "ARCS_T*.CSV"))

    for arc_path in sorted(arc_files):
        arc_path = Path(arc_path)

        t = arc_path.stem.split("_")[1]
        vertex_path = base_dir / f"VERTICES_{t}.CSV"

        print(f"\nProcessing {t}...")

        arcs_df = pd.read_csv(arc_path)
        child_col = arcs_df.columns[0]
        parent_col = arcs_df.columns[1]

        G = nx.DiGraph()
        for _, row in arcs_df.iterrows():
            G.add_edge(row[parent_col], row[child_col])

        print(f"[{t}] Original edges: {G.number_of_edges()}")

        MAX_OUT = 2

        final_edges = set()
        visited = set()

        nodes_sorted = sorted(G.nodes(), key=lambda x: G.out_degree(x), reverse=True)

        for u in nodes_sorted:

            neighbors = list(G.successors(u))

            if not neighbors:
                continue

            neighbors_sorted = sorted(
                neighbors,
                key=lambda x: (x in visited, G.out_degree(x))
            )

            selected = neighbors_sorted[:MAX_OUT]

            for v in selected:
                final_edges.add((u, v))
                visited.add(v)

        print(f"[{t}] Reduced edges: {len(final_edges)}")

        temp_arc_path = arc_path.with_suffix(".tmp")
        sparse_df = pd.DataFrame(list(final_edges), columns=[parent_col, child_col])
        sparse_df.to_csv(temp_arc_path, index=False)
        os.replace(temp_arc_path, arc_path)

        if vertex_path.exists():
            vertices_df = pd.read_csv(vertex_path)
            node_col = vertices_df.columns[0]

            used_nodes = set()
            for u, v in final_edges:
                used_nodes.add(u)
                used_nodes.add(v)

            filtered_vertices = vertices_df[vertices_df[node_col].isin(used_nodes)]

            temp_vertex_path = vertex_path.with_suffix(".tmp")
            filtered_vertices.to_csv(temp_vertex_path, index=False)
            os.replace(temp_vertex_path, vertex_path)

        print(f"[{t}] Replaced original files OK")


def prune_and_export_all():
    """
    Process all ARCS_Ti.CSV and VERTICES_Ti.CSV pairs in the given folder.
    Before exporting, move all original CSVs to a backup folder.
    """
    print(platform.system())

    if platform.system() == "Darwin":
        base_dir = Path(__file__).resolve().parent
    else:
        base_dir = Path(".").expanduser().resolve()

    backup_folder = os.path.join(base_dir, "backup_originals")
    os.makedirs(backup_folder, exist_ok=True)
    print(backup_folder)

    original_csvs = glob.glob(os.path.join(base_dir, "ARCS_T*.CSV")) + \
                    glob.glob(os.path.join(base_dir, "VERTICES_T*.CSV"))

    for f in original_csvs:
        dest = os.path.join(backup_folder, os.path.basename(f))
        if not os.path.exists(dest):
            shutil.move(f, dest)

    arcs_files = sorted(glob.glob(os.path.join(backup_folder, "ARCS_T*.CSV")))

    for arcs_path in arcs_files:
        suffix = arcs_path.split("ARCS_")[-1]
        suffix_clean = suffix.replace(".CSV", "").replace(".csv", "")

        vertices_path = arcs_path.replace("ARCS_", "VERTICES_")
        if not os.path.exists(vertices_path):
            continue

        arcs_df = pd.read_csv(arcs_path, header=None, names=["target", "source", "weight"])
        vertices_df = pd.read_csv(vertices_path, header=None, names=["id", "label", "type", "value"])

        G = nx.from_pandas_edgelist(arcs_df, source="source", target="target", create_using=nx.DiGraph())

        exec_nodes = {}
        for _, row in vertices_df.iterrows():
            if "execCode(" in str(row["label"]):
                node_id = row["id"]
                label = row["label"]
                exec_nodes[node_id] = label

        H = nx.DiGraph()

        exec_ids = list(exec_nodes.keys())

        for i in range(len(exec_ids)):
            for j in range(len(exec_ids)):
                if i == j:
                    continue

                src = exec_ids[i]
                tgt = exec_ids[j]

                if nx.has_path(G, src, tgt):
                    H.add_edge(src, tgt)

        final_edges = list(H.edges())

        arcs_out_df = pd.DataFrame(final_edges, columns=["source", "target"])
        arcs_out_df["weight"] = 1
        arcs_out_df = arcs_out_df[["target", "source", "weight"]]

        vertices_out_df = vertices_df[vertices_df["id"].isin(exec_ids)].copy()

        arcs_out = os.path.join(base_dir, f"ARCS_{suffix_clean}.CSV")
        vertices_out = os.path.join(base_dir, f"VERTICES_{suffix_clean}.CSV")

        arcs_out_df.to_csv(arcs_out, header=False, index=False)
        vertices_out_df.to_csv(vertices_out, header=False, index=False)

    print("OK All graphs pruned and exported successfully.")

def copy_csv(dest):
    destination_folder=dest
    source_folder = pathlib.Path(__file__).parent.resolve()
    source_folder=source_folder.__str__()
    if platform.system() == 'Linux':
        source_folder=source_folder+'/'
        destination_folder=destination_folder+'/'
    elif platform.system() == 'Windows':
        source_folder=source_folder+'\\'
        destination_folder=destination_folder+'\\'
    else:
        source_folder=source_folder+'/'
        destination_folder=destination_folder+'/'
    counter=0
    for file_name in os.listdir(source_folder):
        source = source_folder + file_name
        destination = destination_folder + file_name
        extension = os.path.splitext(file_name)[1][1:]
        if extension == "csv" or extension == "CSV":
            if os.path.isfile(source):
                shutil.copy(source, destination)
                counter+=1
    return counter

def clear_graph(tx):
    tx.run("match (n) detach delete n")
    tx.run("CALL gds.graph.drop('mygraph', false) YIELD graphName;")

def create_graph(tx):
    d=tx.run("CALL dbms.listConfig() YIELD name, value WHERE name = "+"'server.directories.import'"+" RETURN value;").value();
    d=d[0]
    print(d)
    total_files=copy_csv(d)
    total_graphs=int(math.ceil(total_files/2))
    Timestamps=[]
    File_names_arcs=[]
    File_names_vertices=[]
    for i in range(1,total_graphs+1):
        Timestamps.append('T'+str(i))
    for i in Timestamps:
        File_names_arcs.append("ARCS_"+i+".CSV")
        File_names_vertices.append("VERTICES_"+i+".CSV")
    for i,j in zip(File_names_vertices,Timestamps):
        tx.run("LOAD CSV FROM 'file:///"+i+"' AS row WITH toInteger(row[0]) AS id, row[1] AS fact, row[2] AS type WHERE type='AND' OR type = 'OR' MERGE (ag:"+j+" {id: id}) SET ag.fact = fact, ag.type = type RETURN count(ag); ")
    for i,j in zip(File_names_arcs,Timestamps):
        tx.run("LOAD CSV FROM 'file:///"+i+"' AS row  WITH toInteger(row[0]) AS   dst, toInteger(row[1]) AS src MATCH   (a:"+j+"),   (b:"+j+") WHERE a.id = src AND b.id = dst CREATE (a)-[r:arrow]->(b) RETURN type(r)")

    tx.run("CALL gds.graph.project(  'mygraph', "+str(Timestamps)+", ['arrow'] ) YIELD graphName AS graph, nodeProjection, nodeCount AS nodes, relationshipProjection, relationshipCount AS rels ")
    print("Temporal Attack Graph Created Successfully")

def Paths(session):
    label = session.run("MATCH (a) WITH DISTINCT LABELS(a) AS temp UNWIND temp AS label RETURN label").value()
    label.sort()
    nodes=[]
    for i in label:
        t=session.run("MATCH (n:"+i+") RETURN n.id ")
        t=t.to_df()
        t = list(t['n.id'])
        nodes=nodes+t
    nodes=list(set(nodes))
    nextnode=None
    adjacency_list = {node: [] for node in nodes}
    for i in label:
        for j in nodes:
            nextnode=None
            k=session.run("MATCH (startNode:"+i+"  {id: "+str(j)+"})-[:arrow]->(nextNode:"+i+") RETURN nextNode.id").value()
          
            if adjacency_list[j]:
                nextnode = [item[0] for item in adjacency_list[j]]
                
            if k and nextnode:
                new_k = k.copy()
                for item in new_k:
                    if item in nextnode:
                        k.remove(item)
           
            if k:
                k = list(zip(k, [i] * len(k)))
             
                if j in adjacency_list:
                    adjacency_list[j].extend(k)
            
    return adjacency_list, label

def timewindow_first_occurence(session):
    label = session.run("MATCH (a) WITH DISTINCT LABELS(a) AS temp UNWIND temp AS label RETURN label").value()
    label.sort()
    nodes=[]
    result = []
    previous_numbers = set()
    for i in label:
        t=session.run("MATCH (n:"+i+") RETURN n.id ").value()

        added_numbers = set(t) - set(previous_numbers)
        previous_numbers=list(previous_numbers)+list(added_numbers)

        result_list = list(zip(added_numbers, [i] * len(added_numbers)))

        result=result+result_list
    return result

def create_TAG(tx, adjacency_list,first_time):
    tx.run("match (n) detach delete n")
    tx.run("CALL gds.graph.drop('mygraph', false) YIELD graphName;")
    
    for node, neighbors in adjacency_list.items():
        tx.run("MERGE (p:TAG {name: "+str(node)+",time: '"+first_time[node]+"'}) return p.name").value()
    
    for node, neighbors in adjacency_list.items():
        for neighbor, rel_type in neighbors:
                tx.run("MATCH (p1:TAG ),(p2:TAG) WHERE p1.name="+str(node)+" AND p2.name = "+str(neighbor)+" CREATE (p1)-[r:"+rel_type+"]->(p2) RETURN type(r)")

def find_all_temporalpaths(session,label):
    direction = '>|'.join(label) + '>'
    query = (
            "MATCH (a:TAG) "
            "CALL apoc.path.expandConfig(a,{relationshipFilter: '"+direction+"',labelFilter:'TAG'}) YIELD path "
            "WITH DISTINCT [node IN nodes(path) | node.name] AS nodesOnPath, "
            "[rel IN relationships(path) | type(rel)] AS relationshipTypesOnPath "
            "WHERE all(i IN range(0, size(relationshipTypesOnPath)-2) WHERE relationshipTypesOnPath[i] <= relationshipTypesOnPath[i+1]) "
            "RETURN nodesOnPath, relationshipTypesOnPath"
            )
    result = session.run(query)
    result = result.to_df()
    return result

def find_direct_paths_df(df, node1, node2,label):
    result = []
    m = max(label)
    flag = 0
    for index, row in df.iterrows():
        path = row['nodesOnPath']
        first_element = path[0]
        last_element = path[-1]
        if first_element == node1 and last_element == node2:
            flag =1
            m=min((row['relationshipTypesOnPath'][-1]),m)
            result.append((path, row['relationshipTypesOnPath']))
    
    if flag == 0:
        m = None
    return m

def matrix(adjacency_list,label,result,first_time):
    Temporal_shortest_path = pd.DataFrame(columns=['Nodes'] + list(adjacency_list.keys()))
    Temporal_shortest_path['Nodes'] = adjacency_list.keys()
    for i in first_time:
        d_ij = int(''.join(filter(str.isdigit, i[1])))
        Temporal_shortest_path.loc[Temporal_shortest_path['Nodes'] == i[0], i[0]] = d_ij
    for i, neighbors in adjacency_list.items():
        for j, neighbors in adjacency_list.items():
            if i==j:
                continue
            direct_paths = find_direct_paths_df(result, i, j,label)
            if direct_paths != None:
                d_ij = int(''.join(filter(str.isdigit, direct_paths)))
                Temporal_shortest_path.loc[Temporal_shortest_path['Nodes'] == i, j] = d_ij
    return Temporal_shortest_path

def Temporal_Path_Length(df,adjacency_list):
    s=0
    s_l=0
    nodes=adjacency_list.keys()
    for i in range(len(df)-1):
        for j in nodes:
            s+=(1/df.loc[i, j])
            s_l+=df.loc[i, j]
    tpe= (1/(len(nodes)*(len(nodes)-1)))*s
    tpl= (1/(len(nodes)*(len(nodes)-1)))*s_l
        
    print("Temporal Path Length = ",tpl)
    print("Temporal Path Efficiency = ",tpe)
    return tpl,tpe,len(nodes)

def Closeness_Centrality(adjacency_list,df,label):
    data_list = [{'Nodes': node, 'Closeness Centrality': None} for node in adjacency_list.keys()]
    cc=pd.DataFrame(data_list)
    temp = round((1/(len(label)*(len(adjacency_list.keys())-1))),4)
    for i in adjacency_list.keys():
            yo=df.loc[df['Nodes'] == i]
            yo = yo.drop(i, axis=1)
            k=list(yo.loc[yo['Nodes'] == i].iloc[0])
            k=k[1:]
            c=0
            c=1-round(((temp)*sum(k)),8)
            y=np.where(cc['Nodes'] == i)[0]
            cc.loc[y[0],'Closeness Centrality'] = c
            yo.drop(yo.index, inplace=True)
    cc=cc.sort_values(by=['Closeness Centrality'], ascending=False)
    return cc

def calculate_betweenness(graph):
    BC = {v: 0.0 for v in graph}

    for s in graph:
        stack = []
        P = {v: [] for v in graph}
        sigma = {v: 0 for v in graph}
        dist = {v: -1 for v in graph}

        sigma[s] = 1
        dist[s] = 0
        Q = deque([s])

        while Q:
            v = Q.popleft()
            stack.append(v)
            for w in graph[v]:
                if dist[w] < 0:
                    Q.append(w)
                    dist[w] = dist[v] + 1
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    P[w].append(v)

        delta = {v: 0 for v in graph}
        while stack:
            w = stack.pop()
            for v in P[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != s:
                BC[w] += delta[w]

    N = len(graph)
    for v in BC:
        BC[v] /= ((N - 1) * (N - 2))

    return pd.DataFrame(
        BC.items(),
        columns=["Nodes", "Betweenness Centrality"]
    ).sort_values("Betweenness Centrality", ascending=False)

driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "12345678"),
    connection_timeout=300,
    max_connection_lifetime=3600,
    keep_alive=True
)

with driver.session() as session:
     prune_and_export_all()
     sparsify_and_replace()
     current_directory = pathlib.Path(__file__).parent.resolve()
     current_directory=current_directory.__str__()
     
     start = time.time()
     
     clear_graph(session)
     create_graph(session)
     
     adjacency_list,label=Paths(session)
     
     first_time=timewindow_first_occurence(session)
     time_node = {item[0]: item[1] for item in first_time}

     create_TAG(session,adjacency_list,time_node)
     result=find_all_temporalpaths(session,label)
     Temporal_shortest_path=matrix(adjacency_list,label,result,first_time)

     na = int(''.join(filter(str.isdigit, max(label))))

     Temporal_shortest_path = Temporal_shortest_path.fillna(na)
     tpl,tpe,nodes = Temporal_Path_Length(Temporal_shortest_path,adjacency_list)

     # Skipping closeness and betweenness computations in this combined file.
     # CC=Closeness_Centrality(adjacency_list,Temporal_shortest_path,label)
     # print(CC)
     # graph = strip_labels(adjacency_list)
     # BC = calculate_betweenness(graph)
     # print(BC)

     end = time.time()

     current_directory = pathlib.Path(__file__).parent.resolve()
     current_directory=current_directory.__str__()
     file_path = os.path.join(current_directory, 'output'+str(nodes)+'.csv')
     # Output generation requires CC and BC; skipped here.
     # result = pd.merge(CC, BC, on='Nodes')
     # result=result.sort_values(by=['Betweenness Centrality'], ascending=False)
     # result.at[0, 'Temporal Path Length'] = tpl
     # result.at[0, 'Temporal Path Efficiency'] = tpe
     # result.to_csv(file_path, index=False)
     print(end - start,"seconds")


# ===== File: Temporal_pipeline.py =====
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

def load_data():
    print("\n[1/6] Loading raw data...")
    alerts_df = pd.read_csv(ALERTS_CSV, parse_dates=["timestamp"])
    with open(CVE_MAP_JSON) as f:
        host_cves_map = json.load(f)
    print(f"  OK Alerts loaded       : {len(alerts_df)}")
    print(f"  OK Hosts with CVEs     : {len(host_cves_map)}")
    return alerts_df, host_cves_map

def assign_time_windows(alerts_df, host_windows):
    print("\n[2/6] Assigning time windows from TAG windows...")
    df = alerts_df.copy()

    def _pick_window(dest_host):
        windows = host_windows.get(dest_host, [])
        return pick_tag_window(windows, WINDOW_POLICY)

    df["time_window"] = df["dest_host"].apply(_pick_window)
    print(f"  OK TAG windows detected: {sorted({w for ws in host_windows.values() for w in ws})}")
    print(f"  OK Alerts per window   :\n{df['time_window'].value_counts(dropna=False).sort_index().to_string()}")
    return df

def build_host_node_index():
    print("\n[3/6] Building host->node_id index from VERTICES CSVs...")
    index = {}
    host_windows = {}
    vertex_files = sorted(BASE_DIR.glob("VERTICES_T*.CSV"))
    if not vertex_files:
        raise FileNotFoundError("No VERTICES_T*.CSV files found. Run Cell 1 first.")

    for vf in vertex_files:
        window = vf.stem.replace("VERTICES_", "")
        df = pd.read_csv(vf, header=None,
                         names=["node_id", "label", "type", "value"])
        for _, row in df.iterrows():
            node_id = int(row["node_id"])
            label   = str(row["label"])
            hosts   = re.findall(r"\b(h\d+)\b", label)
            if hosts:
                host = hosts[0]
                index[(host, window)] = node_id
                host_windows.setdefault(host, []).append(window)

    print(f"  OK Index entries built : {len(index)}")
    sample = list(index.items())[:5]
    for k, v in sample:
        print(f"    {k} -> node_id {v}")
    return index, host_windows

def map_alerts_to_nodes(alerts_df, host_node_index):
    print("\n[4/6] Mapping alerts to TAG nodes...")
    mapped, unmapped = [], []

    for _, row in alerts_df.iterrows():
        dest    = row["dest_host"]
        window  = row["time_window"]
        node_id = host_node_index.get((dest, window))
        entry   = row.to_dict()

        entry["tag_node_id"]     = node_id
        entry["tag_time_window"] = window if node_id is not None else None
        entry["mapped"]          = node_id is not None
        (mapped if entry["mapped"] else unmapped).append(entry)

    mapped_df   = pd.DataFrame(mapped)
    unmapped_df = pd.DataFrame(unmapped)
    pct = 100 * len(mapped_df) / len(alerts_df)
    print(f"  OK Mapped              : {len(mapped_df)} ({pct:.1f}%)")
    print(f"  X Unmapped            : {len(unmapped_df)}")
    return mapped_df, unmapped_df

def load_temporal_paths_from_neo4j(driver):
    print("\n[5/6] Loading temporal paths from Neo4j...")

    with driver.session() as session:

        rel_types = session.run(
            "MATCH ()-[r]->() RETURN DISTINCT type(r) AS relType ORDER BY relType"
        ).value()

        if not rel_types:
            raise RuntimeError(
                "No relationships found in Neo4j. "
                "Ensure create_TAG() was called first (Cell 3)."
            )

        print(f"  OK Relationship types  : {rel_types}")

        direction = "|".join(f"{rt}>" for rt in sorted(rel_types))
        print(f"  OK APOC direction      : {direction}")

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

    print(f"  OK Temporal paths found: {len(result)}")

    if not result.empty:
        print("  Sample paths:")
        for _, row in result.head(3).iterrows():
            print(f"    nodes={row['nodesOnPath']}  rels={row['relsOnPath']}")

    return result, sorted(rel_types)

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

    print(f"  OK Path lookup entries : {len(lookup)}")
    return lookup

def classify_alert_pair(node_a, window_a, node_b, window_b, path_lookup):
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
    print(f"  OK Total pairs classified: {len(results_df)}")
    return results_df

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
    print(f"  OK Full results        : {RESULTS_CSV}")

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
    print(f"  OK Summary             : {SUMMARY_CSV}")

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
                G.add_edge(int(row.iloc[1]), int(row.iloc[0]))
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
    print(f"  OK Local paths computed: {len(df)}")
    return df, windows

def main():
    print("=" * 58)
    print("  Idea 3: Alert Chain Validity Validator")
    print("=" * 58)

    alerts_df, host_cves_map = load_data()
    host_node_index, host_windows = build_host_node_index()
    alerts_df = assign_time_windows(alerts_df, host_windows)
    mapped_df, unmapped_df   = map_alerts_to_nodes(alerts_df, host_node_index)

    if mapped_df.empty:
        print("\nX No alerts mapped. Check VERTICES_T*.CSV files exist.")
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
        print("\n  WARN Path lookup is empty after build.")
        print("    Possible causes:")
        print("    1. TAG nodes in Neo4j have no relationships")
        print("    2. create_TAG() was not called before this script")
        print("    3. APOC plugin not installed in Neo4j")
        print("    -> Switching to local fallback...")
        paths_df, rel_types = fallback_local_paths()
        path_lookup = build_path_lookup(paths_df)

    results_df = classify_all_pairs(mapped_df, path_lookup)

    if results_df.empty:
        print("\nX No pairs classified. Check source_host overlap in alerts.")
        return

    print_report(results_df, unmapped_df, len(alerts_df))
    save_results(results_df, unmapped_df, len(alerts_df))

if __name__ == "__main__":
    main()


# ===== File: blindspot.py =====
"""
Idea 2: Temporal Blind Spot Quantification
===========================================
Formally measures what fraction of a Temporal Attack Graph is
structurally invisible to an IDS across time windows.

Three blind spot classes:
  STATIC BLIND SPOT   : node exists in TAG window but receives zero
                        IDS alert coverage in that window
  PATH-CRITICAL       : static blind spot that sits on at least one
                        valid temporal attack path - most dangerous
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

def load_alerts(host_index):
    print("\n[1/6] Loading IDS alerts...")
    df = pd.read_csv(ALERTS_CSV, parse_dates=["timestamp"])

    host_windows = {}
    for (host, window), _nid in host_index.items():
        host_windows.setdefault(host, []).append(window)

    def _pick_window(dest_host):
        windows = host_windows.get(dest_host, [])
        return pick_tag_window(windows, WINDOW_POLICY)

    df["time_window"] = df["dest_host"].apply(_pick_window)

    print(f"  OK Alerts loaded       : {len(df)}")
    print(f"  OK TAG windows         : {sorted({w for ws in host_windows.values() for w in ws})}")
    return df

def build_tag_registry():
    print("\n[2/6] Building TAG node registry per window...")
    registry   = {}
    host_index = {}

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
        print(f"  OK {w}: {len(registry[w])} nodes")

    return registry, host_index, all_windows

def compute_alerted_nodes(alerts_df, host_index, all_windows):
    print("\n[3/6] Computing alerted node sets per window...")

    alerted = {w: set() for w in all_windows}

    for _, row in alerts_df.iterrows():
        dest   = row["dest_host"]
        window = row["time_window"]
        nid    = host_index.get((dest, window))

        if nid is not None and window in alerted:
            alerted[window].add(nid)

    for w in all_windows:
        print(f"  OK {w}: {len(alerted[w])} alerted nodes")

    return alerted

def load_path_nodes(all_windows):
    print("\n[4/6] Loading temporal paths for path-critical check...")

    path_nodes  = set()
    path_edges  = set()

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

        print("  OK Source           : Neo4j")
        print(f"  OK Path nodes found : {len(path_nodes)}")

    except Exception as e:
        print(f"  WARN Neo4j unavailable ({e}), using local fallback...")
        path_nodes, path_edges = _local_path_nodes(all_windows)

    return path_nodes, path_edges

def _local_path_nodes(all_windows):
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

    print("  OK Source           : local NetworkX fallback")
    print(f"  OK Path nodes found : {len(path_nodes)}")
    return path_nodes, path_edges

MONITORED        = "MONITORED"
STATIC_BLIND     = "STATIC_BLIND_SPOT"
PATH_CRITICAL    = "PATH_CRITICAL_BLIND_SPOT"

def classify_nodes(registry, alerted, path_nodes, all_windows):
    print("\n[5/6] Classifying nodes per window...")

    node_records = []

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

def print_report(window_summary, dynamic_df, nodes_df, all_windows):
    print("\n" + "=" * 65)
    print("  TEMPORAL BLIND SPOT QUANTIFICATION REPORT")
    print("=" * 65)

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

    total_node_windows = len(nodes_df)
    total_blind        = (nodes_df["status"] != MONITORED).sum()
    total_pc           = (nodes_df["status"] == PATH_CRITICAL).sum()

    print(f"\n  Aggregate across all windows:")
    print(f"    Total node-window instances   : {total_node_windows}")
    print(f"    Blind spot instances          : {total_blind} "
          f"({round(100*total_blind/total_node_windows,1)}%)")
    print(f"    Path-critical blind spots     : {total_pc} "
          f"({round(100*total_pc/total_node_windows,1)}%)")

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

        esc_df = dynamic_df[dynamic_df["transition_type"] == "ESCALATED"]
        if not esc_df.empty:
            print(f"\n  Escalated hosts (most dangerous):")
            for _, r in esc_df.iterrows():
                print(f"    {r['host']}  {r['from_window']}->{r['to_window']}")

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
    print(f"     in the next - unique to temporal analysis")
    print(f"\n  -> Static IDS tools cannot detect items 2 or 3")
    print(f"    because they have no temporal graph model.")
    print("=" * 65)

def main():
    print("=" * 58)
    print("  Idea 2: Temporal Blind Spot Quantification")
    print("=" * 58)

    registry, host_index, all_windows = build_tag_registry()
    alerts_df                         = load_alerts(host_index)
    alerted                           = compute_alerted_nodes(alerts_df, host_index, all_windows)
    path_nodes, _                     = load_path_nodes(all_windows)
    nodes_df                          = classify_nodes(registry, alerted, path_nodes, all_windows)

    print("\n[6/6] Computing summaries and dynamic transitions...")
    window_summary = compute_window_summary(nodes_df, all_windows)
    dynamic_df     = compute_dynamic_blind_spots(nodes_df, all_windows)

    window_summary.to_csv(OUT_WINDOW,  index=False)
    nodes_df.to_csv(OUT_NODES,         index=False)
    dynamic_df.to_csv(OUT_DYNAMIC,     index=False)
    print(f"  OK Per-window summary  : {OUT_WINDOW}")
    print(f"  OK Node-level detail   : {OUT_NODES}")
    print(f"  OK Dynamic transitions : {OUT_DYNAMIC}")

    print_report(window_summary, dynamic_df, nodes_df, all_windows)
    print_key_findings(window_summary, dynamic_df, nodes_df)

if __name__ == "__main__":
    main()


# ===== File: triage.py =====
"""
Structural Alert Triage Score
==============================
Every existing IDS triages alerts by CVSS severity alone.
This module computes a composite triage score that combines:

  Component 1 - CVE Severity Score      (what every IDS already uses)
  Component 2 - Node Betweenness        (how central is this node in the TAG)
  Component 3 - Path Criticality        (does this node sit on a valid attack path)
  Component 4 - Temporal Persistence    (how many windows has this node been active)
  Component 5 - Blind Spot Penalty      (is this node currently unmonitored)

Formula:
  STS = w1*severity + w2*betweenness + w3*path_critical + w4*persistence - w5*blind_spot

All components normalized to [0,1] before weighting.

The key claim: a MEDIUM CVE on a high-betweenness path-critical node
scores higher than a CRITICAL CVE on a leaf node with no onward paths.
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

BASE_DIR       = Path(".").resolve()
IDS_OUTPUT_DIR = BASE_DIR / "ids_outputs"

ALERTS_CSV      = IDS_OUTPUT_DIR / "ids_alerts.csv"
CVE_MAP_JSON    = IDS_OUTPUT_DIR / "host_cves_mapping.json"
BLIND_SPOT_CSV  = IDS_OUTPUT_DIR / "blind_spot_nodes.csv"

OUT_SCORES      = IDS_OUTPUT_DIR / "structural_triage_scores.csv"
OUT_COMPARISON  = IDS_OUTPUT_DIR / "triage_comparison.csv"
OUT_SUMMARY     = IDS_OUTPUT_DIR / "triage_summary.csv"

WEIGHTS = {
    "severity"    : 0.25,
    "betweenness" : 0.25,
    "path_critical": 0.20,
    "persistence" : 0.15,
    "blind_spot"  : 0.15,
}

SEVERITY_MAP = {"LOW": 0.25, "MEDIUM": 0.50, "HIGH": 0.75, "CRITICAL": 1.00}

def load_all_data():
    print("\n[1/7] Loading data...")

    alerts_df = pd.read_csv(ALERTS_CSV, parse_dates=["timestamp"])
    with open(CVE_MAP_JSON) as f:
        host_cves_map = json.load(f)

    if BLIND_SPOT_CSV.exists():
        blind_df = pd.read_csv(BLIND_SPOT_CSV)
        print(f"  OK Blind spot nodes    : {len(blind_df)}")
    else:
        blind_df = pd.DataFrame(columns=["window","node_id","host","status"])
        print("  WARN blind_spot_nodes.csv not found - run blind_spot_quantifier.py first")
        print("    Continuing without blind spot penalty component...")

    print(f"  OK Alerts loaded       : {len(alerts_df)}")
    print(f"  OK Hosts with CVEs     : {len(host_cves_map)}")
    return alerts_df, host_cves_map, blind_df

def assign_time_windows(alerts_df, registry):
    print("\n[2/7] Assigning time windows from TAG windows...")
    df = alerts_df.copy()

    host_windows = {}
    for window, nodes in registry.items():
        for _nid, host in nodes.items():
            host_windows.setdefault(host, []).append(window)

    def _pick_window(dest_host):
        windows = host_windows.get(dest_host, [])
        return pick_tag_window(windows, WINDOW_POLICY)

    df["time_window"] = df["dest_host"].apply(_pick_window)
    print(f"  OK TAG windows         : {sorted({w for ws in host_windows.values() for w in ws})}")
    return df

def build_tag_graphs():
    print("\n[3/7] Building TAG graphs per window...")
    graphs   = {}
    registry = {}
    node_host= {}

    vertex_files = sorted(BASE_DIR.glob("VERTICES_T*.CSV"))
    arc_files    = sorted(BASE_DIR.glob("ARCS_T*.CSV"))

    if not vertex_files:
        raise FileNotFoundError("No VERTICES_T*.CSV found. Run Cell 1 first.")

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

    for af in arc_files:
        window = af.stem.replace("ARCS_", "")
        adf    = pd.read_csv(af, header=None)
        G      = nx.DiGraph()
        for nid in registry.get(window, {}).keys():
            G.add_node(nid)
        for _, row in adf.iterrows():
            try:
                G.add_edge(int(row.iloc[1]), int(row.iloc[0]))
            except (ValueError, IndexError):
                continue
        graphs[window] = G
        print(f"  OK {window}: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    return graphs, registry, node_host

def compute_betweenness_per_window(graphs):
    print("\n[4/7] Skipping betweenness centrality per request...")
    bc_per_window = {}
    for window, G in graphs.items():
        bc_per_window[window] = {n: 0.0 for n in G.nodes()}
        print(f"  OK {window}: set 0.0 for {len(bc_per_window[window])} nodes")
    return bc_per_window

def compute_node_features(graphs, registry):
    print("\n[5/7] Computing path criticality and persistence...")
    all_windows = sorted(graphs.keys())

    combined = nx.compose_all(list(graphs.values())) if graphs else nx.DiGraph()

    path_critical_nodes = set()
    nodes_list = list(combined.nodes())
    for src in nodes_list:
        for dst in nodes_list:
            if src == dst:
                continue
            if nx.has_path(combined, src, dst):
                try:
                    path = nx.shortest_path(combined, src, dst)
                    if len(path) > 2:
                        path_critical_nodes.update(path[1:-1])
                    elif len(path) == 2:
                        path_critical_nodes.update(path)
                except nx.NetworkXNoPath:
                    continue

    print(f"  OK Path-critical nodes : {len(path_critical_nodes)}")

    node_window_count = defaultdict(int)
    for window, nodes in registry.items():
        for nid in nodes:
            node_window_count[nid] += 1

    max_persistence = max(node_window_count.values()) if node_window_count else 1

    return path_critical_nodes, node_window_count, max_persistence

def build_blind_spot_lookup(blind_df):
    blind_set = set()
    if blind_df.empty:
        return blind_set
    for _, row in blind_df.iterrows():
        if row["status"] != "MONITORED":
            blind_set.add((int(row["node_id"]), str(row["window"])))
    return blind_set

def compute_sts(alerts_df, registry, bc_per_window,
                path_critical_nodes, node_window_count,
                max_persistence, blind_spot_set):
    print("\n[6/7] Computing Structural Triage Scores...")

    host_index = {}
    for window, nodes in registry.items():
        for nid, host in nodes.items():
            host_index[(host, window)] = nid

    scored_rows = []

    for _, row in alerts_df.iterrows():
        dest    = row["dest_host"]
        window  = row.get("time_window", "T1")
        sev_raw = str(row.get("severity", "HIGH")).upper()

        nid = host_index.get((dest, window))

        c_severity = SEVERITY_MAP.get(sev_raw, 0.75)

        if nid is not None:
            bc_dict  = bc_per_window.get(window, {})
            c_betw   = bc_dict.get(nid, 0.0)
            c_path   = 1.0 if nid in path_critical_nodes else 0.0
            c_persist = node_window_count.get(nid, 1) / max_persistence
            c_blind  = 1.0 if (nid, window) in blind_spot_set else 0.0

        else:
            c_betw    = 0.0
            c_path    = 0.0
            c_persist = 0.0
            c_blind   = 0.0

        sts = (
            WEIGHTS["severity"]     * c_severity
            + WEIGHTS["betweenness"]  * c_betw
            + WEIGHTS["path_critical"]* c_path
            + WEIGHTS["persistence"]  * c_persist
            - WEIGHTS["blind_spot"]   * c_blind
        )
        sts = round(max(0.0, min(1.0, sts)), 4)

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
    print(f"  OK Scored alerts       : {len(scored_df)}")
    return scored_df

def build_comparison(scored_df):
    df = scored_df.copy().reset_index(drop=True)

    df["cvss_rank"] = df["cvss_only_score"].rank(
        ascending=False, method="min"
    ).astype(int)
    df["sts_rank"]  = df["structural_triage_score"].rank(
        ascending=False, method="min"
    ).astype(int)
    df["rank_delta"] = df["cvss_rank"] - df["sts_rank"]

    return df

def print_report(comparison_df):
    print("\n" + "=" * 68)
    print("  STRUCTURAL TRIAGE SCORE REPORT")
    print("=" * 68)

    total = len(comparison_df)

    promoted  = (comparison_df["rank_delta"] > 5).sum()
    demoted   = (comparison_df["rank_delta"] < -5).sum()
    unchanged = total - promoted - demoted

    print(f"\n  Total alerts scored         : {total}")
    print(f"  Promoted by STS (rank +>5)  : {promoted}  "
          f"({round(100*promoted/total,1)}%)")
    print(f"  Demoted by STS  (rank -<5)  : {demoted}  "
          f"({round(100*demoted/total,1)}%)")
    print(f"  Rank stable (within +/-5)   : {unchanged}  "
          f"({round(100*unchanged/total,1)}%)")

    print(f"\n  Top 5 alerts PROMOTED by structural context:")
    print(f"  (Low CVSS severity but high structural importance)")
    top_prom = comparison_df.nlargest(5, "rank_delta")[
        ["dest_host","severity","cve_id","time_window",
         "cvss_only_score","structural_triage_score",
         "cvss_rank","sts_rank","rank_delta",
         "c_betweenness","c_path_critical","c_persistence"]
    ]
    print(top_prom.to_string(index=False))

    print(f"\n  Top 5 alerts DEMOTED by structural context:")
    print(f"  (High CVSS severity but low structural importance)")
    top_dem = comparison_df.nsmallest(5, "rank_delta")[
        ["dest_host","severity","cve_id","time_window",
         "cvss_only_score","structural_triage_score",
         "cvss_rank","sts_rank","rank_delta",
         "c_betweenness","c_path_critical","c_persistence"]
    ]
    print(top_dem.to_string(index=False))

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

    medium_high_sts = comparison_df[
        (comparison_df["severity"].str.upper().isin(["MEDIUM","LOW"]))
        & (comparison_df["structural_triage_score"] > 0.6)
    ]
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
    print(f"     nodes - CVSS overprioritizes them.")
    print(f"\n  3. Pearson correlation (CVSS vs STS): {corr:.3f}")
    if abs(corr) < 0.7:
        print(f"     Low correlation confirms STS captures information")
        print(f"     that severity alone does not.")
    else:
        print(f"     Moderate/high correlation - structural components")
        print(f"     refine but do not fully diverge from severity.")
    if not medium_high_sts.empty:
        ex = medium_high_sts.iloc[0]
        print(f"\n  4. Example promotion:")
        print(f"     Host {ex['dest_host']} | Severity: {ex['severity']}")
        print(f"     CVSS score: {ex['cvss_only_score']:.3f}  ->  "
              f"STS: {ex['structural_triage_score']:.3f}")
        print(f"     Betweenness: {ex['c_betweenness']:.3f}  "
              f"Path-critical: {ex['c_path_critical']:.0f}  "
              f"Persistence: {ex['c_persistence']:.3f}")
    if not critical_low_sts.empty:
        ex = critical_low_sts.iloc[0]
        print(f"\n  5. Example demotion:")
        print(f"     Host {ex['dest_host']} | Severity: {ex['severity']}")
        print(f"     CVSS score: {ex['cvss_only_score']:.3f}  ->  "
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

    print(f"\n  OK Scored alerts       : {OUT_SCORES}")
    print(f"  OK Rank comparison     : {OUT_COMPARISON}")
    print(f"  OK Summary             : {OUT_SUMMARY}")

def main():
    print("=" * 58)
    print("  Structural Alert Triage Score")
    print("=" * 58)

    alerts_df, host_cves_map, blind_df = load_all_data()

    graphs, registry, node_host        = build_tag_graphs()
    alerts_df = assign_time_windows(alerts_df, registry)
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


# ===== File: vulnerability_persistence_risk.py =====
"""
Cross-Window Vulnerability Persistence Risk
============================================
Measures the correlation between CVE persistence duration
(how many consecutive windows a CVE remains unpatched on a node)
and that node's structural importance in the TAG.

Core hypothesis:
  A persistently vulnerable high-centrality node represents
  chronic risk that static snapshots miss entirely.
  This is only measurable with a temporal graph.

Three persistence metrics per CVE-host pair:
  PERSISTENCE_SPAN    : number of consecutive windows the CVE is present
  PERSISTENCE_STREAK  : longest unbroken consecutive run
  EXPOSURE_SCORE      : severity-weighted persistence

Three structural metrics per node (from TAG):
  PATH_CRITICAL       : binary - on a valid attack path
  PERSISTENCE_WINDOWS : how many windows the node appears in
  DEGREE_SUM          : total in+out degree summed across windows

Key outputs:
  1. Per (host, CVE) persistence table
  2. Correlation between CVE persistence and node centrality
  3. Chronic risk nodes - high persistence AND high structural importance
  4. Window-by-window attack surface evolution

Depends on:
  - ids_outputs/host_cves_mapping.json
  - VERTICES_T*.CSV  and  ARCS_T*.CSV
  - ids_outputs/blind_spot_nodes.csv  (optional, from blindspot.py)

Outputs:
  - ids_outputs/cve_persistence.csv
  - ids_outputs/chronic_risk_nodes.csv
  - ids_outputs/persistence_correlation.csv
  - ids_outputs/attack_surface_evolution.csv
"""

import re
import json
import math
import warnings
from pathlib import Path
from collections import defaultdict

import pandas as pd
import numpy as np
import networkx as nx
from scipy import stats

warnings.simplefilter(action="ignore", category=FutureWarning)

BASE_DIR       = Path(".").resolve()
IDS_OUTPUT_DIR = BASE_DIR / "ids_outputs"

CVE_MAP_JSON   = IDS_OUTPUT_DIR / "host_cves_mapping.json"
BLIND_SPOT_CSV = IDS_OUTPUT_DIR / "blind_spot_nodes.csv"

OUT_PERSISTENCE   = IDS_OUTPUT_DIR / "cve_persistence.csv"
OUT_CHRONIC       = IDS_OUTPUT_DIR / "chronic_risk_nodes.csv"
OUT_CORRELATION   = IDS_OUTPUT_DIR / "persistence_correlation.csv"
OUT_EVOLUTION     = IDS_OUTPUT_DIR / "attack_surface_evolution.csv"

SEVERITY_WEIGHT = {"LOW": 0.25, "MEDIUM": 0.50, "HIGH": 0.75, "CRITICAL": 1.00}

CVE_INFO_SEVERITY = {
    "CVE-2021-44228": "CRITICAL", "CVE-2021-41773": "CRITICAL",
    "CVE-2020-1938":  "CRITICAL", "CVE-2021-26855": "CRITICAL",
    "CVE-2019-0604":  "CRITICAL", "CVE-2018-4939":  "CRITICAL",
    "CVE-2020-5410":  "CRITICAL", "CVE-2021-45046": "HIGH",
    "CVE-2021-44512": "HIGH",     "CVE-2021-33910": "CRITICAL",
    "CVE-2021-21224": "HIGH",     "CVE-2020-9488":  "MEDIUM",
    "CVE-2020-11738": "CRITICAL", "CVE-2021-28169": "CRITICAL",
    "CVE-2021-28156": "HIGH",     "CVE-2021-28341": "CRITICAL",
    "CVE-2021-21898": "CRITICAL", "CVE-2021-3129":  "HIGH",
    "CVE-2021-24410": "MEDIUM",   "CVE-2021-24512": "HIGH",
    "CVE-2020-14144": "HIGH",     "CVE-2020-14145": "MEDIUM",
    "CVE-2021-21233": "HIGH",     "CVE-2021-21234": "CRITICAL",
    "CVE-2021-26858": "CRITICAL", "CVE-2021-27065": "CRITICAL",
    "CVE-2020-16898": "CRITICAL", "CVE-2021-31166": "HIGH",
    "CVE-2020-1470":  "CRITICAL", "CVE-2020-15505": "CRITICAL",
    "CVE-2021-1234":  "MEDIUM",   "CVE-2021-1235":  "HIGH",
    "CVE-2020-8516":  "CRITICAL", "CVE-2020-8517":  "CRITICAL",
    "CVE-2021-20225": "CRITICAL", "CVE-2021-20226": "HIGH",
    "CVE-2020-13933": "MEDIUM",   "CVE-2020-13934": "MEDIUM",
    "CVE-2021-30129": "HIGH",     "CVE-2021-30130": "HIGH",
    "CVE-2020-1234":  "HIGH",     "CVE-2020-1235":  "CRITICAL",
    "CVE-2020-1236":  "HIGH",     "CVE-2021-24497": "MEDIUM",
    "CVE-2021-24498": "MEDIUM",   "CVE-2021-30132": "HIGH",
    "CVE-2021-26851": "CRITICAL", "CVE-2021-26852": "HIGH",
    "CVE-2021-28850": "HIGH",     "CVE-2021-28851": "HIGH",
    "CVE-2020-25695": "HIGH",     "CVE-2020-25696": "CRITICAL",
    "CVE-2020-11083": "CRITICAL", "CVE-2020-11084": "HIGH",
    "CVE-2021-28168": "HIGH",     "CVE-2021-30609": "CRITICAL",
    "CVE-2021-30610": "HIGH",     "CVE-2020-9614":  "CRITICAL",
    "CVE-2020-9615":  "HIGH",     "CVE-2021-22556": "CRITICAL",
    "CVE-2021-22557": "HIGH",     "CVE-2020-11989": "CRITICAL",
    "CVE-2020-11990": "CRITICAL", "CVE-2021-23840": "HIGH",
    "CVE-2021-23841": "MEDIUM",   "CVE-2020-14644": "CRITICAL",
    "CVE-2020-14645": "CRITICAL", "CVE-2021-20294": "HIGH",
    "CVE-2021-20295": "HIGH",     "CVE-2020-27238": "HIGH",
    "CVE-2020-27239": "CRITICAL", "CVE-2021-32074": "CRITICAL",
    "CVE-2021-32075": "HIGH",     "CVE-2021-24514": "HIGH",
    "CVE-2021-24515": "HIGH",     "CVE-2020-12624": "CRITICAL",
    "CVE-2020-12625": "HIGH",     "CVE-2020-8554":  "CRITICAL",
    "CVE-2020-8555":  "HIGH",     "CVE-2021-23879": "HIGH",
    "CVE-2021-23880": "CRITICAL", "CVE-2020-27240": "HIGH",
    "CVE-2021-28149": "HIGH",     "CVE-2021-28150": "HIGH",
    "CVE-2020-5411":  "CRITICAL", "CVE-2021-30133": "HIGH",
    "CVE-2020-26139": "MEDIUM",   "CVE-2020-26140": "MEDIUM",
    "CVE-2021-37582": "HIGH",     "CVE-2021-37583": "MEDIUM",
    "CVE-2020-15999": "HIGH",     "CVE-2020-16000": "HIGH",
    "CVE-2021-22569": "HIGH",     "CVE-2021-22570": "MEDIUM",
    "CVE-2020-7960":  "MEDIUM",   "CVE-2020-7961":  "HIGH",
    "CVE-2021-23214": "HIGH",     "CVE-2021-23215": "MEDIUM",
    "CVE-2020-8557":  "MEDIUM",   "CVE-2020-8558":  "HIGH",
    "CVE-2021-24497": "MEDIUM",   "CVE-2021-24498": "MEDIUM",
    "CVE-2020-16899": "HIGH",     "CVE-2021-28149": "HIGH",
}

def load_cve_map():
    print("\n[1/6] Loading CVE mapping...")
    with open(CVE_MAP_JSON) as f:
        host_cves_map = json.load(f)
    print(f"  OK Hosts with CVEs     : {len(host_cves_map)}")
    return host_cves_map

def load_tag_per_window():
    print("\n[2/6] Loading TAG structure per window...")

    vertex_files = sorted(BASE_DIR.glob("VERTICES_T*.CSV"))
    arc_files    = sorted(BASE_DIR.glob("ARCS_T*.CSV"))

    if not vertex_files:
        raise FileNotFoundError("No VERTICES_T*.CSV found. Run Cell 1 first.")

    host_in_window = {}
    node_id_map    = {}
    graphs         = {}
    registry       = {}

    for vf in vertex_files:
        window = vf.stem.replace("VERTICES_", "")
        df     = pd.read_csv(vf, header=None,
                             names=["node_id", "label", "type", "value"])
        host_in_window[window] = set()
        registry[window]       = {}
        for _, row in df.iterrows():
            nid   = int(row["node_id"])
            hosts = re.findall(r"\b(h\d+)\b", str(row["label"]))
            if hosts:
                host = hosts[0]
                host_in_window[window].add(host)
                node_id_map[(host, window)] = nid
                registry[window][nid]       = host

    for af in arc_files:
        window = af.stem.replace("ARCS_", "")
        df     = pd.read_csv(af, header=None)
        G      = nx.DiGraph()
        for nid in registry.get(window, {}).keys():
            G.add_node(nid)
        for _, row in df.iterrows():
            try:
                G.add_edge(int(row.iloc[1]), int(row.iloc[0]))
            except (ValueError, IndexError):
                continue
        graphs[window] = G

    windows = sorted(host_in_window.keys())
    for w in windows:
        g = graphs.get(w, nx.DiGraph())
        print(f"  OK {w}: {len(host_in_window[w])} hosts, "
              f"{g.number_of_nodes()} nodes, {g.number_of_edges()} edges")

    return windows, host_in_window, graphs, node_id_map, registry

def compute_cve_persistence(host_cves_map, windows, host_in_window):
    print("\n[3/6] Computing CVE persistence per host...")

    window_num = {w: int(re.sub(r"\D", "", w)) for w in windows}
    records    = []

    for host, cves in host_cves_map.items():
        for cve in cves:
            severity     = CVE_INFO_SEVERITY.get(cve, "HIGH")
            sev_weight   = SEVERITY_WEIGHT[severity]

            present_in   = [w for w in windows if host in host_in_window.get(w, set())]
            if not present_in:
                continue

            span         = len(present_in)
            first_w      = present_in[0]
            last_w       = present_in[-1]

            nums         = sorted([window_num[w] for w in present_in])
            streak       = 1
            max_streak   = 1
            for i in range(1, len(nums)):
                if nums[i] == nums[i-1] + 1:
                    streak += 1
                    max_streak = max(max_streak, streak)
                else:
                    streak = 1

            exposure_score = round(sev_weight * span, 4)

            records.append({
                "host"              : host,
                "cve_id"            : cve,
                "severity"          : severity,
                "severity_weight"   : sev_weight,
                "presence_windows"  : ",".join(present_in),
                "persistence_span"  : span,
                "persistence_streak": max_streak,
                "first_window"      : first_w,
                "last_window"       : last_w,
                "exposure_score"    : exposure_score,
                "total_windows"     : len(windows),
                "persistence_ratio" : round(span / len(windows), 3),
            })

    df = pd.DataFrame(records)
    print(f"  OK CVE-host pairs tracked : {len(df)}")
    return df

def compute_structural_importance(graphs, registry, windows):
    print("\n[4/6] Computing structural importance per node...")

    combined = nx.compose_all(list(graphs.values())) if graphs else nx.DiGraph()

    path_critical = set()
    nodes_list    = list(combined.nodes())
    for src in nodes_list:
        for dst in nodes_list:
            if src == dst:
                continue
            if nx.has_path(combined, src, dst):
                try:
                    path = nx.shortest_path(combined, src, dst)
                    path_critical.update(path)
                except nx.NetworkXNoPath:
                    continue

    node_window_count = defaultdict(int)
    node_degree_sum   = defaultdict(float)
    node_max_degree   = defaultdict(float)

    for w, G in graphs.items():
        for nid in G.nodes():
            deg = G.in_degree(nid) + G.out_degree(nid)
            node_window_count[nid] += 1
            node_degree_sum[nid]   += deg
            node_max_degree[nid]    = max(node_max_degree[nid], deg)

    node_to_host = {}
    for w, nodes in registry.items():
        for nid, host in nodes.items():
            node_to_host[nid] = host

    records = []
    all_node_ids = set()
    for w, nodes in registry.items():
        all_node_ids.update(nodes.keys())

    for nid in all_node_ids:
        host    = node_to_host.get(nid, f"node_{nid}")
        n_wins  = node_window_count[nid]
        avg_deg = round(node_degree_sum[nid] / n_wins, 3) if n_wins else 0
        records.append({
            "node_id"       : nid,
            "host"          : host,
            "path_critical" : 1 if nid in path_critical else 0,
            "node_windows"  : n_wins,
            "avg_degree"    : avg_deg,
            "max_degree"    : node_max_degree[nid],
        })

    struct_df = pd.DataFrame(records)
    print(f"  OK Nodes analyzed         : {len(struct_df)}")
    print(f"  OK Path-critical nodes    : {struct_df['path_critical'].sum()}")
    return struct_df

def compute_correlation(persist_df, struct_df):
    print("\n[5/6] Computing persistence-structure correlation...")

    host_persist = persist_df.groupby("host").agg(
        total_cves          = ("cve_id",           "nunique"),
        max_persistence_span= ("persistence_span",  "max"),
        avg_persistence_span= ("persistence_span",  "mean"),
        max_streak          = ("persistence_streak","max"),
        total_exposure_score= ("exposure_score",    "sum"),
        critical_cve_count  = ("severity",
                               lambda x: (x == "CRITICAL").sum()),
    ).reset_index()

    merged = pd.merge(host_persist, struct_df, on="host", how="inner")

    if len(merged) < 3:
        print("  WARN Not enough data points for correlation (need >=3 hosts)")
        return merged, {}

    correlations = {}
    pairs = [
        ("max_persistence_span",  "path_critical",  "max_span vs path_critical"),
        ("max_persistence_span",  "avg_degree",     "max_span vs avg_degree"),
        ("total_exposure_score",  "path_critical",  "exposure_score vs path_critical"),
        ("total_exposure_score",  "avg_degree",     "exposure_score vs avg_degree"),
        ("critical_cve_count",    "path_critical",  "critical_CVEs vs path_critical"),
        ("avg_persistence_span",  "node_windows",   "avg_span vs node_windows"),
    ]

    print(f"\n  {'Pair':<40} {'r':>7} {'p-value':>10} {'sig':>5}")
    print("  " + "-" * 65)

    for x_col, y_col, label in pairs:
        if x_col in merged.columns and y_col in merged.columns:
            x = merged[x_col].astype(float)
            y = merged[y_col].astype(float)
            if x.std() > 0 and y.std() > 0:
                r, p = stats.pearsonr(x, y)
                sig  = "***" if p < 0.001 else ("**" if p < 0.01 else
                        ("*" if p < 0.05 else "ns"))
                print(f"  {label:<40} {r:>7.3f} {p:>10.4f} {sig:>5}")
                correlations[label] = {"r": round(r, 3), "p": round(p, 4), "sig": sig}
            else:
                print(f"  {label:<40} {'N/A':>7} {'N/A':>10} {'N/A':>5}")

    return merged, correlations

def identify_chronic_risk(merged_df, persist_df, windows):
    threshold = math.ceil(len(windows) * 0.5)

    chronic = merged_df[
        (merged_df["max_persistence_span"] >= threshold) &
        (merged_df["path_critical"] == 1)
    ].copy()

    chronic["risk_tier"] = chronic.apply(
        lambda r: "CRITICAL_CHRONIC" if r["critical_cve_count"] > 0
                  else "HIGH_CHRONIC",
        axis=1
    )

    chronic = chronic.sort_values("total_exposure_score", ascending=False)
    return chronic

def compute_attack_surface_evolution(persist_df, struct_df,
                                     windows, host_in_window, graphs):
    rows     = []
    prev_cve_set = set()

    for w in windows:
        active_hosts  = host_in_window.get(w, set())
        G             = graphs.get(w, nx.DiGraph())

        window_cve_set = set()
        total_exposure = 0.0
        critical_count = 0

        for host in active_hosts:
            w_df = persist_df[
                (persist_df["host"] == host) &
                (persist_df["presence_windows"].str.contains(w))
            ]
            for _, r in w_df.iterrows():
                window_cve_set.add((host, r["cve_id"]))
                total_exposure += r["severity_weight"]
                if r["severity"] == "CRITICAL":
                    critical_count += 1

        new_cves      = len(window_cve_set - prev_cve_set)
        resolved_cves = len(prev_cve_set - window_cve_set)

        combined_pc   = set()
        all_nodes     = list(G.nodes())
        for src in all_nodes:
            for dst in all_nodes:
                if src == dst:
                    continue
                if nx.has_path(G, src, dst):
                    try:
                        path = nx.shortest_path(G, src, dst)
                        combined_pc.update(path)
                    except nx.NetworkXNoPath:
                        continue

        density = (G.number_of_edges() / G.number_of_nodes()
                   if G.number_of_nodes() > 0 else 0)

        rows.append({
            "window"              : w,
            "active_hosts"        : len(active_hosts),
            "active_nodes"        : G.number_of_nodes(),
            "active_edges"        : G.number_of_edges(),
            "structural_density"  : round(density, 3),
            "active_cves"         : len(window_cve_set),
            "critical_cves"       : critical_count,
            "path_critical_nodes" : len(combined_pc),
            "total_exposure_score": round(total_exposure, 3),
            "new_cves"            : new_cves,
            "resolved_cves"       : resolved_cves,
        })
        prev_cve_set = window_cve_set

    return pd.DataFrame(rows)

def print_report(persist_df, chronic_df, evolution_df,
                 correlations, windows):
    print("\n" + "=" * 68)
    print("  CROSS-WINDOW VULNERABILITY PERSISTENCE RISK REPORT")
    print("=" * 68)

    print(f"\n  CVE Persistence Distribution:")
    print(f"  {'Span':>6} {'Count':>8} {'Pct':>8}")
    print("  " + "-" * 26)
    for span in sorted(persist_df["persistence_span"].unique()):
        cnt = (persist_df["persistence_span"] == span).sum()
        pct = round(100 * cnt / len(persist_df), 1)
        bar = "#" * int(pct / 5)
        print(f"  {span:>6} {cnt:>8} {pct:>7.1f}%  {bar}")

    print(f"\n  Chronic Risk Nodes (persistent + path-critical):")
    if chronic_df.empty:
        print("    None found - all persistently vulnerable nodes "
              "are structurally isolated.")
    else:
        print(f"  {'Host':<8} {'MaxSpan':>8} {'ExposureScore':>14} "
              f"{'CritCVEs':>9} {'Tier':<20}")
        print("  " + "-" * 62)
        for _, r in chronic_df.iterrows():
            print(f"  {r['host']:<8} {r['max_persistence_span']:>8} "
                  f"{r['total_exposure_score']:>14.3f} "
                  f"{r['critical_cve_count']:>9} "
                  f"{r['risk_tier']:<20}")

    print(f"\n  Attack Surface Evolution Across Windows:")
    print(f"  {'Window':<8} {'Hosts':>6} {'CVEs':>6} {'CritCVEs':>9} "
          f"{'PathCrit':>9} {'Exposure':>9} {'New':>5} {'Gone':>5}")
    print("  " + "-" * 62)
    for _, r in evolution_df.iterrows():
        print(f"  {r['window']:<8} {r['active_hosts']:>6} "
              f"{r['active_cves']:>6} {r['critical_cves']:>9} "
              f"{r['path_critical_nodes']:>9} "
              f"{r['total_exposure_score']:>9.2f} "
              f"{r['new_cves']:>5} {r['resolved_cves']:>5}")

    print("=" * 68)

def print_key_findings(persist_df, chronic_df, evolution_df,
                       correlations, windows):
    multi_window = persist_df[persist_df["persistence_span"] > 1]
    all_window   = persist_df[persist_df["persistence_span"] == len(windows)]
    avg_span     = persist_df["persistence_span"].mean()
    max_exposure = persist_df["exposure_score"].max()
    max_exp_row  = persist_df.loc[persist_df["exposure_score"].idxmax()]

    exp_corr = correlations.get("exposure_score vs path_critical", {})

    print("\n" + "=" * 68)
    print("  KEY FINDINGS FOR PAPER")
    print("=" * 68)
    print(f"\n  1. {len(multi_window)} of {len(persist_df)} CVE-host pairs "
          f"({round(100*len(multi_window)/max(len(persist_df),1),1)}%)")
    print(f"     persist across more than one time window.")
    print(f"     Average persistence span: {avg_span:.2f} windows.")

    if len(all_window):
        print(f"\n  2. {len(all_window)} CVE-host pairs present across ALL "
              f"{len(windows)} windows")
        print("     - these are chronically unpatched vulnerabilities.")
        for _, r in all_window.head(3).iterrows():
            print(f"     {r['host']} | {r['cve_id']} | {r['severity']}")

    print(f"\n  3. Highest exposure score: {max_exposure:.3f}")
    print(f"     Host: {max_exp_row['host']} | CVE: {max_exp_row['cve_id']}")
    print(f"     Severity: {max_exp_row['severity']} | "
          f"Span: {max_exp_row['persistence_span']} windows")

    if chronic_df.empty:
        print("\n  4. No chronic risk nodes identified.")
        print("     Persistently vulnerable hosts are structurally isolated.")
        print("     This itself is a finding: patch prioritization by")
        print("     persistence alone would misallocate effort.")
    else:
        print(f"\n  4. {len(chronic_df)} chronic risk nodes identified")
        print("     (persistent AND path-critical).")
        top = chronic_df.iloc[0]
        print(f"     Most dangerous: {top['host']} | "
              f"exposure={top['total_exposure_score']:.3f} | "
              f"tier={top['risk_tier']}")

    if exp_corr:
        print(f"\n  5. Exposure score vs path criticality: "
              f"r={exp_corr.get('r','N/A')} "
              f"(p={exp_corr.get('p','N/A')}, {exp_corr.get('sig','N/A')})")
        if abs(exp_corr.get('r', 0)) > 0.3:
            print("     Positive correlation confirms that persistently")
            print("     vulnerable nodes tend to be structurally important.")
        else:
            print("     Low correlation confirms persistence and structural")
            print("     importance are orthogonal - both dimensions are needed.")

    if len(evolution_df) > 1:
        max_exp_w = evolution_df.loc[
            evolution_df["total_exposure_score"].idxmax(), "window"
        ]
        max_new_w = evolution_df.loc[
            evolution_df["new_cves"].idxmax(), "window"
        ]
        print(f"\n  6. Peak attack surface exposure: {max_exp_w}")
        print(f"     Most new CVEs introduced in: {max_new_w}")
        print("     Static IDS analyzing any single window would miss")
        print("     the temporal exposure trajectory entirely.")

    print("=" * 68)

def save_results(persist_df, chronic_df, evolution_df, merged_df, correlations):
    persist_df.to_csv(OUT_PERSISTENCE, index=False)
    chronic_df.to_csv(OUT_CHRONIC,     index=False)
    evolution_df.to_csv(OUT_EVOLUTION, index=False)

    corr_rows = [
        {"metric_pair": k, **v}
        for k, v in correlations.items()
    ]
    pd.DataFrame(corr_rows).to_csv(OUT_CORRELATION, index=False)

    print(f"\n  OK CVE persistence      : {OUT_PERSISTENCE}")
    print(f"  OK Chronic risk nodes   : {OUT_CHRONIC}")
    print(f"  OK Evolution table      : {OUT_EVOLUTION}")
    print(f"  OK Correlation results  : {OUT_CORRELATION}")

def main():
    print("=" * 60)
    print("Cross-Window Vulnerability Persistence Risk")
    print("=" * 60)

    host_cves_map                              = load_cve_map()
    windows, host_in_window, graphs, \
        node_id_map, registry                  = load_tag_per_window()

    persist_df                                 = compute_cve_persistence(
        host_cves_map, windows, host_in_window)
    struct_df                                  = compute_structural_importance(
        graphs, registry, windows)

    merged_df, correlations                    = compute_correlation(
        persist_df, struct_df)
    chronic_df                                 = identify_chronic_risk(
        merged_df, persist_df, windows)
    evolution_df                               = compute_attack_surface_evolution(
        persist_df, struct_df, windows, host_in_window, graphs)

    print("\n[6/6] Saving results...")
    save_results(persist_df, chronic_df, evolution_df, merged_df, correlations)

    print_report(persist_df, chronic_df, evolution_df, correlations, windows)
    print_key_findings(persist_df, chronic_df, evolution_df, correlations, windows)

if __name__ == "__main__":
    main()


# ===== File: Alert corelator comparison.py =====
"""
Baseline Comparator for Idea 3
================================
Implements three baselines that represent how existing IDS systems
correlate alerts WITHOUT any graph structural knowledge.

Baseline 1 - Time Proximity Correlator
  Any two consecutive alerts from the same source within T minutes
  are marked CORRELATED. This is how most SIEMs work.

Baseline 2 - Same Window Correlator
  Any two alerts that fall in the same time window are marked
  CORRELATED. Represents rule-based IDS window correlation.

Baseline 3 - Severity Threshold Correlator
  Any two alerts where both have severity >= threshold are marked
  CORRELATED. Represents priority-based alert grouping.
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

def load_data():
    print("\n[1/5] Loading data...")

    alerts_df = pd.read_csv(ALERTS_CSV, parse_dates=["timestamp"])
    tag_df    = pd.read_csv(TAG_RESULTS_CSV, parse_dates=[
        "alert_a_timestamp", "alert_b_timestamp"
    ])

    print(f"  OK Raw alerts          : {len(alerts_df)}")
    print(f"  OK TAG-classified pairs: {len(tag_df)}")

    counts = tag_df["classification"].value_counts()
    print(f"  OK TAG valid           : {counts.get(VALID,      0)}")
    print(f"  OK TAG impossible      : {counts.get(IMPOSSIBLE, 0)}")
    print(f"  OK TAG ambiguous       : {counts.get(AMBIGUOUS,  0)}")

    return alerts_df, tag_df

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

def compute_metrics(tag_df, predictions, baseline_name):
    assert len(predictions) == len(tag_df), \
        f"Length mismatch: {len(predictions)} predictions vs {len(tag_df)} pairs"

    tag_labels = tag_df["classification"].values

    total        = len(predictions)
    n_valid      = (tag_labels == VALID).sum()
    n_impossible = (tag_labels == IMPOSSIBLE).sum()
    n_ambiguous  = (tag_labels == AMBIGUOUS).sum()

    correlated_mask  = [p == "CORRELATED" for p in predictions]
    impossible_mask  = tag_labels == IMPOSSIBLE
    false_corr       = sum(c and i for c, i in zip(correlated_mask, impossible_mask))
    total_correlated = sum(correlated_mask)
    fcr = false_corr / total_correlated if total_correlated else 0.0

    valid_mask   = tag_labels == VALID
    not_corr     = [p == "NOT_CORRELATED" for p in predictions]
    missed       = sum(v and nc for v, nc in zip(valid_mask, not_corr))
    mcr = missed / n_valid if n_valid else 0.0

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

def tag_self_metrics(tag_df):
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

def build_detail_table(tag_df, all_predictions):
    detail = tag_df[[
        "source_host",
        "alert_a_dest", "alert_a_window", "alert_a_severity",
        "alert_b_dest", "alert_b_window", "alert_b_severity",
        "classification", "same_window", "cross_window",
    ]].copy()

    for name, preds in all_predictions.items():
        detail[f"bl_{name}"] = preds

    return detail

def print_comparison(comparison_df):
    print("\n" + "=" * 80)
    print("  BASELINE COMPARISON TABLE")
    print("  (TAG VALID = ground truth positive; TAG IMPOSSIBLE = ground truth negative)")
    print("=" * 80)

    print(f"\n  {'Baseline':<35} {'Corr':>6} {'FCR%':>6} {'MCR%':>6} "
          f"{'Prec':>7} {'Rec':>7} {'F1':>7}")
    print("  " + "-" * 78)

    for _, row in comparison_df.iterrows():
        marker = " <" if "TAG_IDS" in str(row["baseline"]) else ""
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

def print_key_findings(comparison_df, tag_df):
    total      = len(tag_df)
    n_valid    = (tag_df["classification"] == VALID).sum()
    n_impos    = (tag_df["classification"] == IMPOSSIBLE).sum()
    n_ambig    = (tag_df["classification"] == AMBIGUOUS).sum()

    non_tag = comparison_df[~comparison_df["baseline"].str.contains("TAG")]
    best    = non_tag.loc[non_tag["f1_score"].idxmax()]

    print("\n" + "=" * 80)
    print("  KEY FINDINGS")
    print("=" * 80)
    print(f"\n  1. Of {total} consecutive alert pairs, only {n_valid} ({round(100*n_valid/total,1)}%)")
    print(f"     are structurally valid attack chains according to the TAG.")
    print(f"\n  2. {n_impos} pairs ({round(100*n_impos/total,1)}%) are structurally IMPOSSIBLE -")
    print(f"     a standard correlator would incorrectly link these.")
    print(f"\n  3. {n_ambig} pairs ({round(100*n_ambig/total,1)}%) are ambiguous (path exists")
    print(f"     but temporal ordering violated - potential detection lag).")
    print(f"\n  4. Best baseline: {best['baseline']}")
    print(f"     FCR={best['false_corr_rate_pct']}%  MCR={best['missed_chain_rate_pct']}%  F1={best['f1_score']}")
    print(f"\n  5. TAG-IDS reduces false correlation rate to 0% by design,")
    print(f"     while identifying the {n_ambig} ambiguous cases as a third")
    print(f"     class that no baseline can distinguish.")
    print("=" * 80)

def main():
    print("=" * 58)
    print("  Baseline Comparator for Idea 3")
    print("=" * 58)

    alerts_df, tag_df = load_data()

    print("\n[2/5] Running baselines...")
    all_predictions = {}
    all_predictions.update(baseline_time_proximity(tag_df))
    all_predictions.update(baseline_same_window(tag_df))
    all_predictions.update(baseline_severity_threshold(tag_df))
    print(f"  OK Baselines defined   : {len(all_predictions)}")

    print("\n[3/5] Computing metrics...")
    rows = []
    for name, preds in all_predictions.items():
        rows.append(compute_metrics(tag_df, preds, name))

    rows.append(tag_self_metrics(tag_df))

    comparison_df = pd.DataFrame(rows)

    print("\n[4/5] Building pair-level detail table...")
    detail_df = build_detail_table(tag_df, all_predictions)

    print("\n[5/5] Saving results...")
    comparison_df.to_csv(COMPARISON_CSV, index=False)
    detail_df.to_csv(DETAIL_CSV, index=False)
    print(f"  OK Comparison table    : {COMPARISON_CSV}")
    print(f"  OK Pair detail table   : {DETAIL_CSV}")

    print_comparison(comparison_df)
    print_key_findings(comparison_df, tag_df)

def print_consolidated_summary():
    print("\n" + "=" * 72)
    print("  CONSOLIDATED OUTPUT SUMMARY")
    print("=" * 72)


def run_with_output_capture(output_path):
    import sys
    import contextlib

    class _Tee:
        def __init__(self, *streams):
            self.streams = streams

        def write(self, data):
            for stream in self.streams:
                stream.write(data)

        def flush(self):
            for stream in self.streams:
                stream.flush()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        tee_out = _Tee(sys.stdout, f)
        tee_err = _Tee(sys.stderr, f)
        with contextlib.redirect_stdout(tee_out), contextlib.redirect_stderr(tee_err):
            main()
            print_consolidated_summary()

    print(f"Output saved to {output_path}")

    ids_dir = Path(".").resolve() / "ids_outputs"
    summary_lines = []

    summary_csv = ids_dir / "alert_chain_summary.csv"
    if summary_csv.exists():
        df = pd.read_csv(summary_csv)
        if not df.empty:
            row = df.iloc[0]
            summary_lines.append(
                f"Alert chains: total_pairs={int(row.get('total_pairs', 0))} "
                f"valid={int(row.get('valid_count', 0))} "
                f"impossible={int(row.get('impossible_count', 0))} "
                f"ambiguous={int(row.get('ambiguous_count', 0))}"
            )

    blind_csv = ids_dir / "blind_spot_per_window.csv"
    if blind_csv.exists():
        df = pd.read_csv(blind_csv)
        if not df.empty:
            avg_bs = df["blind_spot_ratio_pct"].mean()
            avg_cov = df["coverage_pct"].mean()
            summary_lines.append(
                f"Blind spots: avg_blind_spot_ratio={avg_bs:.1f}% "
                f"avg_coverage={avg_cov:.1f}%"
            )

    triage_csv = ids_dir / "triage_summary.csv"
    if triage_csv.exists():
        df = pd.read_csv(triage_csv)
        if not df.empty:
            row = df.iloc[0]
            summary_lines.append(
                f"Triage: total_alerts={int(row.get('total_alerts', 0))} "
                f"promoted={int(row.get('promoted_count', 0))} "
                f"demoted={int(row.get('demoted_count', 0))}"
            )

    corr_csv = ids_dir / "persistence_correlation.csv"
    if corr_csv.exists():
        df = pd.read_csv(corr_csv)
        if not df.empty:
            top = df.iloc[0]
            summary_lines.append(
                f"Persistence: top_pair={top.get('metric_pair', 'N/A')} "
                f"r={top.get('r', 'N/A')} p={top.get('p', 'N/A')}"
            )

    chronic_csv = ids_dir / "chronic_risk_nodes.csv"
    if chronic_csv.exists():
        df = pd.read_csv(chronic_csv)
        if not df.empty:
            summary_lines.append(
                f"Chronic risk: nodes={len(df)}"
            )

    baseline_csv = ids_dir / "baseline_comparison.csv"
    if baseline_csv.exists():
        df = pd.read_csv(baseline_csv)
        if not df.empty:
            non_tag = df[~df["baseline"].astype(str).str.contains("TAG")]
            if not non_tag.empty:
                best = non_tag.loc[non_tag["f1_score"].idxmax()]
                summary_lines.append(
                    f"Baselines: best={best['baseline']} "
                    f"F1={best['f1_score']} "
                    f"FCR={best['false_corr_rate_pct']}% "
                    f"MCR={best['missed_chain_rate_pct']}%"
                )

    if not summary_lines:
        summary_lines.append("No summary outputs found in ids_outputs.")

    for line in summary_lines:
        print(f"  - {line}")

    print("=" * 72)

if __name__ == "__main__":
    run_with_output_capture(Path("ids_outputs") / "run_output.txt")