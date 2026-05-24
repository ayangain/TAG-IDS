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


print("╔" + "=" * 58 + "╗")
print("║" + "  Temporal Attack Graph with CVE Integration".center(58) + "║")
print("╚" + "=" * 58 + "╝\n")

total_hosts  = int(input("Enter total number of hosts (default: 10): ") or 10)
time_windows = int(input("Enter number of time windows (default: 4): ") or 4)

min_hosts_per_window = 3
time_windows = max(1, time_windows)

print(f"✓ Configuration: {total_hosts} total hosts across {time_windows} time windows")

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
print(f"✓ Active hosts per window: {hosts_per_window_dist}")
print(f"✓ Unique hosts scheduled across all windows: {len(covered_hosts)}\n")

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

print(f"\n✓ COMPLETE: {time_windows} time windows, {total_hosts} hosts, {len(cves_export)} with CVEs")
csvs = sorted(Path(".").glob("*.CSV"))
print(f"✓ Generated {len(csvs)} CSV files")

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


# Realistic severity distribution per base CVE severity level.
# A CRITICAL CVE mostly fires CRITICAL alerts but occasionally
# produces HIGH/MEDIUM/LOW depending on sensor context — this
# matches real IDS behaviour and enables STS promotion/demotion
# to be demonstrated across the full severity spectrum.
SEVERITY_NOISE = {
    AlertSeverity.CRITICAL : [0.05, 0.10, 0.20, 0.65],   # LOW/MED/HIGH/CRIT weights
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
                # ── FIXED: realistic severity distribution ────────
                # Use CVE base severity as anchor but sample around it
                # so all four severity levels appear in the dataset.
                # This enables STS promotion/demotion to be visible
                # across the full severity spectrum.
                base_sev = self.CVE_SEVERITY.get(cve_id, AlertSeverity.HIGH)
                severity  = random.choices(
                    list(AlertSeverity),
                    weights=SEVERITY_NOISE[base_sev],
                )[0]
            else:
                cve_id      = None
                attack_type = "Unclassified Network Attack"
                # ── FIXED: balanced unclassified alert distribution
                severity = random.choices(
                    list(AlertSeverity),
                    weights=[0.15, 0.35, 0.35, 0.15],  # LOW/MED/HIGH/CRIT
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
        print(f"✓ Alerts saved to {filename}")

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
    print(f"✓ Loaded CVE mapping for {len(host_cves_map)} hosts")
else:
    print("⚠ host_cves_mapping.json not found. Run cell 1 first.")

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

# Severity distribution report
print("\nSeverity Distribution:")
print(alerts_df["severity"].value_counts().to_string())

if (not only_in_tag and not only_in_ids
        and missing_cve_for_dst == 0 and mismatched_attack_type == 0):
    print("\n✓ IDS alerts consistent with temporal graph and mappings.")
else:
    print("\n⚠ Review inconsistencies listed above.")