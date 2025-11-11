#!/usr/bin/env python3
import csv, os
from datetime import datetime

EVID = os.environ.get("EVID_PATH", "/evidence")
OUT = os.environ.get("OUT_PATH", "/workspace/timeline.csv")

rows = []

def add_row(ts, source, detail):
    rows.append({"timestamp": ts, "source": source, "detail": detail})

def read_lines(path, tag):
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # primeira coluna com timestamp ISO-like
                ts = line.split("|")[0].strip().split(" ")[0]
                add_row(ts, tag, line)
    except FileNotFoundError:
        pass

# EVTX exports (txt)
read_lines(os.path.join(EVID, "win_evtx", "Security.evtx.txt"), "Security.evtx")
read_lines(os.path.join(EVID, "win_evtx", "Microsoft-Windows-PowerShell_Operational.evtx.txt"), "PowerShell")
read_lines(os.path.join(EVID, "win_evtx", "TaskScheduler.evtx.txt"), "TaskScheduler")

# Network pcap text
read_lines(os.path.join(EVID, "network", "sample.pcap.txt"), "pcap")

# CASB alerts
casb_csv = os.path.join(EVID, "casb", "alerts.csv")
if os.path.exists(casb_csv):
    with open(casb_csv, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            add_row(row.get("timestamp_utc-3",""), "CASB", f"{row.get('user')} {row.get('action')} {row.get('dest_domain')} {row.get('policy')} {row.get('severity')}")

# Recent files
recent_csv = os.path.join(EVID, "filesystem", "RecentFiles.csv")
if os.path.exists(recent_csv):
    with open(recent_csv, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            add_row(row.get("timestamp_utc-3",""), "RecentFiles", f"{row.get('user')} {row.get('action')} {row.get('path')}")

# JumpLists
jumps_csv = os.path.join(EVID, "filesystem", "JumpLists.csv")
if os.path.exists(jumps_csv):
    with open(jumps_csv, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            add_row(row.get("timestamp_utc-3",""), "JumpLists", f"{row.get('app')} {row.get('item_path')}")

# Sort by timestamp
def keyfun(x):
    try:
        return datetime.fromisoformat(x["timestamp"].replace("Z",""))
    except Exception:
        return datetime.max

rows.sort(key=keyfun)

# Write CSV
with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["timestamp","source","detail"])
    w.writeheader()
    for r in rows:
        w.writerow(r)

print(f"Wrote timeline with {len(rows)} rows to {OUT}")
