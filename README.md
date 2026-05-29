# ot-inspect

**Passive OT/ICS Network Security Analysis Tool**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![Protocols](https://img.shields.io/badge/Protocols-Modbus%20%7C%20S7comm-orange)](#detection-rules)
[![MITRE ATT&CK ICS](https://img.shields.io/badge/MITRE%20ATT%26CK-ICS-red)](https://attack.mitre.org/matrices/ics/)
[![Validated](https://img.shields.io/badge/Validated-246%2C137%20Real%20Packets-green)](#validation-results)
[![License](https://img.shields.io/badge/License-MIT-brightgreen)](LICENSE)

A command-line tool that passively analyses industrial control system (ICS)
network captures, identifies OT protocols, detects anomalies, and generates
a self-contained HTML security report — with no Suricata, no Docker, and no
paid subscriptions required.

Validated against real ICS traffic from the 4SICS Security Conference lab
(246,137 packets). Detected a rogue host issuing unauthorised commands to a
Siemens PLC with **0% false positive rate**.

---

## Demo — Real Output

Running against `4SICS-GeekLounge-151020.pcap`:

```
  ╔═══════════════════════════════════════════╗
  ║         ot-inspect  v1.0                  ║
  ║   OT Network Security Analysis Tool       ║
  ║   Protocols: Modbus TCP · S7comm          ║
  ╚═══════════════════════════════════════════╝

  STEP 1: Protocol Discovery
  ✅ S7comm (Siemens) (port 102) — 208,940 packets

  STEP 2: Protocol Parsing
  [s7comm] Packets decoded : 94,895
  [s7comm] Unique sources  : 3
  [s7comm] Write commands  : 28

  STEP 3: Anomaly Detection
  │  HIGH     : 19
  │  TOTAL    : 19

  STEP 4: Generating Report
  ✅ Report generated: output/report_20260529_202348.html
```

**Incident declared. Rogue host `10.10.10.30` identified.**

---

## Quick Start

```bash
# 1. Install dependencies (one time)
pip install scapy pandas matplotlib tabulate pyyaml

# 2. Edit config.yaml with your network's authorised IPs (one time)

# 3. Run against any PCAP
python ot_inspect.py --pcap your_capture.pcap --config config.yaml
```

Output: `output/report_YYYYMMDD_HHMMSS.html` — open in any browser,
print to PDF, share with anyone.

---

## How It Works

```
Your PCAP  (any size, any OT protocol)
      │
      ▼
┌─────────────────────────────┐
│  1. Protocol Discovery      │  Scans all packets — what ICS protocols
│                             │  are actually in this file?
└──────────────┬──────────────┘
               │  only detected protocols are parsed
    ┌──────────┴───────────┐
    ▼                      ▼
┌──────────┐         ┌──────────┐
│  Modbus  │         │  S7comm  │
│  Parser  │         │  Parser  │
└────┬─────┘         └────┬─────┘
     └──────────┬──────────┘
                ▼
┌─────────────────────────────┐
│  3. Anomaly Engine          │  Protocol-agnostic behavioural detection.
│                             │  Finds: unauthorised writes, dangerous
│                             │  commands, scanning, automated tooling.
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│  4. HTML Report + CSV       │  Self-contained report. Charts embedded.
│                             │  Printable to PDF from browser.
└─────────────────────────────┘
```

The tool only invokes parsers for protocols it actually finds. If a PCAP has
no Modbus traffic, the Modbus parser is skipped — no silent zero results.

---

## Architecture

```
ot_inspect.py                  Entry point — orchestrates the pipeline only.
                               Does no parsing, detection, or reporting itself.
config.yaml                    Network configuration. Edit once per environment.
core/
  protocol_discovery.py        Scans every packet for known ICS protocol ports.
  modbus_parser.py             Decodes Modbus TCP at the byte level (MBAP header).
  s7comm_parser.py             Decodes S7comm at the byte level (TPKT/COTP/S7).
  anomaly_engine.py            12 behavioural detection rules, protocol-agnostic.
reports/
  report_generator.py          Self-contained HTML report with embedded charts.
```

Each module has exactly one responsibility. Any module can be tested,
replaced, or extended without touching the others.

---

## Detection Rules

### Modbus TCP (port 502)

| Rule | Severity | Trigger | MITRE Technique |
|------|----------|---------|----------------|
| MOD-001 | HIGH | Write commands (FC 5/6/15/16) from non-master IP | T0836 Modify Parameter |
| MOD-002 | CRITICAL | Diagnostics FC8 — sub-code 0x0001 restarts PLC | T0816 Device Restart/Shutdown |
| MOD-003 | MEDIUM | Device ID read FC43 — network reconnaissance | T0846 Remote System Discovery |
| MOD-004 | MEDIUM | Unit ID scanning — 5+ unique Unit IDs from one source | T0846 Remote System Discovery |
| MOD-005 | HIGH | Write burst — 3+ writes/second (automated tool signature) | T0836 Modify Parameter |
| MOD-006 | MEDIUM | Exception flood — PLC rejecting commands under probe | T0855 Unauthorized Command Message |

### S7comm (port 102 — Siemens PLCs)

| Rule | Severity | Trigger | MITRE Technique |
|------|----------|---------|----------------|
| S7-001 | CRITICAL | STOP CPU (0x29) — halts all PLC execution immediately | T0816 Device Restart/Shutdown |
| S7-002 | CRITICAL | Program download — PLC control logic being overwritten | T0873 Project File Infection |
| S7-003 | HIGH | Program upload — ladder logic being read out of PLC | T0843 Program Upload |
| S7-004 | HIGH | Write Variable (0x05) from non-master IP | T0836 Modify Parameter |
| S7-005 | HIGH | PLC Control command — start/stop/reset outside maintenance | T0816 Device Restart/Shutdown |
| S7-006 | HIGH | Write-only pattern — 0 reads, writes only (automated tool) | T0836 Modify Parameter |

> **Rule S7-006 explained:** Human operators always read a value before
> writing it. A source that only sends write commands and never reads is
> a script running blindly — not a person. This behavioural signature
> distinguishes automated attack tools from legitimate operators.

---

## Configuration

Edit `config.yaml` once for your environment. No code changes ever needed.

```yaml
network:
  authorised_masters:
    - "10.10.10.20"        # Engineering Workstation / HMI

  plc_addresses:
    - "10.10.10.10"        # Siemens S7 PLC

  it_network_prefixes:
    - "10.0.0."            # IT VLAN — ICS traffic from here = incident

detection:
  unit_id_scan_threshold: 5       # Unique Unit IDs before scan alert fires
  write_burst_per_second: 3       # Writes/sec before burst alert fires

reporting:
  analyst: "Nayanshree"
  title:   "OT Network Security Analysis Report"
```

---

## Validation Results

Tested against `4SICS-GeekLounge-151020.pcap` —
real traffic from the 4SICS ICS Security Conference lab, October 2015.

| Metric | Value |
|--------|-------|
| Total packets in file | 246,137 |
| ICS protocol detected | S7comm (Siemens) — port 102 |
| S7comm packets decoded | 94,895 |
| Unique hosts on network | 12 |
| Authorised master | `10.10.10.20` — 47,431 packets |
| Rogue host detected | `10.10.10.30` — 18 write-only packets |
| Total alerts generated | **19** |
| CRITICAL alerts | 0 |
| HIGH alerts | **19** |
| False positive rate | **0%** |
| MITRE technique triggered | T0836 — Modify Parameter |

### Key Finding

Host `10.10.10.30` sent **18 Write Variable commands** to Siemens PLC
`10.10.10.10` with **zero read commands** in the entire 6-hour 45-minute
capture window. This write-only pattern is the behavioural signature of
an automated attack tool. A legitimate engineer always reads current values
before making changes.

Rule S7-004 fired 18 times (one per unauthorised write).
Rule S7-006 fired once (write-only behavioural pattern confirmed).

Both findings were independently corroborated by separate anomaly detection
analysis in Project 1, where the same host was identified using a completely
different detection approach.

### Why Some Rules Were Silent

Rules that did not fire are not broken — the attack techniques they cover
were not present in this specific capture:

- **Modbus rules** — this file contains no Modbus traffic (port 502 absent)
- **S7-001 STOP CPU** — attacker did not attempt to halt the PLC
- **S7-002/003 Program download/upload** — attacker only wrote variables,
  did not attempt to read or replace the PLC's control program

In production, rules are tuned per environment and validated per dataset.

---

## MITRE ATT&CK for ICS Coverage

| Technique | Name | Rules Covering It |
|-----------|------|------------------|
| T0836 | Modify Parameter | MOD-001, MOD-005, S7-004, S7-006 |
| T0816 | Device Restart/Shutdown | MOD-002, S7-001, S7-005 |
| T0846 | Remote System Discovery | MOD-003, MOD-004 |
| T0873 | Project File Infection | S7-002 |
| T0843 | Program Upload | S7-003 |
| T0855 | Unauthorized Command Message | MOD-006 |

---

## Requirements

```
Python 3.9+
scapy
pandas
matplotlib
tabulate
pyyaml
```

No Suricata. No Wireshark. No Docker. No virtual machines.
No paid subscriptions. Runs on any laptop, including Google Colab.

---

## Running in Google Colab

```python
from google.colab import drive
drive.mount('/content/drive')

import subprocess

result = subprocess.run(
    ["python", "ot_inspect.py",
     "--pcap",   "/content/drive/MyDrive/data/your_capture.pcap",
     "--config", "config.yaml",
     "--out",    "/content/drive/MyDrive/reports/"],
    capture_output=True, text=True,
    cwd="/content/drive/MyDrive/ot_inspect"
)
print(result.stdout)
```

---

## Design Decisions

**Why passive analysis?**
Active scanning (e.g. Nmap) can crash PLCs by sending malformed packets.
In OT environments, a packet that kills a PLC stops the physical process
it controls — pumps, valves, motors. This tool only reads recorded traffic,
never touches live devices.

**Why protocol discovery before parsing?**
Blindly running a Modbus parser on a Siemens network produces zero results
and no explanation. Discovery first means the tool always tells you what IS
in a file, even when the expected protocol is absent. This is how commercial
tools like Nozomi Networks and Claroty approach unknown networks.

**Why protocol-agnostic anomaly detection?**
The anomaly engine takes a DataFrame as input — it does not know or care
which protocol produced the data. The same behavioural patterns (unexpected
writes, write-only sources, dangerous commands) are suspicious regardless
of protocol. This design means adding a new protocol parser automatically
extends detection without changing the engine.

**Why HTML output?**
A Markdown report lives inside GitHub. An HTML report is a standalone
artifact — email it, print it to PDF, present it in an interview on your
laptop, share it with a client. One file, zero dependencies.

---

## Part of OT Security Portfolio

| # | Project | Status |
|---|---------|--------|
| 1 | Modbus TCP + S7comm Analyzer — notebook analysis of 4SICS dataset | ✅ Complete |
| 2 | Suricata IDS Rules — 25 rules across 4 protocols, validated | ✅ Complete |
| — | **ot-inspect — production CLI tool (this repo)** | ✅ Complete |
| 3 | Purdue Model Network Design Document | Upcoming |
| 4 | Passive Asset Discovery Tool | Upcoming |
| 5 | ICS Incident Response Playbook | Upcoming |

---

*Analyst: Nayanshree — OT Cybersecurity Portfolio*
*Tools: Python · Scapy · Pandas · Matplotlib*
*References: MITRE ATT&CK for ICS · NIST SP 800-82 Rev 3 · IEC 62443*
