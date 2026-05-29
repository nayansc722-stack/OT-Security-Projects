# ot-inspect

**Passive OT/ICS Network Security Analysis Tool**

A command-line tool for analysing industrial control system network captures. Identifies ICS protocols, detects anomalies, maps findings to MITRE ATT&CK for ICS, and generates a self-contained HTML security report.

Built as part of an OT cybersecurity portfolio. Validated against real ICS traffic from the 4SICS Security Conference lab (246,137 packets).

---

## Quick Start

```bash
# Install dependencies (one time)
pip install scapy pandas matplotlib tabulate pyyaml

# Run against any PCAP
python ot_inspect.py --pcap your_capture.pcap

# With custom config (specify your network's authorised IPs)
python ot_inspect.py --pcap capture.pcap --config config.yaml
```

Output: `output/report_YYYYMMDD_HHMMSS.html` — open in any browser.

---

## What It Does

```
Your PCAP
    │
    ▼
┌─────────────────────────┐
│  1. Protocol Discovery  │  What ICS protocols are in this file?
│     (all 246k packets)  │  Modbus? S7comm? DNP3? EtherNet/IP?
└────────────┬────────────┘
             │
    ┌─────────┴──────────┐
    ▼                    ▼
┌──────────┐      ┌──────────┐
│  Modbus  │      │  S7comm  │   (only parsers for detected protocols run)
│  Parser  │      │  Parser  │
└────┬─────┘      └────┬─────┘
     │                 │
     └────────┬────────┘
              ▼
┌─────────────────────────┐
│  3. Anomaly Engine      │  Protocol-agnostic behavioural detection
│     MOD-001 to MOD-006  │  Unauthorised writes, dangerous commands,
│     S7-001 to S7-006    │  reconnaissance, scanning, bursts
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  4. HTML Report         │  Self-contained, browser-ready
│     + alerts.csv        │  Charts embedded, printable to PDF
└─────────────────────────┘
```

---

## Architecture

```
ot_inspect.py               Entry point — orchestrates the pipeline
config.yaml                 Network config — edit once for your environment
core/
  protocol_discovery.py     Scans PCAP for all ICS protocol ports
  modbus_parser.py          Decodes Modbus TCP at the byte level
  s7comm_parser.py          Decodes S7comm (Siemens PLC) at the byte level
  anomaly_engine.py         Protocol-agnostic behavioural detection rules
reports/
  report_generator.py       Self-contained HTML report with embedded charts
```

Each module has exactly one responsibility. The entry point only coordinates — it does no parsing, detection, or reporting itself. This separation means any module can be tested, replaced, or extended without touching the others.

---

## Detection Rules

### Modbus TCP (port 502)

| Rule | Severity | Trigger | MITRE |
|------|----------|---------|-------|
| MOD-001 | HIGH | Write commands (FC 5/6/15/16) from non-master IP | T0836 |
| MOD-002 | CRITICAL | Diagnostics FC8 — PLC restart risk | T0816 |
| MOD-003 | MEDIUM | Device ID read FC43 — reconnaissance | T0846 |
| MOD-004 | MEDIUM | Unit ID scanning (≥5 unique Unit IDs) | T0846 |
| MOD-005 | HIGH | Write burst — automated tool signature | T0836 |
| MOD-006 | MEDIUM | Exception flood — PLC rejecting commands | T0855 |

### S7comm (port 102 — Siemens PLCs)

| Rule | Severity | Trigger | MITRE |
|------|----------|---------|-------|
| S7-001 | CRITICAL | STOP CPU — halts PLC immediately | T0816 |
| S7-002 | CRITICAL | Program download — overwrites control logic | T0873 |
| S7-003 | HIGH | Program upload — reads out ladder logic | T0843 |
| S7-004 | HIGH | Write Variable from non-master IP | T0836 |
| S7-005 | HIGH | PLC Control command (start/stop/reset) | T0816 |
| S7-006 | HIGH | Write-only pattern — automated tool signature | T0836 |

---

## Configuration

Edit `config.yaml` once for your network:

```yaml
network:
  authorised_masters:
    - "192.168.10.100"    # Your SCADA/HMI IP
  plc_addresses:
    - "192.168.1.10"      # Your PLC IPs
  it_network_prefixes:
    - "10.0.0."           # Your IT VLAN

detection:
  unit_id_scan_threshold: 5      # Lower = more sensitive
  write_burst_per_second: 3      # Writes/sec before burst alert
```

No code changes needed when moving between environments.

---

## Validation Results

Tested against `4SICS-GeekLounge-151020.pcap` (246,137 packets, real ICS conference traffic):

| Finding | Value |
|---------|-------|
| Protocol discovered | S7comm (Siemens) — 94,895 packets |
| Authorised master inferred | `10.10.10.20` (47,431 packets) |
| Rogue host detected | `10.10.10.30` (18 write-only packets) |
| Rule S7-004 fired | 18 alerts |
| Rule S7-006 fired | 1 alert (write-only pattern) |
| False positive rate | **0%** |

All alerts were confirmed as the same rogue host identified by independent analysis in Project 1, cross-validating both detection approaches.

---

## MITRE ATT&CK for ICS Coverage

| Technique | Name | Rules |
|-----------|------|-------|
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

No Suricata, no Wireshark, no Docker, no paid subscriptions.

---


