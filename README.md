# OT Security Project 1: Modbus TCP Traffic Analyzer & Anomaly Detector

**Author:** [NSC]  
**Date:** 2026  
**Dataset:** Public ICS PCAP files from ITI/ICS-Security-Tools & Netresec  
**Skills Demonstrated:** OT protocol analysis, Modbus TCP dissection, anomaly detection, MITRE ATT&CK for ICS mapping

```

authorised_masters:
    - "10.10.10.20"       # Your authorised master IP from Project 1

  plc_addresses:
    - "10.10.10.10"       # Your PLC IP from Project 1

STRUCTURE:
---
## Section 1: Modbus TCP Protocol Primer

Before analysing traffic, we need to understand the structure. This is what makes you sound credible in an interview.


Modbus TCP Packet Structure (Port 502)
═══════════════════════════════════════
[ Ethernet / IP / TCP ]
  └─ Modbus Application Data Unit (ADU)
       ├─ MBAP Header (7 bytes)
       │    ├─ Transaction ID   [2B] — increments per request
       │    ├─ Protocol ID      [2B] — always 0x0000 for Modbus
       │    ├─ Length           [2B] — bytes following
       │    └─ Unit ID          [1B] — target PLC slave ID (0-255)
       └─ Protocol Data Unit (PDU)
            ├─ Function Code    [1B] — the COMMAND
            └─ Data             [nB] — registers, coils, values

KEY FUNCTION CODES (memorise these):
  0x01 (01)  — Read Coils               [NORMAL — sensor status reads]
  0x02 (02)  — Read Discrete Inputs     [NORMAL]
  0x03 (03)  — Read Holding Registers   [NORMAL — most common polling]
  0x04 (04)  — Read Input Registers     [NORMAL]
  0x05 (05)  — Write Single Coil        [⚠️  SUSPICIOUS if unexpected source]
  0x06 (06)  — Write Single Register    [⚠️  SUSPICIOUS if unexpected source]
  0x08 (08)  — Diagnostics              [🚨 DANGEROUS — sub-code 0x0001 = RESTART PLC]
  0x0F (15)  — Write Multiple Coils     [🚨 HIGH IMPACT write]
  0x10 (16)  — Write Multiple Registers [🚨 HIGH IMPACT write]
  0x2B (43)  — Read Device Identification [ℹ️  Reconnaissance indicator]

MITRE ATT&CK for ICS mapping:
  Unauthorized writes  → T0836 Modify Parameter
  Diagnostic abuse     → T0816 Device Restart/Shutdown
  FC 0x2B scanning     → T0846 Remote System Discovery
  Cross-unit scanning  → T0843 Program Upload



# ─────────────────────────────────────────────────────────────────────────────
# FINAL COMBINED INCIDENT REPORT — Fully Dynamic, works for any dataset
# ─────────────────────────────────────────────────────────────────────────────

import os
from datetime import datetime as dt

# ── Modbus stats — all pulled from actual data
modbus_total       = len(df)
modbus_sources     = df['src_ip'].nunique()
modbus_targets     = df['dst_ip'].nunique()
modbus_alerts      = len(alert_df)
modbus_crit        = (alert_df['severity'] == 'CRITICAL').sum()
modbus_high        = (alert_df['severity'] == 'HIGH').sum()
modbus_med         = (alert_df['severity'] == 'MEDIUM').sum()
modbus_rogue       = sorted(set(alert_df['src_ip'].unique()) - AUTHORISED_MASTERS)
modbus_auth        = ', '.join(f'`{ip}`' for ip in sorted(AUTHORISED_MASTERS))
modbus_plcs        = ', '.join(f'`{ip}`' for ip in sorted(df['dst_ip'].unique()))
modbus_fc_profile  = df[df['direction'] == 'REQUEST']['fc_name'].value_counts()
modbus_time_start  = df['timestamp'].min()
modbus_time_end    = df['timestamp'].max()
modbus_duration    = modbus_time_end - modbus_time_start
modbus_incident    = len(modbus_rogue) > 0

# ── Modbus MITRE techniques detected
modbus_mitre_rows  = ''
for _, row in alert_df.groupby(['mitre_id', 'mitre_name']).size().reset_index(name='count').iterrows():
    modbus_mitre_rows += f"| {row['mitre_id']} | {row['mitre_name']} | {row['count']} alerts |\n"

# ── Modbus alert breakdown by rule
modbus_rule_rows = ''
for _, row in alert_df.groupby(['rule_id', 'severity']).size().reset_index(name='count').iterrows():
    modbus_rule_rows += f"| {row['rule_id']} | {row['severity']} | {row['count']} |\n"

# ── S7comm stats — all pulled from actual data
s7_requests        = df_s7[df_s7['direction'] == 'REQUEST']
s7_responses       = df_s7[df_s7['direction'] == 'RESPONSE']
s7_total           = len(df_s7)
s7_sources         = s7_requests['src_ip'].nunique()
s7_targets         = s7_requests['dst_ip'].nunique()
s7_auth_master     = s7_requests['src_ip'].value_counts().idxmax()
s7_all_sources     = s7_requests['src_ip'].value_counts()
s7_all_targets     = s7_requests['dst_ip'].value_counts()
s7_alerts_total    = len(alert_s7_df)
s7_high            = (alert_s7_df['severity'] == 'HIGH').sum()
s7_crit            = (alert_s7_df['severity'] == 'CRITICAL').sum()
s7_med             = (alert_s7_df['severity'] == 'MEDIUM').sum() if 'MEDIUM' in alert_s7_df['severity'].values else 0
s7_rogue_ips       = sorted(set(alert_s7_df['src_ip'].unique()) - {s7_auth_master})
s7_func_profile    = s7_requests['func_name'].value_counts()
s7_time_start      = df_s7['timestamp'].min()
s7_time_end        = df_s7['timestamp'].max()
s7_duration        = s7_time_end - s7_time_start
s7_incident        = len(s7_rogue_ips) > 0

# ── S7comm attack timeline (only if alerts exist)
if s7_alerts_total > 0:
    s7_attack_start    = alert_s7_df['timestamp'].min()
    s7_attack_end      = alert_s7_df['timestamp'].max()
    s7_attack_duration = s7_attack_end - s7_attack_start
    s7_attack_block = f"""
### Attack Timeline
| Event | Timestamp |
|-------|-----------|
| First alert | {s7_attack_start} |
| Last alert  | {s7_attack_end} |
| Attack window | {s7_attack_duration} |
"""
else:
    s7_attack_block = "\n*No attack timeline — no alerts generated.*\n"

# ── S7comm MITRE techniques
s7_mitre_rows = ''
for _, row in alert_s7_df.groupby(['mitre', 'mitre_name']).size().reset_index(name='count').iterrows():
    s7_mitre_rows += f"| {row['mitre']} | {row['mitre_name']} | {row['count']} alerts |\n"

# ── S7comm alert breakdown by rule
s7_rule_rows = ''
for _, row in alert_s7_df.groupby(['rule', 'severity']).size().reset_index(name='count').iterrows():
    s7_rule_rows += f"| {row['rule']} | {row['severity']} | {row['count']} |\n"

# ── S7comm source IP breakdown
s7_source_rows = ''
for ip, count in s7_all_sources.items():
    tag = '(authorised master)' if ip == s7_auth_master else '⚠️  (suspicious)' if ip in s7_rogue_ips else ''
    s7_source_rows += f"| `{ip}` | {count} | {tag} |\n"

# ── Overall incident status
overall_status = '⚠️  INCIDENT DECLARED' if (modbus_incident or s7_incident) else '✅ NO INCIDENT — Normal traffic only'
incident_ips = ', '.join(f'`{ip}`' for ip in (modbus_rogue + s7_rogue_ips)) if (modbus_rogue or s7_rogue_ips) else 'None'

# ── Build the report
report = f"""# ICS Security Incident Report — Combined Multi-Protocol Analysis

| Field | Value |
|-------|-------|
| **Report Date** | {dt.now().strftime('%Y-%m-%d %H:%M UTC')} |
| **Analyst** | Nayanshree |
| **Datasets** | Synthetic Modbus TCP + 4SICS-GeekLounge-151020.pcap (real) |
| **Protocols Analysed** | Modbus TCP (port 502), S7comm (port 102) |
| **Classification** | TLP:AMBER |

---

## Executive Summary

Two datasets were analysed across two ICS protocols.

| Dataset | Type | Packets | Protocol | Alerts |
|---------|------|---------|----------|--------|
| Synthetic Modbus | Simulated | {modbus_total:,} | Modbus TCP | {modbus_alerts} |
| 4SICS-GeekLounge-151020.pcap | Real capture | {s7_total:,} decoded | S7comm | {s7_alerts_total} |

**Overall Status: {overall_status}**
**Rogue hosts identified: {incident_ips}**
**Total alerts across both datasets: {modbus_alerts + s7_alerts_total}**

---

## Section 1 — Modbus TCP Analysis

### Dataset
- **Type:** Synthetic — generated to validate detection pipeline
- **Total packets:** {modbus_total:,}
- **Capture window:** {modbus_time_start} → {modbus_time_end}
- **Duration:** {modbus_duration}

### Network Topology
- **Authorised master(s):** {modbus_auth}
- **Target devices:** {modbus_plcs}
- **Unique source IPs:** {modbus_sources}
- **Unique target IPs:** {modbus_targets}

### Function Code Profile
{modbus_fc_profile.to_markdown()}

### Alert Summary
| Rule | Severity | Count |
|------|----------|-------|
{modbus_rule_rows}
| **Total** | | **{modbus_alerts}** |

**Severity breakdown:** CRITICAL: {modbus_crit} · HIGH: {modbus_high} · MEDIUM: {modbus_med}

### MITRE ATT&CK for ICS
| Technique | Name | Alerts |
|-----------|------|--------|
{modbus_mitre_rows}

### Finding
{'⚠️  INCIDENT: Rogue IP(s) ' + ', '.join(modbus_rogue) + ' issued unauthorised commands.' if modbus_incident else '✅ No unauthorised sources detected.'}

---

## Section 2 — S7comm Analysis (Siemens PLC Protocol)

### Dataset
- **Type:** Real network capture — 4SICS ICS Security Conference Lab, Oct 2015
- **Raw packets in file:** 246,137
- **S7comm packets decoded:** {s7_total:,}
- **Capture window:** {s7_time_start} → {s7_time_end}
- **Duration:** {s7_duration}

### Network Topology
| Source IP | Packets Sent | Role |
|-----------|-------------|------|
{s7_source_rows}

- **Inferred authorised master:** `{s7_auth_master}` (highest traffic volume)
- **Unique target PLCs:** {s7_targets}

### Function Code Profile
{s7_func_profile.to_markdown()}

### Alert Summary
| Rule | Severity | Count |
|------|----------|-------|
{s7_rule_rows}
| **Total** | | **{s7_alerts_total}** |

**Severity breakdown:** CRITICAL: {s7_crit} · HIGH: {s7_high} · MEDIUM: {s7_med}

### MITRE ATT&CK for ICS
| Technique | Name | Alerts |
|-----------|------|--------|
{s7_mitre_rows if s7_mitre_rows else '| — | No techniques triggered | — |'}

{s7_attack_block}

### Key Finding
{'⚠️  INCIDENT: Rogue IP(s) ' + ', '.join(f"`{ip}`" for ip in s7_rogue_ips) + ' issued unauthorised S7comm commands to PLC. Pattern is consistent with automated tooling — writes only, no reads observed.' if s7_incident else '✅ No unauthorised sources detected in S7comm traffic.'}

---

## Recommendations

1. **Network segmentation** — Restrict S7comm (port 102) and Modbus TCP
   (port 502) access to authorised master IPs only via OT firewall ACL.

2. **Protocol whitelisting** — Write function codes (Modbus FC 5/6/15/16,
   S7comm 0x05) should be blocked from all hosts except designated
   engineering workstations.

3. **IDS deployment** — Deploy Suricata rules from `ot_detection.rules`
   on an OT network tap to detect these patterns in real time.

4. **Asset inventory** — Investigate all source IPs that are not in the
   authorised master list: {incident_ips}

5. **NIST SP 800-82 Rev 3 controls:**
   - AC-3 Access Enforcement
   - SI-3 Malicious Code Protection
   - CM-7 Least Functionality

---

## Analyst Notes

The 4SICS-GeekLounge-151020.pcap file contained no Modbus traffic despite
having {246137:,} total packets. Protocol discovery scanning revealed
{s7_total:,} S7comm packets on port 102 instead. This demonstrates a key
OT security reality: real networks are multi-protocol environments requiring
protocol-agnostic discovery before targeted analysis.

---
*Generated by: modbus_analyzer.ipynb | Tools: Python, Scapy, Pandas, Matplotlib*
"""

