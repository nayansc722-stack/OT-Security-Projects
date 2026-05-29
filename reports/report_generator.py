"""
reports/report_generator.py
────────────────────────────
Generates a self-contained HTML security report from analysis results.

The report is a single .html file that:
- Opens in any browser with no server or dependencies
- Embeds all charts as base64 (no external files needed)
- Prints cleanly to PDF from the browser
- Looks like a professional security product output

Why HTML over Markdown:
    Markdown lives inside GitHub and requires rendering.
    HTML is a standalone artifact — email it, screenshot it,
    print it to PDF, present it in an interview. It is portable.
"""

import base64
import io
import os
from datetime import datetime
from typing import Dict, List, Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend — works in Colab and CLI
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd


# ── Colour palette
COLOURS = {
    "CRITICAL": "#FF3333",
    "HIGH":     "#FF8800",
    "MEDIUM":   "#FFD700",
    "LOW":      "#00CC66",
    "INFO":     "#4DBBFF",
    "bg":       "#060A10",
    "bg2":      "#0C1220",
    "bg3":      "#111827",
    "border":   "#1E2D45",
    "text":     "#C8D8EE",
    "dim":      "#5A7090",
    "green":    "#00FF88",
}


def _fig_to_base64(fig) -> str:
    """Convert a matplotlib figure to a base64 PNG string for embedding in HTML."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                facecolor=COLOURS["bg"])
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def _make_alert_dashboard(alert_df: pd.DataFrame) -> str:
    """Generate alert dashboard chart and return as base64."""
    if alert_df.empty:
        return ""

    fig, axes = plt.subplots(1, 3, figsize=(16, 4))
    fig.patch.set_facecolor(COLOURS["bg"])

    sev_order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_colors = [COLOURS[s] for s in sev_order]

    # ── Plot 1: Severity breakdown
    ax1 = axes[0]
    ax1.set_facecolor(COLOURS["bg2"])
    sev_counts = (alert_df["severity"]
                  .value_counts()
                  .reindex(sev_order)
                  .dropna())
    bars = ax1.bar(sev_counts.index, sev_counts.values,
                   color=[COLOURS.get(s, "#888") for s in sev_counts.index],
                   edgecolor=COLOURS["border"])
    ax1.set_title("Alerts by Severity", color="white", pad=10)
    ax1.tick_params(colors=COLOURS["text"])
    ax1.spines[:].set_color(COLOURS["border"])
    ax1.set_facecolor(COLOURS["bg2"])
    for bar, val in zip(bars, sev_counts.values):
        ax1.text(bar.get_x() + bar.get_width()/2, val + 0.1,
                 str(int(val)), ha="center", color="white", fontweight="bold")

    # ── Plot 2: Alerts by rule
    ax2 = axes[1]
    ax2.set_facecolor(COLOURS["bg2"])
    rule_counts = alert_df["rule_id"].value_counts()
    ax2.barh(rule_counts.index, rule_counts.values,
             color=COLOURS["INFO"], edgecolor=COLOURS["border"])
    ax2.set_title("Alerts by Rule", color="white", pad=10)
    ax2.tick_params(colors=COLOURS["text"], labelsize=8)
    ax2.spines[:].set_color(COLOURS["border"])

    # ── Plot 3: MITRE technique coverage
    ax3 = axes[2]
    ax3.set_facecolor(COLOURS["bg2"])
    if "mitre_id" in alert_df.columns:
        mitre = (alert_df.groupby(["mitre_id", "mitre_name"])
                 .size()
                 .reset_index(name="count"))
        labels = [f"{r['mitre_id']}\n{r['mitre_name']}"
                  for _, r in mitre.iterrows()]
        ax3.barh(labels, mitre["count"],
                 color=COLOURS["MEDIUM"], edgecolor=COLOURS["border"])
    ax3.set_title("MITRE ATT&CK for ICS", color="white", pad=10)
    ax3.tick_params(colors=COLOURS["text"], labelsize=7)
    ax3.spines[:].set_color(COLOURS["border"])

    plt.suptitle("Alert Dashboard", color="white", fontsize=13, y=1.02)
    plt.tight_layout()
    return _fig_to_base64(fig)


def _make_timeline(modbus_df: pd.DataFrame, s7_df: pd.DataFrame,
                   alert_df: pd.DataFrame) -> str:
    """Generate traffic timeline chart and return as base64."""
    has_modbus = modbus_df is not None and not modbus_df.empty
    has_s7     = s7_df is not None and not s7_df.empty

    if not has_modbus and not has_s7:
        return ""

    fig, axes = plt.subplots(
        1 + int(has_modbus) + int(has_s7) - 1,  # at least 1
        1, figsize=(16, 4 * max(1, int(has_modbus) + int(has_s7)))
    )
    if not isinstance(axes, (list, type(plt.subplots(1,1)[1]))):
        axes = [axes]
    fig.patch.set_facecolor(COLOURS["bg"])

    plot_idx = 0
    for label, df, normal_fcs, write_fcs, danger_fcs in [
        ("Modbus TCP", modbus_df,
         [1,2,3,4], [5,6,15,16], [8,43]) if has_modbus else (None,None,None,None,None),
        ("S7comm",     s7_df,
         [0x04, 0xF0], [0x05], [0x29,0x1A,0x1B,0x1C]) if has_s7 else (None,None,None,None,None),
    ]:
        if df is None or df.empty:
            continue
        ax = axes[plot_idx] if len(axes) > 1 else axes[0]
        ax.set_facecolor(COLOURS["bg2"])
        req = df[df["direction"] == "REQUEST"].set_index("timestamp").sort_index()

        def rc(mask):
            sub = req[mask] if mask.any() else req.iloc[0:0]
            return sub.resample("30s").size() if not sub.empty else pd.Series(dtype=float)

        fc_col = "function_code" if "function_code" in req.columns else "func_code"
        norm  = req[req[fc_col].isin(normal_fcs)]
        write = req[req[fc_col].isin(write_fcs)]
        dang  = req[req[fc_col].isin(danger_fcs)]

        if not norm.empty:
            rs = norm.resample("30s").size()
            ax.fill_between(rs.index, rs.values, alpha=0.3,
                            color=COLOURS["green"], label="Normal reads")
        if not write.empty:
            rs = write.resample("30s").size()
            ax.plot(rs.index, rs.values, color=COLOURS["HIGH"],
                    linewidth=2, marker="o", markersize=4, label="Writes")
        if not dang.empty:
            rs = dang.resample("30s").size()
            ax.plot(rs.index, rs.values, color=COLOURS["CRITICAL"],
                    linewidth=2, marker="^", markersize=6, label="Dangerous/Recon")

        # Mark critical alert times
        if alert_df is not None and not alert_df.empty:
            crit = alert_df[alert_df["severity"] == "CRITICAL"]
            for _, row in crit.iterrows():
                ax.axvline(x=row["timestamp"], color=COLOURS["CRITICAL"],
                           linewidth=1, alpha=0.6, linestyle="--")

        ax.set_title(f"{label} Traffic Timeline", color="white")
        ax.set_xlabel("Time", color=COLOURS["dim"])
        ax.set_ylabel("Pkts/30s", color=COLOURS["dim"])
        ax.tick_params(colors=COLOURS["text"])
        ax.spines[:].set_color(COLOURS["border"])
        ax.legend(facecolor=COLOURS["bg3"], edgecolor=COLOURS["border"],
                  labelcolor="white", fontsize=8)
        plot_idx += 1

    plt.tight_layout()
    return _fig_to_base64(fig)


def _alert_rows_html(alert_df: pd.DataFrame) -> str:
    """Render alert table rows as HTML."""
    if alert_df.empty:
        return '<tr><td colspan="7" style="text-align:center;color:#5A7090;">No alerts generated</td></tr>'

    rows = []
    for _, row in alert_df.iterrows():
        sev   = row["severity"]
        color = COLOURS.get(sev, "#888")
        rows.append(f"""
        <tr>
            <td><span class="badge" style="background:{color}">{sev}</span></td>
            <td class="mono">{row['rule_id']}</td>
            <td class="mono">{row['src_ip']}</td>
            <td class="mono">{row['dst_ip']}</td>
            <td class="mono">{row.get('mitre_id','—')}</td>
            <td>{row['description']}</td>
            <td style="font-size:11px;color:#5A7090">{row.get('raw_detail','')}</td>
        </tr>""")
    return "\n".join(rows)


def generate(
    output_path:    str,
    config:         dict,
    pcap_path:      str,
    discovery:      object,
    modbus_df:      Optional[pd.DataFrame],
    s7_df:          Optional[pd.DataFrame],
    alert_df:       pd.DataFrame,
) -> str:
    """
    Generate a self-contained HTML security report.

    Args:
        output_path : Where to write the .html file
        config      : Parsed config.yaml dict
        pcap_path   : Path to the analysed PCAP (for display)
        discovery   : DiscoveryResult object from protocol_discovery
        modbus_df   : Parsed Modbus DataFrame (or None)
        s7_df       : Parsed S7comm DataFrame (or None)
        alert_df    : Combined alerts DataFrame from AnomalyEngine

    Returns:
        Path to the written HTML file
    """
    rep_cfg  = config.get("reporting", {})
    analyst  = rep_cfg.get("analyst", "Unknown")
    title    = rep_cfg.get("title", "OT Security Analysis Report")
    now      = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # ── Compute stats
    total_alerts  = len(alert_df)
    crit_count    = (alert_df["severity"] == "CRITICAL").sum() if not alert_df.empty else 0
    high_count    = (alert_df["severity"] == "HIGH").sum()     if not alert_df.empty else 0
    med_count     = (alert_df["severity"] == "MEDIUM").sum()   if not alert_df.empty else 0
    rogue_ips     = []
    if not alert_df.empty:
        auth = set(config.get("network", {}).get("authorised_masters", []))
        rogue_ips = sorted(set(alert_df["src_ip"].unique()) - auth)

    incident_declared = crit_count > 0 or high_count > 0

    # ── Generate charts
    dashboard_b64 = _make_alert_dashboard(alert_df)
    timeline_b64  = _make_timeline(modbus_df, s7_df, alert_df)

    # ── Protocol summary rows
    proto_rows = ""
    if discovery and discovery.has_ics_traffic:
        for port, finding in sorted(
            discovery.protocols_found.items(),
            key=lambda x: -x[1].packet_count
        ):
            proto_rows += f"""
            <tr>
                <td class="mono">{finding.name}</td>
                <td class="mono">{port}</td>
                <td>{finding.packet_count:,}</td>
                <td>{finding.unique_sources}</td>
                <td>{finding.unique_destinations}</td>
            </tr>"""
    else:
        proto_rows = '<tr><td colspan="5" style="color:#5A7090">No ICS protocols found on standard ports</td></tr>'

    # ── Alert rows
    alert_rows = _alert_rows_html(alert_df)

    # ── MITRE summary
    mitre_rows = ""
    if not alert_df.empty and "mitre_id" in alert_df.columns:
        for _, row in (alert_df.groupby(["mitre_id", "mitre_name"])
                       .size().reset_index(name="count").iterrows()):
            mitre_rows += f"""
            <tr>
                <td class="mono">{row['mitre_id']}</td>
                <td>{row['mitre_name']}</td>
                <td>{row['count']}</td>
            </tr>"""

    # ── Chart img tags
    dashboard_img = (
        f'<img src="data:image/png;base64,{dashboard_b64}" style="width:100%;border-radius:4px">'
        if dashboard_b64 else ""
    )
    timeline_img = (
        f'<img src="data:image/png;base64,{timeline_b64}" style="width:100%;border-radius:4px">'
        if timeline_b64 else ""
    )

    status_colour = COLOURS["CRITICAL"] if incident_declared else COLOURS["LOW"]
    status_text   = "⚠  INCIDENT DECLARED" if incident_declared else "✅  NORMAL TRAFFIC"
    rogue_text    = ", ".join(f"<code>{ip}</code>" for ip in rogue_ips) if rogue_ips else "None"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg:     {COLOURS['bg']};
    --bg2:    {COLOURS['bg2']};
    --bg3:    {COLOURS['bg3']};
    --border: {COLOURS['border']};
    --text:   {COLOURS['text']};
    --dim:    {COLOURS['dim']};
    --green:  {COLOURS['green']};
    --mono:   'Share Tech Mono', monospace;
    --main:   'Exo 2', sans-serif;
  }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--main);
         padding: 32px 40px; max-width: 1200px; margin: 0 auto; line-height: 1.6; }}
  h1   {{ font-size: 26px; color: #fff; margin-bottom: 4px; font-weight: 700; }}
  h2   {{ font-size: 13px; font-family: var(--mono); color: var(--green);
         letter-spacing: 2px; text-transform: uppercase; margin: 36px 0 14px;
         padding-bottom: 6px; border-bottom: 1px solid var(--border); }}
  h3   {{ font-size: 13px; color: #fff; margin: 20px 0 10px; font-weight: 600; }}
  p    {{ margin-bottom: 10px; font-size: 14px; }}
  code {{ font-family: var(--mono); background: var(--bg3); padding: 2px 6px;
         border-radius: 2px; font-size: 12px; color: var(--green); }}
  .mono {{ font-family: var(--mono); font-size: 12px; }}
  .header {{ border: 1px solid var(--green); padding: 24px 28px; margin-bottom: 32px;
             background: linear-gradient(135deg,#060F0A,var(--bg)); position: relative; }}
  .header::before {{ content:''; position:absolute; top:0; left:0; right:0; height:2px;
                     background: linear-gradient(90deg, var(--green), transparent); }}
  .badge-tlp {{ display:inline-block; background:var(--bg3); border:1px solid var(--border);
               font-family:var(--mono); font-size:11px; padding:2px 8px; margin-bottom:8px; }}
  .status {{ display:inline-block; padding:6px 16px; font-family:var(--mono);
             font-size:14px; font-weight:bold; border:1px solid; margin:12px 0;
             color:{status_colour}; border-color:{status_colour}; }}
  .meta-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:16px; }}
  .meta-item {{ background:var(--bg2); border:1px solid var(--border); padding:10px 14px; }}
  .meta-label {{ font-family:var(--mono); font-size:10px; color:var(--dim);
                letter-spacing:1px; text-transform:uppercase; }}
  .meta-value {{ font-size:14px; color:#fff; margin-top:2px; }}
  .count-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-top:8px; }}
  .count-box  {{ background:var(--bg2); border:1px solid var(--border);
                padding:16px; text-align:center; }}
  .count-num  {{ font-size:32px; font-weight:700; font-family:var(--mono); }}
  .count-label {{ font-size:11px; color:var(--dim); margin-top:4px; font-family:var(--mono); }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }}
  th {{ background:var(--bg3); color:#4DBBFF; font-family:var(--mono); font-size:10px;
       letter-spacing:1px; text-transform:uppercase; padding:8px 12px;
       text-align:left; border:1px solid var(--border); }}
  td {{ padding:8px 12px; border:1px solid var(--border); color:var(--text);
       background:var(--bg2); vertical-align:top; }}
  tr:hover td {{ background:#111D30; }}
  .badge {{ display:inline-block; padding:2px 8px; font-family:var(--mono);
            font-size:11px; color:#000; font-weight:bold; border-radius:2px; }}
  .chart-wrap {{ margin-top:12px; }}
  .rec-box {{ background:var(--bg2); border:1px solid var(--border); border-left:3px solid var(--green);
              padding:14px 18px; margin-bottom:8px; font-size:13px; }}
  .rec-num {{ font-family:var(--mono); color:var(--green); font-size:16px;
              float:left; margin-right:12px; line-height:1.4; }}
  .footer {{ margin-top:48px; padding-top:16px; border-top:1px solid var(--border);
             font-family:var(--mono); font-size:11px; color:var(--dim); text-align:center; }}
  @media print {{
    body {{ background:#fff; color:#000; padding:20px; }}
    .header {{ border-color:#000; background:#f5f5f5; }}
    h2 {{ color:#333; border-color:#ccc; }}
    .meta-item, .count-box, .rec-box {{ background:#f9f9f9; border-color:#ddd; }}
    td, th {{ background:#fff!important; border-color:#ddd; color:#000; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="badge-tlp">TLP:AMBER</div>
  <h1>{title}</h1>
  <div class="status">{status_text}</div>
  <div class="meta-grid">
    <div class="meta-item">
      <div class="meta-label">Report Date</div>
      <div class="meta-value">{now}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Analyst</div>
      <div class="meta-value">{analyst}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Dataset</div>
      <div class="meta-value mono">{os.path.basename(pcap_path)}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Rogue Hosts Identified</div>
      <div class="meta-value">{rogue_text if rogue_text != 'None' else '<span style="color:#5A7090">None detected</span>'}</div>
    </div>
  </div>
</div>

<h2>// Executive Summary</h2>
<div class="count-grid">
  <div class="count-box">
    <div class="count-num" style="color:{COLOURS['CRITICAL']}">{crit_count}</div>
    <div class="count-label">CRITICAL</div>
  </div>
  <div class="count-box">
    <div class="count-num" style="color:{COLOURS['HIGH']}">{high_count}</div>
    <div class="count-label">HIGH</div>
  </div>
  <div class="count-box">
    <div class="count-num" style="color:{COLOURS['MEDIUM']}">{med_count}</div>
    <div class="count-label">MEDIUM</div>
  </div>
  <div class="count-box">
    <div class="count-num" style="color:#fff">{total_alerts}</div>
    <div class="count-label">TOTAL ALERTS</div>
  </div>
</div>

<h2>// Protocol Discovery</h2>
<table>
  <tr><th>Protocol</th><th>Port</th><th>Packets</th><th>Sources</th><th>Targets</th></tr>
  {proto_rows}
</table>

<h2>// Alert Dashboard</h2>
<div class="chart-wrap">{dashboard_img}</div>

<h2>// Traffic Timeline</h2>
<div class="chart-wrap">{timeline_img}</div>

<h2>// All Alerts</h2>
<table>
  <tr>
    <th>Severity</th><th>Rule</th><th>Source IP</th><th>Dest IP</th>
    <th>MITRE</th><th>Description</th><th>Detail</th>
  </tr>
  {alert_rows}
</table>

<h2>// MITRE ATT&CK for ICS Coverage</h2>
<table>
  <tr><th>Technique</th><th>Name</th><th>Alert Count</th></tr>
  {mitre_rows if mitre_rows else '<tr><td colspan="3" style="color:#5A7090">No techniques triggered</td></tr>'}
</table>

<h2>// Recommendations</h2>
<div class="rec-box">
  <span class="rec-num">01</span>
  <strong>Network Segmentation</strong> — Restrict ICS protocol ports (502, 102, 20000, 44818)
  to authorised master IPs only via OT firewall ACL. No IT host should reach these ports.
</div>
<div class="rec-box">
  <span class="rec-num">02</span>
  <strong>Protocol Whitelisting</strong> — Block write function codes (Modbus FC 5/6/15/16,
  S7comm 0x05) from all hosts except designated engineering workstations at the protocol-aware firewall.
</div>
<div class="rec-box">
  <span class="rec-num">03</span>
  <strong>IDS Deployment</strong> — Deploy <code>ot_detection_v2.rules</code> on an OT network
  tap (Suricata). Rules S7-004 and MOD-001 through MOD-003 would have alerted on this traffic in real time.
</div>
<div class="rec-box">
  <span class="rec-num">04</span>
  <strong>Asset Inventory</strong> — Investigate all source IPs not in the authorised master list:
  {rogue_text}. Determine whether these are compromised assets, rogue devices, or misconfigurations.
</div>
<div class="rec-box">
  <span class="rec-num">05</span>
  <strong>NIST SP 800-82 Rev 3 Controls</strong> —
  AC-3 (Access Enforcement), SI-3 (Malicious Code Protection), CM-7 (Least Functionality).
</div>

<div class="footer">
  Generated by ot-inspect | Tools: Python · Scapy · Pandas · Matplotlib &nbsp;|&nbsp;
  MITRE ATT&CK for ICS: attack.mitre.org/matrices/ics/ &nbsp;|&nbsp;
  NIST SP 800-82 Rev 3
</div>

</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
