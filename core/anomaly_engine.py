"""
core/anomaly_engine.py
──────────────────────
Protocol-agnostic anomaly detection engine.

Takes parsed DataFrames from any protocol parser and applies
behavioural detection rules to produce standardised Alert objects.

Design principle:
    The engine does not know or care which protocol produced the data.
    It looks for BEHAVIOURS that are suspicious regardless of protocol:
    - Writing from unexpected sources
    - Dangerous commands (restart, stop, reprogram)
    - Reconnaissance patterns (scanning, enumeration)
    - Operational anomalies (bursts, flooding)

    This mirrors how commercial OT security platforms (Nozomi, Claroty)
    work — they normalise all protocol data into a common model, then
    apply behavioural analytics on top.

Alert severity levels:
    CRITICAL  Act immediately. Process impact likely or imminent.
    HIGH      Investigate within the hour. Probable attack indicator.
    MEDIUM    Investigate today. Suspicious but may be legitimate.
    LOW       Monitor. Possible misconfiguration or policy violation.
"""

from dataclasses import dataclass, field
from typing import List, Set
from collections import defaultdict

import pandas as pd


@dataclass
class Alert:
    """A single anomaly detection alert."""
    timestamp:   pd.Timestamp
    rule_id:     str
    severity:    str          # CRITICAL / HIGH / MEDIUM / LOW
    protocol:    str          # Modbus / S7comm / General
    src_ip:      str
    dst_ip:      str
    description: str
    mitre_id:    str
    mitre_name:  str
    raw_detail:  str = ""     # Additional technical detail

    @property
    def severity_order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(self.severity, 4)


class AnomalyEngine:
    """
    Detects anomalies in parsed OT protocol traffic.

    Usage:
        engine = AnomalyEngine(config)
        alerts = engine.analyse_modbus(modbus_df)
        alerts += engine.analyse_s7comm(s7_df)
        alerts_df = engine.to_dataframe(alerts)
    """

    def __init__(self, config: dict):
        """
        Args:
            config: Parsed config.yaml dict. The engine reads:
                    - network.authorised_masters
                    - network.it_network_prefixes
                    - network.plc_addresses
                    - detection.* thresholds
        """
        net = config.get("network", {})
        det = config.get("detection", {})

        self.authorised_masters: Set[str] = set(
            net.get("authorised_masters", [])
        )
        self.plc_addresses: Set[str] = set(
            net.get("plc_addresses", [])
        )
        self.it_prefixes: List[str] = net.get("it_network_prefixes", [])

        # Detection thresholds — read from config
        self.unit_id_scan_threshold   = det.get("unit_id_scan_threshold", 5)
        self.write_burst_per_second   = det.get("write_burst_per_second", 3)
        self.exception_flood_count    = det.get("exception_flood_count", 5)
        self.exception_flood_window   = det.get("exception_flood_window_seconds", 30)

    def _is_it_network(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in self.it_prefixes)

    def _is_unauthorised(self, ip: str) -> bool:
        return ip not in self.authorised_masters

    def _make_alert(self, row, rule_id, severity, protocol,
                    description, mitre_id, mitre_name, detail="") -> Alert:
        return Alert(
            timestamp=row["timestamp"],
            rule_id=rule_id,
            severity=severity,
            protocol=protocol,
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            description=description,
            mitre_id=mitre_id,
            mitre_name=mitre_name,
            raw_detail=detail,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # MODBUS DETECTION RULES
    # ─────────────────────────────────────────────────────────────────────────

    def analyse_modbus(self, df: pd.DataFrame) -> List[Alert]:
        """
        Apply all Modbus anomaly detection rules.

        Args:
            df: DataFrame from modbus_parser.parse()

        Returns:
            List of Alert objects
        """
        alerts = []
        if df.empty:
            return alerts

        requests = df[df["direction"] == "REQUEST"].copy()

        # ── RULE MOD-001: Unauthorised write commands
        # Any write FC (5, 6, 15, 16) from a non-master IP
        write_mask = requests["is_write"] & requests["src_ip"].apply(self._is_unauthorised)
        for _, row in requests[write_mask].iterrows():
            alerts.append(self._make_alert(
                row, "MOD-001", "HIGH", "Modbus",
                f"Unauthorised write (FC {row['function_code']} — {row['fc_name']}) "
                f"from {row['src_ip']} to {row['dst_ip']} Unit {row['unit_id']}",
                "T0836", "Modify Parameter",
                f"Register: {row['register_addr']}  Value: {row['value']}"
            ))

        # ── RULE MOD-002: Dangerous commands — FC 8 Diagnostics (any source)
        # FC 8 sub-code 0x0001 restarts the PLC communication stack.
        # So dangerous that even an authorised master sending it should be logged.
        danger_mask = requests["is_dangerous"]
        for _, row in requests[danger_mask].iterrows():
            alerts.append(self._make_alert(
                row, "MOD-002", "CRITICAL", "Modbus",
                f"Diagnostics FC8 from {row['src_ip']} — "
                f"sub-code 0x0001 restarts PLC {row['dst_ip']} Unit {row['unit_id']}",
                "T0816", "Device Restart/Shutdown",
                "Any Diagnostics FC8 warrants investigation regardless of source"
            ))

        # ── RULE MOD-003: Reconnaissance — Device ID reads (FC 43)
        recon_mask = requests["is_recon"]
        for _, row in requests[recon_mask].iterrows():
            alerts.append(self._make_alert(
                row, "MOD-003", "MEDIUM", "Modbus",
                f"Device ID read (FC 43) from {row['src_ip']} — "
                f"querying device identity from {row['dst_ip']}",
                "T0846", "Remote System Discovery",
                "FC 43 is used by tools like PLCScan and Metasploit Redpoint module"
            ))

        # ── RULE MOD-004: Unit ID scanning
        # Single source querying many different Unit IDs = scanning for slaves
        src_unit_counts = requests.groupby("src_ip")["unit_id"].nunique()
        for src_ip, n_units in src_unit_counts.items():
            if n_units >= self.unit_id_scan_threshold:
                sample = requests[requests["src_ip"] == src_ip].iloc[0]
                alerts.append(self._make_alert(
                    sample, "MOD-004", "MEDIUM", "Modbus",
                    f"Unit ID scanning from {src_ip} — "
                    f"queried {n_units} unique Unit IDs (threshold: {self.unit_id_scan_threshold})",
                    "T0846", "Remote System Discovery",
                    f"Unit IDs queried: {sorted(requests[requests['src_ip']==src_ip]['unit_id'].unique().tolist())}"
                ))

        # ── RULE MOD-005: Write burst detection
        # High write rate from same IP = automated tool, not human operator
        write_df = requests[requests["is_write"]].copy()
        if not write_df.empty:
            write_df["ts_sec"] = (
                write_df["timestamp"].astype("int64") // 10**9
            )
            burst = (
                write_df.groupby(["src_ip", "ts_sec"])
                .size()
                .reset_index(name="count")
            )
            for src_ip in burst[burst["count"] >= self.write_burst_per_second]["src_ip"].unique():
                sample = write_df[write_df["src_ip"] == src_ip].iloc[0]
                peak   = burst[burst["src_ip"] == src_ip]["count"].max()
                alerts.append(self._make_alert(
                    sample, "MOD-005", "HIGH", "Modbus",
                    f"Write burst from {src_ip} — "
                    f"peak {peak} writes/second (threshold: {self.write_burst_per_second}). "
                    f"Consistent with automated attack tooling.",
                    "T0836", "Modify Parameter",
                    f"Human operators do not write at {peak}/second"
                ))

        # ── RULE MOD-006: Exception flood — PLC rejecting commands
        # PLC sends error responses when receiving invalid/unauthorised packets
        if "is_error" in df.columns:
            errors = df[(df["direction"] == "RESPONSE") & df["is_error"]].copy()
            if not errors.empty:
                errors["ts_window"] = (
                    errors["timestamp"].astype("int64") // (self.exception_flood_window * 10**9)
                )
                flood = (
                    errors.groupby(["src_ip", "ts_window"])
                    .size()
                    .reset_index(name="count")
                )
                for src_ip in flood[flood["count"] >= self.exception_flood_count]["src_ip"].unique():
                    sample = errors[errors["src_ip"] == src_ip].iloc[0]
                    peak   = flood[flood["src_ip"] == src_ip]["count"].max()
                    alerts.append(self._make_alert(
                        sample, "MOD-006", "MEDIUM", "Modbus",
                        f"Exception flood from PLC {src_ip} — "
                        f"{peak} exception responses in {self.exception_flood_window}s window. "
                        f"PLC rejecting commands — possibly under attack.",
                        "T0855", "Unauthorized Command Message",
                        f"Exception responses indicate the PLC received commands it rejected"
                    ))

        return alerts

    # ─────────────────────────────────────────────────────────────────────────
    # S7COMM DETECTION RULES
    # ─────────────────────────────────────────────────────────────────────────

    def analyse_s7comm(self, df: pd.DataFrame) -> List[Alert]:
        """
        Apply all S7comm anomaly detection rules.

        Args:
            df: DataFrame from s7comm_parser.parse()

        Returns:
            List of Alert objects
        """
        alerts = []
        if df.empty:
            return alerts

        requests = df[df["direction"] == "REQUEST"].copy()

        # ── RULE S7-001: PLC Stop command — CRITICAL
        # Immediately halts all PLC execution
        stop_mask = requests["func_code"] == 0x29
        for _, row in requests[stop_mask].iterrows():
            alerts.append(self._make_alert(
                row, "S7-001", "CRITICAL", "S7comm",
                f"STOP CPU from {row['src_ip']} — "
                f"PLC {row['dst_ip']} execution halted immediately. "
                f"Process control suspended.",
                "T0816", "Device Restart/Shutdown",
                "S7comm function 0x29 halts all ladder logic execution"
            ))

        # ── RULE S7-002: Program download — CRITICAL
        # Writing new control logic to the PLC
        dl_mask = requests["is_download"]
        for _, row in requests[dl_mask].iterrows():
            alerts.append(self._make_alert(
                row, "S7-002", "CRITICAL", "S7comm",
                f"Program DOWNLOAD to PLC {row['dst_ip']} from {row['src_ip']} — "
                f"control logic being overwritten ({row['func_name']}). "
                f"STUXNET used this technique.",
                "T0873", "Project File Infection",
                f"Function: {row['func_name']} (0x{row['func_code']:02X})"
            ))

        # ── RULE S7-003: Program upload — HIGH
        # Reading PLC's control logic out — espionage or pre-modification recon
        ul_mask = requests["is_upload"]
        for _, row in requests[ul_mask].iterrows():
            alerts.append(self._make_alert(
                row, "S7-003", "HIGH", "S7comm",
                f"Program UPLOAD from PLC {row['dst_ip']} by {row['src_ip']} — "
                f"ladder logic being read out. "
                f"Indicates espionage or preparation for modification.",
                "T0843", "Program Upload",
                f"Function: {row['func_name']} (0x{row['func_code']:02X})"
            ))

        # ── RULE S7-004: Unauthorised write variable
        # Write Variable from non-master IP
        # This is the rule that caught 10.10.10.30 in Project 1
        write_mask = (
            requests["is_write"]
            & requests["src_ip"].apply(self._is_unauthorised)
        )
        for _, row in requests[write_mask].iterrows():
            alerts.append(self._make_alert(
                row, "S7-004", "HIGH", "S7comm",
                f"Unauthorised Write Variable from {row['src_ip']} "
                f"to PLC {row['dst_ip']}. "
                f"Source is not in authorised master list.",
                "T0836", "Modify Parameter",
                f"Authorised masters: {sorted(self.authorised_masters)}"
            ))

        # ── RULE S7-005: PLC control command (start/stop/reset)
        ctrl_mask = requests["is_control"] & (requests["func_code"] != 0x29)
        for _, row in requests[ctrl_mask].iterrows():
            alerts.append(self._make_alert(
                row, "S7-005", "HIGH", "S7comm",
                f"PLC Control command from {row['src_ip']} to {row['dst_ip']} — "
                f"{row['func_name']}. "
                f"Operational state change outside normal operations.",
                "T0816", "Device Restart/Shutdown",
                f"Function: {row['func_name']} (0x{row['func_code']:02X})"
            ))

        # ── RULE S7-006: Write-only pattern — automated tool signature
        # A source that only sends Write Variable with no Read Variable
        # is almost certainly running a script, not a human operator.
        # Human operators always read before they write.
        src_funcs = requests.groupby("src_ip")["func_code"].apply(set)
        for src_ip, func_set in src_funcs.items():
            if src_ip in self.authorised_masters:
                continue
            has_writes = 0x05 in func_set
            has_reads  = 0x04 in func_set
            if has_writes and not has_reads:
                write_count = len(requests[
                    (requests["src_ip"] == src_ip) & (requests["func_code"] == 0x05)
                ])
                sample = requests[requests["src_ip"] == src_ip].iloc[0]
                alerts.append(self._make_alert(
                    sample, "S7-006", "HIGH", "S7comm",
                    f"Write-only pattern from {src_ip} — "
                    f"{write_count} writes, 0 reads. "
                    f"Consistent with automated attack tool. "
                    f"Human operators always read before writing.",
                    "T0836", "Modify Parameter",
                    "This behavioural signature distinguishes scripts from human operators"
                ))

        return alerts

    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def to_dataframe(alerts: List[Alert]) -> pd.DataFrame:
        """Convert list of Alert objects to a sorted DataFrame."""
        if not alerts:
            return pd.DataFrame()
        df = pd.DataFrame([vars(a) for a in alerts])
        df["_order"] = df["severity"].map(
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        )
        return (
            df.sort_values(["_order", "timestamp"])
            .drop(columns="_order")
            .reset_index(drop=True)
        )
