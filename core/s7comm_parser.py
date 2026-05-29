"""
core/s7comm_parser.py
─────────────────────
Parses S7comm packets from a PCAP into a structured DataFrame.

S7comm is Siemens' proprietary protocol for S7-300, S7-400, S7-1200, S7-1500 PLCs.
It runs on port 102 inside two transport layers:

    TPKT (4 bytes):
        [0]   Version = 0x03
        [1]   Reserved = 0x00
        [2-3] Total packet length

    COTP (variable, typically 3 bytes for data transfer):
        [4]   Length
        [5]   PDU type (0xF0 = Data)
        [6]   TPDU number + last data unit flag

    S7comm header (starts at byte 7):
        [7]   Protocol ID = 0x32 (always — this is how we identify S7comm)
        [8]   Message type (Job=0x01, Ack=0x02, Ack+data=0x03, Userdata=0x07)
        [9-10]  Reserved
        [11-12] PDU reference (matches request to response)
        [13-14] Parameter length
        [15-16] Data length
        [17]  Function code (first byte of parameter area)

STUXNET (2010) used S7comm to reprogram Siemens PLCs controlling
Iranian uranium centrifuges — the most famous ICS cyberattack in history.
"""

import struct
from typing import Optional

import pandas as pd
from scapy.all import rdpcap, TCP, IP, Raw

S7_PORT = 102

# S7comm function codes — the commands that can be sent to a Siemens PLC
S7_FUNCTIONS = {
    0xF0: "Setup Communication",      # Session setup — always first packet
    0x04: "Read Variable",            # Normal polling — read sensor/data
    0x05: "Write Variable",           # ⚠️  Write data to PLC memory
    0x1A: "Request Download",         # 🚨 Start writing new program
    0x1B: "Download Block",           # 🚨 Transmit program block
    0x1C: "Download Ended",           # 🚨 Finish program write
    0x1D: "Start Upload",             # 🚨 Start reading PLC program
    0x1E: "Upload Block",             # 🚨 Receive program block
    0x1F: "End Upload",               # 🚨 Finish program read
    0x28: "PLC Control",              # 🚨 Start/Stop/Reset PLC
    0x29: "PLC Stop",                 # 🚨 CRITICAL — halts all PLC execution
}

# S7comm message types — tells you direction and type of communication
S7_MSG_TYPES = {
    0x01: "Job (Request)",            # Engineering WS → PLC
    0x02: "Ack (no data)",            # PLC → Engineering WS (simple confirm)
    0x03: "Ack (with data)",          # PLC → Engineering WS (data response)
    0x07: "Userdata",                 # Diagnostics and special functions
}

# Categorise function codes by risk
WRITE_FCS    = {0x05}
DOWNLOAD_FCS = {0x1A, 0x1B, 0x1C}
UPLOAD_FCS   = {0x1D, 0x1E, 0x1F}
CONTROL_FCS  = {0x28, 0x29}
DANGER_FCS   = DOWNLOAD_FCS | UPLOAD_FCS | CONTROL_FCS


def _find_s7_start(payload: bytes) -> Optional[int]:
    """
    Find the byte position of the S7comm header inside a TPKT/COTP packet.
    Scans for the S7comm protocol ID byte (0x32).

    Returns the index of 0x32, or None if not found.
    """
    for i in range(4, min(20, len(payload))):
        if payload[i] == 0x32:
            return i
    return None


def _decode_s7(payload: bytes) -> Optional[dict]:
    """
    Decode an S7comm packet from raw TCP payload bytes.
    Returns None if payload is not valid S7comm.
    """
    if len(payload) < 10:
        return None

    # Must start with TPKT magic bytes 0x03 0x00
    if payload[0] != 0x03 or payload[1] != 0x00:
        return None

    s7_start = _find_s7_start(payload)
    if s7_start is None or len(payload) < s7_start + 10:
        return None

    try:
        msg_type  = payload[s7_start + 1]
        pdu_ref   = struct.unpack(">H", payload[s7_start + 4:s7_start + 6])[0]
        param_len = struct.unpack(">H", payload[s7_start + 6:s7_start + 8])[0]
        data_len  = struct.unpack(">H", payload[s7_start + 8:s7_start + 10])[0]

        # Function code is the first byte of the parameter area
        func_code = None
        func_name = "Unknown"
        param_start = s7_start + 10
        if param_len > 0 and len(payload) > param_start:
            func_code = payload[param_start]
            func_name = S7_FUNCTIONS.get(func_code, f"Unknown 0x{func_code:02X}")

        # Error info in Ack messages
        error_class = None
        error_code  = None
        if msg_type in [0x02, 0x03] and len(payload) >= s7_start + 12:
            error_class = payload[s7_start + 10]
            error_code  = payload[s7_start + 11]

        return {
            "msg_type":    msg_type,
            "msg_name":    S7_MSG_TYPES.get(msg_type, f"Unknown 0x{msg_type:02X}"),
            "pdu_ref":     pdu_ref,
            "func_code":   func_code,
            "func_name":   func_name,
            "param_len":   param_len,
            "data_len":    data_len,
            "error_class": error_class,
            "error_code":  error_code,
            "is_response": msg_type in [0x02, 0x03],
        }

    except Exception:
        return None


def parse(pcap_path: str, verbose: bool = True) -> pd.DataFrame:
    """
    Parse all S7comm packets from a PCAP file.

    Args:
        pcap_path : Path to PCAP file
        verbose   : Print progress messages

    Returns:
        DataFrame with one row per S7comm packet.
        Empty DataFrame if no S7comm traffic found.
    """
    if verbose:
        print(f"[s7comm] Parsing: {pcap_path}")

    packets = rdpcap(pcap_path)
    records = []
    skipped = 0

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw)):
            continue

        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        if sport != S7_PORT and dport != S7_PORT:
            continue

        s7 = _decode_s7(bytes(pkt[Raw].load))
        if s7 is None:
            skipped += 1
            continue

        fc = s7["func_code"]
        records.append({
            "timestamp":    pd.to_datetime(float(pkt.time), unit="s"),
            "src_ip":       pkt[IP].src,
            "dst_ip":       pkt[IP].dst,
            "src_port":     sport,
            "dst_port":     dport,
            "direction":    "REQUEST" if dport == S7_PORT else "RESPONSE",
            "msg_type":     s7["msg_name"],
            "func_code":    fc,
            "func_name":    s7["func_name"],
            "pdu_ref":      s7["pdu_ref"],
            "data_len":     s7["data_len"],
            "is_response":  s7["is_response"],
            "is_write":     fc in WRITE_FCS if fc else False,
            "is_download":  fc in DOWNLOAD_FCS if fc else False,
            "is_upload":    fc in UPLOAD_FCS if fc else False,
            "is_control":   fc in CONTROL_FCS if fc else False,
            "is_dangerous": fc in DANGER_FCS if fc else False,
            "error_class":  s7["error_class"],
            "error_code":   s7["error_code"],
        })

    df = pd.DataFrame(records)

    if verbose:
        if df.empty:
            print(f"[s7comm] No S7comm packets found (port {S7_PORT} not in capture)")
        else:
            print(f"[s7comm] Packets decoded : {len(df):,}")
            print(f"[s7comm] Skipped (non-S7): {skipped:,}")
            print(f"[s7comm] Unique sources  : {df['src_ip'].nunique()}")
            print(f"[s7comm] Unique targets  : {df['dst_ip'].nunique()}")
            req = df[df["direction"] == "REQUEST"]
            if not req.empty:
                print(f"[s7comm] Write commands  : {req['is_write'].sum()}")
                print(f"[s7comm] Danger commands : {req['is_dangerous'].sum()}")

    return df
