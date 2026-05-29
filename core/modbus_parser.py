"""
core/modbus_parser.py
─────────────────────
Parses Modbus TCP packets from a PCAP into a structured DataFrame.

Modbus TCP wire format (port 502):
    Bytes 0-1  : Transaction ID  — increments per request
    Bytes 2-3  : Protocol ID     — always 0x0000 (validates Modbus)
    Bytes 4-5  : Length          — bytes remaining after this field
    Byte  6    : Unit ID         — target slave device (1-247)
    Byte  7    : Function Code   — the command being issued
    Bytes 8+   : Data            — register address, values, etc.

Function codes (FC) are the commands. Knowing these is essential:
    0x01 (1)   Read Coils              — reads binary outputs (on/off)
    0x02 (2)   Read Discrete Inputs    — reads binary inputs (sensors)
    0x03 (3)   Read Holding Registers  — reads analogue values (most common)
    0x04 (4)   Read Input Registers    — reads analogue sensor inputs
    0x05 (5)   Write Single Coil       — turns one output on or off ⚠️
    0x06 (6)   Write Single Register   — changes one analogue value ⚠️
    0x08 (8)   Diagnostics             — can restart PLC 🚨
    0x0F (15)  Write Multiple Coils    — changes many outputs at once 🚨
    0x10 (16)  Write Multiple Regs     — changes many values at once 🚨
    0x2B (43)  Read Device ID          — reconnaissance / enumeration
"""

import struct
from typing import Optional

import pandas as pd
from scapy.all import rdpcap, TCP, IP, Raw

MODBUS_PORT = 502

# Human-readable names for function codes
FC_NAMES = {
    1:  "Read Coils",
    2:  "Read Discrete Inputs",
    3:  "Read Holding Registers",
    4:  "Read Input Registers",
    5:  "Write Single Coil",
    6:  "Write Single Register",
    7:  "Read Exception Status",
    8:  "Diagnostics",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    43: "Read Device ID (Recon)",
}

# Which function codes are write/control commands
WRITE_FCS   = {5, 6, 15, 16}
DANGER_FCS  = {8}
RECON_FCS   = {43}


def _decode_mbap(payload: bytes) -> Optional[dict]:
    """
    Decode a Modbus Application Protocol (MBAP) header + PDU.
    Returns None if payload is not valid Modbus.

    The key validation check is Protocol ID == 0x0000.
    Any TCP packet on port 502 that does not have 0x0000 at bytes 2-3
    is not Modbus and is discarded.
    """
    if len(payload) < 8:
        return None

    try:
        transaction_id = struct.unpack(">H", payload[0:2])[0]
        protocol_id    = struct.unpack(">H", payload[2:4])[0]
        length         = struct.unpack(">H", payload[4:6])[0]
        unit_id        = payload[6]
        function_code  = payload[7]

        # Protocol ID must be 0 for valid Modbus
        if protocol_id != 0:
            return None

        # High bit set on FC = error response
        is_error = bool(function_code & 0x80)
        actual_fc = function_code & 0x7F if is_error else function_code
        exception_code = payload[8] if (is_error and len(payload) > 8) else None

        # Extract register address and value if present
        register_addr = (
            struct.unpack(">H", payload[8:10])[0]
            if len(payload) >= 10 else None
        )
        value = (
            struct.unpack(">H", payload[10:12])[0]
            if len(payload) >= 12 else None
        )

        return {
            "transaction_id": transaction_id,
            "unit_id":        unit_id,
            "function_code":  actual_fc,
            "fc_hex":         f"0x{actual_fc:02X}",
            "register_addr":  register_addr,
            "value":          value,
            "is_error":       is_error,
            "exception_code": exception_code,
            "payload_len":    length,
        }

    except Exception:
        return None


def parse(pcap_path: str, verbose: bool = True) -> pd.DataFrame:
    """
    Parse all Modbus TCP packets from a PCAP file.

    Args:
        pcap_path : Path to PCAP file
        verbose   : Print progress messages

    Returns:
        DataFrame with one row per Modbus packet.
        Empty DataFrame if no Modbus traffic found.
    """
    if verbose:
        print(f"[modbus] Parsing: {pcap_path}")

    packets = rdpcap(pcap_path)
    records = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw)):
            continue

        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        if sport != MODBUS_PORT and dport != MODBUS_PORT:
            continue

        mbap = _decode_mbap(bytes(pkt[Raw].load))
        if mbap is None:
            continue

        fc = mbap["function_code"]
        records.append({
            "timestamp":      pd.to_datetime(float(pkt.time), unit="s"),
            "src_ip":         pkt[IP].src,
            "dst_ip":         pkt[IP].dst,
            "src_port":       sport,
            "dst_port":       dport,
            "direction":      "REQUEST" if dport == MODBUS_PORT else "RESPONSE",
            "unit_id":        mbap["unit_id"],
            "function_code":  fc,
            "fc_hex":         mbap["fc_hex"],
            "fc_name":        FC_NAMES.get(fc, f"Unknown FC {fc}"),
            "is_write":       fc in WRITE_FCS,
            "is_dangerous":   fc in DANGER_FCS,
            "is_recon":       fc in RECON_FCS,
            "register_addr":  mbap["register_addr"],
            "value":          mbap["value"],
            "is_error":       mbap["is_error"],
            "exception_code": mbap["exception_code"],
            "transaction_id": mbap["transaction_id"],
        })

    df = pd.DataFrame(records)

    if verbose:
        if df.empty:
            print(f"[modbus] No Modbus TCP packets found (port {MODBUS_PORT} not in capture)")
        else:
            print(f"[modbus] Packets decoded: {len(df):,}")
            print(f"[modbus] Unique sources : {df['src_ip'].nunique()}")
            print(f"[modbus] Unique targets : {df['dst_ip'].nunique()}")
            req = df[df["direction"] == "REQUEST"]
            if not req.empty:
                print(f"[modbus] Write commands : {req['is_write'].sum()}")
                print(f"[modbus] Danger commands: {req['is_dangerous'].sum()}")

    return df
