"""
core/protocol_discovery.py
──────────────────────────
First step of analysis. Scans a PCAP and identifies which ICS protocols
are present before any protocol-specific parsing begins.

Why this exists:
    Real OT networks are multi-protocol. A tool that only looks for Modbus
    will silently produce no results on a Siemens network. This module
    looks at every packet first and reports what IS there, so the right
    parsers are invoked automatically.

This is the same approach used by commercial OT security tools (Nozomi,
Claroty, Dragos) when they first see a new network environment.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set

from scapy.all import rdpcap, TCP, UDP, IP, ARP


# ── Protocol port map — every known ICS protocol port
# Keyed by port number, value is (protocol name, transport)
ICS_PORTS = {
    502:   ("Modbus TCP",           "TCP"),
    20000: ("DNP3",                 "TCP"),
    44818: ("EtherNet/IP",          "TCP"),
    102:   ("S7comm (Siemens)",     "TCP"),
    4840:  ("OPC-UA",               "TCP"),
    1911:  ("Niagara Fox",          "TCP"),
    9600:  ("OMRON FINS",           "TCP"),
    2404:  ("IEC 60870-5-104",      "TCP"),
    47808: ("BACnet",               "UDP"),
    18245: ("GE SRTP",              "TCP"),
    1962:  ("PCWorx (Phoenix)",     "TCP"),
    20547: ("ProConOS",             "TCP"),
    789:   ("Red Lion Controls",    "TCP"),
    4000:  ("Emerson ROC",          "UDP"),
}


@dataclass
class ProtocolFinding:
    """Result for a single protocol found in the PCAP."""
    name: str
    port: int
    transport: str
    packet_count: int
    source_ips: Set[str]
    destination_ips: Set[str]
    first_seen: float
    last_seen: float

    @property
    def duration_seconds(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def unique_sources(self) -> int:
        return len(self.source_ips)

    @property
    def unique_destinations(self) -> int:
        return len(self.destination_ips)


@dataclass
class DiscoveryResult:
    """Full result from scanning a PCAP."""
    total_packets: int = 0
    total_ip_packets: int = 0
    total_tcp_packets: int = 0
    total_udp_packets: int = 0
    arp_packets: int = 0
    non_ip_packets: int = 0
    protocols_found: Dict[int, ProtocolFinding] = field(default_factory=dict)
    all_tcp_ports: Counter = field(default_factory=Counter)
    all_udp_ports: Counter = field(default_factory=Counter)
    unique_hosts: Set[str] = field(default_factory=set)

    @property
    def has_ics_traffic(self) -> bool:
        return len(self.protocols_found) > 0

    @property
    def dominant_protocol(self) -> str:
        if not self.protocols_found:
            return "None"
        top = max(self.protocols_found.values(), key=lambda p: p.packet_count)
        return top.name


def discover_protocols(pcap_path: str, verbose: bool = True) -> DiscoveryResult:
    """
    Scan a PCAP file and identify all ICS protocols present.

    Args:
        pcap_path: Path to the PCAP file
        verbose:   Print progress to stdout

    Returns:
        DiscoveryResult with full protocol inventory
    """
    if verbose:
        print(f"[discovery] Loading: {pcap_path}")

    packets = rdpcap(pcap_path)
    result  = DiscoveryResult(total_packets=len(packets))

    if verbose:
        print(f"[discovery] Total packets: {len(packets):,}")
        print(f"[discovery] Scanning for ICS protocols...")

    # Temporary storage for building ProtocolFindings
    proto_data = defaultdict(lambda: {
        "count": 0,
        "src_ips": set(),
        "dst_ips": set(),
        "first": None,
        "last": None,
    })

    for pkt in packets:
        ts = float(pkt.time)

        if pkt.haslayer(ARP):
            result.arp_packets += 1

        if not pkt.haslayer(IP):
            result.non_ip_packets += 1
            continue

        result.total_ip_packets += 1
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        result.unique_hosts.add(src_ip)
        result.unique_hosts.add(dst_ip)

        # ── TCP
        if pkt.haslayer(TCP):
            result.total_tcp_packets += 1
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            result.all_tcp_ports[dport] += 1

            # Check both directions (request and response)
            for port in [dport, sport]:
                if port in ICS_PORTS:
                    d = proto_data[port]
                    d["count"] += 1
                    d["src_ips"].add(src_ip)
                    d["dst_ips"].add(dst_ip)
                    if d["first"] is None or ts < d["first"]:
                        d["first"] = ts
                    if d["last"] is None or ts > d["last"]:
                        d["last"] = ts

        # ── UDP
        elif pkt.haslayer(UDP):
            result.total_udp_packets += 1
            dport = pkt[UDP].dport
            result.all_udp_ports[dport] += 1
            if dport in ICS_PORTS:
                d = proto_data[dport]
                d["count"] += 1
                d["src_ips"].add(src_ip)
                d["dst_ips"].add(dst_ip)
                if d["first"] is None or ts < d["first"]:
                    d["first"] = ts
                if d["last"] is None or ts > d["last"]:
                    d["last"] = ts

    # Build ProtocolFinding objects
    for port, data in proto_data.items():
        if data["count"] > 0:
            name, transport = ICS_PORTS[port]
            result.protocols_found[port] = ProtocolFinding(
                name=name,
                port=port,
                transport=transport,
                packet_count=data["count"],
                source_ips=data["src_ips"],
                destination_ips=data["dst_ips"],
                first_seen=data["first"],
                last_seen=data["last"],
            )

    if verbose:
        _print_discovery_summary(result)

    return result


def _print_discovery_summary(result: DiscoveryResult) -> None:
    """Print a formatted discovery summary to stdout."""
    print()
    print("=" * 60)
    print("  PROTOCOL DISCOVERY RESULTS")
    print("=" * 60)
    print(f"  Total packets    : {result.total_packets:,}")
    print(f"  IP packets       : {result.total_ip_packets:,}")
    print(f"  TCP packets      : {result.total_tcp_packets:,}")
    print(f"  UDP packets      : {result.total_udp_packets:,}")
    print(f"  Unique hosts     : {len(result.unique_hosts)}")
    print()

    if result.has_ics_traffic:
        print(f"  ICS protocols found: {len(result.protocols_found)}")
        print()
        for port, finding in sorted(
            result.protocols_found.items(),
            key=lambda x: -x[1].packet_count
        ):
            print(f"  ✅ {finding.name} (port {port})")
            print(f"     Packets  : {finding.packet_count:,}")
            print(f"     Sources  : {finding.unique_sources} unique IPs")
            print(f"     Targets  : {finding.unique_destinations} unique IPs")
            print()
    else:
        print("  ❌ No known ICS protocols found on standard ports.")
        print()
        print("  Top 10 TCP destination ports:")
        for port, count in result.all_tcp_ports.most_common(10):
            label = ICS_PORTS.get(port, ("Unknown",))[0]
            print(f"    Port {port:>6}: {count:>8,} packets  {label}")
