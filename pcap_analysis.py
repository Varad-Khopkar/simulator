# pcap_analysis.py
# PCAP analysis + firewall flow simulation for H-SAFE (headless)

from typing import List, Dict

from scapy.all import rdpcap, IP, TCP, UDP, ICMP

from schema import Packet, Detection, new_packet
from rule_implementation import apply_rules


# =========================
# PORT → LANE MAPPING
# =========================

PORT_LANES = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
}

DEFAULT_LANE = "OTHER"


# =========================
# PCAP PARSING
# =========================

def parse_pcap(file_path: str) -> List[Packet]:
    """
    Parse PCAP file and normalize packets to H-SAFE Packet schema.
    """

    packets: List[Packet] = []
    scapy_packets = rdpcap(file_path)

    for pkt in scapy_packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        protocol = None
        src_port = None
        dst_port = None

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
        else:
            continue

        packets.append(
            new_packet(
                src_ip=ip.src,
                dst_ip=ip.dst,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                payload_size=len(bytes(pkt))
            )
        )

    return packets


# =========================
# FLOW ENRICHMENT
# =========================

def _assign_lane(packet: Packet) -> str:
    """
    Assign logical lane based on destination port.
    """
    if packet["dst_port"] is None:
        return DEFAULT_LANE
    return PORT_LANES.get(packet["dst_port"], DEFAULT_LANE)


# =========================
# PCAP FIREWALL SIMULATION
# =========================

def simulate_pcap_flow(
    pcap_path: str,
    rules: List[Dict],
    speed: int = 1
) -> Dict:
    """
    Simulate firewall behavior over PCAP traffic.

    speed:
    - Logical speed factor (used by UI or backend, not sleep-based)
    """

    packets = parse_pcap(pcap_path)

    detections: List[Detection] = apply_rules(packets, rules)

    timeline = []
    action_count = {"ALLOW": 0, "DENY": 0, "ALERT": 0}

    for index, packet in enumerate(packets):
        packet_detections = [
            d for d in detections if d["packet"] == packet
        ]

        if packet_detections:
            # Firewall enforces first matching rule (already ordered)
            decision = packet_detections[0]["action"]
        else:
            decision = "ALLOW"  # default firewall behavior

        action_count[decision] += 1

        timeline.append({
            "index": index,
            "timestamp": packet["timestamp"],
            "src_ip": packet["src_ip"],
            "dst_ip": packet["dst_ip"],
            "protocol": packet["protocol"],
            "dst_port": packet["dst_port"],
            "lane": _assign_lane(packet),
            "action": decision
        })

        # DENY stops further evaluation for this packet only
        # (already handled in rule engine)

    return {
        "summary": {
            "total_packets": len(packets),
            "allow": action_count["ALLOW"],
            "deny": action_count["DENY"],
            "alert": action_count["ALERT"],
            "speed_factor": speed
        },
        "timeline": timeline,
        "detections": detections
    }
