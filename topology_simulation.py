# topology_simulation.py
# Network topology and traffic simulation for H-SAFE Firewall Simulator

import time
from typing import Dict, List

from schema import Packet, new_packet


# =========================
# INTERNAL HELPERS
# =========================

def _get_ip(topology: Dict, node_name: str) -> str:
    return topology["nodes"][node_name]["ip"]


def _path_exists(paths: List[tuple], src: str, dst: str) -> bool:
    return (src, dst) in paths


# =========================
# PUBLIC API
# =========================

def simulate_attack(
    topology: Dict,
    attacker_node: str,
    target_node: str,
    protocol: str = "TCP",
    dst_port: int = 80,
    packet_count: int = 5,
    payload_size: int = 512
) -> List[Packet]:
    """
    Simulate attack traffic flowing through the firewall.
    """

    packets: List[Packet] = []

    if attacker_node not in topology["nodes"]:
        raise ValueError("Invalid attacker node")

    if target_node not in topology["nodes"]:
        raise ValueError("Invalid target node")

    paths = topology.get("paths", [])

    # Enforce that traffic must pass through firewall if defined
    if "firewall" in topology["nodes"]:
        if not (
            _path_exists(paths, attacker_node, "firewall")
            and _path_exists(paths, "firewall", target_node)
        ):
            raise ValueError("No valid path through firewall")
        src_ip = _get_ip(topology, attacker_node)
        dst_ip = _get_ip(topology, target_node)
    else:
        src_ip = _get_ip(topology, attacker_node)
        dst_ip = _get_ip(topology, target_node)

    for _ in range(packet_count):
        packet = new_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=4444 if protocol in {"TCP", "UDP"} else None,
            dst_port=dst_port if protocol in {"TCP", "UDP"} else None,
            payload_size=payload_size
        )
        packets.append(packet)

        # deterministic spacing
        time.sleep(0.01)

    return packets
