# rule_implementation.py
# Firewall rule evaluation + enforcement engine for H-SAFE

from typing import List, Dict

from schema import Packet, Rule, Detection, validate_packet, new_detection


# =========================
# INTERNAL MATCHING LOGIC
# =========================

def _match_condition(packet_value, rule_value) -> bool:
    if rule_value is None:
        return True
    return packet_value == rule_value


def _match_payload_size(packet: Packet, min_size, max_size) -> bool:
    size = packet["payload_size"]

    if min_size is not None and size < min_size:
        return False
    if max_size is not None and size > max_size:
        return False

    return True


def _packet_matches_rule(packet: Packet, rule: Rule) -> Dict:
    """
    Returns matched fields dict if rule matches the packet.
    Returns empty dict if rule does not match.
    """

    matched_fields = {}
    conditions = rule["conditions"]

    # Protocol check
    if rule["protocol"] is not None:
        if packet["protocol"] != rule["protocol"]:
            return {}

    field_map = {
        "src_ip": packet["src_ip"],
        "dst_ip": packet["dst_ip"],
        "src_port": packet["src_port"],
        "dst_port": packet["dst_port"]
    }

    for field, packet_value in field_map.items():
        rule_value = conditions.get(field)
        if not _match_condition(packet_value, rule_value):
            return {}
        if rule_value is not None:
            matched_fields[field] = packet_value

    if not _match_payload_size(
        packet,
        conditions.get("min_payload_size"),
        conditions.get("max_payload_size")
    ):
        return {}

    if conditions.get("min_payload_size") is not None:
        matched_fields["min_payload_size"] = conditions["min_payload_size"]
    if conditions.get("max_payload_size") is not None:
        matched_fields["max_payload_size"] = conditions["max_payload_size"]

    return matched_fields


# =========================
# PUBLIC API
# =========================

def apply_rules(packets: List[Packet], rules: List[Rule]) -> List[Detection]:
    """
    Apply firewall rules to packets.

    Rule behavior:
    - ALERT: generate detection, continue evaluation
    - DENY: generate detection, stop evaluation for packet
    - ALLOW: stop evaluation for packet, no detection
    """

    detections: List[Detection] = []

    for packet in packets:
        if not validate_packet(packet):
            continue

        for rule in rules:
            if not rule.get("enabled", True):
                continue

            matched_fields = _packet_matches_rule(packet, rule)
            if not matched_fields:
                continue

            action = rule.get("action", "ALERT")

            # ALERT
            if action == "ALERT":
                detections.append(
                    new_detection(
                        rule=rule,
                        packet=packet,
                        matched_fields=matched_fields
                    )
                )
                continue

            # DENY
            if action == "DENY":
                detections.append(
                    new_detection(
                        rule=rule,
                        packet=packet,
                        matched_fields=matched_fields
                    )
                )
                break

            # ALLOW
            if action == "ALLOW":
                break

            # Unknown action is a configuration error
            raise ValueError(f"Unknown rule action: {action}")

    return detections
