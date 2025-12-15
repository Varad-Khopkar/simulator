# schema.py
# Single source of truth for all data contracts used in H-SAFE Firewall Simulator

from typing import TypedDict, Optional, Dict, List
import time
import uuid


# =========================
# PACKET SCHEMA
# =========================

class Packet(TypedDict):
    src_ip: str
    dst_ip: str
    protocol: str                  # TCP | UDP | ICMP
    src_port: Optional[int]
    dst_port: Optional[int]
    payload_size: int
    timestamp: float


# =========================
# RULE SCHEMA
# =========================

class RuleConditions(TypedDict):
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    min_payload_size: Optional[int]
    max_payload_size: Optional[int]


class Rule(TypedDict):
    rule_id: str
    name: str
    description: str
    severity: str                  # LOW | MEDIUM | HIGH | CRITICAL
    protocol: Optional[str]
    conditions: RuleConditions
    action: str                    # ALLOW | DENY | ALERT
    enabled: bool
    position: Optional[int]        # Lower = higher priority



# =========================
# DETECTION SCHEMA
# =========================

class Detection(TypedDict):
    detection_id: str
    rule_id: str
    rule_name: str
    severity: str
    action: str
    matched_fields: Dict
    packet: Packet
    timestamp: float


# =========================
# POST-ATTACK ANALYSIS SCHEMA
# =========================

class AnalysisSummary(TypedDict):
    total_packets: int
    total_detections: int
    unique_rules_triggered: int
    highest_severity: str


class AnalysisReport(TypedDict):
    summary: AnalysisSummary
    affected_assets: Dict[str, int]
    detections_by_severity: Dict[str, int]
    timeline: List[Dict]


# =========================
# VALIDATION HELPERS
# =========================

_ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_ALLOWED_ACTIONS = {"ALLOW", "DENY", "ALERT"}


def _has_keys(data: dict, keys: List[str]) -> bool:
    return all(key in data for key in keys)


def validate_packet(packet: dict) -> bool:
    required_keys = Packet.__annotations__.keys()
    return isinstance(packet, dict) and _has_keys(packet, list(required_keys))


def validate_rule(rule: dict) -> bool:
    required_keys = Rule.__annotations__.keys()
    if not isinstance(rule, dict) or not _has_keys(rule, list(required_keys)):
        return False

    if rule["severity"] not in _ALLOWED_SEVERITIES:
        return False

    if rule["action"] not in _ALLOWED_ACTIONS:
        return False

    return True


def validate_detection(detection: dict) -> bool:
    required_keys = Detection.__annotations__.keys()
    return isinstance(detection, dict) and _has_keys(detection, list(required_keys))


# =========================
# FACTORY HELPERS
# =========================

def new_packet(
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    payload_size: int
) -> Packet:
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        payload_size=payload_size,
        timestamp=time.time()
    )


def new_detection(
    rule: Rule,
    packet: Packet,
    matched_fields: Dict
) -> Detection:
    return Detection(
        detection_id=str(uuid.uuid4()),
        rule_id=rule["rule_id"],
        rule_name=rule["name"],
        severity=rule["severity"],
        action=rule["action"],
        matched_fields=matched_fields,
        packet=packet,
        timestamp=time.time()
    )
