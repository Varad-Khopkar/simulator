# post_attack_analysis.py
# Post-event intelligence and correlation for H-SAFE Firewall Simulator

from typing import Dict, List
from collections import defaultdict

from schema import Detection


# =========================
# INTERNAL HELPERS
# =========================

_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _max_severity(severities: List[str]) -> str:
    if not severities:
        return "LOW"
    return max(severities, key=lambda s: _SEVERITY_ORDER.index(s))


# =========================
# PUBLIC API
# =========================

def analyze_firewall_run(simulation_result: Dict) -> Dict:
    """
    Analyze firewall simulation output and produce intelligence.
    
    Expected input structure:
    {
        "summary": {...},
        "timeline": [...],
        "detections": [...]
    }
    """

    timeline = simulation_result.get("timeline", [])
    detections: List[Detection] = simulation_result.get("detections", [])

    # ---------------------
    # Counters & Buckets
    # ---------------------

    action_counts = defaultdict(int)
    protocol_counts = defaultdict(int)
    lane_counts = defaultdict(int)
    dst_ip_hits = defaultdict(int)
    rule_hits = defaultdict(int)
    severity_hits = defaultdict(int)

    for event in timeline:
        action_counts[event["action"]] += 1
        protocol_counts[event["protocol"]] += 1
        lane_counts[event["lane"]] += 1
        dst_ip_hits[event["dst_ip"]] += 1

    for det in detections:
        rule_hits[det["rule_id"]] += 1
        severity_hits[det["severity"]] += 1

    # ---------------------
    # Timeline Highlights
    # ---------------------

    critical_events = [
        {
            "timestamp": d["timestamp"],
            "rule_id": d["rule_id"],
            "action": d["action"],
            "dst_ip": d["packet"]["dst_ip"]
        }
        for d in detections
        if d["severity"] == "CRITICAL"
    ]

    # ---------------------
    # Top Targets
    # ---------------------

    top_targets = sorted(
        dst_ip_hits.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    # ---------------------
    # Final Intelligence Report
    # ---------------------

    report = {
        "overview": {
            "total_packets": simulation_result["summary"]["total_packets"],
            "allowed": action_counts.get("ALLOW", 0),
            "denied": action_counts.get("DENY", 0),
            "alerted": action_counts.get("ALERT", 0),
            "highest_severity": _max_severity(list(severity_hits.keys()))
        },
        "traffic_profile": {
            "by_protocol": dict(protocol_counts),
            "by_lane": dict(lane_counts)
        },
        "security_findings": {
            "rule_hit_count": dict(rule_hits),
            "severity_distribution": dict(severity_hits),
            "top_targeted_assets": [
                {"ip": ip, "hits": hits} for ip, hits in top_targets
            ]
        },
        "critical_timeline": critical_events,
        "assessment": _generate_assessment(
            action_counts,
            severity_hits,
            top_targets
        )
    }

    return report


# =========================
# ASSESSMENT ENGINE
# =========================

def _generate_assessment(
    action_counts: Dict[str, int],
    severity_hits: Dict[str, int],
    top_targets: List
) -> str:
    """
    Generate a human-readable security assessment.
    """

    if severity_hits.get("CRITICAL", 0) > 0:
        return (
            "CRITICAL activity detected. Immediate investigation recommended. "
            "Firewall successfully blocked high-risk traffic, but targeted assets "
            "show signs of sustained probing."
        )

    if action_counts.get("DENY", 0) > 0:
        return (
            "Suspicious activity detected and blocked. "
            "Firewall rules appear effective, but tuning may be required "
            "to reduce alert volume."
        )

    if action_counts.get("ALERT", 0) > 0:
        return (
            "Potentially suspicious traffic observed. "
            "No direct policy violations detected."
        )

    return (
        "No malicious activity detected. Traffic appears benign."
    )
