# policy_order_analyzer.py
# Firewall rule order and reachability analysis for H-SAFE

from typing import List, Dict, Tuple

from schema import Rule


# =========================
# INTERNAL HELPERS
# =========================


def _rule_sort_key(rule: Rule, fallback_index: int):
    """
    Explicit position wins.
    Missing position falls back to list order.
    """
    if rule.get("position") is not None:
        return (rule["position"], fallback_index)
    return (float("inf"), fallback_index)

def _conditions_overlap(c1: Dict, c2: Dict) -> bool:
    """
    Check whether two rule condition sets overlap.
    None = wildcard.
    """
    for key in ["src_ip", "dst_ip", "src_port", "dst_port"]:
        v1 = c1.get(key)
        v2 = c2.get(key)

        if v1 is not None and v2 is not None and v1 != v2:
            return False

    return True


def _protocol_overlap(p1, p2) -> bool:
    if p1 is None or p2 is None:
        return True
    return p1 == p2


def _rule_covers(r1: Rule, r2: Rule) -> bool:
    """
    Returns True if r1 fully covers r2 traffic-wise.
    """
    if not _protocol_overlap(r1["protocol"], r2["protocol"]):
        return False

    return _conditions_overlap(r1["conditions"], r2["conditions"])


# =========================
# PUBLIC ANALYZER
# =========================

def analyze_policy_order(rules: List[Rule]) -> Dict:
    """
    Analyze firewall rule ordering issues.

    Returns structured findings:
    - shadowed_rules
    - allow_before_deny
    - overlapping_rules
    - recommendations
    """

    findings = {
        "shadowed_rules": [],
        "allow_before_deny": [],
        "overlapping_rules": [],
        "recommendations": []
    }

    # Ensure deterministic order
    ordered_rules = [
    r for r in rules if r.get("enabled", True)
]


    # ---------------------
    # Pairwise Analysis
    # ---------------------

    for i, rule_i in enumerate(ordered_rules):
        for j in range(i + 1, len(ordered_rules)):
            rule_j = ordered_rules[j]

            # Check traffic overlap
            if not _rule_covers(rule_i, rule_j):
                continue

            # Case 1: Shadowed rule
            if rule_i["action"] in {"ALLOW", "DENY"}:
                findings["shadowed_rules"].append({
                    "shadowed_rule_id": rule_j["rule_id"],
                    "shadowed_by": rule_i["rule_id"],
                    "reason": f"{rule_i['action']} rule earlier in policy"
                })

            # Case 2: ALLOW before DENY (dangerous)
            if rule_i["action"] == "ALLOW" and rule_j["action"] == "DENY":
                findings["allow_before_deny"].append({
                    "allow_rule": rule_i["rule_id"],
                    "deny_rule": rule_j["rule_id"],
                    "risk": "DENY rule may never trigger"
                })

            # Case 3: Overlapping ALERT rules
            if rule_i["action"] == "ALERT" and rule_j["action"] == "ALERT":
                findings["overlapping_rules"].append({
                    "rule_1": rule_i["rule_id"],
                    "rule_2": rule_j["rule_id"],
                    "note": "Multiple ALERT rules match same traffic"
                })

    # ---------------------
    # Recommendations
    # ---------------------

    if findings["allow_before_deny"]:
        findings["recommendations"].append(
            "Review ALLOW rules placed before DENY rules; "
            "consider reordering to avoid bypassing security controls."
        )

    if findings["shadowed_rules"]:
        findings["recommendations"].append(
            "Remove or refactor shadowed rules that will never be evaluated."
        )

    if findings["overlapping_rules"]:
        findings["recommendations"].append(
            "Consolidate overlapping ALERT rules to reduce noise."
        )

    if not findings["recommendations"]:
        findings["recommendations"].append(
            "Policy order appears clean with no critical issues detected."
        )

    return findings
