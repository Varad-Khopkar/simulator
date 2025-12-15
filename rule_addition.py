# rule_addition.py
# Firewall policy management for H-SAFE

import json
import os
import uuid
from typing import List

from schema import Rule, RuleConditions, validate_rule

RULE_STORE_PATH = "rules.json"


# =========================
# INTERNAL HELPERS
# =========================

def _load_rules_from_disk() -> List[Rule]:
    if not os.path.exists(RULE_STORE_PATH):
        return []

    with open(RULE_STORE_PATH, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            if not isinstance(data, list):
                return []
            return data
        except json.JSONDecodeError:
            return []


def _save_rules_to_disk(rules: List[Rule]) -> None:
    with open(RULE_STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=4)


# =========================
# PUBLIC API
# =========================

def add_rule(
    name: str,
    description: str,
    severity: str,
    protocol: str | None,
    conditions: RuleConditions,
    enabled: bool = True
) -> Rule:
    """
    Create, validate, and persist a new firewall rule.
    """

    rule: Rule = {
        "rule_id": str(uuid.uuid4()),
        "name": name,
        "description": description,
        "severity": severity,
        "protocol": protocol,
        "conditions": conditions,
        "enabled": enabled
    }

    if not validate_rule(rule):
        raise ValueError("Invalid rule schema or values")

    rules = _load_rules_from_disk()
    rules.append(rule)
    _save_rules_to_disk(rules)

    return rule


def get_all_rules(include_disabled: bool = False) -> List[Rule]:
    """
    Retrieve all stored firewall rules.
    """

    rules = _load_rules_from_disk()

    if include_disabled:
        return rules

    return [rule for rule in rules if rule.get("enabled") is True]


def get_rule_by_id(rule_id: str) -> Rule | None:
    """
    Fetch a single rule by rule_id.
    """

    rules = _load_rules_from_disk()

    for rule in rules:
        if rule.get("rule_id") == rule_id:
            return rule

    return None


def disable_rule(rule_id: str) -> bool:
    """
    Disable a firewall rule without deleting it.
    """

    rules = _load_rules_from_disk()
    updated = False

    for rule in rules:
        if rule.get("rule_id") == rule_id:
            rule["enabled"] = False
            updated = True
            break

    if updated:
        _save_rules_to_disk(rules)

    return updated


def delete_rule(rule_id: str) -> bool:
    """
    Permanently delete a firewall rule.
    """

    rules = _load_rules_from_disk()
    new_rules = [rule for rule in rules if rule.get("rule_id") != rule_id]

    if len(new_rules) == len(rules):
        return False

    _save_rules_to_disk(new_rules)
    return True
