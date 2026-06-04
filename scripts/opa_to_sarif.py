#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DOCS: dict[str, str] = {
    "AZ-STORAGE-001": "https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent",
    "AZ-STORAGE-002": "https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent",
    "AZ-STORAGE-003": "https://learn.microsoft.com/azure/storage/common/storage-network-security",
    "AZ-STORAGE-004": "https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version",
    "AZ-STORAGE-005": "https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer",
}

RULE_ATTR: dict[str, str] = {
    "AZ-STORAGE-001": "allow_nested_items_to_be_public",
    "AZ-STORAGE-002": "shared_access_key_enabled",
    "AZ-STORAGE-003": "public_network_access_enabled",
    "AZ-STORAGE-004": "min_tls_version",
    "AZ-STORAGE-005": "https_traffic_only_enabled",
}

SEVERITY_LEVEL = {
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def load_violations(path: Path) -> list[dict[str, Any]]:
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError as exc:
        sys.exit(f"Input not found: {path} ({exc})")
    except json.JSONDecodeError as exc:
        sys.exit(f"Invalid JSON in {path}: {exc}")
    try:
        value = raw["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError):
        return []
    return value or []


def attr_line_map(tf_path: Path) -> dict[str, int]:
    if not tf_path.exists():
        return {}
    lines = tf_path.read_text().splitlines()
    mapping: dict[str, int] = {}
    for attr in set(RULE_ATTR.values()):
        for idx, line in enumerate(lines, 1):
            if line.lstrip().startswith(f"{attr} ") or line.lstrip().startswith(f"{attr}="):
                if "=" in line:
                    mapping[attr] = idx
                    break
        if attr not in mapping:
            mapping[attr] = 1
    return mapping


def build_sarif(violations: list[dict[str, Any]], tf_path: Path) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    line_map = attr_line_map(tf_path)

    for v in violations:
        rule_id = str(v.get("rule", "UNKNOWN"))
        message = str(v.get("message", "Policy violation"))
        severity = str(v.get("severity", "")).lower()
        level = SEVERITY_LEVEL.get(severity, "note")
        attr = RULE_ATTR.get(rule_id, "")
        start_line = line_map.get(attr, 1)

        if rule_id not in rules:
            rule_entry: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": message},
            }
            help_uri = DOCS.get(rule_id)
            if help_uri:
                rule_entry["helpUri"] = help_uri
            rules[rule_id] = rule_entry

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "terraform/main.tf"},
                            "region": {"startLine": start_line},
                        }
                    }
                ],
            }
        )

    sarif: dict[str, Any] = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "policy-as-code-ai",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert OPA violations JSON to SARIF 2.1.0")
    ap.add_argument("--input", required=True, type=Path, help="OPA eval JSON input")
    ap.add_argument("--output", required=True, type=Path, help="SARIF output path")
    args = ap.parse_args()

    violations = load_violations(args.input)
    sarif = build_sarif(violations, Path("terraform/main.tf"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(sarif, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
