#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Import the shared single source of truth (repo-root rules.json) + HCL locator from src/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import hcl  # noqa: E402
import rules  # noqa: E402

# rule id -> canonical Microsoft Learn URL, and rule id -> SARIF anchor attribute.
# Both derived from rules.json so they can never drift from explainer.py / CI.
DOCS: dict[str, str] = rules.docs()
RULE_ATTR: dict[str, str] = rules.rule_attr()

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


def build_sarif(
    violations: list[dict[str, Any]], tf_path: Path, tf_uri: str
) -> dict[str, Any]:
    rule_index: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    tf_text = tf_path.read_text() if tf_path.exists() else ""

    for v in violations:
        rule_id = str(v.get("rule", "UNKNOWN"))
        message = str(v.get("message", "Policy violation"))
        severity = str(v.get("severity", "")).lower()
        level = SEVERITY_LEVEL.get(severity, "note")
        attr = RULE_ATTR.get(rule_id, "")
        # Resource-scoped line: the attribute *inside the offending resource's*
        # block, so N resources sharing an attribute don't all point at line 1.
        start_line = None
        if tf_text and attr:
            start_line = hcl.find_attr_line(tf_text, v.get("resource", ""), attr)
        start_line = start_line or 1

        if rule_id not in rule_index:
            rule_entry: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": message},
            }
            help_uri = DOCS.get(rule_id)
            if help_uri:
                rule_entry["helpUri"] = help_uri
            rule_index[rule_id] = rule_entry

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": tf_uri},
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
                        "rules": list(rule_index.values()),
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
    ap.add_argument(
        "--tf-file",
        type=Path,
        default=Path("terraform/main.tf"),
        help="Terraform file the findings point at (for line mapping + SARIF uri; "
        "default: terraform/main.tf)",
    )
    args = ap.parse_args()

    violations = load_violations(args.input)
    # SARIF uri stays relative with forward slashes so GitHub anchors it in-repo.
    tf_uri = args.tf_file.as_posix()
    sarif = build_sarif(violations, args.tf_file, tf_uri)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(sarif, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
