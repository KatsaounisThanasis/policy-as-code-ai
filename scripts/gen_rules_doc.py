#!/usr/bin/env python3
"""
Generate RULES.md from the rules.json single source of truth.

Keeps the human-facing rule catalog always in sync with what the engine
actually enforces (run via `make rules-doc`). Pure stdlib.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import rules  # noqa: E402

SERVICE_NAMES = {
    "STORAGE": "Storage Account",
    "NSG": "Network Security Group",
    "KV": "Key Vault",
    "SQL": "SQL Server",
    "APP": "App Service",
    "DISK": "Managed Disk",
    "COSMOS": "Cosmos DB",
    "AKS": "AKS",
    "ACR": "Container Registry",
    "LOG": "Log Analytics",
}


def service_of(rule_id: str) -> str:
    # AZ-STORAGE-001 -> STORAGE
    parts = rule_id.split("-")
    return parts[1] if len(parts) >= 2 else "?"


def render() -> str:
    defs = list(rules.load_rules())
    services = sorted({service_of(r["id"]) for r in defs})
    out: list[str] = [
        "# Policy Catalog",
        "",
        "> Auto-generated from [`rules.json`](rules.json) by `make rules-doc` — do not edit by hand.",
        "",
        f"**{len(defs)} rules across {len(services)} Azure services.** "
        "Each rule is enforced by a Rego policy under `policies/`, carries a deterministic "
        "remediation, and links to the canonical Microsoft Learn guidance.",
        "",
        "| Rule | Sev | Service | Check | Deterministic fix | Docs |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    display = rules.fix_display()
    for r in defs:
        svc = SERVICE_NAMES.get(service_of(r["id"]), service_of(r["id"]))
        msg = r["message"].replace("|", "\\|")
        fix = display.get(r["id"], "").replace("|", "\\|")
        out.append(
            f"| `{r['id']}` | {r['severity']} | {svc} | {msg} | `{fix}` | [ref]({r['doc']}) |"
        )
    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate RULES.md from rules.json")
    ap.add_argument("--output", "-o", type=Path, default=Path("RULES.md"))
    args = ap.parse_args()
    args.output.write_text(render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
