#!/usr/bin/env python3
"""
Single source of truth loader.

Reads the repo-root ``rules.json`` and exposes the per-rule metadata that used
to be hand-duplicated across ``src/explainer.py`` (DOCS + REMEDIATIONS),
``scripts/opa_to_sarif.py`` (DOCS + RULE_ATTR) and the CI PR-comment fix table.
Every consumer now derives its maps from here, so a rule is defined in exactly
one place. The ``.rego`` files still own the detection logic;
``tests/test_rules_consistency.py`` binds the two.

Pure stdlib on purpose — the project ships zero runtime dependencies.
"""

from __future__ import annotations

import json
import os
from functools import cache
from pathlib import Path
from typing import Any


def _resolve_rules_path() -> Path:
    """Locate rules.json: $PAC_RULES_JSON, then repo-root next to src/, then CWD.

    The repo-root case (src/rules.py -> ../rules.json) covers `python3 src/...`
    runs and editable installs; the env override + CWD fallback let an installed
    `pac-explain` be pointed at a rules.json in another checkout.
    """
    env = os.environ.get("PAC_RULES_JSON")
    if env:
        return Path(env)
    repo_root = Path(__file__).resolve().parent.parent / "rules.json"
    if repo_root.exists():
        return repo_root
    return Path.cwd() / "rules.json"


RULES_PATH = _resolve_rules_path()


@cache
def load_rules(path: str | None = None) -> tuple[dict[str, Any], ...]:
    """Return the rule dicts as an (immutable, cached) tuple."""
    p = Path(path) if path else _resolve_rules_path()
    try:
        data = json.loads(p.read_text())
    except FileNotFoundError as exc:  # pragma: no cover - config must exist
        raise RuntimeError(
            f"rules.json not found at {p}. Set PAC_RULES_JSON or run from the repo root."
        ) from exc
    return tuple(data["rules"])


def by_id() -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in load_rules()}


def docs() -> dict[str, str]:
    """rule id -> canonical Microsoft Learn URL."""
    return {r["id"]: r["doc"] for r in load_rules() if r.get("doc")}


def remediations() -> dict[str, dict[str, str]]:
    """rule id -> {attribute: HCL value literal} deterministic fix map."""
    return {
        r["id"]: {r["fix"]["attribute"]: r["fix"]["value"]}
        for r in load_rules()
        if r.get("fix")
    }


def rule_attr() -> dict[str, str]:
    """rule id -> attribute to anchor the SARIF finding on (falls back to the fix attribute)."""
    out: dict[str, str] = {}
    for r in load_rules():
        attr = r.get("sarif_attr") or (r.get("fix") or {}).get("attribute")
        if attr:
            out[r["id"]] = attr
    return out


def severities() -> dict[str, str]:
    return {r["id"]: r["severity"] for r in load_rules()}


def messages() -> dict[str, str]:
    return {r["id"]: r["message"] for r in load_rules()}


def fix_display() -> dict[str, str]:
    """rule id -> the human string shown in the CI PR comment."""
    out: dict[str, str] = {}
    for r in load_rules():
        fix = r.get("fix")
        if not fix:
            continue
        text = r.get("fix_display") or f'{fix["attribute"]} = {fix["value"]}'
        if r.get("note"):
            text += f'  ({r["note"]})'
        out[r["id"]] = text
    return out
