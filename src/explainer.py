#!/usr/bin/env python3
"""
AI Drift Explainer
==================
Reads OPA violations produced from a Terraform plan and asks a local Ollama
model to produce, for each violation:
  - a short risk explanation
  - a Terraform remediation snippet
  - a verification hint

LLM calls run in parallel via asyncio (significant speedup when there are
multiple violations).

A hardcoded mapping points each rule to the canonical Microsoft Learn doc
so the report always cites a stable reference, independent of the LLM.

With --remediate, the script also patches terraform/main.tf into
terraform/main_fixed.tf using a deterministic per-rule remediation map and
prints a unified diff between them.

Usage:
    python src/explainer.py                          # explain only
    python src/explainer.py --remediate              # explain + write main_fixed.tf + show diff
    python src/explainer.py -m qwen2.5-coder:3b -i .scan/violations.json -o .scan/explanations.md
"""

from __future__ import annotations

import argparse
import asyncio
import difflib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_MODEL = "qwen2.5-coder:3b"
OLLAMA_URL = "http://localhost:11434/api/generate"

# Canonical Microsoft Learn references per rule id.
# Keep this dict in sync with policies/enforce_security.rego.
DOCS: dict[str, str] = {
    "AZ-STORAGE-001": "https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent",
    "AZ-STORAGE-002": "https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent",
    "AZ-STORAGE-003": "https://learn.microsoft.com/azure/storage/common/storage-network-security",
    "AZ-STORAGE-004": "https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version",
    "AZ-STORAGE-005": "https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer",
}

# Deterministic remediation: rule id -> { attribute_name: new_value_as_hcl_literal }.
# Values are written verbatim as the right-hand-side of an HCL assignment.
# Strings must include their own quotes; booleans/numbers are bare tokens.
REMEDIATIONS: dict[str, dict[str, str]] = {
    "AZ-STORAGE-001": {"allow_nested_items_to_be_public": "false"},
    "AZ-STORAGE-002": {"shared_access_key_enabled": "false"},
    "AZ-STORAGE-003": {"public_network_access_enabled": "false"},
    "AZ-STORAGE-004": {"min_tls_version": '"TLS1_2"'},
    "AZ-STORAGE-005": {"https_traffic_only_enabled": "true"},
}

SYSTEM_PROMPT = """You are a senior cloud security engineer reviewing an Azure Terraform plan.
For each policy violation, produce a response in this EXACT format and nothing else:

### Why this is risky
<2-3 sentences explaining the concrete real-world risk>

### Terraform remediation
```hcl
<only the corrected attribute lines for the offending resource, no full resource block>
```

### Verification
<1 sentence describing how an engineer can confirm the fix>

Rules: be precise, no filler, no preamble, no closing remarks. Output only the three sections.
"""


# ---------------------------------------------------------------------------
# LLM (Ollama) calls
# ---------------------------------------------------------------------------

def _call_ollama_sync(model: str, system: str, user: str, timeout: int) -> str:
    """Blocking call to Ollama /api/generate, used by the async wrapper."""
    payload = {
        "model": model,
        "system": system,
        "prompt": user,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 512},
    }
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Ollama API unreachable at {OLLAMA_URL}: {exc}") from exc
    return data.get("response", "").strip()


async def call_ollama_async(model: str, system: str, user: str, timeout: int) -> str:
    """Async wrapper: runs the blocking urllib call in a thread."""
    return await asyncio.to_thread(_call_ollama_sync, model, system, user, timeout)


async def explain_all(
    violations: list[dict[str, Any]], model: str, timeout: int
) -> list[str]:
    """Run all LLM calls in parallel and return responses in the same order."""
    tasks = [
        call_ollama_async(model, SYSTEM_PROMPT, build_user_prompt(v), timeout)
        for v in violations
    ]
    results: list[str] = []
    raw = await asyncio.gather(*tasks, return_exceptions=True)
    for item in raw:
        if isinstance(item, Exception):
            results.append(f"_LLM call failed: {item}_")
        else:
            results.append(item)
    return results


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def load_violations(path: Path) -> list[dict[str, Any]]:
    """Extract the violations list from OPA eval JSON output."""
    try:
        raw = json.loads(path.read_text())
        return raw["result"][0]["expressions"][0]["value"] or []
    except (FileNotFoundError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        sys.exit(f"Could not parse violations from {path}: {exc}")


def build_user_prompt(v: dict[str, Any]) -> str:
    return (
        f"Resource address : {v.get('resource', '?')}\n"
        f"Rule ID          : {v.get('rule', '?')}\n"
        f"Severity         : {v.get('severity', '?')}\n"
        f"Policy message   : {v.get('message', '?')}\n"
    )


def severity_tag(sev: str) -> str:
    return {"high": "[HIGH]", "medium": "[MED] ", "low": "[LOW] "}.get(sev, "[?]   ")


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

def apply_remediations(
    source_text: str, violations: list[dict[str, Any]]
) -> tuple[str, list[tuple[str, str, str]]]:
    """
    Apply per-violation remediations to the source HCL text.
    Returns (patched_text, applied_changes) where applied_changes is a list of
    (rule_id, attribute_name, new_value) tuples that were actually applied.
    Attributes not found in the source are skipped (with no error).
    """
    patched = source_text
    applied: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()  # (rule_id, attr) — avoid duplicate work
    for v in violations:
        rule = v.get("rule", "")
        fixes = REMEDIATIONS.get(rule)
        if not fixes:
            continue
        for attr, new_val in fixes.items():
            key = (rule, attr)
            if key in seen:
                continue
            seen.add(key)
            # Match: optional leading whitespace, attr name, padding, =, padding, value, to EOL
            pattern = re.compile(
                rf"^(?P<lead>\s*)(?P<name>{re.escape(attr)})(?P<pad>\s*=\s*).*$",
                re.MULTILINE,
            )
            new_text, n = pattern.subn(
                lambda m, nv=new_val: f"{m.group('lead')}{m.group('name')}{m.group('pad')}{nv}",
                patched,
            )
            if n > 0:
                patched = new_text
                applied.append((rule, attr, new_val))
    return patched, applied


def unified_diff_str(old_text: str, new_text: str, old_name: str, new_name: str) -> str:
    diff = difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=old_name,
        tofile=new_name,
        n=3,
    )
    return "".join(diff)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def _async_main(args: argparse.Namespace) -> int:
    if not args.input.exists():
        sys.exit(f"Input not found: {args.input}. Run scripts/scan_iac.sh first.")

    violations = load_violations(args.input)
    if not violations:
        print("No violations to explain. All clear.")
        return 0

    print(f"Found {len(violations)} violation(s). Querying {args.model} in parallel...\n")

    answers = await explain_all(violations, args.model, args.timeout)

    md_parts: list[str] = [
        "# AI Drift Explainer Report",
        "",
        f"_Model: `{args.model}` via Ollama. Source: `{args.input}`._",
    ]

    for idx, (v, answer) in enumerate(zip(violations, answers), 1):
        header = f"{severity_tag(v.get('severity', ''))} {v.get('rule', '?')} on {v.get('resource', '?')}"
        print(f"[{idx}/{len(violations)}] {header}")
        print(answer)
        ref = DOCS.get(v.get("rule", ""), "")
        if ref:
            print(f"Reference: {ref}")
        print("\n" + "-" * 72 + "\n")

        md_parts += [
            "",
            f"## {header}",
            "",
            f"**Policy message:** {v.get('message', '?')}",
            "",
            answer,
        ]
        if ref:
            md_parts += ["", f"**Azure docs:** <{ref}>"]

    # --- Remediation block ---
    if args.remediate:
        src_path: Path = args.tf_source
        out_path: Path = args.tf_output
        if not src_path.exists():
            print(f"WARN: --remediate requested but {src_path} does not exist; skipping.")
            return 0

        original = src_path.read_text()
        patched, applied = apply_remediations(original, violations)

        if not applied:
            print("No applicable remediations found in REMEDIATIONS map.")
        else:
            out_path.write_text(patched)
            print(f"\n=== REMEDIATION ===")
            print(f"Applied {len(applied)} change(s) -> wrote {out_path}")
            for rule, attr, val in applied:
                print(f"  {rule}: {attr} = {val}")

            diff = unified_diff_str(original, patched, str(src_path), str(out_path))
            print("\n--- unified diff ---")
            print(diff if diff else "(no textual diff?)")

            md_parts += [
                "",
                "## Auto-Remediation",
                "",
                f"`{src_path}` -> `{out_path}`",
                "",
                "Applied changes:",
                "",
            ]
            for rule, attr, val in applied:
                md_parts.append(f"- **{rule}**: `{attr} = {val}`")
            md_parts += ["", "```diff", diff.rstrip("\n"), "```"]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(md_parts) + "\n")
    print(f"\nWrote report -> {args.output}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="AI Drift Explainer for OPA Terraform violations")
    ap.add_argument("--input", "-i", type=Path, default=Path(".scan/violations.json"),
                    help="Path to OPA eval JSON output (default: .scan/violations.json)")
    ap.add_argument("--output", "-o", type=Path, default=Path(".scan/explanations.md"),
                    help="Path to write the markdown report (default: .scan/explanations.md)")
    ap.add_argument("--model", "-m", default=DEFAULT_MODEL,
                    help=f"Ollama model name (default: {DEFAULT_MODEL})")
    ap.add_argument("--timeout", type=int, default=180,
                    help="Per-request timeout in seconds (default: 180)")
    ap.add_argument("--remediate", action="store_true",
                    help="Also write a patched Terraform file and print a unified diff")
    ap.add_argument("--tf-source", type=Path, default=Path("terraform/main.tf"),
                    help="Source Terraform file to patch (default: terraform/main.tf)")
    ap.add_argument("--tf-output", type=Path, default=Path(".scan/main_fixed.tf"),
                    help="Patched Terraform file output (default: .scan/main_fixed.tf). "
                         "Kept outside terraform/ so it doesn't conflict with main.tf.")
    args = ap.parse_args()

    return asyncio.run(_async_main(args))


if __name__ == "__main__":
    sys.exit(main())
