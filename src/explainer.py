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
import os
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
    "AZ-NSG-001": "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview",
    "AZ-NSG-002": "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview",
    "AZ-KV-001": "https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview",
    "AZ-KV-002": "https://learn.microsoft.com/azure/key-vault/general/network-security",
    "AZ-SQL-001": "https://learn.microsoft.com/azure/azure-sql/database/network-access-controls-overview",
    "AZ-SQL-002": "https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings",
    "AZ-APP-001": "https://learn.microsoft.com/azure/app-service/configure-ssl-bindings",
    "AZ-APP-002": "https://learn.microsoft.com/azure/app-service/configure-ssl-bindings",
    "AZ-DISK-001": "https://learn.microsoft.com/azure/virtual-machines/disks-restrict-import-export-overview",
    "AZ-DISK-002": "https://learn.microsoft.com/azure/virtual-machines/disks-restrict-import-export-overview",
    "AZ-COSMOS-001": "https://learn.microsoft.com/azure/cosmos-db/how-to-configure-firewall",
    "AZ-AKS-001": "https://learn.microsoft.com/azure/aks/manage-local-accounts-managed-azure-ad",
    "AZ-AKS-002": "https://learn.microsoft.com/azure/aks/use-azure-policy",
    "AZ-ACR-001": "https://learn.microsoft.com/azure/container-registry/container-registry-authentication",
    "AZ-ACR-002": "https://learn.microsoft.com/azure/container-registry/container-registry-access-selected-networks",
    "AZ-LOG-001": "https://learn.microsoft.com/azure/azure-monitor/logs/private-link-security",
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
    # NSG: an allow-any-inbound rule has no single "correct" CIDR/port, so the
    # deterministic, fail-closed fix is to deny it until a human scopes it.
    # Flipping access to Deny clears both AZ-NSG-001 and AZ-NSG-002.
    "AZ-NSG-001": {"access": '"Deny"'},
    "AZ-NSG-002": {"access": '"Deny"'},
    "AZ-KV-001": {"purge_protection_enabled": "true"},
    "AZ-KV-002": {"public_network_access_enabled": "false"},
    "AZ-SQL-001": {"public_network_access_enabled": "false"},
    "AZ-SQL-002": {"minimum_tls_version": '"1.2"'},
    "AZ-APP-001": {"https_only": "true"},
    "AZ-APP-002": {"minimum_tls_version": '"1.2"'},
    "AZ-DISK-001": {"public_network_access_enabled": "false"},
    "AZ-DISK-002": {"network_access_policy": '"DenyAll"'},
    "AZ-COSMOS-001": {"public_network_access_enabled": "false"},
    "AZ-AKS-001": {"local_account_disabled": "true"},
    "AZ-AKS-002": {"azure_policy_enabled": "true"},
    "AZ-ACR-001": {"admin_enabled": "false"},
    "AZ-ACR-002": {"public_network_access_enabled": "false"},
    "AZ-LOG-001": {"internet_query_enabled": "false"},
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
# LLM backends — pluggable via the LLM_BACKEND env var (default: ollama)
#
#   LLM_BACKEND=ollama        (default)  -> local Ollama; nothing leaves the box
#   LLM_BACKEND=azureopenai              -> Azure OpenAI Chat Completions
#   LLM_BACKEND=anthropic                -> Anthropic Messages API
#
# Each backend turns a (system, user) prompt into plain text. Everything else
# (scan, remediation, SARIF, verify) is backend-agnostic. Local-first by
# default; bring-your-own cloud API only if you opt in.
# ---------------------------------------------------------------------------

def _post_json(url: str, payload: dict, headers: dict, timeout: int) -> dict:
    """POST a JSON body and return the decoded JSON response."""
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _call_ollama_sync(model: str, system: str, user: str, timeout: int) -> str:
    """Blocking call to Ollama /api/generate."""
    payload = {
        "model": model,
        "system": system,
        "prompt": user,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 512},
    }
    try:
        data = _post_json(OLLAMA_URL, payload, {}, timeout)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Ollama API unreachable at {OLLAMA_URL}: {exc}") from exc
    return data.get("response", "").strip()


class LLMBackend:
    """A backend turns a (system, user) prompt into text, synchronously."""

    name = "base"
    model = ""

    def complete_sync(self, system: str, user: str, timeout: int) -> str:
        raise NotImplementedError


class OllamaBackend(LLMBackend):
    name = "ollama"

    def __init__(self, model: str | None = None) -> None:
        self.model = model or DEFAULT_MODEL

    def complete_sync(self, system: str, user: str, timeout: int) -> str:
        return _call_ollama_sync(self.model, system, user, timeout)


class AzureOpenAIBackend(LLMBackend):
    name = "azureopenai"

    def __init__(self, model: str | None = None) -> None:
        self.endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
        self.api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
        self.model = model or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "")
        self.api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01")
        missing = [
            n for n, v in (
                ("AZURE_OPENAI_ENDPOINT", self.endpoint),
                ("AZURE_OPENAI_API_KEY", self.api_key),
                ("AZURE_OPENAI_DEPLOYMENT", self.model),
            ) if not v
        ]
        if missing:
            sys.exit(f"azureopenai backend needs env var(s): {', '.join(missing)}")

    def complete_sync(self, system: str, user: str, timeout: int) -> str:
        url = (
            f"{self.endpoint}/openai/deployments/{self.model}"
            f"/chat/completions?api-version={self.api_version}"
        )
        payload = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": 512,
        }
        data = _post_json(url, payload, {"api-key": self.api_key}, timeout)
        return data["choices"][0]["message"]["content"].strip()


class AnthropicBackend(LLMBackend):
    name = "anthropic"
    DEFAULT_ANTHROPIC_MODEL = "claude-3-5-sonnet-latest"

    def __init__(self, model: str | None = None) -> None:
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get("ANTHROPIC_MODEL", self.DEFAULT_ANTHROPIC_MODEL)
        if not self.api_key:
            sys.exit("anthropic backend needs env var: ANTHROPIC_API_KEY")

    def complete_sync(self, system: str, user: str, timeout: int) -> str:
        payload = {
            "model": self.model,
            "max_tokens": 512,
            "temperature": 0.2,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        data = _post_json("https://api.anthropic.com/v1/messages", payload, headers, timeout)
        return "".join(block.get("text", "") for block in data.get("content", [])).strip()


_BACKENDS: dict[str, type[LLMBackend]] = {
    "ollama": OllamaBackend,
    "azureopenai": AzureOpenAIBackend,
    "azure": AzureOpenAIBackend,
    "anthropic": AnthropicBackend,
}


def get_backend(name: str | None = None, model: str | None = None) -> LLMBackend:
    """Resolve a backend from an explicit name, else $LLM_BACKEND, else ollama."""
    key = (name or os.environ.get("LLM_BACKEND") or "ollama").lower()
    cls = _BACKENDS.get(key)
    if cls is None:
        choices = ", ".join(sorted(set(_BACKENDS)))
        sys.exit(f"Unknown LLM backend '{key}'. Choose one of: {choices}.")
    return cls(model)


async def explain_all(
    violations: list[dict[str, Any]], backend: LLMBackend, timeout: int
) -> list[str]:
    """Run all backend calls in parallel and return responses in the same order."""
    tasks = [
        asyncio.to_thread(
            backend.complete_sync, SYSTEM_PROMPT, build_user_prompt(v), timeout
        )
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

    backend = get_backend(args.backend, args.model)
    print(
        f"Found {len(violations)} violation(s). "
        f"Querying `{backend.model}` via {backend.name} in parallel...\n"
    )

    answers = await explain_all(violations, backend, args.timeout)

    md_parts: list[str] = [
        "# AI Drift Explainer Report",
        "",
        f"_Model: `{backend.model}` via {backend.name}. Source: `{args.input}`._",
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
    ap.add_argument("--backend", default=None,
                    help="LLM backend: ollama | azureopenai | anthropic "
                         "(default: $LLM_BACKEND, else ollama)")
    ap.add_argument("--model", "-m", default=None,
                    help="Model / deployment name (backend-specific; "
                         f"defaults per backend, e.g. {DEFAULT_MODEL} for ollama)")
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
