# 🛡️ Policy-as-Code + AI Drift Explainer

> **Local-first policy-as-code with provable remediation.**
> The AI explains why each Terraform misconfiguration is risky. A deterministic engine writes the fix. The pipeline then re-runs the policy gate to prove the fix holds. All of it runs on your machine, so your infrastructure code never leaves it.

![Policy as Code](https://img.shields.io/badge/policy--as--code-OPA%2FRego-7D4698)
![Terraform](https://img.shields.io/badge/IaC-Terraform-844FBA)
![LLM](https://img.shields.io/badge/LLM-local-000000)
![Cloud](https://img.shields.io/badge/cloud-Azure-0078D4)
[![Policy-as-Code CI](https://github.com/KatsaounisThanasis/policy-as-code-ai/actions/workflows/policy-scan.yml/badge.svg)](https://github.com/KatsaounisThanasis/policy-as-code-ai/actions/workflows/policy-scan.yml)
![License](https://img.shields.io/badge/license-MIT-green)

![Demo: scan finds violations, the local LLM explains them, a deterministic engine fixes them](demo/demo.gif)

**60-second tour:** `make scan` finds the misconfigurations, `make explain` has a local LLM tell you why each one is risky, `make remediate` writes the fix, and `make verify` re-runs the gate to prove it's clean. Nothing leaves your machine.

### Try it in 30 seconds — no Azure, no Terraform

```bash
make scan-offline     # or: ./scripts/scan_iac.sh --plan-json examples/insecure_plan.json
```

Scans a bundled, pre-generated plan with OPA only — all 21 violations, no Azure account and no `terraform` install required (needs just `opa` + `jq`). For the full explain → fix → prove loop, see [Quick start](#quick-start).

📖 [Rule catalog (RULES.md)](RULES.md) · [Architecture (ARCHITECTURE.md)](ARCHITECTURE.md)

---

## The problem

Security scanners (Checkov, tfsec, OPA, KICS) are good at telling you what's wrong with your Infrastructure-as-Code, and not much help after that. A typical run dumps 200 findings into a backlog. A security engineer files a ticket. Weeks later an infra engineer maybe fixes it. Meanwhile the misconfiguration ships to production.

Two gaps stay open:

1. **Understanding.** A finding like `AZ-STORAGE-003: public_network_access_enabled` means nothing to a developer in a hurry. Why does it matter? What's the blast radius?
2. **Action.** Even when the fix is obvious, somebody still has to write it and prove it actually closes the finding.

## What this does

A closed loop that turns a raw policy violation into a verified fix:

```
terraform plan ─▶ OPA/Rego scan ─▶ AI explains each violation ─▶ deterministic fix ─▶ re-scan proves 0 violations
```

- OPA/Rego evaluates the Terraform plan and emits structured violations.
- A local LLM writes a short risk explanation and a verification hint for each one, with a link to the matching Microsoft Learn doc.
- A deterministic remediation engine patches the offending attributes and emits a unified diff.
- The patched file gets re-scanned, and the report shows it now passes with 0 violations. That's the proof.

## Why it's different

Plenty of tools now do "AI scans IaC and opens a PR." This one makes three deliberate choices that most of them get wrong.

### 🔒 Local-first / private / zero-cost

Everything runs on your machine via a local LLM. Your Terraform usually encodes network topology, resource names, and security posture, and none of it gets sent to a third-party LLM API. No per-review token bill, no data-egress risk. Most competitors send your IaC to a cloud API and tell you to strip secrets first.

### ✅ Provable remediation

The fix isn't just generated, it's verified. The patched Terraform is re-evaluated against the same policy set, and the report shows `0 violations`. A clean re-scan is hard evidence the fix is correct, not a hopeful "looks good to me."

### 🎯 Deterministic fixes, AI for understanding

The LLM explains; it doesn't write the fix. Remediation comes from a deterministic rule→attribute map, so it's reproducible and free of hallucinations. That covers the unambiguous cases ("set TLS to 1.2", "disable public access"). Context-dependent ones, like "which CIDR is allowed?", are left for a human to approve. Fixes are **resource-scoped** — only the flagged resource is patched, never an identically-named attribute on a compliant one.

### 🧩 One rule, one definition

Every rule's metadata — severity, message, docs link, remediation — lives in a single [`rules.json`](rules.json). The Rego detection, the SARIF export, the auto-fix map and the CI PR comment all derive from it, and a consistency test fails CI if a policy and the catalog disagree. Adding a rule is two edits (a Rego policy + a `rules.json` entry), not five scattered ones.

## Architecture

![Architecture Diagram](docs/architecture.svg)

## Quick start

**Prerequisites:** `terraform`, `opa`, `jq`, `az` (logged in), a local LLM runtime (Ollama by default), `python3`. *(Offline mode — `make scan-offline` — needs only `opa` and `jq`.)*

```bash
# 0. verify your toolchain
make tools-check

# ...or skip Azure entirely and scan the bundled plan fixture:
make scan-offline

# 1. scan: terraform plan -> OPA -> violations  (exit 2 = violations found, expected)
make scan

# 2. explain: local LLM writes risk + fix + verification for each violation
make explain

# 3. remediate: write a fixed Terraform file + unified diff
make remediate

# 4. verify: re-scan the fixed Terraform and PROVE it passes the gate (0 violations)
make verify

# or run the whole story end-to-end
make demo
```

## Install

The full loop runs from the repo (it shells out to `opa`/`terraform` and reads the
`policies/` tree), so the primary "install" is a clone — or use the GitHub Action path in
[Continuous Integration](#continuous-integration). For development, or to run just the
explain + deterministic-fix half as a CLI:

```bash
pip install -e ".[dev]"     # editable install + pytest/ruff
pac-explain -i .scan/violations.json --remediate   # explain + fix a violations.json
```

`pac-explain` needs a `violations.json` (from `make scan` / `make scan-offline`) and
`rules.json` (found via the repo, or point `PAC_RULES_JSON` at it). Zero runtime
dependencies — everything is stdlib.

## Tests

```bash
make test          # runs the OPA policy tests + the Python unit tests
```

Currently **45 OPA tests + 26 pytest**, all green and gated in CI.

- **OPA** (`policies/**/*_test.rego`): every rule is checked to fire on a violating
  resource and stay silent on a compliant one, plus whole-policy checks (fully-compliant
  → 0 denials, fully-insecure → all rules fire).
- **pytest** (`tests/`): the parser, prompt builder, resource-scoped remediator and async
  LLM fan-out (`test_explainer.py`, LLM mocked); the HCL block locator (`test_hcl.py`); the
  SARIF converter (`test_opa_to_sarif.py`); and `test_rules_consistency.py`, which fails the
  moment a Rego policy and `rules.json` disagree on an id, severity or message. No network
  or local model needed.

## LLM backends (pluggable)

The explainer is local-first by default (Ollama, `qwen2.5-coder:3b`), so nothing leaves
your machine. To use a hosted model instead, set one env var. The rest of the pipeline
(scan, remediation, SARIF, verify) doesn't change.

```bash
# default — local, private
ollama pull qwen2.5-coder:3b
make explain

# Azure OpenAI
export LLM_BACKEND=azureopenai
export AZURE_OPENAI_ENDPOINT="https://<resource>.openai.azure.com"
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_DEPLOYMENT="<deployment-name>"
make explain

# Anthropic
export LLM_BACKEND=anthropic
export ANTHROPIC_API_KEY="..."
make explain
```

Backends sit behind a small `LLMBackend` abstraction in `src/explainer.py`
(`get_backend()` resolves `--backend`/`$LLM_BACKEND`), so adding another provider is one
class. The unit tests mock that interface, so the suite never touches a real model.

## What it catches today

**21 rules across 10 Azure services** — Storage, Network Security Group, Key Vault, SQL Server, App Service, Managed Disk, Cosmos DB, AKS, Container Registry, Log Analytics. Each rule has a Rego policy under `policies/<category>/`, a deterministic fix, and a Microsoft Learn reference.

👉 **[RULES.md](RULES.md)** is the full catalog (rule · severity · check · fix · docs). It's generated from [`rules.json`](rules.json) by `make rules-doc`, so it never drifts from what the engine enforces.

> **Deterministic vs. human judgement:** most findings have one unambiguous fix that gets
> auto-applied. The NSG "allow-any" rule has no single correct CIDR or port, so its fix is
> fail-closed (`access = "Deny"`): it shuts the hole and leaves the precise scoping to a
> human. That's the boundary the tool is honest about.

> **No cost, no risk:** the pipeline only runs `terraform plan`, never `apply`. OPA reads
> the plan JSON, so no Azure resources are ever created.

## Continuous Integration

`.github/workflows/policy-scan.yml` runs on every pull request and push to `main`:

- The **`tests` job** runs the OPA policy tests and the Python unit tests.
- The **`policy-scan` job** evaluates the policy set against a committed Terraform plan
  fixture (`examples/insecure_plan.json`), then:
  - converts the violations to SARIF (`scripts/opa_to_sarif.py`) and uploads them, so
    findings show up in the repo's **Security ▸ Code scanning** tab with file locations and
    severities;
  - posts a PR comment (updated in place, not duplicated) listing each violation and its
    deterministic fix.

The CI is cloud-free and LLM-free on purpose. It scans a plan fixture instead of calling
Azure, and the AI explanations stay a local `make explain` step, so the "your IaC never
leaves your machine" guarantee holds even in CI.

## Project layout

```
.
├── rules.json                   # single source of truth: per-rule metadata (docs/fix/sarif)
├── RULES.md                     # generated catalog (make rules-doc)
├── ARCHITECTURE.md              # design map (overview, data flow, decisions, risks)
├── terraform/main.tf            # intentionally-insecure Azure baseline (10 resource types)
├── policies/                    # OPA policy set (Rego v1), one folder per category
│   ├── storage/  network/  keyvault/  sql/  appservice/
│   └── disk/  cosmos/  aks/  acr/  loganalytics/      # each: rules + tests
├── scripts/scan_iac.sh          # plan -> json -> opa eval pipeline (+ --plan-json offline)
├── scripts/opa_to_sarif.py      # OPA violations -> SARIF (for the Security tab)
├── scripts/gen_rules_doc.py     # rules.json -> RULES.md
├── src/explainer.py             # local-LLM explainer + resource-scoped remediator
├── src/rules.py                 # rules.json loader (shared by explainer/sarif/CI)
├── src/hcl.py                   # minimal HCL block locator (resource scoping)
├── examples/insecure_plan.json  # sanitized plan fixture used by CI + offline mode
├── Makefile                     # scan / scan-offline / explain / remediate / verify / demo / test / rules-doc
└── .scan/                       # generated reports (sample output kept in repo)
```

## License

[MIT](./LICENSE)
