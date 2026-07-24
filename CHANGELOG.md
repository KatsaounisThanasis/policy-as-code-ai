# Changelog

All notable changes to this project are documented here.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0]

### Added
- **Single source of truth (`rules.json`).** Per-rule metadata (severity, message, docs
  link, deterministic remediation, SARIF anchor) lives in one file. The explainer, the
  SARIF export and the CI PR comment all derive from it; a consistency test fails CI if a
  Rego policy and the catalog disagree. Adding a rule is two edits, not five.
- **Offline scan mode** — `scripts/scan_iac.sh --plan-json <plan.json>` and
  `make scan-offline`. Scan a pre-generated plan with OPA only, no `terraform` and no Azure
  credentials. Anyone can try the tool in seconds against `examples/insecure_plan.json`.
- **`RULES.md` catalog**, generated from `rules.json` by `make rules-doc`
  (`scripts/gen_rules_doc.py`) so the documented rules never drift from the enforced ones.
- **`ARCHITECTURE.md`** — overview, data-flow diagram, file map, execution flow, design
  decisions and risks.
- **`pyproject.toml`** — project metadata, ruff + pytest config, a `dev` extra, and a
  `pac-explain` console script (the explain + deterministic-fix half of the pipeline).
- New tests: `test_hcl.py`, `test_opa_to_sarif.py`, `test_rules_consistency.py`
  (26 pytest total, plus 45 OPA tests).

### Fixed
- **Remediation is now resource-scoped.** `apply_remediations` patches only the offending
  resource's block via a small HCL locator (`src/hcl.py`); it no longer risks rewriting an
  identically-named attribute on an already-compliant resource.
- **SARIF line mapping is resource-scoped and the file path is parametric** (`--tf-file`).
  Findings anchor on the attribute inside the offending resource instead of all pointing at
  the first match / line 1, and no longer hard-code `terraform/main.tf`.
- Refreshed the default Anthropic model.

## [0.1.0]

### Added
- Initial release: local-first Policy-as-Code for Azure IaC with a closed
  scan → explain → deterministic-fix → re-scan-proves-clean loop.
- OPA/Rego policy set across 10 Azure services, a local-LLM drift explainer with pluggable
  backends (Ollama / Azure OpenAI / Anthropic), and cloud-free CI that uploads SARIF to the
  Security tab and posts a PR comment.
