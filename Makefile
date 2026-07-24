SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

ARM_SUBSCRIPTION_ID ?= 58a01866-f499-4bc5-92ab-dc83166f7792
export ARM_SUBSCRIPTION_ID

ifeq ($(shell test -t 1 && command -v tput >/dev/null 2>&1 && echo yes),yes)
BOLD := $(shell tput bold)
RESET := $(shell tput sgr0)
GREEN := $(shell tput setaf 2)
RED := $(shell tput setaf 1)
YELLOW := $(shell tput setaf 3)
CYAN := $(shell tput setaf 6)
else
BOLD :=
RESET :=
GREEN :=
RED :=
YELLOW :=
CYAN :=
endif

.PHONY: help tools-check az-login-check scan scan-offline explain remediate verify demo test clean clean-all gif rules-doc

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "%sAvailable targets:%s\n", "$(BOLD)", "$(RESET)"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %s%-20s%s %s\n", "$(CYAN)", $$1, "$(RESET)", $$2}' $(MAKEFILE_LIST)

tools-check: ## Verify required tools are on PATH
	@missing=0; \
	for t in terraform opa jq az ollama python3; do \
	  if command -v $$t >/dev/null 2>&1; then \
	    printf "%sOK%s      %s\n" "$(GREEN)" "$(RESET)" "$$t"; \
	  else \
	    printf "%sMISSING%s %s\n" "$(RED)" "$(RESET)" "$$t"; \
	    missing=1; \
	  fi; \
	done; \
	exit $$missing

az-login-check: ## Show active Azure subscription or fail if not logged in
	@if az account show >/dev/null 2>&1; then \
	  info=$$(az account show --query '[name,id]' -o tsv); \
	  IFS=$$'\t' read -r name id <<< "$$info"; \
	  printf "%sAzure subscription:%s %s (%s)\n" "$(BOLD)" "$(RESET)" "$$name" "$$id"; \
	else \
	  echo "Error: not logged in to Azure. Run 'az login' and ensure ARM_SUBSCRIPTION_ID is set." >&2; \
	  exit 1; \
	fi

scan: tools-check ## Run terraform plan and OPA scan (exit 2 is expected)
	@if ./scripts/scan_iac.sh; then \
	  exit 0; \
	else \
	  status=$$?; \
	  if [ $$status -eq 2 ]; then \
	    printf "%sViolations detected (expected).%s\n" "$(YELLOW)" "$(RESET)"; \
	    exit 0; \
	  fi; \
	  exit $$status; \
	fi

scan-offline: ## Scan the bundled example plan with OPA only (no terraform, no Azure)
	@if ./scripts/scan_iac.sh --plan-json examples/insecure_plan.json; then \
	  exit 0; \
	else \
	  status=$$?; \
	  if [ $$status -eq 2 ]; then \
	    printf "%sViolations detected (expected).%s\n" "$(YELLOW)" "$(RESET)"; \
	    exit 0; \
	  fi; \
	  exit $$status; \
	fi

rules-doc: ## Regenerate RULES.md from rules.json (single source of truth)
	@python3 scripts/gen_rules_doc.py --output RULES.md
	@printf "%sWrote RULES.md%s\n" "$(GREEN)" "$(RESET)"

explain: ## Generate explanations from .scan/violations.json
	@if [ ! -f .scan/violations.json ]; then \
	  echo "Error: .scan/violations.json not found. Run 'make scan' first." >&2; \
	  exit 1; \
	fi; \
	python3 src/explainer.py

remediate: ## Generate remediation output (may fail if flag is unsupported)
	@python3 src/explainer.py --remediate

demo: ## Run tools-check, scan, and explain with headers
	@printf "%s== Tools check ==%s\n" "$(BOLD)" "$(RESET)"
	@$(MAKE) --no-print-directory tools-check
	@printf "%s== Scan ==%s\n" "$(BOLD)" "$(RESET)"
	@$(MAKE) --no-print-directory scan
	@printf "%s== Explain ==%s\n" "$(BOLD)" "$(RESET)"
	@$(MAKE) --no-print-directory explain

verify: ## Re-scan the remediated Terraform and prove it passes with 0 violations
	@if [ ! -f .scan/main_fixed.tf ]; then \
	  echo "Error: .scan/main_fixed.tf not found. Run 'make remediate' first." >&2; \
	  exit 1; \
	fi
	@./scripts/verify_fix.sh

gif: ## Record the demo into demo/demo.gif (needs vhs + ollama + az login)
	@command -v vhs >/dev/null 2>&1 || { echo "Error: vhs not installed (https://github.com/charmbracelet/vhs)." >&2; exit 1; }
	@vhs demo/demo.tape
	@echo "Wrote demo/demo.gif"

test: ## Run OPA tests and pytest if any exist
	@has_tests=0; \
	if [ -n "$$(find policies -name '*_test.rego' 2>/dev/null | head -n 1)" ]; then \
	  has_tests=1; \
	  opa test policies/; \
	fi; \
	py_tests=$$(find src tests -type f \( -name "test_*.py" -o -name "*_test.py" \) 2>/dev/null | head -n 1); \
	if [ -n "$$py_tests" ]; then \
	  has_tests=1; \
	  pytest src/ tests/; \
	fi; \
	if [ $$has_tests -eq 0 ]; then \
	  echo "no tests yet"; \
	fi

clean: ## Remove scan and terraform artifacts
	@do_clean=0; \
	if [ -t 1 ]; then \
	  read -r -p "Remove .scan and terraform artifacts? [y/N] " ans; \
	  case "$$ans" in \
	    [yY]|[yY][eE][sS]) do_clean=1 ;; \
	    *) do_clean=0 ;; \
	  esac; \
	else \
	  do_clean=1; \
	fi; \
	if [ $$do_clean -eq 0 ]; then \
	  echo "Aborted."; \
	  exit 1; \
	fi; \
	rm -rf .scan terraform/.terraform terraform/.terraform.lock.hcl

clean-all: ## Clean and remove any generated remediation files
	@$(MAKE) --no-print-directory clean
	@rm -f terraform/main_fixed.tf .scan/main_fixed.tf
