#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform"
POLICY_DIR="${REPO_ROOT}/policies"
OUT_DIR="${REPO_ROOT}/.scan"
PLAN_BIN="${OUT_DIR}/tfplan"
PLAN_JSON="${OUT_DIR}/tfplan.json"
VIOLATIONS_JSON="${OUT_DIR}/violations.json"

if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  RED="$(tput setaf 1)"
  GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"
  BOLD="$(tput bold)"
  RESET="$(tput sgr0)"
else
  RED=""
  GREEN=""
  YELLOW=""
  BOLD=""
  RESET=""
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "${RED}Error: required command not found: ${cmd}.${RESET}" >&2
    exit 1
  fi
}

# Offline mode: scan a pre-generated `terraform show -json` plan directly, with
# no terraform and no Azure credentials. Pass --plan-json PATH (or set
# PLAN_JSON_IN). This is what lets anyone try the tool in seconds against the
# bundled examples/insecure_plan.json — no cloud account required.
PLAN_JSON_IN="${PLAN_JSON_IN:-}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan-json) PLAN_JSON_IN="${2:?--plan-json needs a path}"; shift 2 ;;
    --plan-json=*) PLAN_JSON_IN="${1#*=}"; shift ;;
    -h|--help) echo "usage: scan_iac.sh [--plan-json <plan.json>]"; exit 0 ;;
    *) echo "${RED}Unknown argument: $1${RESET}" >&2; exit 1 ;;
  esac
done

require_cmd opa
require_cmd jq

mkdir -p "$OUT_DIR"

if [ -n "$PLAN_JSON_IN" ]; then
  if [ ! -f "$PLAN_JSON_IN" ]; then
    echo "${RED}Error: plan JSON not found: ${PLAN_JSON_IN}.${RESET}" >&2
    exit 1
  fi
  echo "${BOLD}Offline mode: scanning ${PLAN_JSON_IN} (no terraform, no Azure).${RESET}"
  cp "$PLAN_JSON_IN" "$PLAN_JSON"
else
  require_cmd terraform
  if [ ! -d "${TF_DIR}/.terraform" ]; then
    echo "${BOLD}Initializing Terraform...${RESET}"
    (cd "$TF_DIR" && terraform init -input=false -upgrade)
  fi

  echo "${BOLD}Running terraform plan...${RESET}"
  if ! (cd "$TF_DIR" && terraform plan -out="$PLAN_BIN" -input=false -lock=false); then
    echo "${RED}Error: terraform plan failed. Ensure Azure auth env vars are set (ARM_SUBSCRIPTION_ID, ARM_TENANT_ID, ARM_CLIENT_ID, ARM_CLIENT_SECRET) or run 'az login'.${RESET}" >&2
    exit 1
  fi

  echo "${BOLD}Converting plan to JSON...${RESET}"
  (cd "$TF_DIR" && terraform show -json "$PLAN_BIN" > "$PLAN_JSON")
fi

echo "${BOLD}Evaluating OPA policies...${RESET}"
opa eval --format=json -i "$PLAN_JSON" -d "$POLICY_DIR" 'data.terraform.security.deny' > "$VIOLATIONS_JSON"

violation_count="$(jq '.result[0].expressions[0].value | length' "$VIOLATIONS_JSON")"

if [ "$violation_count" -gt 0 ]; then
  echo "${YELLOW}Violations:${RESET}"
  jq -r '.result[0].expressions[0].value[] | "rule=\(.rule) severity=\(.severity) resource=\(.resource) message=\(.message)"' "$VIOLATIONS_JSON"
fi

if [ "$violation_count" -eq 0 ]; then
  echo "${GREEN}Summary: 0 violations.${RESET}"
  exit 0
fi

echo "${RED}Summary: ${violation_count} violation(s).${RESET}"
exit 2
