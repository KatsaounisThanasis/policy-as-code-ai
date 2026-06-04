#!/usr/bin/env bash
# Re-scan the remediated Terraform to PROVE the fix passes the policy gate.
# Temporarily swaps .scan/main_fixed.tf into terraform/main.tf (reusing the
# already-initialised provider plugins), runs plan -> OPA, then restores the
# original via a trap so the insecure baseline is always put back.
set -euo pipefail

# Mirror the Makefile default so direct runs don't hang on Azure IMDS auth.
: "${ARM_SUBSCRIPTION_ID:=58a01866-f499-4bc5-92ab-dc83166f7792}"
export ARM_SUBSCRIPTION_ID

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform"
POLICY_FILE="${REPO_ROOT}/policies/enforce_security.rego"
OUT_DIR="${REPO_ROOT}/.scan"
FIXED="${OUT_DIR}/main_fixed.tf"
MAIN="${TF_DIR}/main.tf"
PLAN_BIN="${OUT_DIR}/verify_tfplan"
PLAN_JSON="${OUT_DIR}/verify_tfplan.json"
VIOLATIONS_JSON="${OUT_DIR}/verify_violations.json"

if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"
  BOLD="$(tput bold)"; RESET="$(tput sgr0)"
else
  RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""
fi

for cmd in terraform opa jq; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "${RED}Error: required command not found: ${cmd}.${RESET}" >&2; exit 1; }
done

if [ ! -f "$FIXED" ]; then
  echo "${RED}Error: ${FIXED} not found. Run 'make remediate' first.${RESET}" >&2
  exit 1
fi

# Restore the original baseline no matter how we exit.
BACKUP="$(mktemp)"
cp "$MAIN" "$BACKUP"
restore() { cp "$BACKUP" "$MAIN"; rm -f "$BACKUP"; }
trap restore EXIT

echo "${BOLD}Verifying remediated Terraform against the policy gate...${RESET}"
cp "$FIXED" "$MAIN"

if ! (cd "$TF_DIR" && timeout 120 terraform plan -out="$PLAN_BIN" -input=false -lock=false >/dev/null); then
  echo "${RED}Error: terraform plan failed or timed out during verify.${RESET}" >&2
  exit 1
fi
(cd "$TF_DIR" && terraform show -json "$PLAN_BIN" > "$PLAN_JSON")
opa eval --format=json -i "$PLAN_JSON" -d "$POLICY_FILE" 'data.terraform.security.deny' > "$VIOLATIONS_JSON"

count="$(jq '.result[0].expressions[0].value | length' "$VIOLATIONS_JSON")"

if [ "$count" -eq 0 ]; then
  echo "${GREEN}✓ Proof: remediated Terraform passes the policy gate with 0 violations.${RESET}"
  exit 0
fi

echo "${YELLOW}Remaining violations:${RESET}"
jq -r '.result[0].expressions[0].value[] | "rule=\(.rule) resource=\(.resource)"' "$VIOLATIONS_JSON"
echo "${RED}✗ ${count} violation(s) still present after remediation.${RESET}"
exit 2
