"""
Bind the single source of truth (rules.json) to the Rego detection logic.

The .rego files own detection; rules.json owns metadata (severity, message, doc,
remediation, SARIF anchor). Historically the rule id / severity / message were
hand-duplicated across explainer.py, opa_to_sarif.py, the CI PR comment and the
policies. Now everything derives from rules.json — this test fails CI the moment
a Rego rule and rules.json disagree, so drift can no longer ship silently.
"""

import re
from pathlib import Path

import rules

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = REPO_ROOT / "policies"

# One deny block emits "rule"/"severity"/"message" in that order.
_DENY_RE = re.compile(
    r'"rule":\s*"(?P<id>[^"]+)"'
    r'.*?"severity":\s*"(?P<severity>[^"]+)"'
    r'.*?"message":\s*"(?P<message>[^"]+)"',
    re.DOTALL,
)


def _rego_rules() -> dict[str, dict[str, str]]:
    """Extract {id: {severity, message}} from every non-test .rego file."""
    found: dict[str, dict[str, str]] = {}
    for f in sorted(POLICY_DIR.glob("*/enforce_*.rego")):
        if f.name.endswith("_test.rego"):
            continue
        for m in _DENY_RE.finditer(f.read_text()):
            found[m.group("id")] = {
                "severity": m.group("severity"),
                "message": m.group("message"),
            }
    return found


def test_rego_and_rules_json_have_the_same_ids():
    rego_ids = set(_rego_rules())
    json_ids = set(rules.by_id())
    assert rego_ids == json_ids, (
        f"Rego-only ids: {sorted(rego_ids - json_ids)}; "
        f"rules.json-only ids: {sorted(json_ids - rego_ids)}"
    )


def test_severity_and_message_match_rego():
    rego = _rego_rules()
    defs = rules.by_id()
    mismatches = []
    for rid, r in rego.items():
        d = defs[rid]
        if d["severity"] != r["severity"]:
            mismatches.append(f"{rid} severity: rego={r['severity']} json={d['severity']}")
        if d["message"] != r["message"]:
            mismatches.append(f"{rid} message differs")
    assert not mismatches, "; ".join(mismatches)


def test_every_rule_is_fully_specified():
    problems = []
    for rid, r in rules.by_id().items():
        if not r.get("doc"):
            problems.append(f"{rid}: missing doc")
        if not r.get("sarif_attr"):
            problems.append(f"{rid}: missing sarif_attr")
        fix = r.get("fix") or {}
        if not fix.get("attribute") or not fix.get("value"):
            problems.append(f"{rid}: incomplete fix")
    assert not problems, "; ".join(problems)


def test_derived_maps_cover_all_rules():
    ids = set(rules.by_id())
    assert set(rules.docs()) == ids
    assert set(rules.remediations()) == ids
    assert set(rules.rule_attr()) == ids
    assert set(rules.fix_display()) == ids
