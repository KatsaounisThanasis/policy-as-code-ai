import sys
from pathlib import Path

# opa_to_sarif lives in scripts/; make it importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import opa_to_sarif as o  # noqa: E402


def test_build_sarif_uri_is_parametric_and_line_is_resource_scoped(tmp_path):
    tf = tmp_path / "m.tf"
    tf.write_text(
        'resource "azurerm_storage_account" "sa" {\n'
        "  name = \"x\"\n"
        "  public_network_access_enabled = true\n"
        "}\n"
    )
    violations = [
        {
            "rule": "AZ-STORAGE-003",
            "severity": "high",
            "message": "msg",
            "resource": "azurerm_storage_account.sa",
        }
    ]
    sarif = o.build_sarif(violations, tf, "terraform/custom.tf")
    result = sarif["runs"][0]["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert result["level"] == "error"
    assert loc["artifactLocation"]["uri"] == "terraform/custom.tf"  # #1 parametric
    assert loc["region"]["startLine"] == 3  # #2 scoped to the attribute line
    # helpUri comes from rules.json
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"].startswith("https://learn.microsoft.com")


def test_severity_level_mapping(tmp_path):
    tf = tmp_path / "m.tf"
    tf.write_text("x = 1\n")
    violations = [
        {"rule": "R1", "severity": "high", "message": "m"},
        {"rule": "R2", "severity": "medium", "message": "m"},
        {"rule": "R3", "severity": "low", "message": "m"},
        {"rule": "R4", "severity": "weird", "message": "m"},
    ]
    results = o.build_sarif(violations, tf, "u")["runs"][0]["results"]
    assert [r["level"] for r in results] == ["error", "warning", "note", "note"]


def test_load_violations_empty_and_malformed(tmp_path):
    good = tmp_path / "v.json"
    good.write_text('{"result":[{"expressions":[{"value":[]}]}]}')
    assert o.load_violations(good) == []

    weird = tmp_path / "w.json"
    weird.write_text('{"unexpected": true}')
    assert o.load_violations(weird) == []
