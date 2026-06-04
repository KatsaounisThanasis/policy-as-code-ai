import json
import asyncio
import pytest
import explainer

def test_load_violations_valid(tmp_path):
    f = tmp_path / "violations.json"
    data = {
        "result": [
            {
                "expressions": [
                    {
                        "value": [{"rule": "AZ-STORAGE-001", "message": "msg"}]
                    }
                ]
            }
        ]
    }
    f.write_text(json.dumps(data))
    violations = explainer.load_violations(f)
    assert len(violations) == 1
    assert violations[0]["rule"] == "AZ-STORAGE-001"

def test_load_violations_invalid(tmp_path):
    f = tmp_path / "violations.json"
    f.write_text("invalid json {")
    with pytest.raises(SystemExit):
        explainer.load_violations(f)

    # Missing file
    with pytest.raises(SystemExit):
        explainer.load_violations(tmp_path / "missing.json")

def test_build_user_prompt():
    v = {
        "resource": "res_addr",
        "rule": "AZ-STORAGE-001",
        "severity": "high",
        "message": "test message"
    }
    prompt = explainer.build_user_prompt(v)
    assert "res_addr" in prompt
    assert "AZ-STORAGE-001" in prompt
    assert "high" in prompt
    assert "test message" in prompt

def test_severity_tag():
    assert explainer.severity_tag("high") == "[HIGH]"
    assert explainer.severity_tag("medium") == "[MED] "
    assert explainer.severity_tag("low") == "[LOW] "
    assert explainer.severity_tag("unknown") == "[?]   "

def test_apply_remediations():
    source = """
resource "azurerm_storage_account" "example" {
  name = "example"
  allow_nested_items_to_be_public = true
  shared_access_key_enabled = true
  public_network_access_enabled = true
  min_tls_version = "TLS1_0"
  https_traffic_only_enabled = false
}
"""
    violations = [
        {"rule": "AZ-STORAGE-001"},
        {"rule": "AZ-STORAGE-002"},
        {"rule": "AZ-STORAGE-003"},
        {"rule": "AZ-STORAGE-004"},
        {"rule": "AZ-STORAGE-005"},
    ]
    patched, applied = explainer.apply_remediations(source, violations)
    
    assert len(applied) == 5
    assert 'allow_nested_items_to_be_public = false' in patched
    assert 'shared_access_key_enabled = false' in patched
    assert 'public_network_access_enabled = false' in patched
    assert 'min_tls_version = "TLS1_2"' in patched
    assert 'https_traffic_only_enabled = true' in patched
    
def test_apply_remediations_missing_attr_skipped():
    source = """
resource "azurerm_storage_account" "example" {
  allow_nested_items_to_be_public = true
}
"""
    violations = [
        {"rule": "AZ-STORAGE-001"},
        {"rule": "AZ-STORAGE-002"}, # shared_access_key_enabled is missing in source
    ]
    patched, applied = explainer.apply_remediations(source, violations)
    assert len(applied) == 1
    assert 'allow_nested_items_to_be_public = false' in patched
    assert 'shared_access_key_enabled' not in patched

def test_unified_diff_str():
    old = "line 1\nline 2\n"
    new = "line 1\nline 3\n"
    diff = explainer.unified_diff_str(old, new, "old_file", "new_file")
    assert "--- old_file" in diff
    assert "+++ new_file" in diff
    assert "-line 2" in diff
    assert "+line 3" in diff

def test_explain_all(monkeypatch):
    def mock_call(model, system, user, timeout):
        if "fail_res" in user:
            raise Exception("Mock timeout")
        return f"Response for {model}"

    monkeypatch.setattr(explainer, "_call_ollama_sync", mock_call)

    violations = [
        {"resource": "res1"},
        {"resource": "fail_res"},
    ]
    
    results = asyncio.run(explainer.explain_all(violations, "mock-model", 10))
    
    assert len(results) == 2
    assert results[0] == "Response for mock-model"
    assert "_LLM call failed:" in results[1]
    assert "Mock timeout" in results[1]
