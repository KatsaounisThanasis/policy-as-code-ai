package terraform.security

import rego.v1

mock_kv(after) := {
	"resource_changes": [{
		"address": "test_kv_addr",
		"type": "azurerm_key_vault",
		"change": {
			"after": after
		}
	}]
}

test_az_kv_001_fires if {
	rules := {v.rule | some v in deny with input as mock_kv({"purge_protection_enabled": false})}
	"AZ-KV-001" in rules
}

test_az_kv_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_kv({"purge_protection_enabled": true})}
	not "AZ-KV-001" in rules
}

test_az_kv_002_fires if {
	rules := {v.rule | some v in deny with input as mock_kv({"public_network_access_enabled": true})}
	"AZ-KV-002" in rules
}

test_az_kv_002_compliant if {
	rules := {v.rule | some v in deny with input as mock_kv({"public_network_access_enabled": false})}
	not "AZ-KV-002" in rules
}
