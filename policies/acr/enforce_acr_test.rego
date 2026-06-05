package terraform.security

import rego.v1

mock_acr(after) := {
	"resource_changes": [{
		"address": "test_acr_addr",
		"type": "azurerm_container_registry",
		"change": {
			"after": after
		}
	}]
}

test_az_acr_001_fires if {
	rules := {v.rule | some v in deny with input as mock_acr({"admin_enabled": true})}
	"AZ-ACR-001" in rules
}

test_az_acr_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_acr({"admin_enabled": false})}
	not "AZ-ACR-001" in rules
}

test_az_acr_002_fires if {
	rules := {v.rule | some v in deny with input as mock_acr({"public_network_access_enabled": true})}
	"AZ-ACR-002" in rules
}

test_az_acr_002_compliant if {
	rules := {v.rule | some v in deny with input as mock_acr({"public_network_access_enabled": false})}
	not "AZ-ACR-002" in rules
}
