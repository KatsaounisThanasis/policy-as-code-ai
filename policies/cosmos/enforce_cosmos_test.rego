package terraform.security

import rego.v1

mock_cosmos(after) := {
	"resource_changes": [{
		"address": "test_cosmos_addr",
		"type": "azurerm_cosmosdb_account",
		"change": {
			"after": after
		}
	}]
}

test_az_cosmos_001_fires if {
	rules := {v.rule | some v in deny with input as mock_cosmos({"public_network_access_enabled": true})}
	"AZ-COSMOS-001" in rules
}

test_az_cosmos_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_cosmos({"public_network_access_enabled": false})}
	not "AZ-COSMOS-001" in rules
}
