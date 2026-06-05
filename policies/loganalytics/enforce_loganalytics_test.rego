package terraform.security

import rego.v1

mock_law(after) := {
	"resource_changes": [{
		"address": "test_law_addr",
		"type": "azurerm_log_analytics_workspace",
		"change": {
			"after": after
		}
	}]
}

test_az_log_001_fires if {
	rules := {v.rule | some v in deny with input as mock_law({"internet_query_enabled": true})}
	"AZ-LOG-001" in rules
}

test_az_log_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_law({"internet_query_enabled": false})}
	not "AZ-LOG-001" in rules
}
