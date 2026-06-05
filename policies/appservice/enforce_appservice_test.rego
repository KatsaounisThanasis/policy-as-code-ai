package terraform.security

import rego.v1

mock_app(after) := {
	"resource_changes": [{
		"address": "test_app_addr",
		"type": "azurerm_linux_web_app",
		"change": {
			"after": after
		}
	}]
}

test_az_app_001_fires if {
	rules := {v.rule | some v in deny with input as mock_app({"https_only": false})}
	"AZ-APP-001" in rules
}

test_az_app_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_app({"https_only": true})}
	not "AZ-APP-001" in rules
}

test_az_app_002_fires if {
	rules := {v.rule | some v in deny with input as mock_app({"site_config": [{"minimum_tls_version": "1.0"}]})}
	"AZ-APP-002" in rules
}

test_az_app_002_compliant if {
	rules := {v.rule | some v in deny with input as mock_app({"site_config": [{"minimum_tls_version": "1.2"}]})}
	not "AZ-APP-002" in rules
}
