package terraform.security

import rego.v1

mock_disk(after) := {
	"resource_changes": [{
		"address": "test_disk_addr",
		"type": "azurerm_managed_disk",
		"change": {
			"after": after
		}
	}]
}

test_az_disk_001_fires if {
	rules := {v.rule | some v in deny with input as mock_disk({"public_network_access_enabled": true})}
	"AZ-DISK-001" in rules
}

test_az_disk_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_disk({"public_network_access_enabled": false})}
	not "AZ-DISK-001" in rules
}

test_az_disk_002_fires if {
	rules := {v.rule | some v in deny with input as mock_disk({"network_access_policy": "AllowAll"})}
	"AZ-DISK-002" in rules
}

test_az_disk_002_compliant if {
	rules := {v.rule | some v in deny with input as mock_disk({"network_access_policy": "DenyAll"})}
	not "AZ-DISK-002" in rules
}
