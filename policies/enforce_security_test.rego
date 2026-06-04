package terraform.security

import rego.v1

mock_resource(after) := {
	"resource_changes": [{
		"address": "test_addr",
		"type": "azurerm_storage_account",
		"change": {
			"after": after
		}
	}]
}

test_az_storage_001_fires if {
	rules := {v.rule | some v in deny with input as mock_resource({"allow_nested_items_to_be_public": true})}
	"AZ-STORAGE-001" in rules
}

test_az_storage_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_resource({"allow_nested_items_to_be_public": false})}
	not "AZ-STORAGE-001" in rules
}

test_az_storage_002_fires if {
	rules := {v.rule | some v in deny with input as mock_resource({"shared_access_key_enabled": true})}
	"AZ-STORAGE-002" in rules
}

test_az_storage_002_compliant if {
	rules := {v.rule | some v in deny with input as mock_resource({"shared_access_key_enabled": false})}
	not "AZ-STORAGE-002" in rules
}

test_az_storage_003_fires if {
	rules := {v.rule | some v in deny with input as mock_resource({"public_network_access_enabled": true})}
	"AZ-STORAGE-003" in rules
}

test_az_storage_003_compliant if {
	rules := {v.rule | some v in deny with input as mock_resource({"public_network_access_enabled": false})}
	not "AZ-STORAGE-003" in rules
}

test_az_storage_004_fires if {
	rules := {v.rule | some v in deny with input as mock_resource({"min_tls_version": "TLS1_0"})}
	"AZ-STORAGE-004" in rules
}

test_az_storage_004_compliant if {
	rules := {v.rule | some v in deny with input as mock_resource({"min_tls_version": "TLS1_2"})}
	not "AZ-STORAGE-004" in rules
}

test_az_storage_005_fires if {
	rules := {v.rule | some v in deny with input as mock_resource({"https_traffic_only_enabled": false})}
	"AZ-STORAGE-005" in rules
}

test_az_storage_005_compliant if {
	rules := {v.rule | some v in deny with input as mock_resource({"https_traffic_only_enabled": true})}
	not "AZ-STORAGE-005" in rules
}

test_fully_compliant if {
	input_data := mock_resource({
		"allow_nested_items_to_be_public": false,
		"shared_access_key_enabled": false,
		"public_network_access_enabled": false,
		"min_tls_version": "TLS1_2",
		"https_traffic_only_enabled": true
	})
	count(deny) == 0 with input as input_data
}

test_fully_insecure if {
	input_data := mock_resource({
		"allow_nested_items_to_be_public": true,
		"shared_access_key_enabled": true,
		"public_network_access_enabled": true,
		"min_tls_version": "TLS1_0",
		"https_traffic_only_enabled": false
	})
	count(deny) == 5 with input as input_data
}
