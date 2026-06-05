package terraform.security

import rego.v1

mock_nsg(after) := {
	"resource_changes": [{
		"address": "test_nsg_addr",
		"type": "azurerm_network_security_rule",
		"change": {
			"after": after
		}
	}]
}

test_az_nsg_001_fires if {
	rules := {v.rule | some v in deny with input as mock_nsg({
		"access": "Allow",
		"direction": "Inbound",
		"source_address_prefix": "*",
		"destination_port_range": "22"
	})}
	"AZ-NSG-001" in rules
}

test_az_nsg_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_nsg({
		"access": "Allow",
		"direction": "Inbound",
		"source_address_prefix": "10.0.0.0/24",
		"destination_port_range": "443"
	})}
	not "AZ-NSG-001" in rules
}

test_az_nsg_002_fires if {
	rules := {v.rule | some v in deny with input as mock_nsg({
		"access": "Allow",
		"direction": "Inbound",
		"source_address_prefix": "10.0.0.0/24",
		"destination_port_range": "*"
	})}
	"AZ-NSG-002" in rules
}

test_az_nsg_002_compliant if {
	rules := {v.rule | some v in deny with input as mock_nsg({
		"access": "Allow",
		"direction": "Inbound",
		"source_address_prefix": "*",
		"destination_port_range": "80"
	})}
	not "AZ-NSG-002" in rules
}

test_az_nsg_fully_open_fires_both if {
	rules := {v.rule | some v in deny with input as mock_nsg({
		"access": "Allow",
		"direction": "Inbound",
		"source_address_prefix": "*",
		"destination_port_range": "*"
	})}
	"AZ-NSG-001" in rules
	"AZ-NSG-002" in rules
}
