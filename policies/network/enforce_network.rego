package terraform.security

import rego.v1

# Helper to filter Azure NSG rules
nsg_rules contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_network_security_rule"
}

# Rule AZ-NSG-001: Deny public access to sensitive ports
deny contains {
	"resource": resource.address,
	"rule": "AZ-NSG-001",
	"severity": "high",
	"message": "NSG rule allows inbound access from a public source to a sensitive or unrestricted port. Restrict 'source_address_prefix' and 'destination_port_range'."
} if {
	some resource in nsg_rules
	resource.change.after.access == "Allow"
	resource.change.after.direction == "Inbound"
	resource.change.after.source_address_prefix in {"*", "0.0.0.0/0", "Internet"}
	resource.change.after.destination_port_range in {"22", "3389", "*"}
}

# Rule AZ-NSG-002: Deny all destination ports for inbound traffic
deny contains {
	"resource": resource.address,
	"rule": "AZ-NSG-002",
	"severity": "medium",
	"message": "NSG rule opens all destination ports ('*') to inbound traffic. Restrict 'destination_port_range' to specific ports."
} if {
	some resource in nsg_rules
	resource.change.after.access == "Allow"
	resource.change.after.direction == "Inbound"
	resource.change.after.destination_port_range == "*"
}
