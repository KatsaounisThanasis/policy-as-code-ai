package terraform.security

import rego.v1

# Helper to filter Azure Key Vaults
key_vaults contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_key_vault"
}

# Rule AZ-KV-001: Deny purge protection disabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-KV-001",
	"severity": "high",
	"message": "Key Vault purge protection is disabled. Set 'purge_protection_enabled' to true."
} if {
	some resource in key_vaults
	resource.change.after.purge_protection_enabled == false
}

# Rule AZ-KV-002: Deny public network access enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-KV-002",
	"severity": "high",
	"message": "Key Vault allows public network access. Set 'public_network_access_enabled' to false."
} if {
	some resource in key_vaults
	resource.change.after.public_network_access_enabled == true
}
