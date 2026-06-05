package terraform.security

import rego.v1

# Helper to filter Azure Container Registries
container_registries contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_container_registry"
}

# Rule AZ-ACR-001: Deny admin user enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-ACR-001",
	"severity": "high",
	"message": "Container Registry admin user is enabled. Set 'admin_enabled' to false."
} if {
	some resource in container_registries
	resource.change.after.admin_enabled == true
}

# Rule AZ-ACR-002: Deny public network access enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-ACR-002",
	"severity": "medium",
	"message": "Container Registry allows public network access. Set 'public_network_access_enabled' to false."
} if {
	some resource in container_registries
	resource.change.after.public_network_access_enabled == true
}
