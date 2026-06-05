package terraform.security

import rego.v1

# Helper to filter Azure Managed Disks
managed_disks contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_managed_disk"
}

# Rule AZ-DISK-001: Deny public network access enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-DISK-001",
	"severity": "high",
	"message": "Managed Disk allows public network access. Set 'public_network_access_enabled' to false."
} if {
	some resource in managed_disks
	resource.change.after.public_network_access_enabled == true
}

# Rule AZ-DISK-002: Deny network access policy AllowAll
deny contains {
	"resource": resource.address,
	"rule": "AZ-DISK-002",
	"severity": "medium",
	"message": "Managed Disk network access policy is AllowAll. Set 'network_access_policy' to 'DenyAll'."
} if {
	some resource in managed_disks
	resource.change.after.network_access_policy == "AllowAll"
}
