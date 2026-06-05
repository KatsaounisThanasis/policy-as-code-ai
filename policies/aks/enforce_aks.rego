package terraform.security

import rego.v1

# Helper to filter Azure AKS Clusters
aks_clusters contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_kubernetes_cluster"
}

# Rule AZ-AKS-001: Deny local accounts enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-AKS-001",
	"severity": "high",
	"message": "AKS local accounts are enabled. Set 'local_account_disabled' to true."
} if {
	some resource in aks_clusters
	resource.change.after.local_account_disabled == false
}

# Rule AZ-AKS-002: Deny Azure Policy addon disabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-AKS-002",
	"severity": "medium",
	"message": "AKS Azure Policy add-on is disabled. Set 'azure_policy_enabled' to true."
} if {
	some resource in aks_clusters
	resource.change.after.azure_policy_enabled == false
}
