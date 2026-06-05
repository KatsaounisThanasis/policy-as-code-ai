package terraform.security

import rego.v1

# Helper to filter Azure Log Analytics Workspaces
log_workspaces contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_log_analytics_workspace"
}

# Rule AZ-LOG-001: Deny internet query enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-LOG-001",
	"severity": "medium",
	"message": "Log Analytics workspace allows queries over the public internet. Set 'internet_query_enabled' to false."
} if {
	some resource in log_workspaces
	resource.change.after.internet_query_enabled == true
}
