package terraform.security

import rego.v1

# Helper to filter Azure Cosmos DB Accounts
cosmos_accounts contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_cosmosdb_account"
}

# Rule AZ-COSMOS-001: Deny public network access enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-COSMOS-001",
	"severity": "high",
	"message": "Cosmos DB allows public network access. Set 'public_network_access_enabled' to false."
} if {
	some resource in cosmos_accounts
	resource.change.after.public_network_access_enabled == true
}
