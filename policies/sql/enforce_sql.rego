package terraform.security

import rego.v1

# Helper to filter Azure SQL Servers
sql_servers contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_mssql_server"
}

# Rule AZ-SQL-001: Deny public network access enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-SQL-001",
	"severity": "high",
	"message": "SQL Server allows public network access. Set 'public_network_access_enabled' to false."
} if {
	some resource in sql_servers
	resource.change.after.public_network_access_enabled == true
}

# Rule AZ-SQL-002: Deny minimum TLS version not 1.2
deny contains {
	"resource": resource.address,
	"rule": "AZ-SQL-002",
	"severity": "medium",
	"message": "SQL Server minimum TLS version is not 1.2. Set 'minimum_tls_version' to '1.2'."
} if {
	some resource in sql_servers
	is_object(resource.change.after)
	not is_sql_tls1_2(resource.change.after)
}

is_sql_tls1_2(after) if {
	after.minimum_tls_version == "1.2"
}
