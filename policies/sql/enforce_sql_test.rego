package terraform.security

import rego.v1

mock_sql(after) := {
	"resource_changes": [{
		"address": "test_sql_addr",
		"type": "azurerm_mssql_server",
		"change": {
			"after": after
		}
	}]
}

test_az_sql_001_fires if {
	rules := {v.rule | some v in deny with input as mock_sql({"public_network_access_enabled": true})}
	"AZ-SQL-001" in rules
}

test_az_sql_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_sql({"public_network_access_enabled": false})}
	not "AZ-SQL-001" in rules
}

test_az_sql_002_fires if {
	rules := {v.rule | some v in deny with input as mock_sql({"minimum_tls_version": "1.1"})}
	"AZ-SQL-002" in rules
}

test_az_sql_002_compliant if {
	rules := {v.rule | some v in deny with input as mock_sql({"minimum_tls_version": "1.2"})}
	not "AZ-SQL-002" in rules
}
