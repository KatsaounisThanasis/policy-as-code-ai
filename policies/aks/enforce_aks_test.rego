package terraform.security

import rego.v1

mock_aks(after) := {
	"resource_changes": [{
		"address": "test_aks_addr",
		"type": "azurerm_kubernetes_cluster",
		"change": {
			"after": after
		}
	}]
}

test_az_aks_001_fires if {
	rules := {v.rule | some v in deny with input as mock_aks({"local_account_disabled": false})}
	"AZ-AKS-001" in rules
}

test_az_aks_001_compliant if {
	rules := {v.rule | some v in deny with input as mock_aks({"local_account_disabled": true})}
	not "AZ-AKS-001" in rules
}

test_az_aks_002_fires if {
	rules := {v.rule | some v in deny with input as mock_aks({"azure_policy_enabled": false})}
	"AZ-AKS-002" in rules
}

test_az_aks_002_compliant if {
	rules := {v.rule | some v in deny with input as mock_aks({"azure_policy_enabled": true})}
	not "AZ-AKS-002" in rules
}
