package terraform.security

import rego.v1

# Helper to filter Azure storage accounts
storage_accounts contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_storage_account"
}

# Rule AZ-STORAGE-001: Deny nested items to be public
deny contains {
	"resource": resource.address,
	"rule": "AZ-STORAGE-001",
	"severity": "high",
	"message": "Storage account allows nested items to be public. Set 'allow_nested_items_to_be_public' to false."
} if {
	some resource in storage_accounts
	resource.change.after.allow_nested_items_to_be_public == true
}

# Rule AZ-STORAGE-002: Deny shared access key enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-STORAGE-002",
	"severity": "medium",
	"message": "Storage account has shared access key enabled. Set 'shared_access_key_enabled' to false."
} if {
	some resource in storage_accounts
	resource.change.after.shared_access_key_enabled == true
}

# Rule AZ-STORAGE-003: Deny public network access enabled
deny contains {
	"resource": resource.address,
	"rule": "AZ-STORAGE-003",
	"severity": "high",
	"message": "Storage account has public network access enabled. Set 'public_network_access_enabled' to false."
} if {
	some resource in storage_accounts
	resource.change.after.public_network_access_enabled == true
}

# Rule AZ-STORAGE-004: Deny min TLS version not TLS1_2
deny contains {
	"resource": resource.address,
	"rule": "AZ-STORAGE-004",
	"severity": "medium",
	"message": "Storage account minimum TLS version is not TLS1_2. Set 'min_tls_version' to 'TLS1_2'."
} if {
	some resource in storage_accounts
	is_object(resource.change.after)
	not is_tls1_2(resource.change.after)
}

is_tls1_2(after) if {
	after.min_tls_version == "TLS1_2"
}

# Rule AZ-STORAGE-005: Deny https traffic only enabled false
deny contains {
	"resource": resource.address,
	"rule": "AZ-STORAGE-005",
	"severity": "high",
	"message": "Storage account does not require HTTPS traffic. Set 'https_traffic_only_enabled' to true."
} if {
	some resource in storage_accounts
	resource.change.after.https_traffic_only_enabled == false
}

# Top-level helpers
violation_count := count(deny)

has_violations if {
	count(deny) > 0
}
