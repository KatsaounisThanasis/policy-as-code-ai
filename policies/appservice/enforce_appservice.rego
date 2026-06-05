package terraform.security

import rego.v1

# Helper to filter Azure Linux Web Apps
web_apps contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_linux_web_app"
}

# Rule AZ-APP-001: Deny HTTPS only false
deny contains {
	"resource": resource.address,
	"rule": "AZ-APP-001",
	"severity": "high",
	"message": "App Service does not enforce HTTPS. Set 'https_only' to true."
} if {
	some resource in web_apps
	resource.change.after.https_only == false
}

# Rule AZ-APP-002: Deny minimum TLS version not 1.2 in site_config
deny contains {
	"resource": resource.address,
	"rule": "AZ-APP-002",
	"severity": "medium",
	"message": "App Service minimum TLS version is not 1.2. Set site_config 'minimum_tls_version' to '1.2'."
} if {
	some resource in web_apps
	some sc in resource.change.after.site_config
	sc.minimum_tls_version != "1.2"
}
