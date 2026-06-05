# AI Drift Explainer Report

_Model: `qwen2.5-coder:3b` via ollama. Source: `.scan/violations.json`._

## [MED]  AZ-AKS-002 on azurerm_kubernetes_cluster.aks

**Policy message:** AKS Azure Policy add-on is disabled. Set 'azure_policy_enabled' to true.

### Why this is risky
Disabling the AKS Azure Policy add-on can lead to potential security vulnerabilities and compliance issues, as it may not enforce certain policies that are crucial for maintaining security and compliance.

### Terraform remediation
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  # other configurations...
  azure_policy_enabled = true
}
```

### Verification
An engineer can confirm the fix by checking the `azure_policy_enabled` attribute of the AKS cluster resource in the Azure portal or using the Azure CLI command `az aks show`.

**Azure docs:** <https://learn.microsoft.com/azure/aks/use-azure-policy>

## [HIGH] AZ-AKS-001 on azurerm_kubernetes_cluster.aks

**Policy message:** AKS local accounts are enabled. Set 'local_account_disabled' to true.

### Why this is risky
Local accounts in an Azure Kubernetes Service (AKS) cluster allow unauthenticated users to access the cluster, which can lead to unauthorized access and potential data breaches.

### Terraform remediation
```hcl
local_account_disabled = true
```

### Verification
An engineer can confirm the fix by checking the `local_account_disabled` attribute of the AKS cluster resource in the Azure portal or using the Azure CLI command `az aks show --name <aks-cluster-name> -g <resource-group-name>` and verifying that it is set to `true`.

**Azure docs:** <https://learn.microsoft.com/azure/aks/manage-local-accounts-managed-azure-ad>

## [HIGH] AZ-APP-001 on azurerm_linux_web_app.app

**Policy message:** App Service does not enforce HTTPS. Set 'https_only' to true.

### Why this is risky
If the app service does not enforce HTTPS, it can expose sensitive data to unauthorized users and potentially be vulnerable to man-in-the-middle attacks.

### Terraform remediation
```hcl
resource "azurerm_linux_web_app" "app" {
  name                = var.app_name
  location            = var.location
  resource_group_name = var.resource_group_name
  https_only          = true
}
```

### Verification
Check the 'https_only' attribute of the app service in Azure portal or using `azurerm_linux_web_app` data source.

**Azure docs:** <https://learn.microsoft.com/azure/app-service/configure-ssl-bindings>

## [MED]  AZ-APP-002 on azurerm_linux_web_app.app

**Policy message:** App Service minimum TLS version is not 1.2. Set site_config 'minimum_tls_version' to '1.2'.

### Why this is risky
If the minimum TLS version is set to a lower version, it can expose your application to man-in-the-middle attacks and other security vulnerabilities.

### Terraform remediation
```hcl
site_config {
  minimum_tls_version = "1.2"
}
```

### Verification
Check the `minimum_tls_version` attribute of the `azurerm_linux_web_app.app` resource in the Terraform state file to ensure it is set to '1.2'.

**Azure docs:** <https://learn.microsoft.com/azure/app-service/configure-ssl-bindings>

## [HIGH] AZ-ACR-001 on azurerm_container_registry.acr

**Policy message:** Container Registry admin user is enabled. Set 'admin_enabled' to false.

### Why this is risky
If the admin user is enabled, it grants full administrative privileges to anyone with access to the registry, increasing the risk of unauthorized access and data breaches.

### Terraform remediation
```hcl
admin_enabled = false
```

### Verification
Check the `admin_enabled` attribute in the `azurerm_container_registry` resource block. It should be set to `false`.

**Azure docs:** <https://learn.microsoft.com/azure/container-registry/container-registry-authentication>

## [MED]  AZ-ACR-002 on azurerm_container_registry.acr

**Policy message:** Container Registry allows public network access. Set 'public_network_access_enabled' to false.

### Why this is risky
Public network access enables unauthorized access to the container registry, which could lead to data breaches or unauthorized modifications.

### Terraform remediation
```hcl
public_network_access_enabled = false
```

### Verification
Check the `public_network_access_enabled` attribute of the `azurerm_container_registry.acr` resource in your Terraform state file.

**Azure docs:** <https://learn.microsoft.com/azure/container-registry/container-registry-access-selected-networks>

## [HIGH] AZ-COSMOS-001 on azurerm_cosmosdb_account.cosmos

**Policy message:** Cosmos DB allows public network access. Set 'public_network_access_enabled' to false.

### Why this is risky
If the Cosmos DB account allows public network access, it can be accessed from anywhere on the internet without authentication, which poses a significant security risk.

### Terraform remediation
```hcl
public_network_access_enabled = false
```

### Verification
An engineer can confirm the fix by checking the `public_network_access_enabled` attribute of the Cosmos DB account resource in Azure.

**Azure docs:** <https://learn.microsoft.com/azure/cosmos-db/how-to-configure-firewall>

## [HIGH] AZ-KV-002 on azurerm_key_vault.kv

**Policy message:** Key Vault allows public network access. Set 'public_network_access_enabled' to false.

### Why this is risky
Key Vault allowing public network access can expose sensitive data to unauthorized entities, increasing the risk of data breaches and unauthorized access.

### Terraform remediation
```hcl
public_network_access_enabled = false
```

### Verification
An engineer can confirm the fix by checking the 'public_network_access_enabled' attribute in the Azure portal or using the Azure CLI command `az key-vault show --name <key_vault_name>`.

**Azure docs:** <https://learn.microsoft.com/azure/key-vault/general/network-security>

## [HIGH] AZ-KV-001 on azurerm_key_vault.kv

**Policy message:** Key Vault purge protection is disabled. Set 'purge_protection_enabled' to true.

### Why this is risky
Key Vault purge protection is disabled, which means that the data in the vault can be permanently deleted without any recovery method. This could lead to loss of sensitive information and irrecoverable data.

### Terraform remediation
```hcl
purge_protection_enabled = true
```

### Verification
An engineer can confirm the fix by checking the 'purge_protection_enabled' attribute in the Azure portal or using the Azure CLI command `az key-vault show --name <vault-name>`.

**Azure docs:** <https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview>

## [MED]  AZ-LOG-001 on azurerm_log_analytics_workspace.law

**Policy message:** Log Analytics workspace allows queries over the public internet. Set 'internet_query_enabled' to false.

### Why this is risky
Log Analytics workspaces allow unrestricted access to queries over the public internet, which can expose sensitive data and lead to unauthorized access.

### Terraform remediation
```hcl
internet_query_enabled = false
```

### Verification
An engineer can confirm the fix by checking the 'internet_query_enabled' attribute of the Log Analytics workspace resource in Azure.

**Azure docs:** <https://learn.microsoft.com/azure/azure-monitor/logs/private-link-security>

## [HIGH] AZ-DISK-001 on azurerm_managed_disk.disk

**Policy message:** Managed Disk allows public network access. Set 'public_network_access_enabled' to false.

### Why this is risky
Managed Disk allowing public network access can expose sensitive data to unauthorized users, potentially leading to data breaches or unauthorized modifications.

### Terraform remediation
```hcl
public_network_access_enabled = false
```

### Verification
An engineer can confirm the fix by checking the 'public_network_access_enabled' attribute of the Managed Disk resource in Azure portal.

**Azure docs:** <https://learn.microsoft.com/azure/virtual-machines/disks-restrict-import-export-overview>

## [MED]  AZ-DISK-002 on azurerm_managed_disk.disk

**Policy message:** Managed Disk network access policy is AllowAll. Set 'network_access_policy' to 'DenyAll'.

### Why this is risky
Managed Disk network access policy being set to AllowAll can expose the disk to unauthorized network traffic, potentially leading to data breaches or unauthorized modifications.

### Terraform remediation
```hcl
network_access_policy = "DenyAll"
```

### Verification
An engineer can verify the fix by checking the `network_access_policy` attribute of the Managed Disk resource in Azure.

**Azure docs:** <https://learn.microsoft.com/azure/virtual-machines/disks-restrict-import-export-overview>

## [HIGH] AZ-NSG-001 on azurerm_network_security_rule.bad_any

**Policy message:** NSG rule allows inbound access from a public source to a sensitive or unrestricted port. Restrict 'source_address_prefix' and 'destination_port_range'.

### Why this is risky
An NSG rule allowing inbound access from a public source to a sensitive or unrestricted port can lead to unauthorized access, as it exposes the network to potential threats from the internet.

### Terraform remediation
```hcl
source_address_prefix = "10.0.0.0/8"
```

### Verification
An engineer can confirm the fix by checking the updated NSG rule in Azure portal or using `azurerm_network_security_rule` data source to verify the changes.

**Azure docs:** <https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview>

## [MED]  AZ-NSG-002 on azurerm_network_security_rule.bad_any

**Policy message:** NSG rule opens all destination ports ('*') to inbound traffic. Restrict 'destination_port_range' to specific ports.

### Why this is risky
An open rule that allows all destination ports can expose the network to potential attacks from any port, increasing the risk of unauthorized access and data breaches.

### Terraform remediation
```hcl
destination_port_range = "22"
```

### Verification
Check the `destination_port_range` attribute in the `azurerm_network_security_rule.bad_any` resource.

**Azure docs:** <https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview>

## [HIGH] AZ-SQL-001 on azurerm_mssql_server.sql

**Policy message:** SQL Server allows public network access. Set 'public_network_access_enabled' to false.

### Why this is risky
SQL Server allowing public network access can expose your database to unauthorized access from the internet, which could lead to data breaches and other security incidents.

### Terraform remediation
```hcl
public_network_access_enabled = false
```

### Verification
Run `terraform plan` to ensure that 'public_network_access_enabled' is set to false.

**Azure docs:** <https://learn.microsoft.com/azure/azure-sql/database/network-access-controls-overview>

## [MED]  AZ-SQL-002 on azurerm_mssql_server.sql

**Policy message:** SQL Server minimum TLS version is not 1.2. Set 'minimum_tls_version' to '1.2'.

### Why this is risky
If the SQL Server's minimum TLS version is set to anything other than 1.2, it may expose the server to potential security vulnerabilities, such as man-in-the-middle attacks and data interception.

### Terraform remediation
```hcl
minimum_tls_version = "1.2"
```

### Verification
An engineer can confirm the fix by checking the `minimum_tls_version` attribute of the SQL Server resource in the Azure portal or using the Azure CLI command `az sql server show`.

**Azure docs:** <https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings>

## [HIGH] AZ-STORAGE-001 on azurerm_storage_account.sa

**Policy message:** Storage account allows nested items to be public. Set 'allow_nested_items_to_be_public' to false.

### Why this is risky
If a storage account allows nested items to be public, unauthorized users could access sensitive data stored within the account.

### Terraform remediation
```hcl
allow_nested_items_to_be_public = false
```

### Verification
An engineer can verify the fix by checking the `allow_nested_items_to_be_public` attribute of the storage account resource in Azure.

**Azure docs:** <https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent>

## [HIGH] AZ-STORAGE-005 on azurerm_storage_account.sa

**Policy message:** Storage account does not require HTTPS traffic. Set 'https_traffic_only_enabled' to true.

### Why this is risky
If a storage account does not require HTTPS traffic, it can be vulnerable to man-in-the-middle attacks and data interception. This could lead to sensitive information being exposed or stolen.

### Terraform remediation
```hcl
https_traffic_only_enabled = true
```

### Verification
An engineer can verify the fix by checking the `https_traffic_only_enabled` attribute of the storage account in Azure portal or using the Azure CLI command `az storage account show --name <storage_account_name>`.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer>

## [HIGH] AZ-STORAGE-003 on azurerm_storage_account.sa

**Policy message:** Storage account has public network access enabled. Set 'public_network_access_enabled' to false.

### Why this is risky
If a storage account allows public network access, it can be accessed by anyone on the internet without authentication, which poses a significant security risk as sensitive data could be exposed.

### Terraform remediation
```hcl
public_network_access_enabled = false
```

### Verification
An engineer can confirm the fix by running `terraform plan` and checking that the `public_network_access_enabled` attribute is set to `false`.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/storage-network-security>

## [MED]  AZ-STORAGE-002 on azurerm_storage_account.sa

**Policy message:** Storage account has shared access key enabled. Set 'shared_access_key_enabled' to false.

### Why this is risky
If the storage account has shared access keys enabled, unauthorized users can gain access to sensitive data by using these keys. This poses a significant risk to data confidentiality and integrity.

### Terraform remediation
```hcl
shared_access_key_enabled = false
```

### Verification
An engineer can confirm the fix by running `terraform plan` and checking that the `shared_access_key_enabled` attribute is set to `false`.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent>

## [MED]  AZ-STORAGE-004 on azurerm_storage_account.sa

**Policy message:** Storage account minimum TLS version is not TLS1_2. Set 'min_tls_version' to 'TLS1_2'.

### Why this is risky
Setting the minimum TLS version to a lower version than TLS 1.2 can expose your storage account to potential security vulnerabilities, as it allows for older and less secure protocols that may be exploited by attackers.

### Terraform remediation
```hcl
min_tls_version = "TLS1_2"
```

### Verification
Check the `min_tls_version` attribute of the `azurerm_storage_account` resource in your Terraform state file to ensure it has been set to 'TLS1_2'.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version>

## Auto-Remediation

`terraform/main.tf` -> `.scan/main_fixed.tf`

Applied changes:

- **AZ-AKS-002**: `azure_policy_enabled = true`
- **AZ-AKS-001**: `local_account_disabled = true`
- **AZ-APP-001**: `https_only = true`
- **AZ-APP-002**: `minimum_tls_version = "1.2"`
- **AZ-ACR-001**: `admin_enabled = false`
- **AZ-ACR-002**: `public_network_access_enabled = false`
- **AZ-COSMOS-001**: `public_network_access_enabled = false`
- **AZ-KV-002**: `public_network_access_enabled = false`
- **AZ-KV-001**: `purge_protection_enabled = true`
- **AZ-LOG-001**: `internet_query_enabled = false`
- **AZ-DISK-001**: `public_network_access_enabled = false`
- **AZ-DISK-002**: `network_access_policy = "DenyAll"`
- **AZ-NSG-001**: `access = "Deny"`
- **AZ-NSG-002**: `access = "Deny"`
- **AZ-SQL-001**: `public_network_access_enabled = false`
- **AZ-SQL-002**: `minimum_tls_version = "1.2"`
- **AZ-STORAGE-001**: `allow_nested_items_to_be_public = false`
- **AZ-STORAGE-005**: `https_traffic_only_enabled = true`
- **AZ-STORAGE-003**: `public_network_access_enabled = false`
- **AZ-STORAGE-002**: `shared_access_key_enabled = false`
- **AZ-STORAGE-004**: `min_tls_version = "TLS1_2"`

```diff
--- terraform/main.tf
+++ .scan/main_fixed.tf
@@ -40,11 +40,11 @@
   account_tier             = "Standard"
   account_replication_type = "LRS"
 
-  allow_nested_items_to_be_public = true
-  shared_access_key_enabled       = true
-  public_network_access_enabled   = true
-  min_tls_version                 = "TLS1_0"
-  https_traffic_only_enabled      = false
+  allow_nested_items_to_be_public = false
+  shared_access_key_enabled       = false
+  public_network_access_enabled   = false
+  min_tls_version                 = "TLS1_2"
+  https_traffic_only_enabled      = true
 
   tags = {
     environment = "demo"
@@ -68,7 +68,7 @@
   name                        = "allow-any-inbound"
   priority                    = 100
   direction                   = "Inbound"
-  access                      = "Allow"
+  access                      = "Deny"
   protocol                    = "Tcp"
   source_port_range           = "*"
   destination_port_range      = "*"
@@ -87,8 +87,8 @@
   resource_group_name           = azurerm_resource_group.rg.name
   tenant_id                     = "00000000-0000-0000-0000-000000000000"
   sku_name                      = "standard"
-  purge_protection_enabled      = false
-  public_network_access_enabled = true
+  purge_protection_enabled      = true
+  public_network_access_enabled = false
   tags = {
     environment = "demo"
     purpose     = "policy-as-code"
@@ -102,8 +102,8 @@
   resource_group_name           = azurerm_resource_group.rg.name
   location                      = azurerm_resource_group.rg.location
   version                       = "12.0"
-  minimum_tls_version           = "1.0"  # AZ-SQL-002
-  public_network_access_enabled = true   # AZ-SQL-001
+  minimum_tls_version           = "1.2"
+  public_network_access_enabled = false
   azuread_administrator {
     login_username              = "sqladmin"
     object_id                   = "00000000-0000-0000-0000-000000000000"
@@ -129,9 +129,9 @@
   resource_group_name = azurerm_resource_group.rg.name
   location            = azurerm_service_plan.asp.location
   service_plan_id     = azurerm_service_plan.asp.id
-  https_only          = false  # AZ-APP-001
+  https_only          = true
   site_config {
-    minimum_tls_version = "1.0"  # AZ-APP-002
+    minimum_tls_version = "1.2"
   }
   tags = {
     environment = "demo"
@@ -147,8 +147,8 @@
   storage_account_type          = "Standard_LRS"
   create_option                 = "Empty"
   disk_size_gb                  = 1
-  public_network_access_enabled = true        # AZ-DISK-001
-  network_access_policy         = "AllowAll"  # AZ-DISK-002
+  public_network_access_enabled = false
+  network_access_policy         = "DenyAll"
   tags = {
     environment = "demo"
     purpose     = "policy-as-code"
@@ -162,7 +162,7 @@
   location                      = azurerm_resource_group.rg.location
   offer_type                    = "Standard"
   kind                          = "GlobalDocumentDB"
-  public_network_access_enabled = true   # AZ-COSMOS-001
+  public_network_access_enabled = false
   consistency_policy {
     consistency_level = "Session"
   }
@@ -182,8 +182,8 @@
   resource_group_name    = azurerm_resource_group.rg.name
   location               = azurerm_resource_group.rg.location
   dns_prefix             = "akspolicy"
-  local_account_disabled = false  # AZ-AKS-001 (should be true)
-  azure_policy_enabled   = false  # AZ-AKS-002 (should be true)
+  local_account_disabled = true
+  azure_policy_enabled   = true
   default_node_pool {
     name       = "default"
     node_count = 1
@@ -204,8 +204,8 @@
   resource_group_name           = azurerm_resource_group.rg.name
   location                      = azurerm_resource_group.rg.location
   sku                           = "Premium"
-  admin_enabled                 = true   # AZ-ACR-001
-  public_network_access_enabled = true   # AZ-ACR-002
+  admin_enabled                 = false
+  public_network_access_enabled = false
   tags = {
     environment = "demo"
     purpose     = "policy-as-code"
@@ -219,9 +219,9 @@
   location               = azurerm_resource_group.rg.location
   sku                    = "PerGB2018"
   retention_in_days      = 30
-  internet_query_enabled = true  # AZ-LOG-001 (should be false)
-  tags = {
-    environment = "demo"
-    purpose     = "policy-as-code"
-  }
-}
+  internet_query_enabled = false
+  tags = {
+    environment = "demo"
+    purpose     = "policy-as-code"
+  }
+}
```
