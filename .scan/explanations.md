# AI Drift Explainer Report

_Model: `qwen2.5-coder:3b` via Ollama. Source: `.scan/violations.json`._

## [HIGH] AZ-KV-002 on azurerm_key_vault.kv

**Policy message:** Key Vault allows public network access. Set 'public_network_access_enabled' to false.

### Why this is risky
Key Vault allows public network access, which can expose sensitive data to unauthorized entities over the internet.

### Terraform remediation
```hcl
public_network_access_enabled = false
```

### Verification
Check the `public_network_access_enabled` attribute of the Azure Key Vault resource in your Terraform state file.

**Azure docs:** <https://learn.microsoft.com/azure/key-vault/general/network-security>

## [HIGH] AZ-KV-001 on azurerm_key_vault.kv

**Policy message:** Key Vault purge protection is disabled. Set 'purge_protection_enabled' to true.

### Why this is risky
If key vault purge protection is disabled, an attacker could potentially delete the key vault and all its contents without any recovery mechanism.

### Terraform remediation
```hcl
purge_protection_enabled = true
```

### Verification
Check the 'purge_protection_enabled' attribute of the key vault resource in Azure portal or using Azure CLI.

**Azure docs:** <https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview>

## [HIGH] AZ-NSG-001 on azurerm_network_security_rule.bad_any

**Policy message:** NSG rule allows inbound access from a public source to a sensitive or unrestricted port. Restrict 'source_address_prefix' and 'destination_port_range'.

### Why this is risky
This policy violation exposes the network security group (NSG) to inbound traffic from any public IP address, which could potentially allow unauthorized access to sensitive services or ports.

### Terraform remediation
```hcl
resource "azurerm_network_security_rule" "bad_any" {
  name                = "bad_any"
  resource_group_name = azurerm_resource_group.example.name
  network_security_group_id = azurerm_network_security_group.example.id

  access          = "Deny"
  direction        = "Inbound"
  priority         = 100
  protocol         = "Tcp"

  destination_port_range = ["80", "443"]
}
```

### Verification
An engineer can verify the fix by checking the `source_address_prefix` attribute of the NSG rule in Azure portal or using the Azure CLI command `az network nsg rule list`.

**Azure docs:** <https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview>

## [MED]  AZ-NSG-002 on azurerm_network_security_rule.bad_any

**Policy message:** NSG rule opens all destination ports ('*') to inbound traffic. Restrict 'destination_port_range' to specific ports.

### Why this is risky
An NSG rule that allows all outbound traffic on any port can expose your resources to potential security threats, as it provides an open door for unauthorized access and data exfiltration.

### Terraform remediation
```hcl
destination_port_range = "80,443"
```

### Verification
Check the `destination_port_range` attribute of the NSG rule in Azure Portal or using Azure CLI to ensure it is set to specific ports.

**Azure docs:** <https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview>

## [HIGH] AZ-STORAGE-001 on azurerm_storage_account.sa

**Policy message:** Storage account allows nested items to be public. Set 'allow_nested_items_to_be_public' to false.

### Why this is risky
If a storage account allows nested items to be public, unauthorized users could access sensitive data stored within the account.

### Terraform remediation
```hcl
allow_nested_items_to_be_public = false
```

### Verification
Check the `allow_nested_items_to_be_public` attribute of the storage account resource in Azure portal or using Azure CLI.

**Azure docs:** <https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent>

## [HIGH] AZ-STORAGE-005 on azurerm_storage_account.sa

**Policy message:** Storage account does not require HTTPS traffic. Set 'https_traffic_only_enabled' to true.

### Why this is risky
If a storage account does not require HTTPS traffic, it can be vulnerable to man-in-the-middle attacks and data interception. This could lead to sensitive information being exposed.

### Terraform remediation
```hcl
https_traffic_only_enabled = true
```

### Verification
An engineer can confirm the fix by checking the 'https_traffic_only_enabled' attribute of the storage account resource in Azure portal or using Azure CLI with `az storage account show`.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer>

## [HIGH] AZ-STORAGE-003 on azurerm_storage_account.sa

**Policy message:** Storage account has public network access enabled. Set 'public_network_access_enabled' to false.

### Why this is risky
If the storage account allows public network access, it can be accessed from anywhere on the internet without authentication, which poses a significant security risk as it exposes sensitive data and resources.

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
If the storage account has shared access keys enabled, it exposes sensitive information to unauthorized users and can lead to data breaches if not properly managed.

### Terraform remediation
```hcl
  shared_access_key_enabled = false
```

### Verification
An engineer can confirm the fix by running `terraform plan` and ensuring that the `shared_access_key_enabled` attribute is set to `false`.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent>

## [MED]  AZ-STORAGE-004 on azurerm_storage_account.sa

**Policy message:** Storage account minimum TLS version is not TLS1_2. Set 'min_tls_version' to 'TLS1_2'.

### Why this is risky
If the storage account uses a minimum TLS version less than TLS 1.2, it may expose sensitive data to potential attackers who can exploit vulnerabilities in older versions of TLS.

### Terraform remediation
```hcl
min_tls_version = "TLS1_2"
```

### Verification
Check the 'min_tls_version' attribute of the storage account resource.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version>

## Auto-Remediation

`terraform/main.tf` -> `.scan/main_fixed.tf`

Applied changes:

- **AZ-KV-002**: `public_network_access_enabled = false`
- **AZ-KV-001**: `purge_protection_enabled = true`
- **AZ-NSG-001**: `access = "Deny"`
- **AZ-NSG-002**: `access = "Deny"`
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
```
