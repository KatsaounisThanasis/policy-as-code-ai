# AI Drift Explainer Report

_Model: `qwen2.5-coder:3b` via Ollama. Source: `.scan/violations.json`._

## [HIGH] AZ-STORAGE-001 on azurerm_storage_account.sa

**Policy message:** Storage account allows nested items to be public. Set 'allow_nested_items_to_be_public' to false.

### Why this is risky
If a storage account allows nested items to be public, unauthorized users could potentially access sensitive data stored within the account.

### Terraform remediation
```hcl
allow_nested_items_to_be_public = false
```

### Verification
An engineer can confirm the fix by running `terraform plan` and checking that `allow_nested_items_to_be_public` is set to `false`.

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
Check the 'https_traffic_only_enabled' attribute of the storage account resource in Azure portal or using Azure CLI.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer>

## [HIGH] AZ-STORAGE-003 on azurerm_storage_account.sa

**Policy message:** Storage account has public network access enabled. Set 'public_network_access_enabled' to false.

### Why this is risky
If public network access is enabled, unauthorized users can access the storage account and its resources over the internet, posing a risk to data security.

### Terraform remediation
```hcl
public_network_access_enabled = false
```

### Verification
Check the `public_network_access_enabled` attribute of the `azurerm_storage_account` resource.

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
An engineer can confirm the fix by checking the `shared_access_key_enabled` attribute of the storage account in Azure portal or using the Azure CLI command `az storage account show --name <storage_account_name>`.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent>

## [MED]  AZ-STORAGE-004 on azurerm_storage_account.sa

**Policy message:** Storage account minimum TLS version is not TLS1_2. Set 'min_tls_version' to 'TLS1_2'.

### Why this is risky
If the storage account uses a minimum TLS version lower than TLS 1.2, it can expose sensitive data to potential attackers who might exploit vulnerabilities in older versions of TLS.

### Terraform remediation
```hcl
min_tls_version = "TLS1_2"
```

### Verification
An engineer can confirm the fix by checking the `min_tls_version` attribute of the storage account resource.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version>

## Auto-Remediation

`terraform/main.tf` -> `.scan/main_fixed.tf`

Applied changes:

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
```
