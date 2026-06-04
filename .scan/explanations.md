# AI Drift Explainer Report

_Model: `qwen2.5-coder:3b` via Ollama. Source: `.scan/violations.json`._

## [HIGH] AZ-STORAGE-001 on azurerm_storage_account.sa

**Policy message:** Storage account allows nested items to be public. Set 'allow_nested_items_to_be_public' to false.

### Why this is risky
If a storage account allows nested items to be public, unauthorized users can access and modify data stored within the account, potentially leading to data breaches or unauthorized modifications.

### Terraform remediation
```hcl
allow_nested_items_to_be_public = false
```

### Verification
An engineer can confirm the fix by checking the `allow_nested_items_to_be_public` attribute of the storage account resource in the Azure portal or using the Azure CLI command `az storage account show`.

**Azure docs:** <https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent>

## [HIGH] AZ-STORAGE-005 on azurerm_storage_account.sa

**Policy message:** Storage account does not require HTTPS traffic. Set 'https_traffic_only_enabled' to true.

### Why this is risky
Failure to enable HTTPS traffic on a storage account can expose sensitive data to unauthorized access over unencrypted connections, which could lead to data breaches and compliance issues.

### Terraform remediation
```hcl
https_traffic_only_enabled = true
```

### Verification
Check the `https_traffic_only_enabled` attribute of the storage account resource in Azure.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer>

## [HIGH] AZ-STORAGE-003 on azurerm_storage_account.sa

**Policy message:** Storage account has public network access enabled. Set 'public_network_access_enabled' to false.

### Why this is risky
If a storage account allows public network access, it can be accessed by anyone on the internet without authentication, which poses a significant security risk as it could lead to unauthorized data exposure and potential ransomware attacks.

### Terraform remediation
```hcl
public_network_access_enabled = false
```

### Verification
An engineer can confirm the fix by checking the `public_network_access_enabled` attribute of the storage account resource in Azure.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/storage-network-security>

## [MED]  AZ-STORAGE-002 on azurerm_storage_account.sa

**Policy message:** Storage account has shared access key enabled. Set 'shared_access_key_enabled' to false.

### Why this is risky
If the storage account has shared access keys enabled, it exposes sensitive information and can be used by unauthorized parties to perform operations on the storage account without authentication.

### Terraform remediation
```hcl
shared_access_key_enabled = false
```

### Verification
An engineer can confirm the fix by running `terraform plan` and verifying that `shared_access_key_enabled` is set to `false`.

**Azure docs:** <https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent>

## [MED]  AZ-STORAGE-004 on azurerm_storage_account.sa

**Policy message:** Storage account minimum TLS version is not TLS1_2. Set 'min_tls_version' to 'TLS1_2'.

### Why this is risky
Setting the minimum TLS version to less than TLS 1.2 can expose your storage account to potential security vulnerabilities, as older versions of TLS are no longer considered secure.

### Terraform remediation
```hcl
min_tls_version = "TLS1_2"
```

### Verification
Check the `min_tls_version` attribute in the Azure Storage Account resource block to ensure it is set to 'TLS1_2'.

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
