terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-policy-demo"
  location = "West Europe"
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

resource "random_string" "suffix" {
  length  = 8
  lower   = true
  upper   = false
  numeric = true
  special = false
}

resource "azurerm_storage_account" "sa" {
  name                     = "stpolicy${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true
  shared_access_key_enabled       = true
  public_network_access_enabled   = true
  min_tls_version                 = "TLS1_0"
  https_traffic_only_enabled      = false

  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

# --- Intentionally-insecure Network Security Group (for AZ-NSG rules) ---
resource "azurerm_network_security_group" "nsg" {
  name                = "nsg-policy-demo"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

# Anti-pattern: allows inbound from anywhere ("*") to any port ("*").
resource "azurerm_network_security_rule" "bad_any" {
  name                        = "allow-any-inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}

# --- Intentionally-insecure Key Vault (for AZ-KV rules) ---
# tenant_id is a placeholder GUID on purpose: keeps `terraform plan` valid
# while leaking no real tenant into the committed plan fixture.
resource "azurerm_key_vault" "kv" {
  name                          = "kvpolicy${random_string.suffix.result}"
  location                      = azurerm_resource_group.rg.location
  resource_group_name           = azurerm_resource_group.rg.name
  tenant_id                     = "00000000-0000-0000-0000-000000000000"
  sku_name                      = "standard"
  purge_protection_enabled      = false
  public_network_access_enabled = true
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

# --- Intentionally-insecure SQL Server (for AZ-SQL rules) ---
# Azure AD-only auth (no SQL admin password) so nothing secret lands in the plan.
resource "azurerm_mssql_server" "sql" {
  name                          = "sqlpolicy${random_string.suffix.result}"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  version                       = "12.0"
  minimum_tls_version           = "1.0"  # AZ-SQL-002
  public_network_access_enabled = true   # AZ-SQL-001
  azuread_administrator {
    login_username              = "sqladmin"
    object_id                   = "00000000-0000-0000-0000-000000000000"
    azuread_authentication_only = true
  }
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

# --- Intentionally-insecure App Service (for AZ-APP rules) ---
resource "azurerm_service_plan" "asp" {
  name                = "asp-policy-demo"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  os_type             = "Linux"
  sku_name            = "B1"
}

resource "azurerm_linux_web_app" "app" {
  name                = "apppolicy${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_service_plan.asp.location
  service_plan_id     = azurerm_service_plan.asp.id
  https_only          = false  # AZ-APP-001
  site_config {
    minimum_tls_version = "1.0"  # AZ-APP-002
  }
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

# --- Intentionally-insecure Managed Disk (for AZ-DISK rules) ---
resource "azurerm_managed_disk" "disk" {
  name                          = "disk-policy-demo"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  storage_account_type          = "Standard_LRS"
  create_option                 = "Empty"
  disk_size_gb                  = 1
  public_network_access_enabled = true        # AZ-DISK-001
  network_access_policy         = "AllowAll"  # AZ-DISK-002
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

# --- Intentionally-insecure Cosmos DB (for AZ-COSMOS rules) ---
resource "azurerm_cosmosdb_account" "cosmos" {
  name                          = "cosmospolicy${random_string.suffix.result}"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  public_network_access_enabled = true   # AZ-COSMOS-001
  consistency_policy {
    consistency_level = "Session"
  }
  geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
  }
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

# --- Intentionally-insecure AKS cluster (for AZ-AKS rules) ---
resource "azurerm_kubernetes_cluster" "aks" {
  name                   = "aks-policy-demo"
  resource_group_name    = azurerm_resource_group.rg.name
  location               = azurerm_resource_group.rg.location
  dns_prefix             = "akspolicy"
  local_account_disabled = false  # AZ-AKS-001 (should be true)
  azure_policy_enabled   = false  # AZ-AKS-002 (should be true)
  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_DS2_v2"
  }
  identity {
    type = "SystemAssigned"
  }
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

# --- Intentionally-insecure Container Registry (for AZ-ACR rules) ---
resource "azurerm_container_registry" "acr" {
  name                          = "acrpolicy${random_string.suffix.result}"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  sku                           = "Premium"
  admin_enabled                 = true   # AZ-ACR-001
  public_network_access_enabled = true   # AZ-ACR-002
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}

# --- Intentionally-insecure Log Analytics Workspace (for AZ-LOG rules) ---
resource "azurerm_log_analytics_workspace" "law" {
  name                   = "law-policy-demo"
  resource_group_name    = azurerm_resource_group.rg.name
  location               = azurerm_resource_group.rg.location
  sku                    = "PerGB2018"
  retention_in_days      = 30
  internet_query_enabled = true  # AZ-LOG-001 (should be false)
  tags = {
    environment = "demo"
    purpose     = "policy-as-code"
  }
}
