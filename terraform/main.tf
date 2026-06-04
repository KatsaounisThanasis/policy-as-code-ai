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
