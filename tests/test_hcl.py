import hcl

SRC = (
    'resource "azurerm_storage_account" "a" {\n'
    "  public_network_access_enabled = true\n"
    "}\n"
    "\n"
    'resource "azurerm_storage_account" "b" {\n'
    "  public_network_access_enabled = false\n"
    "}\n"
)


def test_resource_block_lines():
    blocks = hcl.resource_block_lines(SRC)
    assert set(blocks) == {"azurerm_storage_account.a", "azurerm_storage_account.b"}
    assert blocks["azurerm_storage_account.a"] == (1, 3)
    assert blocks["azurerm_storage_account.b"] == (5, 7)


def test_find_attr_line_is_resource_scoped():
    # Same attribute in two blocks resolves to the right line per resource.
    assert hcl.find_attr_line(SRC, "azurerm_storage_account.a", "public_network_access_enabled") == 2
    assert hcl.find_attr_line(SRC, "azurerm_storage_account.b", "public_network_access_enabled") == 6


def test_find_attr_line_missing_attr_falls_back_to_block_start():
    assert hcl.find_attr_line(SRC, "azurerm_storage_account.a", "not_present") == 1


def test_find_attr_line_unknown_block_first_match():
    assert hcl.find_attr_line(SRC, "azurerm_storage_account.zzz", "public_network_access_enabled") == 2


def test_normalize_address():
    assert hcl.normalize_address("azurerm_x.y[0]") == "azurerm_x.y"
    assert hcl.normalize_address('azurerm_x.y["k"]') == "azurerm_x.y"
    assert hcl.normalize_address("module.m.azurerm_x.y") == "azurerm_x.y"
    assert hcl.normalize_address("azurerm_x.y") == "azurerm_x.y"
