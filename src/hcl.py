#!/usr/bin/env python3
"""
Minimal, dependency-free HCL block locator.

Just enough to answer two questions the remediation and SARIF paths need:
  * where does the block for a given Terraform resource address start/end?
  * on which line does an attribute live *inside that block*?

This makes both the auto-fix (src/explainer.py) and the SARIF line mapping
(scripts/opa_to_sarif.py) **resource-scoped** instead of matching an attribute
name anywhere in the file — so two resources that share an attribute no longer
get patched together or point at the same line.

Not a full HCL parser: brace counting is line-based. Balanced braces inside a
single-line string/interpolation (e.g. "${res.name}") net to zero and are fine;
a stray unbalanced brace inside a multi-line string would confuse it — no such
case exists in normal Terraform.
"""

from __future__ import annotations

import re

_RES_HEADER = re.compile(r'^\s*resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{')


def normalize_address(address: str) -> str:
    """Reduce a plan address to the `type.name` used in the .tf source.

    Strips a trailing `[index]`/`["key"]` (count/for_each) and a leading
    `module.<x>.` prefix so `module.db.azurerm_mssql_server.sql[0]` -> `azurerm_mssql_server.sql`.
    """
    a = re.sub(r"\[[^\]]*\]$", "", address.strip())
    a = re.sub(r"^(?:module\.[^.]+\.)+", "", a)
    return a


def resource_block_lines(text: str) -> dict[str, tuple[int, int]]:
    """Map `type.name` -> (start_line, end_line), 1-based inclusive."""
    lines = text.splitlines()
    blocks: dict[str, tuple[int, int]] = {}
    n = len(lines)
    i = 0
    while i < n:
        m = _RES_HEADER.match(lines[i])
        if not m:
            i += 1
            continue
        addr = f"{m.group('type')}.{m.group('name')}"
        depth = lines[i].count("{") - lines[i].count("}")
        j = i
        while depth > 0 and j + 1 < n:
            j += 1
            depth += lines[j].count("{") - lines[j].count("}")
        blocks[addr] = (i + 1, j + 1)
        i = j + 1
    return blocks


def find_attr_line(text: str, address: str, attr: str) -> int | None:
    """1-based line of `attr` inside `address`'s block; block start if the attr
    isn't found there; first match anywhere if the block is unknown; else None."""
    lines = text.splitlines()
    attr_re = re.compile(rf"^\s*{re.escape(attr)}\s*=")
    rng = resource_block_lines(text).get(normalize_address(address))
    if rng:
        for ln in range(rng[0], rng[1] + 1):
            if attr_re.match(lines[ln - 1]):
                return ln
        return rng[0]
    for idx, line in enumerate(lines, 1):
        if attr_re.match(line):
            return idx
    return None
