"""
FalseAlarm — Result Diffing

Compares the results of the current scan against the most recent
previous scan of the same target, so continuous-monitoring workflows
can alert only on what's NEW (new subdomain, new open port, new
vulnerability, etc.) instead of the full result set every time.
"""

from __future__ import annotations

import json
from typing import Any

# Fields that uniquely identify an item within each module's result list.
# Used to match "the same finding" across two scans. Modules not listed
# here fall back to hashing the whole item (still correct, just less
# forgiving of minor field changes like elapsed time).
KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "subdomain": ("domain",),
    "portscan": ("port",),
    "dirfuzz": ("url",),
    "vulnscan": ("vuln_id", "url"),
    "httpprobe": ("url",),
    "websocket": ("url",),
    "cors": ("type", "origin_tested"),
}


def _item_key(module: str, item: dict[str, Any]) -> str:
    """Build a stable string key identifying this finding."""
    fields = KEY_FIELDS.get(module)
    if fields and all(f in item for f in fields):
        return "|".join(str(item.get(f, "")) for f in fields)
    # Fallback: hash the whole item so unknown/future modules still work.
    return json.dumps(item, sort_keys=True, default=str)


def diff_module_results(
    module: str,
    old_data: list[dict[str, Any]],
    new_data: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Diff one module's result list between two scans.

    Returns:
        {"new": [...], "removed": [...]} — items present only in the
        new scan, and items that were present before but disappeared
        (e.g. a port that closed, a subdomain that stopped resolving).
    """
    old_keys = {_item_key(module, item): item for item in old_data}
    new_keys = {_item_key(module, item): item for item in new_data}

    new_items = [item for k, item in new_keys.items() if k not in old_keys]
    removed_items = [item for k, item in old_keys.items() if k not in new_keys]

    return {"new": new_items, "removed": removed_items}


def diff_scan_results(
    old_results: dict[str, dict[str, Any]],
    new_results: dict[str, dict[str, Any]],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Diff a full scan (all modules) against a previous scan.

    Args:
        old_results: Previous scan's {module: {"data": [...], ...}} dict.
        new_results: Current scan's {module: {"data": [...], ...}} dict.

    Returns:
        {module: {"new": [...], "removed": [...]}} for every module that
        has any change. Modules with no changes are omitted.
    """
    diff: dict[str, dict[str, list[dict[str, Any]]]] = {}

    all_modules = set(old_results.keys()) | set(new_results.keys())
    for module in all_modules:
        old_data = old_results.get(module, {}).get("data", []) or []
        new_data = new_results.get(module, {}).get("data", []) or []

        if not isinstance(old_data, list) or not isinstance(new_data, list):
            continue

        module_diff = diff_module_results(module, old_data, new_data)
        if module_diff["new"] or module_diff["removed"]:
            diff[module] = module_diff

    return diff


def format_diff_summary(target: str, diff: dict[str, dict[str, list]], max_items_per_module: int = 10) -> str:
    """Format a diff result as a human-readable Markdown summary,
    suitable for a notification message or terminal panel.
    """
    if not diff:
        return f"No changes detected for **{target}** since the last scan."

    lines = [f"### 🔔 Changes detected for `{target}`\n"]
    for module, changes in diff.items():
        new_items = changes.get("new", [])
        removed_items = changes.get("removed", [])

        if new_items:
            lines.append(f"**{module}** — {len(new_items)} new:")
            for item in new_items[:max_items_per_module]:
                lines.append(f"- `{_describe_item(item)}`")
            if len(new_items) > max_items_per_module:
                lines.append(f"- ...and {len(new_items) - max_items_per_module} more")

        if removed_items:
            lines.append(f"**{module}** — {len(removed_items)} removed:")
            for item in removed_items[:max_items_per_module]:
                lines.append(f"- ~~`{_describe_item(item)}`~~")

        lines.append("")

    return "\n".join(lines)


def _describe_item(item: dict[str, Any]) -> str:
    """Pick the most informative field(s) to show for one finding."""
    for field in ("url", "domain", "port", "name"):
        if field in item:
            return str(item[field])
    return json.dumps(item, default=str)[:120]
