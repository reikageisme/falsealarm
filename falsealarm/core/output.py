"""
FalseAlarm — Output Manager

Export scan results to multiple formats: JSON, CSV, and TXT.
Also provides Rich table formatting for terminal display.
"""

import json
import csv
from pathlib import Path
from typing import Any
from rich.table import Table


class OutputManager:
    """Manages exporting results to various formats."""

    @staticmethod
    async def export(data: Any, filepath: str, fmt: str) -> None:
        """Export data to the specified format.

        Args:
            data: Data to export (list of dicts or dict).
            filepath: Output file path.
            fmt: Format string: 'json', 'csv', 'table', or 'txt'.
        """
        # Normalize data to list
        if isinstance(data, dict):
            flat = []
            for module_name, module_data in data.items():
                if isinstance(module_data, dict) and "data" in module_data:
                    for item in module_data["data"]:
                        item["_module"] = module_name
                        flat.append(item)
                elif isinstance(module_data, list):
                    for item in module_data:
                        item["_module"] = module_name
                        flat.append(item)
                else:
                    flat.append({"_module": module_name, "result": str(module_data)})
            data = flat

        if not data:
            return

        if fmt == "json":
            await OutputManager.export_json(data, filepath)
        elif fmt == "csv":
            await OutputManager.export_csv(data, filepath)
        elif fmt == "txt":
            await OutputManager.export_txt(data, filepath)
        else:
            # Default to JSON
            await OutputManager.export_json(data, filepath)

    @staticmethod
    async def export_json(data: list[dict[str, Any]], filepath: str) -> None:
        """Export data to JSON file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    @staticmethod
    async def export_csv(data: list[dict[str, Any]], filepath: str) -> None:
        """Export data to CSV file."""
        if not data:
            return

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Collect all keys to serve as columns
        keys: set[str] = set()
        for item in data:
            if isinstance(item, dict):
                keys.update(item.keys())
        columns = sorted(list(keys))

        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for item in data:
                if isinstance(item, dict):
                    writer.writerow({k: str(v) for k, v in item.items()})

    @staticmethod
    async def export_txt(data: list[dict[str, Any]], filepath: str) -> None:
        """Export data to a plain text file."""
        if not data:
            return

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            for item in data:
                if isinstance(item, dict):
                    # Format as Key: Value pairs with a separator between records
                    for k, v in item.items():
                        f.write(f"{k}: {v}\n")
                    f.write("-" * 40 + "\n")

    @staticmethod
    def format_table(
        title: str,
        data: list[dict[str, Any]],
        columns: list[str] | None = None,
    ) -> Table:
        """Format data into a Rich Table for terminal display.

        Args:
            title: Table title.
            data: List of dicts to display.
            columns: Optional column names. Auto-detected if not provided.

        Returns:
            Rich Table object.
        """
        table = Table(title=title, show_header=True, header_style="bold cyan")

        if not data:
            return table

        if not columns:
            keys: set[str] = set()
            for item in data:
                keys.update(item.keys())
            columns = sorted(list(keys))

        for col in columns:
            table.add_column(col)

        for item in data:
            row = [str(item.get(col, "")) for col in columns]
            table.add_row(*row)

        return table
