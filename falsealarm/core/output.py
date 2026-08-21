"""
FalseAlarm — Output Manager

Export scan results to multiple formats: JSON, CSV, TXT, and SARIF.
Also provides Rich table formatting for terminal display.
"""

import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from rich.table import Table


class OutputManager:
    """Manages exporting results to various formats."""

    @staticmethod
    def flatten(data: Any) -> list[dict[str, Any]]:
        """Flatten the {module: {"data": [...]}} scan result into a flat
        list of records, each tagged with its ``_module``."""
        if not isinstance(data, dict):
            return data
        flat: list[dict[str, Any]] = []
        for module_name, module_data in data.items():
            if isinstance(module_data, dict) and "data" in module_data:
                for item in module_data["data"]:
                    flat.append({**item, "_module": module_name})
            elif isinstance(module_data, list):
                for item in module_data:
                    flat.append({**item, "_module": module_name})
            else:
                flat.append({"_module": module_name, "result": str(module_data)})
        return flat

    @staticmethod
    def ndjson_lines(data: Any) -> list[str]:
        """Render scan results as NDJSON lines (one JSON object per record)."""
        return [
            json.dumps(item, ensure_ascii=False, default=str)
            for item in OutputManager.flatten(data)
        ]

    @staticmethod
    async def export(data: Any, filepath: str, fmt: str) -> None:
        """Export data to the specified format.

        Args:
            data: Data to export (list of dicts or dict).
            filepath: Output file path. Use ``"-"`` to write to stdout.
            fmt: 'json', 'jsonl', 'csv', 'table', 'txt', or 'sarif'.
        """
        # Normalize data to a flat list of records.
        data = OutputManager.flatten(data)

        if not data and fmt != "sarif":
            return

        # Stream to stdout when the caller asks for "-" (pipe friendly).
        if filepath == "-":
            if fmt == "jsonl":
                for line in OutputManager.ndjson_lines(data):
                    sys.stdout.write(line + "\n")
            else:
                json.dump(data, sys.stdout, ensure_ascii=False, default=str)
                sys.stdout.write("\n")
            sys.stdout.flush()
            return

        if fmt == "json":
            await OutputManager.export_json(data, filepath)
        elif fmt == "jsonl":
            await OutputManager.export_jsonl(data, filepath)
        elif fmt == "csv":
            await OutputManager.export_csv(data, filepath)
        elif fmt == "txt":
            await OutputManager.export_txt(data, filepath)
        elif fmt == "sarif":
            await OutputManager.export_sarif(data, filepath)
        else:
            # Default to JSON
            await OutputManager.export_json(data, filepath)

    @staticmethod
    async def export_jsonl(data: list[dict[str, Any]], filepath: str) -> None:
        """Export data as NDJSON (one JSON object per line)."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for line in OutputManager.ndjson_lines(data):
                f.write(line + "\n")

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
    async def export_sarif(data: list[dict[str, Any]], filepath: str) -> None:
        """Export findings as SARIF 2.1.0 for GitHub Code Scanning and CI."""
        severity_levels = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for item in data:
            module = str(item.get("_module", "falsealarm"))
            rule_id = str(item.get("vuln_id") or f"{module}-finding")
            name = str(item.get("name") or item.get("title") or rule_id)
            severity = str(item.get("severity", "info")).lower()
            location = str(item.get("url") or item.get("target") or "")
            message = str(item.get("description") or item.get("message") or name)

            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": name.replace(" ", "-")[:128],
                    "shortDescription": {"text": name},
                    "properties": {"tags": ["security", module], "severity": severity},
                },
            )
            result: dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": list(rules).index(rule_id),
                "level": severity_levels.get(severity, "note"),
                "message": {"text": message},
                "properties": {"module": module, "severity": severity},
            }
            if location:
                result["locations"] = [
                    {"physicalLocation": {"artifactLocation": {"uri": location}}}
                ]
            fingerprint_source = f"{rule_id}\0{location}\0{message}".encode("utf-8")
            result["fingerprints"] = {
                "falsealarm/v1": hashlib.sha256(fingerprint_source).hexdigest()
            }
            results.append(result)

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "FalseAlarm",
                            "informationUri": "https://github.com/reikageisme/falsealarm",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        await OutputManager.export_json(sarif, filepath)

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
