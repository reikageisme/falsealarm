"""
FalseAlarm — Output Manager

Export scan results to multiple formats: JSON, CSV, and HTML.
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
            fmt: Format string: 'json', 'csv', 'html', or 'txt'.
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
        elif fmt == "html":
            await OutputManager.export_html(data, filepath)
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
    async def export_html(data: list[dict[str, Any]], filepath: str) -> None:
        """Generate a styled HTML report with dark theme."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Build table HTML
        if not data:
            table_html = "<p>No data to display.</p>"
        else:
            keys: set[str] = set()
            for item in data:
                if isinstance(item, dict):
                    keys.update(item.keys())
            columns = sorted(list(keys))

            header_cells = "".join(f"<th>{col}</th>" for col in columns)
            rows_html = ""
            for item in data:
                cells = "".join(
                    f"<td>{item.get(col, '')}</td>" for col in columns
                )
                rows_html += f"<tr>{cells}</tr>\n"

            table_html = f"""<table>
<thead><tr>{header_cells}</tr></thead>
<tbody>{rows_html}</tbody>
</table>"""

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FalseAlarm Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 40px 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            text-align: center;
            font-size: 2rem;
            background: linear-gradient(90deg, #00d2ff, #7b2ff7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        .subtitle {{
            text-align: center;
            color: #888;
            margin-bottom: 30px;
            font-size: 0.9rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: rgba(30, 30, 50, 0.8);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }}
        th {{
            background: rgba(123, 47, 247, 0.3);
            padding: 14px 16px;
            text-align: left;
            font-weight: 600;
            color: #00d2ff;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 0.9rem;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        tr:hover {{ background: rgba(123, 47, 247, 0.1); }}
        tr:last-child td {{ border-bottom: none; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>FalseAlarm Scan Report</h1>
        <p class="subtitle">Generated by FalseAlarm Web Reconnaissance Engine</p>
        {table_html}
    </div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)

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
