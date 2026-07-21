"""
FalseAlarm — Rich-based Logger

Provides colored, formatted console output using the Rich library.
Handles Windows encoding issues by forcing UTF-8 output.
"""

import io
import sys
from datetime import datetime
from typing import Any
from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)
from falsealarm.core.config import ScanConfig


def _make_console(silent: bool = False) -> Console:
    """Create a Rich Console with proper encoding for Windows."""
    # Force UTF-8 output on Windows to avoid cp1252 encoding errors
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    return Console(quiet=silent, force_terminal=True)


class FalseAlarmLogger:
    """Rich-based logger for FalseAlarm.

    Provides formatted, colored output for scan operations including
    banners, status messages, tables, and progress bars.

    Args:
        silent: If True, suppress all output except results.
        verbose: If True, show debug messages.
    """

    def __init__(self, silent: bool = False, verbose: bool = False):
        self.silent = silent
        self.verbose = verbose
        self.console = _make_console(silent)

    def _timestamp(self) -> str:
        """Return formatted timestamp."""
        return datetime.now().strftime("%H:%M:%S")

    def banner(self) -> None:
        """Print the ASCII art banner with gradient colors."""
        if self.silent:
            return
        from falsealarm import BANNER
        lines = BANNER.strip().split("\n")
        colors = [
            "cyan", "bright_cyan", "blue", "bright_blue",
            "magenta", "bright_magenta", "cyan", "bright_cyan",
        ]
        for i, line in enumerate(lines):
            color = colors[i % len(colors)]
            self.console.print(f"[{color}]{line}[/{color}]")

    def info(self, msg: str) -> None:
        """Print info message."""
        if not self.silent:
            self.console.print(
                f"[dim]\\[{self._timestamp()}][/dim] [blue][*][/blue] {msg}"
            )

    def success(self, msg: str) -> None:
        """Print success message."""
        if not self.silent:
            self.console.print(
                f"[dim]\\[{self._timestamp()}][/dim] [green][+][/green] {msg}"
            )

    def warning(self, msg: str) -> None:
        """Print warning message."""
        if not self.silent:
            self.console.print(
                f"[dim]\\[{self._timestamp()}][/dim] [yellow][!][/yellow] {msg}"
            )

    def error(self, msg: str) -> None:
        """Print error message."""
        if not self.silent:
            self.console.print(
                f"[dim]\\[{self._timestamp()}][/dim] [red][-][/red] {msg}"
            )

    def debug(self, msg: str) -> None:
        """Print debug message if verbose is True."""
        if self.verbose and not self.silent:
            self.console.print(
                f"[dim]\\[{self._timestamp()}][/dim] [magenta][D][/magenta] [dim]{msg}[/dim]"
            )

    def module_header(self, name: str) -> None:
        """Print a module header separator."""
        if not self.silent:
            separator = "-" * max(1, 50 - len(name))
            self.console.print(
                f"\n[bold cyan]>> {name.upper()} [/bold cyan]"
                f"[cyan]{separator}[/cyan]"
            )

    def scan_config(self, config: ScanConfig) -> None:
        """Print scan configuration as a formatted list."""
        if self.silent:
            return

        self.console.print("\n[bold cyan]Scan Configuration[/bold cyan]")
        for key, value in config.to_dict().items():
            if value is not None and value != [] and value != "":
                self.console.print(
                    f"  [dim]>[/dim] {key}: [bold]{value}[/bold]"
                )
        self.console.print()

    def table(
        self, title: str, columns: list[str], rows: list[list[Any]]
    ) -> None:
        """Print a Rich formatted table.

        Args:
            title: Table title.
            columns: Column header names.
            rows: List of row data (each row is a list of values).
        """
        if self.silent:
            return
        table = Table(
            title=title, show_header=True, header_style="bold cyan"
        )
        for col in columns:
            table.add_column(col)
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        self.console.print(table)
        self.console.print()

    def get_progress(self) -> Progress:
        """Return a configured Rich progress bar."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=self.console,
            disable=self.silent,
        )
