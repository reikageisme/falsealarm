"""
FalseAlarm — Rich-based Logger

Provides colored, formatted console output using the Rich library.
Handles Windows encoding issues by forcing UTF-8 output.
"""

import os
import sys
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from falsealarm.core.config import ScanConfig


def _make_console(silent: bool = False, stderr: bool = False) -> Console:
    """Create a Rich Console with proper encoding for Windows.

    When ``stderr`` is True the console writes to stderr, keeping stdout
    clean for machine-readable output (pipe mode / NDJSON chaining).
    """
    # Force UTF-8 output on Windows to avoid cp1252 encoding errors
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    # Only force ANSI when asked to (FORCE_COLOR) — otherwise let Rich detect
    # a real terminal so redirected output and CI logs stay plain text.
    # NO_COLOR is honoured by Rich automatically.
    force = True if os.environ.get("FORCE_COLOR") else None
    return Console(quiet=silent, force_terminal=force, stderr=stderr)


class FalseAlarmLogger:
    """Rich-based logger for FalseAlarm.

    Provides formatted, colored output for scan operations including
    banners, status messages, tables, and progress bars.

    Args:
        silent: If True, suppress all output except results.
        verbose: If True, show debug messages.
    """

    @classmethod
    def buffered(cls, verbose: bool = False) -> "FalseAlarmLogger":
        """A logger that records output to a string instead of a live terminal.

        Used for parallel multi-target scans so each target's output can be
        flushed to the real console atomically (no interleaving, no dashboard).
        """
        from rich.console import Console

        obj = cls(silent=False, verbose=verbose, live=False)
        obj.console = Console(record=True, width=100, file=open(os.devnull, "w"))
        obj.interactive = False
        return obj

    def export_text(self) -> str:
        try:
            return self.console.export_text(styles=True)
        except Exception:
            return ""

    def __init__(self, silent: bool = False, verbose: bool = False, stderr: bool = False, live: bool = True):
        self.silent = silent
        self.verbose = verbose
        self.console = _make_console(silent, stderr=stderr)
        self.interactive = live and self.console.is_terminal and not silent and not stderr
        self.pipe_mode = stderr  # logs on stderr, machine output on stdout
        self.dashboard: Any = None  # ScanDashboard while a scan is running (TTY only)

    # ------------------------------------------------------------------ #
    # Live dashboard hooks (no-ops when not attached / not a TTY)
    # ------------------------------------------------------------------ #
    def start_dashboard(self, stats_source=None) -> None:
        if not self.interactive or self.dashboard is not None:
            return
        from falsealarm.core.ui import ScanDashboard

        self.dashboard = ScanDashboard(self.console, stats_source)
        self.dashboard.start()

    def stop_dashboard(self) -> None:
        if self.dashboard is not None:
            self.dashboard.stop()
            self.dashboard = None

    def stage(self, name: str, target: str = "") -> None:
        if self.dashboard is not None:
            self.dashboard.set_stage(name, target)

    def task(self, label: str, total: int) -> None:
        """Declare the size of the current unit of work (templates, words …)."""
        if self.dashboard is not None:
            self.dashboard.set_task(label, total)

    def advance(self, n: int = 1) -> None:
        if self.dashboard is not None:
            self.dashboard.advance(n)

    def finding_hook(self, result) -> None:
        """Stream an injection result (sqli/ssti/nosqli) object as a finding."""
        try:
            from falsealarm.core.findings import finding_from_injection

            item = result.to_dict() if hasattr(result, "to_dict") else dict(result)
            self.finding(finding_from_injection(item))
        except Exception:
            pass

    def finding(self, finding) -> None:
        """Print a confirmed finding as one coloured, copy-friendly line."""
        if self.dashboard is not None:
            self.dashboard.add_finding(finding.severity)
        if self.silent:
            return
        from falsealarm.core.ui import finding_line

        self.console.print(finding_line(finding), soft_wrap=True)

    def _timestamp(self) -> str:
        """Return formatted timestamp."""
        return datetime.now().strftime("%H:%M:%S")

    def banner(self) -> None:
        """Print the ASCII art banner."""
        if self.silent:
            return
        from falsealarm import print_banner
        print_banner(console=self.console)

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
