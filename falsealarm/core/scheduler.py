"""
FalseAlarm — Scan Scheduler

Orchestrates the execution of scan modules. Manages module registration,
sequential/parallel execution, result aggregation, and pause/resume
via the SQLite database.
"""

from __future__ import annotations

import json
import time
import os
from typing import TYPE_CHECKING
from rich.panel import Panel
from rich.markdown import Markdown

if TYPE_CHECKING:
    from falsealarm.core.engine import AsyncEngine
    from falsealarm.core.db import Database
    from falsealarm.core.logger import FalseAlarmLogger
    from falsealarm.core.config import ScanConfig


class ScanScheduler:
    """Orchestrate module execution and manage scan lifecycle.

    The scheduler is responsible for:
    - Registering available scan modules
    - Running modules in sequence or selectively
    - Saving results to the database
    - Supporting pause/resume via scan IDs
    - Aggregating results from all modules

    Args:
        config: ScanConfig with target and module selection.
        engine: AsyncEngine for HTTP operations.
        db: Database for state persistence.
        logger: Logger for output.
    """

    # Quick scan modules (fast, no heavy I/O)
    QUICK_MODULES = {"dns", "headers", "ssl"}

    def __init__(
        self,
        config: "ScanConfig",
        engine: "AsyncEngine",
        db: "Database",
        logger: "FalseAlarmLogger",
    ):
        self.config = config
        self.engine = engine
        self.db = db
        self.logger = logger
        self._modules: dict[str, type] = {}
        self._scan_id: str | None = None

    def register_module(self, module_class) -> None:
        """Register a module class for use in scans.

        Args:
            module_class: A subclass of BaseModule with a 'name' attribute.
        """
        self._modules[module_class.name] = module_class

    def get_available_modules(self) -> list[str]:
        """Return list of registered module names."""
        return list(self._modules.keys())

    def _resolve_modules(self) -> list[str]:
        """Determine which modules to run based on config.

        Returns:
            List of module names to execute.
        """
        if "all" in self.config.modules:
            return list(self._modules.keys())
        elif "quick" in self.config.modules:
            return [m for m in self._modules if m in self.QUICK_MODULES]
        elif self.config.modules:
            # Filter to only registered modules
            valid = []
            for mod_name in self.config.modules:
                if mod_name in self._modules:
                    valid.append(mod_name)
                else:
                    self.logger.warning(
                        f"Unknown module '{mod_name}'. "
                        f"Available: {', '.join(self._modules.keys())}"
                    )
            return valid
        else:
            # Default: run all modules
            return list(self._modules.keys())

    async def run(self) -> dict:
        """Run all selected modules and return combined results.

        Executes modules sequentially, saving each result to the
        database. Returns a dict mapping module names to their results.

        Returns:
            Dict of {module_name: result_data}
        """
        modules_to_run = self._resolve_modules()

        if not modules_to_run:
            self.logger.warning("No modules to run.")
            return {}

        # Start engine
        await self.engine.start()

        # Create scan record
        config_json = json.dumps(self.config.to_dict(), default=str)
        self._scan_id = await self.db.create_scan(
            self.config.target, config_json
        )

        self.logger.info(
            f"Starting scan: [bold]{self.config.target}[/bold]"
        )
        self.logger.info(
            f"├── Modules: [cyan]{', '.join(modules_to_run)}[/cyan]"
        )
        self.logger.info(
            f"├── Rate: {self.config.rate} req/s | "
            f"Threads: {self.config.threads} | "
            f"Timeout: {self.config.timeout}s"
        )
        self.logger.info(
            f"└── Scan ID: [bold]{self._scan_id}[/bold]"
        )

        all_results = {}
        total_start = time.time()

        for module_name in modules_to_run:
            try:
                result = await self.run_module(module_name)
                if result:
                    all_results[module_name] = result.to_dict()
            except KeyboardInterrupt:
                self.logger.warning("Scan interrupted by user.")
                await self.db.update_scan_status(self._scan_id, "interrupted")
                break
            except Exception as e:
                self.logger.error(
                    f"Module '{module_name}' failed: {e}"
                )
                all_results[module_name] = {"error": str(e)}

        total_duration = round(time.time() - total_start, 2)

        # Update scan status
        await self.db.update_scan_status(self._scan_id, "completed")

        self.logger.success(
            f"Scan complete in {total_duration}s | "
            f"Scan ID: [bold]{self._scan_id}[/bold]"
        )

        if self.config.ai_triage:
            self.logger.module_header("AI Triage Analysis")
            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                self.logger.error("GEMINI_API_KEY environment variable not set. Cannot run AI Triage.")
            else:
                self.logger.info("Initializing AI Provider (Gemini)...")
                try:
                    from falsealarm.core.ai.gemini_provider import GeminiProvider
                    ai = GeminiProvider(api_key=api_key)
                    self.logger.info("Sending scan results to AI for analysis. This may take a few seconds...")
                    
                    prompt = (
                        "You are a professional Penetration Tester and Bug Bounty Hunter. "
                        "I have provided you with a JSON dump of my reconnaissance and vulnerability scan results. "
                        "Please analyze this data and provide a concise, highly actionable report in Markdown format. "
                        "Focus on:\n"
                        "1. The most critical vulnerabilities or exposed endpoints found.\n"
                        "2. Potential attack vectors based on the technology stack or discovered paths.\n"
                        "3. Recommendations for further manual testing.\n"
                        "Do not just list the data back to me. Provide hacker-oriented insights."
                    )
                    
                    analysis = await ai.analyze(data=all_results, prompt=prompt)
                    
                    if not self.logger.silent:
                        self.logger.console.print("\n")
                        self.logger.console.print(Panel(
                            Markdown(analysis),
                            title="[bold magenta]🧠 AI Vulnerability Assessment[/bold magenta]",
                            border_style="magenta",
                            padding=(1, 2)
                        ))
                except Exception as e:
                    self.logger.error(f"AI Triage failed: {e}")

        return all_results

    async def run_module(self, module_name: str):
        """Run a single module by name.

        Args:
            module_name: Name of the registered module to run.

        Returns:
            ModuleResult from the module's run() method, or None on error.
        """
        if module_name not in self._modules:
            self.logger.error(
                f"Module '{module_name}' not found. "
                f"Available: {', '.join(self._modules.keys())}"
            )
            return None

        module_class = self._modules[module_name]
        module = module_class(
            engine=self.engine,
            db=self.db,
            config=self.config,
            logger=self.logger,
        )

        try:
            result = await module.run(self.config.target)

            # Save result to database
            if self._scan_id and result:
                await self.db.save_result(
                    self._scan_id,
                    module_name,
                    result.to_dict(),
                )

            return result

        except Exception as e:
            self.logger.error(f"Error in module '{module_name}': {e}")
            raise

    async def pause(self) -> str:
        """Pause the current scan and save state.

        Returns:
            The scan ID that can be used to resume.
        """
        if self._scan_id:
            await self.db.update_scan_status(self._scan_id, "paused")
            self.logger.info(
                f"Scan paused. Resume with: falsealarm --resume {self._scan_id}"
            )
            return self._scan_id
        return ""

    async def resume(self, scan_id: str) -> dict:
        """Resume a previously paused scan.

        Args:
            scan_id: The ID of the scan to resume.

        Returns:
            Combined results dict including previously saved results.
        """
        scan = await self.db.get_scan(scan_id)
        if not scan:
            self.logger.error(f"Scan '{scan_id}' not found.")
            return {}

        if scan["status"] not in ("paused", "interrupted"):
            self.logger.warning(
                f"Scan '{scan_id}' has status '{scan['status']}', "
                "cannot resume."
            )
            return {}

        self._scan_id = scan_id
        await self.db.update_scan_status(scan_id, "running")

        # Get already completed modules
        progress = await self.db.get_progress(scan_id)
        completed_modules = {p["module"] for p in progress}

        # Run remaining modules
        modules_to_run = self._resolve_modules()
        remaining = [m for m in modules_to_run if m not in completed_modules]

        self.logger.info(
            f"Resuming scan {scan_id} — "
            f"{len(completed_modules)} done, {len(remaining)} remaining"
        )

        all_results = {}

        # Load existing results
        existing = await self.db.get_results(scan_id)
        for r in existing:
            if "data" in r:
                all_results[r["module"]] = r["data"]

        # Run remaining
        for module_name in remaining:
            try:
                result = await self.run_module(module_name)
                if result:
                    all_results[module_name] = result.to_dict()
            except Exception as e:
                self.logger.error(f"Module '{module_name}' failed: {e}")

        await self.db.update_scan_status(scan_id, "completed")
        return all_results
