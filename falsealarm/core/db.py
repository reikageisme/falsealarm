"""
FalseAlarm — SQLite State Manager

Async SQLite database for persisting scan state, results, and progress.
Enables pause/resume functionality and historical scan queries.
Uses aiosqlite for non-blocking database operations.
"""

import json
import aiosqlite
from falsealarm.core.utils import generate_scan_id, get_timestamp


class Database:
    """Async SQLite database manager for scan persistence.

    Manages three tables:
    - scans: Scan metadata (id, target, status, config, timestamps)
    - results: Module results (scan_id, module, data)
    - scan_progress: Per-module progress tracking for pause/resume

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str = "falsealarm.db"):
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def init(self) -> None:
        """Initialize the database connection and create tables."""
        self._conn = await aiosqlite.connect(self.db_path, timeout=30.0)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._create_tables()

    async def _create_tables(self) -> None:
        """Create database tables if they don't exist."""
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                config_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                module TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS scan_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                module TEXT NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0,
                total INTEGER NOT NULL DEFAULT 0,
                last_item TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                UNIQUE(scan_id, module)
            );

            CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_results_module ON results(module);
            CREATE INDEX IF NOT EXISTS idx_progress_scan_id ON scan_progress(scan_id);
        """)
        await self._conn.commit()

    async def create_scan(self, target: str, config_json: str) -> str:
        """Create a new scan record.

        Args:
            target: The scan target (domain or URL).
            config_json: JSON string of the ScanConfig.

        Returns:
            The generated scan ID.
        """
        scan_id = generate_scan_id()
        now = get_timestamp()
        await self._conn.execute(
            "INSERT INTO scans (id, target, status, config_json, created_at, updated_at) "
            "VALUES (?, ?, 'running', ?, ?, ?)",
            (scan_id, target, config_json, now, now),
        )
        await self._conn.commit()
        return scan_id

    async def update_scan_status(self, scan_id: str, status: str) -> None:
        """Update the status of a scan.

        Args:
            scan_id: The scan identifier.
            status: New status ('running', 'completed', 'paused', 'error').
        """
        now = get_timestamp()
        await self._conn.execute(
            "UPDATE scans SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, scan_id),
        )
        await self._conn.commit()

    async def save_result(self, scan_id: str, module: str, data: dict) -> None:
        """Save a module result to the database.

        Args:
            scan_id: The scan identifier.
            module: Module name (e.g., 'dns', 'subdomain').
            data: Result data dictionary.
        """
        now = get_timestamp()
        data_json = json.dumps(data, ensure_ascii=False, default=str)
        await self._conn.execute(
            "INSERT INTO results (scan_id, module, data_json, created_at) VALUES (?, ?, ?, ?)",
            (scan_id, module, data_json, now),
        )
        await self._conn.commit()

    async def get_results(
        self, scan_id: str, module: str | None = None
    ) -> list[dict]:
        """Retrieve results for a scan.

        Args:
            scan_id: The scan identifier.
            module: Optional module filter.

        Returns:
            List of result dictionaries.
        """
        if module:
            cursor = await self._conn.execute(
                "SELECT * FROM results WHERE scan_id = ? AND module = ? ORDER BY created_at",
                (scan_id, module),
            )
        else:
            cursor = await self._conn.execute(
                "SELECT * FROM results WHERE scan_id = ? ORDER BY created_at",
                (scan_id,),
            )

        rows = await cursor.fetchall()
        results = []
        for row in rows:
            result = dict(row)
            if "data_json" in result:
                try:
                    result["data"] = json.loads(result["data_json"])
                except json.JSONDecodeError:
                    result["data"] = {}
            results.append(result)
        return results

    async def save_progress(
        self,
        scan_id: str,
        module: str,
        completed: int,
        total: int,
        last_item: str,
    ) -> None:
        """Save or update module progress for pause/resume.

        Args:
            scan_id: The scan identifier.
            module: Module name.
            completed: Number of completed items.
            total: Total number of items.
            last_item: Last processed item identifier.
        """
        now = get_timestamp()
        await self._conn.execute(
            """INSERT INTO scan_progress (scan_id, module, completed, total, last_item, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(scan_id, module) DO UPDATE SET
                   completed = excluded.completed,
                   total = excluded.total,
                   last_item = excluded.last_item,
                   updated_at = excluded.updated_at""",
            (scan_id, module, completed, total, last_item, now),
        )
        await self._conn.commit()

    async def get_progress(self, scan_id: str) -> list[dict]:
        """Get progress data for a scan.

        Args:
            scan_id: The scan identifier.

        Returns:
            List of progress dictionaries per module.
        """
        cursor = await self._conn.execute(
            "SELECT * FROM scan_progress WHERE scan_id = ?", (scan_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_scan(self, scan_id: str) -> dict | None:
        """Get a single scan record.

        Args:
            scan_id: The scan identifier.

        Returns:
            Scan dictionary or None if not found.
        """
        cursor = await self._conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        )
        row = await cursor.fetchone()
        if row:
            result = dict(row)
            if "config_json" in result and result["config_json"]:
                try:
                    result["config"] = json.loads(result["config_json"])
                except json.JSONDecodeError:
                    result["config"] = {}
            return result
        return None

    async def list_scans(self) -> list[dict]:
        """List all saved scans, most recent first.

        Returns:
            List of scan dictionaries.
        """
        cursor = await self._conn.execute(
            "SELECT id, target, status, created_at, updated_at "
            "FROM scans ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def delete_scan(self, scan_id: str) -> None:
        """Delete a scan and all associated data.

        Args:
            scan_id: The scan identifier to delete.
        """
        await self._conn.execute(
            "DELETE FROM scan_progress WHERE scan_id = ?", (scan_id,)
        )
        await self._conn.execute(
            "DELETE FROM results WHERE scan_id = ?", (scan_id,)
        )
        await self._conn.execute(
            "DELETE FROM scans WHERE id = ?", (scan_id,)
        )
        await self._conn.commit()

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None
