import asyncio
import json
import os
import random
import string
import sys
from typing import Any
from urllib.parse import urljoin, urlparse

from falsealarm.core.utils import get_data_path
from falsealarm.modules.base import BaseModule, ModuleResult


def is_baseline_match(
    status: int,
    length: int,
    baseline_status: int,
    baseline_length: int,
    tolerance: int,
) -> bool:
    """Return whether a fuzz response is indistinguishable from the catch-all."""
    return (
        baseline_status not in (0, 404)
        and status == baseline_status
        and abs(length - baseline_length) <= tolerance
    )

class DirFuzzModule(BaseModule):
    name = "dirfuzz"
    description = "Advanced Parameter & Directory Fuzzing"

    def _select_user_agent(self) -> str:
        """Pick the User-Agent the Go engine should send.

        Reuses the running engine's fingerprint when available so the Go
        worker blends in exactly like the Python requests instead of
        advertising a hard-coded 'FalseAlarm-Go-Engine' banner.
        """
        fp = getattr(self.engine, "_fingerprint", None)
        if fp is not None:
            try:
                return fp.get_user_agent()
            except Exception:
                pass
        try:
            from falsealarm.core.fingerprint import RequestFingerprint
            return RequestFingerprint(
                random_agent=getattr(self.config, "random_agent", False)
            ).get_user_agent()
        except Exception:
            return ""

    @staticmethod
    def _is_dir_candidate(item: dict) -> bool:
        """Whether a hit looks like a directory worth recursing into."""
        if item.get("type") != "directory":
            return False
        payload = str(item.get("payload", ""))
        if not payload or "." in payload:  # skip files (foo.js) and empties
            return False
        return item.get("status") in (200, 301, 302, 307, 308, 403)

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        from collections import deque

        base = target if target.startswith("http") else f"http://{target}"
        has_fuzz = "FUZZ" in base
        depth = max(0, int(getattr(self.config, "recursion_depth", 0) or 0))

        all_results: list[dict[str, Any]] = []
        agg = {"paths_tested": 0, "found": 0, "forbidden": 0,
               "false_positives_dropped": 0, "directories_recursed": 0}

        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(base, 0)])
        MAX_DIRS = 60  # safety cap so recursion can't explode

        while queue:
            current, d = queue.popleft()
            norm = current.rstrip("/")
            if norm in visited:
                continue
            visited.add(norm)

            results, stats = await self._fuzz_once(current)
            all_results.extend(results)
            for key in ("paths_tested", "found", "forbidden", "false_positives_dropped"):
                agg[key] += stats.get(key, 0)

            # Recurse into discovered directories (directory mode only).
            if not has_fuzz and depth > 0 and d < depth and len(visited) < MAX_DIRS:
                parent = current if current.endswith("/") else current + "/"
                for item in results:
                    if self._is_dir_candidate(item):
                        child = urljoin(parent, str(item["payload"]) + "/")
                        if child.rstrip("/") not in visited:
                            agg["directories_recursed"] += 1
                            queue.append((child, d + 1))

        return self._make_result(base, all_results, agg)

    async def _fuzz_once(self, target: str):
        """Run one fuzzing pass against a single base URL.

        Returns ``(results, stats)`` so the recursive ``run`` can aggregate
        across multiple directory levels.
        """
        results: list[dict[str, Any]] = []
        stats = {"paths_tested": 0, "found": 0, "forbidden": 0, "false_positives_dropped": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        has_fuzz = "FUZZ" in target

        # Ensure trailing slash if it's a directory brute-force
        if not has_fuzz and not target.endswith("/"):
            target += "/"

        # Load wordlist
        wordlist_path = self.config.wordlist or get_data_path("wordlists/common_dirs.txt")
        paths_to_test = []
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                paths_to_test = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            self.logger.error(f"Failed to load wordlist from {wordlist_path}: {e}")
            return results, stats

        # Baseline checking to reduce False Positives
        # We send a request to a highly unlikely path/param to see the server's default behavior
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        baseline_url = target.replace("FUZZ", random_str) if has_fuzz else urljoin(target, f"wildcard_test_{random_str}")

        self.logger.info(f"Generating false-positive baseline with payload: {random_str}")
        baseline_resp = await self.engine.get(baseline_url, allow_redirects=False)
        baseline_status = baseline_resp.get("status", 0)
        baseline_length = baseline_resp.get("content_length", 0)
        use_baseline = baseline_status not in (0, 404)
        baseline_tolerance = max(50, int(baseline_length * 0.03))
        if use_baseline:
            self.logger.warning(
                f"Target has a catch-all response ({baseline_status}, {baseline_length} bytes). "
                "Engaging Smart Filter."
            )

        def matches_baseline(status: int, length: int) -> bool:
            return is_baseline_match(
                status,
                length,
                baseline_status,
                baseline_length,
                baseline_tolerance,
            )

        # Check if Go engine exists
        if sys.platform == "win32":
            binary_name = "dirfuzz-engine.exe"
        else:
            binary_name = "dirfuzz-engine"

        go_engine_path = os.path.join(os.path.dirname(__file__), "..", "..", "engine-go", binary_name)

        if os.path.exists(go_engine_path):
            self.logger.info("🚀 Engaging Go-based High Speed Fuzzing Engine...")
            target_fuzz = target if has_fuzz else urljoin(target, "FUZZ")

            cmd = [
                go_engine_path,
                "-u", target_fuzz,
                "-w", wordlist_path,
                "-t", str(self.config.threads),
                "-timeout", str(self.config.timeout),
            ]

            # Propagate OPSEC settings so the Go engine matches the Python
            # orchestrator: same proxy, same rate ceiling, same User-Agent.
            if self.config.proxy:
                cmd += ["-proxy", self.config.proxy]
            if self.config.rate and self.config.rate > 0:
                cmd += ["-rate", str(self.config.rate)]
            ua = self._select_user_agent()
            if ua:
                cmd += ["-ua", ua]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                # Stream NDJSON line-by-line from Go subprocess stdout
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    line_str = line.decode('utf-8').strip()
                    if not line_str:
                        continue
                    try:
                        r = json.loads(line_str)
                        if "error" in r:
                            self.logger.error(f"Go engine error: {r['error']}")
                            continue

                        url = r.get("url")
                        status = int(r.get("status") or 0)
                        length = int(r.get("length") or 0)

                        if matches_baseline(status, length):
                            stats["false_positives_dropped"] += 1
                            continue

                        if url:
                            item = {
                                "type": "fuzz" if has_fuzz else "directory",
                                "payload": urlparse(url).path.rstrip("/").split("/")[-1],
                                "url": url,
                                "status": status,
                                "length": length
                            }
                            results.append(item)

                            if status == 403:
                                stats["forbidden"] += 1
                                self.logger.warning(f"Forbidden: {url} [403]")
                            else:
                                stats["found"] += 1
                                self.logger.success(f"Found: {url} [Status: {status}, Size: {length}]")
                    except json.JSONDecodeError:
                        pass

                await process.wait()
                if process.returncode == 0:
                    stats["paths_tested"] = len(paths_to_test)
                    return results, stats
                else:
                    stderr = await process.stderr.read()
                    self.logger.error(f"Go engine failed: {stderr.decode()}")
            except OSError as e:
                self.logger.warning(f"Could not execute Go binary (OS Policy/AV blocking?): {e}")

            self.logger.warning("Falling back to Python Async Engine...")
        else:
            self.logger.warning("Go binary not found. Running in Python Async Engine fallback mode...")

        mode_str = "Parameter Fuzzing" if has_fuzz else "Directory Fuzzing"
        self.logger.info(f"Starting {mode_str} with {len(paths_to_test)} payloads on {target}...")

        # Concurrency limit based on config threads
        sem = asyncio.Semaphore(self.config.threads)

        async def test_path(payload: str):
            test_url = target.replace("FUZZ", payload) if has_fuzz else urljoin(target, payload)
            async with sem:
                stats["paths_tested"] += 1
                try:
                    response = await self.engine.get(test_url, allow_redirects=False)
                    if not response.get("error"):
                        status = response.get("status", 0)
                        length = response.get("content_length", 0)

                        # False Positive Smart Filter
                        if matches_baseline(status, length):
                            stats["false_positives_dropped"] += 1
                            return None

                        if status != 404 and status != 0:
                            item = {
                                "type": "fuzz" if has_fuzz else "directory",
                                "payload": payload,
                                "url": test_url,
                                "status": status,
                                "length": length
                            }

                            if status in (301, 302, 307, 308):
                                item["redirect"] = response.get("headers", {}).get("Location", "")

                            if status == 403:
                                stats["forbidden"] += 1
                                self.logger.warning(f"Forbidden: {test_url} [403]")
                            else:
                                stats["found"] += 1
                                self.logger.success(f"Found: {test_url} [Status: {status}, Size: {length}]")

                            return item
                except Exception:
                    pass
            return None

        # Execute tests concurrently
        tasks = [test_path(p) for p in paths_to_test]
        responses = await asyncio.gather(*tasks)

        for r in responses:
            if r:
                results.append(r)

        return results, stats
