import asyncio
import os
import sys
import json
import random
import string
from typing import Any
from urllib.parse import urlparse, urljoin
from falsealarm.modules.base import BaseModule, ModuleResult
from falsealarm.core.utils import get_data_path


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

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
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
            return self._make_result(target, results, stats)

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
            self.logger.info(f"🚀 Engaging Go-based High Speed Fuzzing Engine...")
            target_fuzz = target if has_fuzz else urljoin(target, "FUZZ")
            
            cmd = [
                go_engine_path,
                "-u", target_fuzz,
                "-w", wordlist_path,
                "-t", str(self.config.threads),
                "-timeout", str(self.config.timeout)
            ]
            
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
                    return self._make_result(target, results, stats)
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

        return self._make_result(target, results, stats)
