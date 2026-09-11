import asyncio
import json
import os
import random
import string
import sys
from typing import Any
from urllib.parse import urljoin, urlparse

from falsealarm.core.similarity import calculate_signature, is_similar
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

    @staticmethod
    def _drop_catch_all(results: list[dict], tested: int) -> tuple[list[dict], int]:
        """Post-hoc soft-200 / catch-all guard.

        Some targets (SPAs, WAF/CDN edges, custom 200-for-everything apps)
        answer *every* path with the same page. The up-front baseline probe
        can miss this when that single request is rate-limited or challenged,
        so as a safety net we look at the whole result set: if a large share
        of paths returned HTTP 200 and those 200s cluster tightly by size,
        they are indistinguishable from the catch-all and are dropped as
        false positives. Redirects (301/302), 403s and genuinely rare-sized
        200 outliers are kept.
        """
        from collections import Counter

        twos = [r for r in results if r.get("status") == 200]
        if len(twos) < 15:
            return results, 0

        BUCKET = 256  # bytes; SPA path-echo makes exact lengths vary slightly
        counts = Counter((r.get("length") or 0) // BUCKET for r in twos)
        # A size bucket is a catch-all when it is implausibly crowded (>=20 hits
        # of the same size is never a real directory listing) or when 200s
        # dominate the scan and the bucket is moderately crowded.
        ratio_ok = tested > 0 and (len(twos) / tested) >= 0.20
        common = {b for b, c in counts.items() if c >= 20 or (ratio_ok and c >= 8)}
        if not common:
            return results, 0

        kept, dropped = [], 0
        for r in results:
            if r.get("status") == 200 and ((r.get("length") or 0) // BUCKET) in common:
                dropped += 1
            else:
                kept.append(r)
        return kept, dropped

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

        # Safety net against catch-all / soft-200 targets that slipped past the
        # per-request baseline filter (e.g. the baseline probe was blocked).
        all_results, dropped = self._drop_catch_all(all_results, agg.get("paths_tested", 0))
        if dropped:
            agg["false_positives_dropped"] += dropped
            agg["found"] = max(0, agg.get("found", 0) - dropped)
            self.logger.warning(
                f"Catch-all/soft-200 detected: dropped {dropped} indistinguishable "
                "hits as false positives."
            )

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

        # Baseline calibration to reduce false positives. Probe several highly
        # unlikely paths so we learn the target's catch-all behaviour AND every
        # response size it serves for non-existent paths — SPAs commonly echo
        # the requested path into the page, so the "not found" page has several
        # sizes. Multiple probes also survive a single blocked/rate-limited
        # request that would otherwise disable the filter entirely.
        from collections import Counter as _Counter

        statuses_seen: list[int] = []
        lengths_seen: list[int] = []
        sigs_seen: list[str] = []
        for _ in range(3):
            rnd = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            b_url = target.replace("FUZZ", rnd) if has_fuzz else urljoin(target, f"wildcard_test_{rnd}")
            br = await self.engine.get(b_url, allow_redirects=False)
            st = br.get("status", 0)
            if st and st != 404:
                statuses_seen.append(st)
                lengths_seen.append(br.get("content_length", 0))
                sigs_seen.append(calculate_signature(br.get("body", "")))

        baseline_status = 0
        baseline_lengths: list[int] = []
        baseline_sigs: list[str] = []
        use_baseline = False
        if statuses_seen:
            baseline_status, hits = _Counter(statuses_seen).most_common(1)[0]
            # Only trust it as a catch-all when the same non-404 status recurs.
            use_baseline = hits >= 2
            keep = [i for i, stt in enumerate(statuses_seen) if stt == baseline_status]
            baseline_lengths = sorted({lengths_seen[i] for i in keep})
            baseline_sigs = list({sigs_seen[i] for i in keep})

        self.logger.info(f"Calibrated false-positive baseline from {len(statuses_seen)} probes.")
        if use_baseline:
            self.logger.warning(
                f"Target has a catch-all response ({baseline_status}, sizes {baseline_lengths}). "
                "Engaging Smart Filter."
            )

        def matches_baseline(status: int, length: int, body: str | None = None) -> bool:
            # A hit is a false positive when it is the target's catch-all page.
            # Prefer a structural body signature (robust when the catch-all is
            # served at several sizes, e.g. an SPA echoing the path); fall back
            # to length when no body is available (the Go engine streams only
            # url/status/length).
            if not use_baseline or status != baseline_status:
                return False
            if body is not None and baseline_sigs:
                sig = calculate_signature(body)
                if any(is_similar(sig, bs, 0.75) for bs in baseline_sigs):
                    return True
            return any(
                is_baseline_match(status, length, baseline_status, bl, max(50, int(bl * 0.05)))
                for bl in baseline_lengths
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

                        # False Positive Smart Filter (body-signature aware)
                        if matches_baseline(status, length, response.get("body", "")):
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
