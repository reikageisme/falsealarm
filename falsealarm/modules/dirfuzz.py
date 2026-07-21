import asyncio
from typing import Any
from urllib.parse import urlparse, urljoin
from falsealarm.modules.base import BaseModule, ModuleResult
from falsealarm.core.utils import get_data_path

class DirFuzzModule(BaseModule):
    name = "dirfuzz"
    description = "Directory and Path Bruteforcing (Fuzzing)"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"paths_tested": 0, "found": 0, "forbidden": 0}

        if not target.startswith("http"):
            target = f"http://{target}"
            
        # Ensure trailing slash
        if not target.endswith("/"):
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

        self.logger.info(f"Fuzzing {len(paths_to_test)} paths on {target}...")

        # Concurrency limit based on config threads
        sem = asyncio.Semaphore(self.config.threads)

        async def test_path(path_suffix: str):
            test_url = urljoin(target, path_suffix)
            async with sem:
                stats["paths_tested"] += 1
                try:
                    # Using head request first for speed, fallback to get if needed
                    # However, some servers block HEAD. For a robust dirbuster, GET is safer.
                    # We will use GET with allow_redirects=False to catch 301/302 properly.
                    response = await self.engine.get(test_url, allow_redirects=False)
                    if not response.get("error"):
                        status = response.get("status", 0)
                        
                        # Logic to determine if a path is "found"
                        # We ignore 404. We capture 200 (OK), 403 (Forbidden), 301/302 (Redirects)
                        if status != 404 and status != 0:
                            item = {
                                "type": "directory",
                                "url": test_url,
                                "status": status,
                                "length": response.get("content_length", 0)
                            }
                            
                            if status in (301, 302, 307, 308):
                                item["redirect"] = response.get("headers", {}).get("Location", "")
                            
                            if status == 403:
                                stats["forbidden"] += 1
                            else:
                                stats["found"] += 1
                                
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
