import base64
import hashlib
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from falsealarm.modules.base import BaseModule, ModuleResult


def mmh3_hash(favicon_bytes: bytes) -> int | None:
    """Compute the Shodan-style favicon hash (mmh3 of base64 payload).

    Returns None when the optional ``mmh3`` package is not installed, so the
    module degrades gracefully instead of failing the whole scan.
    """
    try:
        import mmh3  # optional dependency
    except ImportError:
        return None
    b64 = base64.encodebytes(favicon_bytes)
    return mmh3.hash(b64)


class FaviconModule(BaseModule):
    name = "favicon"
    description = "Favicon hashing (Shodan mmh3 + sha256) for asset pivoting"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"favicons_found": 0, "mmh3_available": False}

        if not target.startswith("http"):
            target = f"https://{target}"

        favicon_url = urljoin(target, "/favicon.ico")

        # Prefer the <link rel="icon"> declared in the HTML, if present.
        try:
            page = await self.engine.get(target)
            if not page.get("error"):
                soup = BeautifulSoup(page.get("body", ""), "html.parser")
                link = soup.find("link", rel=lambda v: v and "icon" in v.lower())
                if link and link.get("href"):
                    favicon_url = urljoin(target, link["href"])
        except Exception as e:
            self.logger.debug(f"Favicon link discovery failed: {e}")

        try:
            resp = await self.engine.get(favicon_url)
            if resp.get("error") or resp.get("status") != 200:
                self.logger.debug(f"No favicon at {favicon_url} (status {resp.get('status')})")
                return self._make_result(target, results, stats)

            raw = resp.get("body", "")
            favicon_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw

            mmh3_value = mmh3_hash(favicon_bytes)
            sha256 = hashlib.sha256(favicon_bytes).hexdigest()
            stats["mmh3_available"] = mmh3_value is not None

            item = {
                "type": "favicon",
                "url": favicon_url,
                "sha256": sha256,
            }
            if mmh3_value is not None:
                item["mmh3"] = mmh3_value
                item["shodan_dork"] = f"http.favicon.hash:{mmh3_value}"
            else:
                item["note"] = "Install 'mmh3' for Shodan-compatible favicon hashing."

            results.append(item)
            stats["favicons_found"] = 1
            host = urlparse(target).hostname or target
            self.logger.success(f"Favicon hashed for {host}: {item.get('shodan_dork', sha256[:16])}")
        except Exception as e:
            self.logger.debug(f"Favicon hashing failed: {e}")

        return self._make_result(target, results, stats)
