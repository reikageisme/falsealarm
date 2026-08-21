from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from falsealarm.modules.base import BaseModule, ModuleResult

# Canary the target should never legitimately redirect to.
CANARY_HOST = "falsealarm-oob.example.net"
CANARY = f"https://{CANARY_HOST}/"

# Common parameter names abused for open redirects.
REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return",
    "returnUrl", "return_url", "dest", "destination", "continue", "r", "u",
    "target", "rurl", "goto", "out", "view", "to", "callback",
]


class OpenRedirectModule(BaseModule):
    name = "openredirect"
    description = "Open-redirect probing on common redirect parameters"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"params_tested": 0, "vulnerable": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        parsed = urlparse(target)
        existing = dict(parse_qsl(parsed.query))

        # Build candidate URLs: if the target already carries params, fuzz those
        # too; always test the common redirect parameter names on the path.
        candidate_params = list(dict.fromkeys(list(existing.keys()) + REDIRECT_PARAMS))

        async def test_param(param: str) -> None:
            query = dict(existing)
            query[param] = CANARY
            test_url = urlunparse(parsed._replace(query=urlencode(query)))
            stats["params_tested"] += 1
            try:
                resp = await self.engine.get(test_url, allow_redirects=False)
            except Exception as e:
                self.logger.debug(f"Open-redirect probe failed for {param}: {e}")
                return
            if resp.get("error"):
                return

            status = resp.get("status", 0)
            location = ""
            for k, v in resp.get("headers", {}).items():
                if k.lower() == "location":
                    location = v
                    break

            # Vulnerable if a 3xx sends us to the attacker-controlled host.
            if status in (301, 302, 303, 307, 308) and location:
                loc_host = urlparse(location).hostname or ""
                if loc_host == CANARY_HOST or location.startswith(CANARY):
                    results.append({
                        "type": "open_redirect",
                        "url": test_url,
                        "parameter": param,
                        "status": status,
                        "location": location,
                    })
                    stats["vulnerable"] += 1
                    self.logger.success(f"Open redirect via '{param}' at {test_url} -> {location}")

        for param in candidate_params:
            await test_param(param)

        return self._make_result(target, results, stats)
