import json
from typing import Any
from urllib.parse import urljoin

from falsealarm.modules.base import BaseModule, ModuleResult

# Minimal introspection query — enough to prove introspection is enabled
# without pulling the entire schema.
INTROSPECTION_QUERY = {
    "query": "{__schema{queryType{name} types{name}}}"
}

COMMON_PATHS = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/graphiql",
    "/api",
]


class GraphQLModule(BaseModule):
    name = "graphql"
    description = "GraphQL endpoint discovery & introspection exposure check"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"endpoints_found": 0, "introspection_enabled": 0}

        if not target.startswith("http"):
            target = f"https://{target}"

        for path in COMMON_PATHS:
            url = urljoin(target, path)
            try:
                resp = await self.engine.request(
                    method="POST",
                    url=url,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(INTROSPECTION_QUERY),
                    allow_redirects=False,
                )
            except Exception as e:
                self.logger.debug(f"GraphQL probe failed for {url}: {e}")
                continue

            if resp.get("error"):
                continue

            body = resp.get("body", "") or ""
            status = resp.get("status", 0)

            # A GraphQL endpoint typically answers the introspection query with
            # a JSON body containing __schema / queryType, or a GraphQL error.
            looks_graphql = ('"__schema"' in body or '"queryType"' in body
                             or '"errors"' in body and "graphql" in body.lower())
            introspection = '"__schema"' in body or '"queryType"' in body

            if looks_graphql and status in (200, 400):
                item = {
                    "type": "graphql_endpoint",
                    "url": url,
                    "status": status,
                    "introspection": introspection,
                }
                results.append(item)
                stats["endpoints_found"] += 1
                if introspection:
                    stats["introspection_enabled"] += 1
                    self.logger.success(f"GraphQL introspection ENABLED at {url}")
                else:
                    self.logger.info(f"GraphQL endpoint at {url} (introspection off)")

        return self._make_result(target, results, stats)
