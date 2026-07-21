import asyncio
from typing import Any
from urllib.parse import urlparse
from falsealarm.modules.base import BaseModule, ModuleResult

class PortScanModule(BaseModule):
    name = "portscan"
    description = "Async TCP Port Scanner"

    # Common ports for fast scanning
    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 6379, 
        11211, 9200, 5432, 1433, 1521, 8000, 8008, 8888
    ]

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"ports_scanned": 0, "open_ports": 0, "closed_ports": 0}

        # Parse target to get hostname/IP
        if target.startswith("http"):
            target = urlparse(target).hostname or target

        # Determine ports to scan
        ports_to_scan = self.TOP_PORTS
        if self.config.ports:
            try:
                if "-" in self.config.ports:
                    start, end = map(int, self.config.ports.split("-"))
                    ports_to_scan = list(range(start, end + 1))
                elif self.config.ports == "all":
                    ports_to_scan = list(range(1, 65536))
                else:
                    ports_to_scan = [int(p) for p in self.config.ports.split(",")]
            except ValueError:
                self.logger.warning(f"Invalid ports format '{self.config.ports}'. Using default top ports.")

        self.logger.info(f"Scanning {len(ports_to_scan)} TCP ports on {target}...")

        # Connection timeout
        conn_timeout = max(1, self.config.timeout // 2)
        sem = asyncio.Semaphore(self.config.threads * 2) # Port scanning can handle higher concurrency

        async def scan_port(port: int):
            async with sem:
                stats["ports_scanned"] += 1
                try:
                    # Async socket connection
                    coro = asyncio.open_connection(target, port)
                    reader, writer = await asyncio.wait_for(coro, timeout=conn_timeout)
                    writer.close()
                    await writer.wait_closed()
                    
                    stats["open_ports"] += 1
                    return {
                        "type": "port",
                        "target": target,
                        "port": port,
                        "state": "open",
                        "protocol": "tcp"
                    }
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    stats["closed_ports"] += 1
                    return None
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port}: {e}")
                    return None

        # Gather tasks
        tasks = [scan_port(port) for port in ports_to_scan]
        scan_results = await asyncio.gather(*tasks)

        for r in scan_results:
            if r:
                results.append(r)

        return self._make_result(target, results, stats)
