import asyncio
from typing import Any
from urllib.parse import urlparse
import websockets
from falsealarm.modules.base import BaseModule, ModuleResult

class WebSocketModule(BaseModule):
    name = "websocket"
    description = "WebSocket Discovery and Analysis"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"ws_endpoints_found": 0, "connections_successful": 0}

        # 1. Discover potential WS endpoints
        # This can be done by parsing HTML for wss:// or dynamically checking /ws, /socket.io
        if not target.startswith("http"):
            target = f"http://{target}"
            
        parsed = urlparse(target)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        base_ws_url = f"{ws_scheme}://{parsed.netloc}"
        
        # Common WebSocket endpoints
        endpoints_to_test = [
            "/",
            "/ws",
            "/websocket",
            "/socket.io/?EIO=4&transport=websocket",
            "/chat",
            "/api/ws"
        ]

        # 2. Test connections
        async def test_ws(endpoint: str):
            ws_url = f"{base_ws_url}{endpoint}"
            try:
                # Attempt to connect
                # timeout = self.config.timeout
                async with websockets.connect(ws_url, open_timeout=self.config.timeout) as ws:
                    stats["connections_successful"] += 1
                    
                    # Connection successful, try to send a ping or wait for welcome message
                    welcome_msg = ""
                    try:
                        # Wait briefly for a welcome message
                        welcome_msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                        pass
                        
                    return {
                        "type": "websocket",
                        "url": ws_url,
                        "status": "open",
                        "welcome_message": welcome_msg[:200] if welcome_msg else None
                    }
                    
            except websockets.exceptions.InvalidStatusCode as e:
                # 403 Forbidden or 401 Unauthorized means WS exists but requires auth
                if e.status_code in (401, 403):
                    stats["ws_endpoints_found"] += 1
                    return {
                        "type": "websocket",
                        "url": ws_url,
                        "status": f"auth_required ({e.status_code})"
                    }
            except (websockets.exceptions.InvalidURI, websockets.exceptions.InvalidHandshake):
                pass
            except OSError:
                # Connection refused / timeout
                pass
            except Exception as e:
                self.logger.debug(f"WS test error for {ws_url}: {e}")
                
            return None

        self.logger.info(f"Probing WebSockets on {base_ws_url}...")
        tasks = [test_ws(ep) for ep in endpoints_to_test]
        ws_results = await asyncio.gather(*tasks)
        
        for r in ws_results:
            if r:
                stats["ws_endpoints_found"] += 1
                results.append(r)

        return self._make_result(target, results, stats)
