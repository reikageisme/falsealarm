"""Tests for OAST/interactsh: session bookkeeping and deferred executor eval."""

import asyncio

import yaml

from falsealarm.core.oast.base import Interaction, OASTSession
from falsealarm.core.templates.executor import TemplateExecutor
from falsealarm.core.templates.loader import parse_template

OAST_TEMPLATE = """
id: blind-ssrf-oast
info:
  name: Blind SSRF via interactsh
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/fetch?url=http://{{interactsh-url}}"
    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["dns"]
      - type: status
        status: [200]
"""


class FakeOASTClient:
    """Hands out predictable ids and 'receives' interactions the test triggers."""

    def __init__(self):
        self._counter = 0
        self.available = True
        self.handed_out: list[str] = []
        self._inbox: list[Interaction] = []

    def new_url(self):
        self._counter += 1
        uid = f"corr{self._counter:013d}"
        self.handed_out.append(uid)
        return f"{uid}.oast.test", uid

    def trigger(self, uid: str, protocol: str = "dns", remote: str = "1.2.3.4"):
        self._inbox.append(Interaction(protocol=protocol, unique_id=uid, full_id=uid,
                                       remote_address=remote, raw_request="GET / HTTP/1.1"))

    async def poll(self):
        got, self._inbox = self._inbox, []
        return got

    async def close(self):
        pass


class FakeEngine:
    def __init__(self, status=200, body="ok"):
        self.status, self.body = status, body
        self.requests = []

    async def request(self, method, url, **kwargs):
        self.requests.append(url)
        return {"url": url, "status": self.status, "body": self.body, "headers": {}, "error": None, "elapsed": 0.01}


def _template():
    return parse_template(yaml.safe_load(OAST_TEMPLATE), "oast.yaml", OAST_TEMPLATE, allow_oast=True)


def test_oast_template_is_loadable_with_allow_oast():
    t = _template()
    assert t.needs_oast is True
    assert t.requests[0].matchers[0]["part"] == "interactsh_protocol"


def test_oast_match_only_after_interaction_received():
    async def go():
        client = FakeOASTClient()
        session = OASTSession(client=client)
        ex = TemplateExecutor(FakeEngine(), oast=session)
        # First pass: request sent, matcher deferred (no interaction yet).
        immediate = await ex.run(_template(), "http://target")
        assert immediate == []
        assert len(ex.oast_pending) == 1
        # The callback hostname was embedded in the request URL.
        uid = client.handed_out[0]
        assert any(uid in u for u in ex.engine.requests)
        # Now the target performs the DNS callback -> resolve.
        client.trigger(uid, "dns")
        found = await ex.resolve_oast(poll_wait=0)
        assert len(found) == 1 and found[0]["vuln_id"] == "blind-ssrf-oast"
    asyncio.run(go())


def test_oast_no_false_positive_without_interaction():
    async def go():
        client = FakeOASTClient()
        session = OASTSession(client=client)
        ex = TemplateExecutor(FakeEngine(), oast=session)
        await ex.run(_template(), "http://target")
        # No trigger() -> no interaction -> no finding.
        assert await ex.resolve_oast(poll_wait=0) == []
    asyncio.run(go())


def test_oast_session_attributes_interactions_by_uid():
    client = FakeOASTClient()
    session = OASTSession(client=client)
    _host, uid = session.register("tmpl")
    client.trigger(uid, "http")
    asyncio.run(session.collect())
    assert len(session.hits_for(uid)) == 1
    assert session.hits_for("other") == []


def test_oast_disabled_skips_interactsh_templates():
    # Without an OAST session, the executor sends the request but never defers
    # or matches (interactsh-url stays unresolved -> request skipped).
    async def go():
        ex = TemplateExecutor(FakeEngine())
        found = await ex.run(_template(), "http://target")
        assert found == [] and ex.oast_pending == []
    asyncio.run(go())


# --------------------------------------------------------------------------- #
# Real InteractshClient against a local interactsh-compatible server
# --------------------------------------------------------------------------- #

def test_real_interactsh_client_register_poll_decrypt(tmp_path):
    """Exercise the real RSA/AES client code path end-to-end over localhost."""
    import base64
    import json
    import os
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs, urlparse

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB

    from falsealarm.core.oast.base import OASTSession
    from falsealarm.core.oast.interactsh import InteractshClient

    state = {"pub": None, "secret": None, "inbox": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(obj).encode())

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            state["pub"] = serialization.load_pem_public_key(base64.b64decode(body["public-key"]))
            state["secret"] = body["secret-key"]
            self._json({"message": "ok"})

        def do_GET(self):
            q = parse_qs(urlparse(self.path).query)
            if self.path.startswith("/fetch"):
                host = q["url"][0].split("//")[-1].split("/")[0]
                label = host.split(".")[0]
                state["inbox"].append({"protocol": "http", "unique-id": label, "full-id": label,
                                       "remote-address": "127.0.0.1", "raw-request": "GET", "timestamp": "now"})
                self._json({"ok": True})
                return
            if not state["inbox"]:
                self._json({"data": [], "aes_key": None})
                return
            aes = os.urandom(32)
            data = []
            for it in state["inbox"]:
                iv = os.urandom(16)
                enc = Cipher(algorithms.AES(aes), CFB(iv)).encryptor()
                data.append(base64.b64encode(iv + enc.update(json.dumps(it).encode()) + enc.finalize()).decode())
            state["inbox"] = []
            aes_enc = state["pub"].encrypt(aes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                             algorithm=hashes.SHA256(), label=None))
            self._json({"data": data, "aes_key": base64.b64encode(aes_enc).decode()})

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    async def go():
        import aiohttp
        client = InteractshClient(server=f"127.0.0.1:{port}", scheme="http", timeout=5)
        assert await client.register() is True
        session = OASTSession(client=client)
        host, uid = session.register("tmpl")
        async with aiohttp.ClientSession() as s:
            await s.get(f"http://127.0.0.1:{port}/fetch?url=http://{host}/x")
        await session.collect()
        hits = session.hits_for(uid)
        await client.close()
        return hits

    try:
        hits = asyncio.run(go())
        assert len(hits) == 1 and hits[0].protocol == "http"
    finally:
        server.shutdown()
