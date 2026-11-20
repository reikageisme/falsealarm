"""
interactsh client — compatible with the public interactsh servers.

Protocol (projectdiscovery/interactsh):
  * Generate an RSA-2048 keypair and a 20-char correlation id.
  * ``POST /register`` with the base64 PEM public key, a random secret, and the
    correlation id.
  * Each callback hostname is ``<correlation-id><random13>.<server-domain>``;
    the 13-char suffix attributes an interaction to one payload.
  * ``GET /poll?id=<corr>&secret=<secret>`` returns ``aes_key`` (RSA-OAEP-SHA256
    encrypted AES key) and ``data`` (AES-CFB encrypted interaction JSON, each
    prefixed with a 16-byte IV).

Needs the ``cryptography`` package (``pip install falsealarm[oast]``).
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import string
from typing import Any

import aiohttp

from falsealarm.core.oast.base import Interaction

DEFAULT_SERVERS = ["oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"]
_CHARSET = string.ascii_lowercase + string.digits


def _rand(n: int) -> str:
    return "".join(secrets.choice(_CHARSET) for _ in range(n))


class InteractshClient:
    """Async interactsh client. Call ``register()`` before handing out URLs."""

    def __init__(self, server: str | None = None, token: str | None = None, timeout: int = 10,
                 scheme: str = "https"):
        self.servers = [server] if server else list(DEFAULT_SERVERS)
        self.token = token
        self.timeout = timeout
        self.scheme = scheme  # "http" only for local testing
        self.server: str | None = None
        self.correlation_id = _rand(20)
        self.secret = str(_uuid4())
        self._private_key: Any = None
        self._public_key_b64 = ""
        self._session: aiohttp.ClientSession | None = None
        self._registered = False

    @property
    def available(self) -> bool:
        return self._registered and self.server is not None

    async def register(self) -> bool:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            return False

        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._public_key_b64 = base64.b64encode(pub_pem).decode()
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
        payload = {
            "public-key": self._public_key_b64,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        }
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = self.token
        for server in self.servers:
            url = f"{self.scheme}://{server}/register"
            try:
                async with self._session.post(url, json=payload, headers=headers) as resp:
                    if resp.status == 200:
                        self.server = server
                        self._registered = True
                        return True
            except Exception:
                continue
        await self.close()
        return False

    def new_url(self) -> tuple[str, str]:
        if not self.available:
            raise RuntimeError("interactsh client not registered")
        unique = self.correlation_id + _rand(13)
        return f"{unique}.{self.server}", unique

    async def poll(self) -> list[Interaction]:
        if not self.available or self._session is None:
            return []
        url = f"{self.scheme}://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        headers = {"Authorization": self.token} if self.token else {}
        try:
            async with self._session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
        except Exception:
            return []
        aes_key_b64 = data.get("aes_key")
        items = data.get("data") or []
        if not aes_key_b64 or not items:
            return []
        try:
            aes_key = self._decrypt_aes_key(aes_key_b64)
        except Exception:
            return []
        out: list[Interaction] = []
        for item in items:
            try:
                plaintext = self._decrypt_data(aes_key, item)
                obj = json.loads(plaintext)
            except Exception:
                continue
            out.append(Interaction(
                protocol=str(obj.get("protocol", "")),
                unique_id=str(obj.get("unique-id") or obj.get("full-id", "")),
                full_id=str(obj.get("full-id", "")),
                raw_request=str(obj.get("raw-request", "")),
                remote_address=str(obj.get("remote-address", "")),
                timestamp=str(obj.get("timestamp", "")),
            ))
        return out

    def _decrypt_aes_key(self, aes_key_b64: str) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        encrypted = base64.b64decode(aes_key_b64)
        return self._private_key.decrypt(
            encrypted,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    @staticmethod
    def _decrypt_data(aes_key: bytes, data_b64: str) -> str:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:  # cryptography >= 43 moved CFB to the decrepit module
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:  # pragma: no cover - older cryptography
            from cryptography.hazmat.primitives.ciphers.modes import CFB

        raw = base64.b64decode(data_b64)
        iv, ciphertext = raw[:16], raw[16:]
        cipher = Cipher(algorithms.AES(aes_key), CFB(iv))
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode("utf-8", errors="replace")

    async def close(self) -> None:
        if self._session and not self._session.closed:
            # Best-effort deregister so the server can free the correlation id.
            try:
                await self._session.post(
                    f"{self.scheme}://{self.server}/deregister",
                    json={"correlation-id": self.correlation_id, "secret-key": self.secret},
                )
            except Exception:
                pass
            await self._session.close()
        self._registered = False


def _uuid4() -> str:
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
