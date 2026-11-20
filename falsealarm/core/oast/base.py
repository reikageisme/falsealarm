"""
OAST client abstraction.

An OAST (out-of-band) client hands out unique callback hostnames and later
reports which of them were hit (via DNS or HTTP) by the target — the mechanism
behind nuclei's ``{{interactsh-url}}`` templates for blind SSRF/RCE/XXE.

The ``OASTClient`` protocol keeps the template executor independent of any
specific provider, so the real interactsh client and a test double are
interchangeable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class Interaction:
    protocol: str            # "dns" | "http" | "smtp" | ...
    unique_id: str           # the per-payload id embedded in the hostname
    full_id: str = ""
    raw_request: str = ""
    remote_address: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "unique_id": self.unique_id,
            "remote_address": self.remote_address,
            "timestamp": self.timestamp,
        }


@runtime_checkable
class OASTClient(Protocol):
    """Minimal interface the template executor needs."""

    @property
    def available(self) -> bool:
        ...

    def new_url(self) -> tuple[str, str]:
        """Return (hostname, unique_id) for a fresh callback target."""
        ...

    async def poll(self) -> list[Interaction]:
        """Return interactions received since the last poll."""
        ...

    async def close(self) -> None:
        ...


@dataclass
class OASTSession:
    """Per-scan bookkeeping of handed-out URLs and received interactions."""
    client: OASTClient
    pending: dict[str, str] = field(default_factory=dict)   # unique_id -> context label
    interactions: dict[str, list[Interaction]] = field(default_factory=dict)  # unique_id -> hits

    def register(self, label: str) -> tuple[str, str]:
        host, uid = self.client.new_url()
        self.pending[uid] = label
        return host, uid

    async def collect(self) -> None:
        for interaction in await self.client.poll():
            # Attribute to a handed-out id: interactions embed the unique id as a
            # prefix of their own full id / unique id.
            for uid in self.pending:
                if interaction.unique_id == uid or interaction.unique_id.startswith(uid) or uid in interaction.full_id:
                    self.interactions.setdefault(uid, []).append(interaction)

    def hits_for(self, uid: str) -> list[Interaction]:
        return self.interactions.get(uid, [])
