"""
FalseAlarm — Request Fingerprint Randomizer

Randomizes HTTP request headers (User-Agent, Accept, Accept-Language,
Accept-Encoding) to reduce the likelihood of being fingerprinted by
monitoring systems. Loads real browser User-Agent strings from a data file.
"""

import random
from pathlib import Path
from falsealarm.core.utils import get_data_path


# Fallback User-Agents if the data file is unavailable
_FALLBACK_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]

_ACCEPT_VALUES = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*",
]

_ACCEPT_LANGUAGE_VALUES = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.5",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,vi;q=0.8",
    "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
]

_ACCEPT_ENCODING_VALUES = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip, deflate, br, zstd",
]


class RequestFingerprint:
    """Generates randomized HTTP request headers.

    Loads User-Agent strings from a data file and randomizes various
    HTTP headers to make requests appear more like normal browser traffic.

    Args:
        ua_file: Path to a file containing User-Agent strings (one per line).
            Defaults to the built-in user_agents.txt.
        random_agent: If True, rotate User-Agent on each call.
            If False, pick one UA and reuse it.
    """

    def __init__(
        self,
        ua_file: str | None = None,
        random_agent: bool = True,
    ):
        self.random_agent = random_agent
        self._user_agents: list[str] = []
        self._fixed_ua: str | None = None

        self._load_user_agents(ua_file)

    def _load_user_agents(self, ua_file: str | None) -> None:
        """Load User-Agent strings from file."""
        path = Path(ua_file) if ua_file else get_data_path("user_agents.txt")

        try:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    self._user_agents = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
        except (OSError, IOError):
            pass

        if not self._user_agents:
            self._user_agents = _FALLBACK_USER_AGENTS.copy()

        # If not rotating, pick one UA to reuse
        if not self.random_agent:
            self._fixed_ua = random.choice(self._user_agents)

    def get_user_agent(self) -> str:
        """Return a User-Agent string.

        If random_agent is True, returns a random UA each time.
        Otherwise, returns the same UA every time.
        """
        if self.random_agent:
            return random.choice(self._user_agents)
        return self._fixed_ua or self._user_agents[0]

    def get_headers(self) -> dict[str, str]:
        """Generate a complete set of randomized HTTP headers.

        Returns a dictionary with randomized User-Agent, Accept,
        Accept-Language, and Accept-Encoding headers. The header
        ordering is also randomized.
        """
        headers = {
            "User-Agent": self.get_user_agent(),
            "Accept": random.choice(_ACCEPT_VALUES),
            "Accept-Language": random.choice(_ACCEPT_LANGUAGE_VALUES),
            "Accept-Encoding": random.choice(_ACCEPT_ENCODING_VALUES),
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        # Randomize header order by rebuilding dict
        items = list(headers.items())
        random.shuffle(items)
        return dict(items)
