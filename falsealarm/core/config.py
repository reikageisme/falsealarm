from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ScanConfig:
    target: str = ""
    targets_file: str | None = None
    targets: list[str] = field(default_factory=list)
    modules: list = field(default_factory=list)
    threads: int = 50
    rate: int = 30
    timeout: int = 10
    delay: float = 0.0
    proxy: str | None = None
    proxy_file: str | None = None
    random_agent: bool = False
    include_third_party_js: bool = False
    http2: bool = False
    output: str | None = None
    report: str | None = None
    format: str = "table"
    silent: bool = False
    verbose: bool = False
    wordlist: str | None = None
    resume: str | None = None
    ports: str | None = None
    ai_triage: bool = False
    diff: bool = False
    adaptive_rate: bool = False
    pipe: bool = False
    recursion_depth: int = 0
    waf_detected: bool = False
    waf_name: str | None = None
    depth: str = "normal"
    notify_type: str | None = None
    notify_webhook: str | None = None
    telegram_token: str | None = None
    telegram_chat_id: str | None = None
    # vulnscan / nuclei-compatible template selection
    templates: list[str] = field(default_factory=list)
    template_tags: list[str] = field(default_factory=list)
    exclude_tags: list[str] = field(default_factory=list)
    severity: list[str] = field(default_factory=list)
    template_ids: list[str] = field(default_factory=list)
    exclude_template_ids: list[str] = field(default_factory=list)
    # authenticated scanning: extra headers ("Name: value") and a Cookie string
    headers: list[str] = field(default_factory=list)
    cookie: str | None = None
    # scope guard: hosts/wildcards/CIDRs/URL prefixes allowed and denied
    scope: list[str] = field(default_factory=list)
    exclude_scope: list[str] = field(default_factory=list)
    # read at most this many bytes of each response body
    max_body: int = 2_000_000
    # number of targets scanned concurrently in a multi-target run
    parallel: int = 1
    # sqli module tuning
    sqli_delay: int = 5
    sqli_techniques: list[str] = field(default_factory=list)
    # out-of-band (interactsh) testing for vulnscan
    oast: bool = False
    oast_server: str | None = None
    oast_token: str | None = None
    oast_wait: int = 6

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanConfig":
        """Create config from dictionary."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered_data)

    def header_dict(self) -> dict[str, str]:
        """Parse ``headers`` ("Name: value") and ``cookie`` into a dict."""
        out: dict[str, str] = {}
        for raw in self.headers:
            if ":" not in raw:
                continue
            name, value = raw.split(":", 1)
            if name.strip():
                out[name.strip()] = value.strip()
        if self.cookie:
            out["Cookie"] = f"{out['Cookie']}; {self.cookie}" if "Cookie" in out else self.cookie
        return out

    @staticmethod
    def read_profile(filepath: str, profile: str = "default", required: bool = True) -> dict[str, Any]:
        """Read one profile from a YAML file.

        A file may hold named profiles (``default:``, ``stealth:`` …) or be a
        flat mapping of settings, which is treated as the ``default`` profile.
        """
        import os

        import yaml

        if not os.path.exists(filepath):
            if required:
                raise FileNotFoundError(f"Configuration file not found: {filepath}")
            return {}
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{filepath} must contain a mapping")
        section = data.get(profile)
        if isinstance(section, dict):
            return section
        if section is None and any(k in set(cls_fields()) for k in data):
            # Flat file: the whole mapping is the default profile.
            if profile == "default":
                return data
        if required:
            raise ValueError(f"Profile '{profile}' not found in {filepath}")
        return {}

    @classmethod
    def layered(cls, *layers: dict[str, Any]) -> "ScanConfig":
        """Merge settings dicts in order (later wins) into a config."""
        merged: dict[str, Any] = {}
        for layer in layers:
            merged.update({k: v for k, v in (layer or {}).items() if v is not None})
        return cls.from_dict(merged)

    @classmethod
    def from_file(cls, filepath: str, profile: str = "default") -> "ScanConfig":
        """Load configuration from a YAML file for a specific profile."""
        import os

        import yaml

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Configuration file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or profile not in data:
            raise ValueError(f"Profile '{profile}' not found in {filepath}")

        return cls.from_dict(data[profile])

    def validate(self) -> None:
        """Validate the configuration."""
        if not self.target and not self.targets_file and not self.targets and not self.resume:
            raise ValueError("Target, targets_file, targets list, or resume ID must be specified.")
        if self.threads <= 0:
            raise ValueError("Threads must be a positive integer.")
        if self.rate <= 0:
            raise ValueError("Rate must be a positive integer.")
        if self.timeout <= 0:
            raise ValueError("Timeout must be a positive integer.")
        if self.delay < 0:
            raise ValueError("Delay cannot be negative.")
        if self.depth not in {"quick", "normal", "deep", "insane"}:
            raise ValueError("Depth must be one of: quick, normal, deep, insane.")
        if self.format not in {"table", "json", "jsonl", "csv", "txt", "sarif"}:
            raise ValueError("Output format must be one of: table, json, jsonl, csv, txt, sarif.")
        if self.max_body < 1024:
            raise ValueError("max_body must be at least 1024 bytes.")
        if self.parallel < 1:
            raise ValueError("Parallel targets must be at least 1.")
        if self.recursion_depth < 0:
            raise ValueError("Recursion depth cannot be negative.")
        bad_sev = {s.lower() for s in self.severity} - {"info", "low", "medium", "high", "critical", "unknown"}
        if bad_sev:
            raise ValueError(f"Unknown severity: {', '.join(sorted(bad_sev))}.")
        if self.notify_type not in {None, "discord", "slack", "telegram"}:
            raise ValueError("Notification type must be discord, slack, or telegram.")
        if self.notify_type in {"discord", "slack"} and not self.notify_webhook:
            raise ValueError(f"A webhook URL is required for {self.notify_type} notifications.")
        if self.notify_type == "telegram" and not (
            self.telegram_token and self.telegram_chat_id
        ):
            raise ValueError("Telegram notifications require both token and chat ID.")


def cls_fields() -> list[str]:
    return [f.name for f in ScanConfig.__dataclass_fields__.values()]
