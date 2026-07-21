from dataclasses import dataclass, field, asdict
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
    http2: bool = False
    output: str | None = None
    format: str = "table"
    silent: bool = False
    verbose: bool = False
    wordlist: str | None = None
    resume: str | None = None
    ports: str | None = None
    ai_triage: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanConfig":
        """Create config from dictionary."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered_data)

    @classmethod
    def from_file(cls, filepath: str, profile: str = "default") -> "ScanConfig":
        """Load configuration from a YAML file for a specific profile."""
        import yaml
        import os
        
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
