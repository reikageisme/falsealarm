from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
import time

if TYPE_CHECKING:
    from falsealarm.core.engine import AsyncEngine
    from falsealarm.core.db import Database
    from falsealarm.core.config import ScanConfig
    from falsealarm.core.logger import FalseAlarmLogger

@dataclass
class ModuleResult:
    """Standard result from a scan module."""
    module: str = ""
    target: str = ""
    data: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    duration: float = 0.0
    timestamp: str = ""
    
    @property
    def count(self) -> int:
        return len(self.data)
    
    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "target": self.target,
            "data": self.data,
            "stats": self.stats,
            "duration": self.duration,
            "timestamp": self.timestamp,
        }

class BaseModule(ABC):
    """Abstract base class for all scan modules."""
    
    name: str = "base"
    description: str = "Base module"
    
    def __init__(self, engine, db, config, logger):
        self.engine = engine
        self.db = db
        self.config = config
        self.logger = logger
    
    @abstractmethod
    async def run(self, target: str) -> ModuleResult:
        """Execute the module scan."""
        ...
    
    def _start_timer(self):
        self._start_time = time.time()
    
    def _elapsed(self) -> float:
        return round(time.time() - self._start_time, 2)
    
    def _make_result(self, target: str, data: list[dict], stats: dict = None) -> ModuleResult:
        from falsealarm.core.utils import get_timestamp
        return ModuleResult(
            module=self.name,
            target=target,
            data=data,
            stats=stats or {},
            duration=self._elapsed(),
            timestamp=get_timestamp(),
        )
