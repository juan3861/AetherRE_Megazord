"""Interface comum dos adaptadores externos."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class Adapter(ABC):
    name: str = "base"

    @abstractmethod
    def available(self) -> bool:
        ...

    @abstractmethod
    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        ...

    def status(self) -> dict[str, Any]:
        return {"name": self.name, "available": self.available()}

    def execution_result(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available(),
            "executed": False,
            "produced_evidence": False,
            "partial": False,
        }
