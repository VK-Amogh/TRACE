"""Base interfaces for external tool adapters."""

from abc import ABC, abstractmethod
import shutil
import subprocess
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class ToolInfo(BaseModel):
    name: str
    command: str
    description: str
    installed: bool
    version: Optional[str] = None
    category: str


class ToolAdapter(ABC):
    """Abstract adapter for external security tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def command(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        pass

    def is_installed(self) -> bool:
        return shutil.which(self.command) is not None

    def get_version(self) -> Optional[str]:
        if not self.is_installed():
            return None
        try:
            res = subprocess.run(
                [self.command, "--version"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            out = (res.stdout or res.stderr).strip().splitlines()
            return out[0] if out else "installed"
        except Exception:
            return "installed"

    def get_info(self) -> ToolInfo:
        return ToolInfo(
            name=self.name,
            command=self.command,
            description=self.description,
            installed=self.is_installed(),
            version=self.get_version(),
            category=self.category,
        )
