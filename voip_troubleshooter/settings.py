"""Application settings for the VoIP troubleshooter."""
from __future__ import annotations

from pathlib import Path
import shutil
from typing import Optional

from pydantic import BaseSettings, Field


def _default_tshark_path() -> Optional[Path]:
    detected = shutil.which("tshark")
    return Path(detected) if detected else None


class AppSettings(BaseSettings):
    """Environment-driven application settings."""

    TSHARK_PATH: Optional[Path] = Field(default_factory=_default_tshark_path)
    SUBPROC_TIMEOUT_S: int = 45
    WORK_DIR: Path = Field(default_factory=lambda: Path("./work"))

    IP_LOOKUP_PROVIDER: str = "stub"
    IP_LOOKUP_API_KEY: Optional[str] = None

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    def require_tshark(self, override: Optional[str] = None) -> Path:
        """Resolve the tshark binary path, validating existence."""
        if override:
            candidate = Path(override).expanduser().resolve()
        else:
            if self.TSHARK_PATH is None:
                raise ValueError(
                    "tshark not found. Install Wireshark/tshark or set TSHARK_PATH in the environment."
                )
            candidate = self.TSHARK_PATH.expanduser().resolve()
        if not candidate.exists():
            raise ValueError(
                "tshark binary does not exist at the provided path. Install tshark or update TSHARK_PATH."
            )
        return candidate


def resolve_tshark_path(override: Optional[str] = None) -> Path:
    """Helper to resolve tshark path using settings or an explicit override."""
    if override:
        candidate = Path(override).expanduser().resolve()
        if not candidate.exists():
            raise ValueError(
                f"tshark binary does not exist at the provided path: {candidate}"
            )
        return candidate
    settings = AppSettings()
    return settings.require_tshark()


__all__ = ["AppSettings", "resolve_tshark_path"]
