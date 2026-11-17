"""Pinned systemd adapter. HTTP inputs never select a unit or command."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Protocol


class SupervisorError(RuntimeError):
    """The fixed service supervisor could not determine an action outcome."""


class SystemdAdapter(Protocol):
    def status(self) -> str: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...


_UNIT_RE = re.compile(r"^[A-Za-z0-9@_.-]+\.service$")


@dataclass(frozen=True)
class PinnedSystemdAdapter:
    unit: str

    def __post_init__(self) -> None:
        if not _UNIT_RE.fullmatch(self.unit):
            raise SupervisorError("Configured management unit is invalid.")

    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ["systemctl", *arguments, self.unit], text=True, capture_output=True, timeout=20, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SupervisorError("The fixed service supervisor is unavailable.") from exc

    def status(self) -> str:
        result = self._run("is-active")
        value = result.stdout.strip()
        return value if value in {"active", "inactive", "failed", "activating", "deactivating"} else "unknown"

    def start(self) -> None:
        if self._run("start").returncode:
            raise SupervisorError("The fixed service supervisor did not confirm start.")

    def stop(self) -> None:
        if self._run("stop").returncode:
            raise SupervisorError("The fixed service supervisor did not confirm stop.")
