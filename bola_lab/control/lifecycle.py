"""Safe management wrapper around the existing local BOLA controller."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from ..controller import SCENARIO_IDS, initialize_run, reset_run, validate_run
from ..storage import StateError, ensure_private_directory, read_private_json, state_path
from .systemd import SupervisorError, SystemdAdapter


class LifecycleError(RuntimeError):
    """A requested lifecycle transition is invalid or cannot be reconciled."""


@dataclass
class RunLifecycle:
    state_dir: str
    supervisor: SystemdAdapter

    def _manifest_expiry(self) -> int | None:
        try:
            data = read_private_json(state_path(ensure_private_directory(self.state_dir), "tokens"))
        except StateError:
            return None
        value = data.get("expires_at")
        return value if isinstance(value, int) else None

    def init(self, scenario: str, ttl: int) -> int:
        if scenario not in SCENARIO_IDS or not 300 <= ttl <= 86400:
            raise LifecycleError("Requested scenario or token lifetime is invalid.")
        if state_path(self.state_dir, "manifest").exists():
            raise LifecycleError("Lab state already exists.")
        if self.supervisor.status() not in {"inactive", "failed"}:
            raise LifecycleError("Lab service state is not safely stopped.")
        try:
            initialize_run(self.state_dir, scenario, ttl)
        except StateError as exc:
            raise LifecycleError("Lab state could not be initialized safely.") from exc
        expiry = self._manifest_expiry()
        if expiry is None:
            raise LifecycleError("Lab state could not be initialized safely.")
        return expiry

    def validate(self) -> int:
        if self.supervisor.status() not in {"inactive", "failed"}:
            raise LifecycleError("Lab service state is not safely stopped.")
        try:
            validate_run(self.state_dir)
        except StateError as exc:
            raise LifecycleError("Lab state validation failed.") from exc
        expiry = self._manifest_expiry()
        if expiry is None:
            raise LifecycleError("Lab state validation failed.")
        return expiry

    def start(self) -> None:
        expiry = self._manifest_expiry()
        if expiry is None or expiry <= int(time.time()):
            raise LifecycleError("Lab credentials are expired or unavailable.")
        try:
            self.supervisor.start()
            if self.supervisor.status() != "active":
                raise LifecycleError("Lab service did not become active.")
        except SupervisorError as exc:
            raise LifecycleError("Lab service outcome is unknown.") from exc

    def stop(self) -> None:
        try:
            self.supervisor.stop()
            if self.supervisor.status() not in {"inactive", "failed"}:
                raise LifecycleError("Lab service did not become inactive.")
        except SupervisorError as exc:
            raise LifecycleError("Lab service outcome is unknown.") from exc

    def reset(self, scenario: str, ttl: int) -> int:
        if scenario not in SCENARIO_IDS or not 300 <= ttl <= 86400:
            raise LifecycleError("Requested scenario or token lifetime is invalid.")
        if self.supervisor.status() not in {"inactive", "failed"}:
            raise LifecycleError("Lab service state is not safely stopped.")
        try:
            reset_run(self.state_dir, scenario, ttl)
        except StateError as exc:
            raise LifecycleError("Lab state could not be reset safely.") from exc
        expiry = self._manifest_expiry()
        if expiry is None:
            raise LifecycleError("Lab state could not be reset safely.")
        return expiry
