"""Safe management wrapper around the existing local BOLA controller."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..controller import SCENARIO_IDS, initialize_run, reset_run, validate_run
from ..storage import StateError, ensure_private_directory, read_private_json, state_path
from .systemd import SupervisorError, SystemdAdapter


class LifecycleError(RuntimeError):
    """A requested lifecycle transition is invalid or cannot be reconciled."""


class IndeterminateLifecycleError(LifecycleError):
    """An external supervisor action may have changed the lab state."""


@dataclass
class RunLifecycle:
    state_dir: str
    supervisor: SystemdAdapter

    def _valid_manifest(self) -> bool:
        try:
            data = read_private_json(state_path(ensure_private_directory(self.state_dir), "manifest"))
        except StateError:
            return False
        return isinstance(data.get("signing_secret"), str) and len(data["signing_secret"]) >= 24

    def init(self, scenario: str, ttl: int) -> None:
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
        if not self._valid_manifest():
            raise LifecycleError("Lab state could not be initialized safely.")

    def validate(self) -> None:
        if self.supervisor.status() not in {"inactive", "failed"}:
            raise LifecycleError("Lab service state is not safely stopped.")
        try:
            validate_run(self.state_dir)
        except StateError as exc:
            raise LifecycleError("Lab state validation failed.") from exc
        if not self._valid_manifest():
            raise LifecycleError("Lab state validation failed.")

    def provision(self, scenario: str, ttl: int) -> None:
        """Create and validate one fresh private run while its service is stopped."""
        if scenario not in SCENARIO_IDS or not 300 <= ttl <= 86400:
            raise LifecycleError("Requested scenario or token lifetime is invalid.")
        if self.supervisor.status() not in {"inactive", "failed"}:
            raise LifecycleError("Lab service state is not safely stopped.")
        try:
            reset_run(self.state_dir, scenario, ttl)
            validate_run(self.state_dir)
        except StateError as exc:
            raise LifecycleError("Lab state could not be provisioned safely.") from exc
        if not self._valid_manifest():
            raise LifecycleError("Lab state could not be provisioned safely.")

    def start(self) -> None:
        if not self._valid_manifest():
            raise LifecycleError("Lab credentials are unavailable.")
        try:
            self.supervisor.start()
            status = self.supervisor.status()
        except SupervisorError as exc:
            raise IndeterminateLifecycleError("Lab service outcome is unknown.") from exc
        if status == "active":
            return
        if status in {"inactive", "failed"}:
            raise LifecycleError("Lab service did not become active.")
        raise IndeterminateLifecycleError("Lab service outcome is unknown.")

    def stop(self) -> None:
        try:
            self.supervisor.stop()
            status = self.supervisor.status()
        except SupervisorError as exc:
            raise IndeterminateLifecycleError("Lab service outcome is unknown.") from exc
        if status in {"inactive", "failed"}:
            return
        if status == "active":
            raise LifecycleError("Lab service did not become inactive.")
        raise IndeterminateLifecycleError("Lab service outcome is unknown.")

    def reset_and_start(self, scenario: str, ttl: int) -> None:
        """Replace the sole lab run and return it to a known running state."""
        was_running = self.supervisor.status() == "active"
        if was_running:
            self.stop()
        try:
            self.provision(scenario, ttl)
            self.start()
        except LifecycleError as exc:
            if was_running:
                raise IndeterminateLifecycleError("Lab reset outcome is unknown.") from exc
            raise

    def reset(self, scenario: str, ttl: int) -> None:
        if scenario not in SCENARIO_IDS or not 300 <= ttl <= 86400:
            raise LifecycleError("Requested scenario or token lifetime is invalid.")
        if self.supervisor.status() not in {"inactive", "failed"}:
            raise LifecycleError("Lab service state is not safely stopped.")
        try:
            reset_run(self.state_dir, scenario, ttl)
        except StateError as exc:
            raise LifecycleError("Lab state could not be reset safely.") from exc
        if not self._valid_manifest():
            raise LifecycleError("Lab state could not be reset safely.")
