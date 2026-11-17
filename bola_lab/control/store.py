"""Redacted durable journal, idempotency, and evaluation leases."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator


class ControlStoreError(RuntimeError):
    """A control-plane persistence precondition was not met."""


class PreconditionRequired(ControlStoreError):
    pass


class StaleVersion(ControlStoreError):
    pass


class IdempotencyConflict(ControlStoreError):
    pass


class LeaseConflict(ControlStoreError):
    pass


def _now() -> int:
    return int(time.time())


def _id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


class ControlStore:
    """Private SQLite state that persists across destructive BOLA run resets."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.path = self.root / "control.sqlite3"
        self._startup_reconciled = False

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        if stat.S_IMODE(self.root.stat().st_mode) & 0o077:
            raise ControlStoreError("Management state directory has unsafe permissions.")
        with self.connection() as connection:
            connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS state (
                  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                  version INTEGER NOT NULL, lifecycle TEXT NOT NULL,
                  validated INTEGER NOT NULL, scenario TEXT, token_expires_at INTEGER,
                  generation INTEGER NOT NULL, updated_at INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO state VALUES (1, 0, 'UNINITIALIZED', 0, NULL, NULL, 0, 0);
                CREATE TABLE IF NOT EXISTS operations (
                  operation_id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
                  request_hash TEXT NOT NULL, state TEXT NOT NULL, result_code TEXT,
                  created_at INTEGER NOT NULL, completed_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                  actor TEXT NOT NULL, route TEXT NOT NULL, key TEXT NOT NULL,
                  request_hash TEXT NOT NULL, operation_id TEXT NOT NULL REFERENCES operations(operation_id),
                  created_at INTEGER NOT NULL, PRIMARY KEY(actor, route, key)
                );
                CREATE TABLE IF NOT EXISTS leases (
                  lease_id TEXT PRIMARY KEY, actor TEXT NOT NULL, generation INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL, released_at INTEGER, created_at INTEGER NOT NULL
                );
                """
            )
            if not self._startup_reconciled:
                interrupted = connection.execute("SELECT 1 FROM operations WHERE state = 'RUNNING' LIMIT 1").fetchone()
                if interrupted:
                    connection.execute("UPDATE operations SET state = 'UNKNOWN', result_code = 'interrupted', completed_at = ? WHERE state = 'RUNNING'", (_now(),))
                    connection.execute("UPDATE state SET lifecycle = 'UNKNOWN', version = version + 1, updated_at = ? WHERE singleton = 1", (_now(),))
                self._startup_reconciled = True
        os.chmod(self.path, 0o600)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connection()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()
        finally:
            connection.close()

    @staticmethod
    def request_hash(payload: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def status(self) -> dict[str, Any]:
        self.initialize()
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM state WHERE singleton = 1").fetchone()
            active = connection.execute(
                "SELECT COUNT(*) FROM leases WHERE released_at IS NULL AND expires_at > ?", (_now(),)
            ).fetchone()[0]
            expired_unreleased = connection.execute(
                "SELECT COUNT(*) FROM leases WHERE released_at IS NULL AND expires_at <= ?", (_now(),)
            ).fetchone()[0]
        return {
            "state_version": str(row["version"]), "lifecycle": row["lifecycle"], "initialized": row["lifecycle"] != "UNINITIALIZED",
            "validated": bool(row["validated"]), "token_expires_at": row["token_expires_at"],
            "credential_generation": row["generation"],
            "evaluation_leases": {"active": active, "expired_unreleased": expired_unreleased},
            "credential_handoff": "BLOCKED",
        }

    def begin_operation(
        self,
        actor: str,
        route: str,
        key: str | None,
        version: str | None,
        payload: dict[str, Any],
        guard: Callable[[sqlite3.Connection, sqlite3.Row], None] | None = None,
    ) -> tuple[str, bool]:
        if not key or not 16 <= len(key) <= 128:
            raise PreconditionRequired("An Idempotency-Key of 16 to 128 characters is required.")
        if version is None:
            raise PreconditionRequired("If-Match is required.")
        digest = self.request_hash(payload)
        with self.transaction() as connection:
            existing = connection.execute("SELECT request_hash, operation_id FROM idempotency WHERE actor = ? AND route = ? AND key = ?", (actor, route, key)).fetchone()
            if existing:
                if existing["request_hash"] != digest:
                    raise IdempotencyConflict("Idempotency key was used with a different request.")
                return existing["operation_id"], True
            state = connection.execute("SELECT * FROM state WHERE singleton = 1").fetchone()
            current = str(state["version"])
            if version != current:
                raise StaleVersion("State version is stale.")
            if state["lifecycle"] == "UNKNOWN":
                raise LeaseConflict("Lifecycle state requires operator reconciliation.")
            if connection.execute("SELECT 1 FROM operations WHERE state = 'RUNNING' LIMIT 1").fetchone():
                raise LeaseConflict("Another lifecycle operation is active.")
            if guard is not None:
                guard(connection, state)
            operation_id = _id("op")
            now = _now()
            connection.execute("INSERT INTO operations VALUES (?, ?, ?, ?, 'RUNNING', NULL, ?, NULL)", (operation_id, actor, route, digest, now))
            connection.execute("INSERT INTO idempotency VALUES (?, ?, ?, ?, ?, ?)", (actor, route, key, digest, operation_id, now))
            return operation_id, False

    def finish_operation(self, operation_id: str, code: str, *, lifecycle: str | None = None, validated: bool | None = None, scenario: str | None = None, token_expires_at: int | None = None, rotate_generation: bool = False) -> None:
        with self.transaction() as connection:
            connection.execute("UPDATE operations SET state = 'SUCCEEDED', result_code = ?, completed_at = ? WHERE operation_id = ?", (code, _now(), operation_id))
            if lifecycle is not None:
                row = connection.execute("SELECT generation FROM state WHERE singleton = 1").fetchone()
                connection.execute("UPDATE state SET version = version + 1, lifecycle = ?, validated = ?, scenario = COALESCE(?, scenario), token_expires_at = COALESCE(?, token_expires_at), generation = ?, updated_at = ? WHERE singleton = 1", (lifecycle, int(bool(validated)), scenario, token_expires_at, row[0] + int(rotate_generation), _now()))
                if rotate_generation:
                    connection.execute("UPDATE leases SET released_at = ? WHERE released_at IS NULL", (_now(),))

    def fail_operation(self, operation_id: str, code: str) -> None:
        with self.transaction() as connection:
            connection.execute("UPDATE operations SET state = 'FAILED', result_code = ?, completed_at = ? WHERE operation_id = ?", (code, _now(), operation_id))

    def mark_operation_unknown(self, operation_id: str, code: str) -> None:
        with self.transaction() as connection:
            connection.execute("UPDATE operations SET state = 'UNKNOWN', result_code = ?, completed_at = ? WHERE operation_id = ?", (code, _now(), operation_id))
            connection.execute("UPDATE state SET lifecycle = 'UNKNOWN', version = version + 1, updated_at = ? WHERE singleton = 1", (_now(),))

    @staticmethod
    def require_no_unreleased_leases(connection: sqlite3.Connection, _: sqlite3.Row) -> None:
        if connection.execute("SELECT 1 FROM leases WHERE released_at IS NULL LIMIT 1").fetchone():
            raise LeaseConflict("Unreleased evaluation leases block this operation.")

    def operation(self, operation_id: str) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute("SELECT operation_id, action, state, result_code, created_at, completed_at FROM operations WHERE operation_id = ?", (operation_id,)).fetchone()
        return dict(row) if row else None

    def active_leases(self) -> bool:
        with self.connection() as connection:
            return bool(connection.execute("SELECT 1 FROM leases WHERE released_at IS NULL LIMIT 1").fetchone())

    def acquire_lease(self, actor: str, duration: int) -> dict[str, Any]:
        if not 60 <= duration <= 3600:
            raise LeaseConflict("Lease duration is outside the allowed range.")
        with self.transaction() as connection:
            state = connection.execute("SELECT lifecycle, generation FROM state WHERE singleton = 1").fetchone()
            if state["lifecycle"] != "RUNNING":
                raise LeaseConflict("Evaluation requires a running lab.")
            if connection.execute("SELECT 1 FROM operations WHERE state = 'RUNNING' LIMIT 1").fetchone():
                raise LeaseConflict("Lifecycle transition is in progress.")
            lease_id, expires_at = _id("lease"), _now() + duration
            connection.execute("INSERT INTO leases VALUES (?, ?, ?, ?, NULL, ?)", (lease_id, actor, state["generation"], expires_at, _now()))
        return {"lease_id": lease_id, "generation": state["generation"], "expires_at": expires_at}

    def renew_lease(self, actor: str, lease_id: str, duration: int) -> dict[str, Any]:
        if not 60 <= duration <= 3600:
            raise LeaseConflict("Lease duration is outside the allowed range.")
        with self.transaction() as connection:
            row = connection.execute("SELECT generation, expires_at, released_at FROM leases WHERE lease_id = ? AND actor = ?", (lease_id, actor)).fetchone()
            if not row or row["released_at"] is not None or row["expires_at"] <= _now():
                raise LeaseConflict("Evaluation lease is unavailable.")
            expires_at = _now() + duration
            connection.execute("UPDATE leases SET expires_at = ? WHERE lease_id = ?", (expires_at, lease_id))
        return {"lease_id": lease_id, "generation": row["generation"], "expires_at": expires_at}

    def release_lease(self, actor: str, lease_id: str) -> bool:
        with self.transaction() as connection:
            changed = connection.execute("UPDATE leases SET released_at = ? WHERE lease_id = ? AND actor = ? AND released_at IS NULL", (_now(), lease_id, actor)).rowcount
        return bool(changed)
