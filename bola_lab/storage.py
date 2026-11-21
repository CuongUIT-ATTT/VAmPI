"""Private state storage and SQLite persistence for the BOLA lab."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

STATE_FILES = {
    "manifest": "active-run.json",
    "database": "lab.sqlite3",
    "operator": "operator-config.json",
    "answers": "answer-sheet.json",
    "lock": "server.lock",
}


class StateError(RuntimeError):
    """Raised when private lab state is unavailable or unsafe."""


def _now() -> int:
    return int(time.time())


def state_path(state_dir: str | Path, name: str) -> Path:
    return Path(state_dir).expanduser().resolve() / STATE_FILES[name]


def ensure_private_directory(state_dir: str | Path, *, create: bool = False) -> Path:
    path = Path(state_dir).expanduser().resolve()
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Docker volumes are commonly created with a permissive mode. The
        # local controller owns the state and tightens it before use.
        os.chmod(path, 0o700)
    if not path.is_dir():
        raise StateError("The lab state directory is unavailable.")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise StateError("The lab state directory must not be group or world accessible.")
    return path


def write_private_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_private_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StateError("Required lab state is unavailable.")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise StateError("Private lab state has unsafe permissions.")
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise StateError("Lab state has an invalid format.")
    return data


def connect_database(state_dir: str | Path) -> sqlite3.Connection:
    database = state_path(state_dir, "database")
    connection = sqlite3.connect(database, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def initialize_database(state_dir: str | Path, principals: list[dict[str, str]], books: list[dict[str, str]], shares: list[dict[str, str]]) -> None:
    database = state_path(state_dir, "database")
    if database.exists():
        database.unlink()
    connection = connect_database(state_dir)
    try:
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE principals (
                username TEXT PRIMARY KEY,
                role TEXT NOT NULL
            );
            CREATE TABLE books (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL REFERENCES principals(username),
                title TEXT NOT NULL,
                secret TEXT NOT NULL
            );
            CREATE TABLE shares (
                book_id TEXT NOT NULL REFERENCES books(id),
                username TEXT NOT NULL REFERENCES principals(username),
                PRIMARY KEY (book_id, username)
            );
            CREATE TABLE credentials (
                jti TEXT PRIMARY KEY,
                username TEXT NOT NULL REFERENCES principals(username),
                role TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'EXPIRED', 'REVOKED')),
                terminal_at INTEGER,
                issuance_operation_id TEXT NOT NULL
            );
            CREATE INDEX credential_subject_history ON credentials(username, issued_at DESC);
            CREATE UNIQUE INDEX credential_active_subject ON credentials(username) WHERE status = 'ACTIVE';
            """
        )
        connection.executemany(
            "INSERT INTO principals (username, role) VALUES (:username, :role)", principals
        )
        connection.executemany(
            "INSERT INTO books (id, owner, title, secret) VALUES (:id, :owner, :title, :secret)", books
        )
        connection.executemany(
            "INSERT INTO shares (book_id, username) VALUES (:book_id, :username)", shares
        )
    finally:
        connection.close()
    os.chmod(database, 0o600)


def _expire_credentials(connection: sqlite3.Connection, now: int) -> None:
    connection.execute(
        "UPDATE credentials SET status = 'EXPIRED', terminal_at = ? "
        "WHERE status = 'ACTIVE' AND expires_at <= ?",
        (now, now),
    )


def _metadata(row: sqlite3.Row | None, username: str, role: str) -> dict[str, Any]:
    if row is None:
        return {"username": username, "role": role, "status": "NOT_ISSUED", "issued_at": None, "expires_at": None}
    return {
        "username": username,
        "role": role,
        "status": row["status"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
    }


def credential_statuses(state_dir: str | Path) -> list[dict[str, Any]]:
    """Return only account/credential metadata, never bearer material or jtis."""
    connection = connect_database(state_dir)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _expire_credentials(connection, _now())
        principals = connection.execute("SELECT username, role FROM principals ORDER BY username").fetchall()
        result = []
        for principal in principals:
            row = connection.execute(
                "SELECT status, issued_at, expires_at FROM credentials WHERE username = ? "
                "ORDER BY issued_at DESC LIMIT 1",
                (principal["username"],),
            ).fetchone()
            result.append(_metadata(row, principal["username"], principal["role"]))
        connection.commit()
        return result
    except sqlite3.Error as exc:
        connection.rollback()
        raise StateError("Credential registry is unavailable.") from exc
    finally:
        connection.close()


def _credential_claims(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "sub": row["username"],
        "role": row["role"],
        "jti": row["jti"],
        "issued_at": row["issued_at"],
        "exp": row["expires_at"],
    }


def issue_initial_credentials(state_dir: str | Path, ttl: int, operation_id: str) -> list[dict[str, Any]]:
    """Atomically create exactly one active credential for every seeded principal."""
    if not 300 <= ttl <= 86400:
        raise StateError("Credential lifetime is outside the allowed range.")
    connection = connect_database(state_dir)
    try:
        connection.execute("BEGIN IMMEDIATE")
        now = _now()
        _expire_credentials(connection, now)
        if connection.execute("SELECT 1 FROM credentials LIMIT 1").fetchone():
            raise StateError("Initial credentials have already been issued.")
        principals = connection.execute("SELECT username, role FROM principals ORDER BY username").fetchall()
        if {(item["username"], item["role"]) for item in principals} != {
            ("admin", "admin"), ("userA", "user"), ("userB", "user")
        }:
            raise StateError("Lab principals are unavailable.")
        expires_at = now + ttl
        claims = []
        for principal in principals:
            jti = secrets.token_urlsafe(32)
            connection.execute(
                "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, 'ACTIVE', NULL, ?)",
                (jti, principal["username"], principal["role"], now, expires_at, operation_id),
            )
            claims.append(
                {
                    "sub": principal["username"],
                    "role": principal["role"],
                    "jti": jti,
                    "issued_at": now,
                    "exp": expires_at,
                }
            )
        connection.commit()
        return claims
    except (sqlite3.Error, StateError) as exc:
        connection.rollback()
        if isinstance(exc, StateError):
            raise
        raise StateError("Credential registry is unavailable.") from exc
    finally:
        connection.close()


def reissue_credential(state_dir: str | Path, username: str, ttl: int, operation_id: str) -> tuple[dict[str, Any], str]:
    """Issue a successor only once the preceding credential is already terminal."""
    if not 300 <= ttl <= 86400:
        raise StateError("Credential lifetime is outside the allowed range.")
    connection = connect_database(state_dir)
    try:
        connection.execute("BEGIN IMMEDIATE")
        now = _now()
        _expire_credentials(connection, now)
        principal = connection.execute("SELECT username, role FROM principals WHERE username = ?", (username,)).fetchone()
        if principal is None or (principal["username"], principal["role"]) not in {
            ("admin", "admin"), ("userA", "user"), ("userB", "user")
        }:
            raise StateError("Requested credential principal is unavailable.")
        previous = connection.execute(
            "SELECT status FROM credentials WHERE username = ? ORDER BY issued_at DESC LIMIT 1", (username,)
        ).fetchone()
        if previous is None:
            raise StateError("Initial credentials have not been issued.")
        if previous["status"] == "ACTIVE":
            raise StateError("Active credentials must be revoked or expire before reissue.")
        expires_at = now + ttl
        jti = secrets.token_urlsafe(32)
        connection.execute(
            "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, 'ACTIVE', NULL, ?)",
            (jti, principal["username"], principal["role"], now, expires_at, operation_id),
        )
        connection.commit()
        return (
            {
                "sub": principal["username"],
                "role": principal["role"],
                "jti": jti,
                "issued_at": now,
                "exp": expires_at,
            },
            previous["status"],
        )
    except (sqlite3.Error, StateError) as exc:
        connection.rollback()
        if isinstance(exc, StateError):
            raise
        raise StateError("Credential registry is unavailable.") from exc
    finally:
        connection.close()


def claims_for_issuance(state_dir: str | Path, operation_id: str) -> list[dict[str, Any]]:
    """Recover persisted claims for an idempotent management-operation replay."""
    connection = connect_database(state_dir)
    try:
        rows = connection.execute(
            "SELECT username, role, jti, issued_at, expires_at FROM credentials WHERE issuance_operation_id = ? ORDER BY username", (operation_id,)
        ).fetchall()
        return [_credential_claims(row) for row in rows]
    finally:
        connection.close()


def active_claims_for_subject(state_dir: str | Path, username: str) -> dict[str, Any]:
    connection = connect_database(state_dir)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _expire_credentials(connection, _now())
        row = connection.execute(
            "SELECT username, role, jti, issued_at, expires_at FROM credentials WHERE username = ? AND status = 'ACTIVE'", (username,)
        ).fetchone()
        connection.commit()
        if row is None:
            raise StateError("Active credential is unavailable.")
        return _credential_claims(row)
    except sqlite3.Error as exc:
        connection.rollback()
        raise StateError("Credential registry is unavailable.") from exc
    finally:
        connection.close()


def revoke_all_credentials(state_dir: str | Path) -> int:
    """Immediately reject all current credentials on the next public request."""
    connection = connect_database(state_dir)
    try:
        connection.execute("BEGIN IMMEDIATE")
        now = _now()
        _expire_credentials(connection, now)
        changed = connection.execute(
            "UPDATE credentials SET status = 'REVOKED', terminal_at = ? WHERE status = 'ACTIVE'", (now,)
        ).rowcount
        connection.commit()
        return changed
    except sqlite3.Error as exc:
        connection.rollback()
        raise StateError("Credential registry is unavailable.") from exc
    finally:
        connection.close()


def credential_is_active(state_dir: str | Path, claims: dict[str, Any]) -> bool:
    """Verify a signed claim still belongs to the current, non-revoked registry row."""
    connection = connect_database(state_dir)
    try:
        now = _now()
        row = connection.execute(
            "SELECT username, role, expires_at, status FROM credentials WHERE jti = ?", (claims["jti"],)
        ).fetchone()
        return bool(
            row
            and row["status"] == "ACTIVE"
            and row["expires_at"] > now
            and row["username"] == claims["sub"]
            and row["role"] == claims["role"]
            and row["expires_at"] == claims["exp"]
        )
    finally:
        connection.close()


def fetch_principal(state_dir: str | Path, username: str) -> dict[str, str] | None:
    connection = connect_database(state_dir)
    try:
        row = connection.execute("SELECT username, role FROM principals WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def fetch_book(state_dir: str | Path, book_id: str) -> dict[str, str] | None:
    connection = connect_database(state_dir)
    try:
        row = connection.execute("SELECT id, owner, title, secret FROM books WHERE id = ?", (book_id,)).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def fetch_first_owned_book(state_dir: str | Path, owner: str) -> dict[str, str] | None:
    connection = connect_database(state_dir)
    try:
        row = connection.execute(
            "SELECT id, owner, title, secret FROM books WHERE owner = ? ORDER BY id LIMIT 1", (owner,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def is_shared_with(state_dir: str | Path, book_id: str, username: str) -> bool:
    connection = connect_database(state_dir)
    try:
        row = connection.execute(
            "SELECT 1 FROM shares WHERE book_id = ? AND username = ?", (book_id, username)
        ).fetchone()
        return row is not None
    finally:
        connection.close()
