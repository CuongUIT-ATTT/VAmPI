"""Local-only BOLA Lab account inspection utility without token disclosure."""

from __future__ import annotations

import argparse
import sys

from .storage import StateError, connect_database, ensure_private_directory


def list_accounts(state_dir_text: str) -> list[dict[str, str]]:
    """Return the locally seeded principals without exposing credentials."""
    state_dir = ensure_private_directory(state_dir_text)
    connection = connect_database(state_dir)
    try:
        rows = connection.execute("SELECT username, role FROM principals ORDER BY username").fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Local-only BOLA Lab account inspection utility")
    parser.add_argument("--state-dir", required=True, help="Private state directory (mode 0700)")
    parser.add_argument("command", choices=("list",))
    args = parser.parse_args()

    try:
        print("BOLA Lab accounts (password authentication is not used):")
        for account in list_accounts(args.state_dir):
            print(f"  - {account['username']} ({account['role']})")
        print("Operators issue bearer credentials only through the mTLS management console.")
        return 0
    except StateError as exc:
        print(f"Account utility error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
