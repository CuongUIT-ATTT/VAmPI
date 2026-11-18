"""Controller and private-state checks for the isolated BOLA lab."""

from __future__ import annotations

import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bola_lab.controller import initialize_run
from bola_lab.storage import fetch_book, read_private_json, state_path


class BolaLabControllerTests(unittest.TestCase):
    def test_controller_cli_creates_private_atomic_artifacts_without_bearers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            result = subprocess.run(
                [sys.executable, "-m", "bola_lab.controller", "--state-dir", str(state), "--scenario", "S02", "init"],
                check=False, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertIn("BOLA Lab đã được khởi tạo thành công.", result.stdout)
            self.assertIn("management console mTLS", result.stdout)
            for principal in ("admin (admin)", "userA (user)", "userB (user)"):
                self.assertIn(principal, result.stdout)
            for name in ("manifest", "database", "operator", "answers"):
                self.assertIn(str(state_path(state, name)), result.stdout)
                self.assertEqual(stat.S_IMODE(state_path(state, name).stat().st_mode), 0o600)
            self.assertNotIn("issued-tokens.json", result.stdout)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            manifest = read_private_json(state_path(state, "manifest"))
            answers = read_private_json(state_path(state, "answers"))
            sensitive_values = [manifest["signing_secret"], manifest["run_id"], fetch_book(state, "book-B1")["secret"], answers["rows"][0]["ground_truth"]["expected_classification"]]
            for value in sensitive_values:
                self.assertNotIn(value, result.stdout)
                self.assertNotIn(value, result.stderr)

    def test_reset_rotates_manifest_and_marker_without_printing_private_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            initialize_run(str(state), "S01", 60)
            old_manifest = read_private_json(state_path(state, "manifest"))
            old_marker = fetch_book(state, "book-B1")["secret"]
            result = subprocess.run(
                [sys.executable, "-m", "bola_lab.controller", "--state-dir", str(state), "--scenario", "S04", "reset"],
                check=False, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Credential và marker private trước đó đã bị vô hiệu hóa", result.stdout)
            new_manifest = read_private_json(state_path(state, "manifest"))
            new_marker = fetch_book(state, "book-B1")["secret"]
            self.assertNotEqual(old_manifest["signing_secret"], new_manifest["signing_secret"])
            self.assertNotEqual(old_marker, new_marker)
            for value in (old_manifest["signing_secret"], old_manifest["run_id"], new_manifest["signing_secret"], new_manifest["run_id"], old_marker, new_marker):
                self.assertNotIn(value, result.stdout)
                self.assertNotIn(value, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
