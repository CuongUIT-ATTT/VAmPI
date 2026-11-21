"""Security and simplified lifecycle coverage for the isolated BOLA management API."""

from __future__ import annotations

import html
import json
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from bola_lab.control.identity import IdentityError, MTLSIdentityProvider, ManagementIdentity, StaticTestIdentityProvider
from bola_lab.control.lifecycle import RunLifecycle
from bola_lab.control.store import ControlStore, LeaseConflict
from bola_lab.control.systemd import SupervisorError
from bola_lab.management import ConsoleConfig, ConsoleConfigurationError, create_management_app
from bola_lab.storage import credential_statuses, read_private_json, state_path


class FakeSystemd:
    def __init__(self) -> None:
        self.state = "inactive"
        self.starts = 0
        self.stops = 0
        self.start_result: str | None = None
        self.stop_result: str | None = None
        self.start_error = False

    def status(self) -> str:
        return self.state

    def start(self) -> None:
        self.starts += 1
        if self.start_error:
            raise SupervisorError("simulated timeout")
        self.state = self.start_result or "active"

    def stop(self) -> None:
        self.stops += 1
        self.state = self.stop_result or "inactive"


class BolaLabManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.state_dir = root / "lab-state"
        self.state_dir.mkdir(mode=0o700)
        self.store = ControlStore(root / "control-state")
        self.systemd = FakeSystemd()
        self.console_clock = [1_700_000_000]
        self.console_config = ConsoleConfig(
            origin="https://management.example.test",
            csrf_secret=b"c" * 32,
            clock=lambda: self.console_clock[0],
        )
        self.app = create_management_app(
            store=self.store,
            lifecycle=RunLifecycle(str(self.state_dir), self.systemd),
            identity_provider=StaticTestIdentityProvider(),
            console_config=self.console_config,
        )
        self.client = self.app.test_client()
        self.operator = ManagementIdentity("spiffe://lab/operator", "operator", "aa")
        self.reader = ManagementIdentity("spiffe://lab/reader", "reader", "bb")
        self.evaluator = ManagementIdentity("spiffe://lab/evaluator", "evaluator", "cc")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def request(self, method: str, path: str, identity: ManagementIdentity | None, *, body: dict | None = None, headers: dict | None = None):
        environment = {"bola.test.identity": identity} if identity else {}
        return self.client.open(path, method=method, json=body, headers=headers, environ_overrides=environment)

    def mutation_headers(self, version: str = "0", key: str = "a" * 16) -> dict[str, str]:
        return {"If-Match": version, "Idempotency-Key": key}

    def start_lab(self, *, key: str = "a" * 16, scenario: str = "S01"):
        return self.request(
            "POST",
            "/management/v1/start",
            self.operator,
            body={"scenario": scenario, "token_ttl_seconds": 3600},
            headers=self.mutation_headers("0", key),
        )

    def stop_lab(self, *, key: str = "b" * 16):
        return self.request(
            "POST",
            "/management/v1/stop",
            self.operator,
            body={},
            headers=self.mutation_headers(self.store.status()["state_version"], key),
        )

    def test_missing_identity_and_bola_bearer_fail_closed(self) -> None:
        response = self.request("GET", "/management/v1/status", None, headers={"Authorization": "Bearer test-token"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json["code"], "unauthenticated")

    def test_production_identity_requires_verified_environ_and_mapped_role(self) -> None:
        provider = MTLSIdentityProvider({"spiffe://lab/operator": "operator"})
        identity = provider.identity_for({"BOLA_MGMT_TLS_VERIFIED": "SUCCESS", "bola.mtls.identity": json.dumps({"subject": "spiffe://lab/operator", "fingerprint": "aa"})})
        self.assertEqual(identity.role, "operator")
        with self.assertRaises(IdentityError):
            provider.identity_for({"bola.mtls.identity": json.dumps({"subject": "spiffe://lab/operator", "fingerprint": "aa"})})

    def test_only_start_reset_stop_are_public_lifecycle_mutations(self) -> None:
        for path in ("/management/v1/init", "/management/v1/validate"):
            response = self.request("POST", path, self.operator, body={}, headers=self.mutation_headers())
            self.assertEqual(response.status_code, 404)
        self.assertEqual(self.request("POST", "/management/v1/start", self.reader, body={}, headers=self.mutation_headers()).status_code, 403)

    def test_start_auto_provisions_validates_and_runs_one_lab(self) -> None:
        start = self.start_lab()
        self.assertEqual(start.status_code, 202)
        self.assertEqual(self.store.operation(start.json["operation_id"])["state"], "SUCCEEDED")
        self.assertEqual(self.store.status()["lifecycle"], "RUNNING")
        self.assertTrue(self.store.status()["validated"])
        self.assertEqual(self.systemd.starts, 1)
        self.assertEqual({item["status"] for item in credential_statuses(self.state_dir)}, {"ACTIVE"})
        manifest = read_private_json(state_path(self.state_dir, "manifest"))
        self.assertEqual(manifest["scenario"], "S01")
        again = self.request("POST", "/management/v1/start", self.operator, body={}, headers=self.mutation_headers(self.store.status()["state_version"], "b" * 16))
        self.assertEqual(again.status_code, 409)

    def test_start_replay_does_not_replace_the_current_run(self) -> None:
        first = self.start_lab(key="a" * 16)
        replay = self.start_lab(key="a" * 16)
        self.assertEqual(replay.status_code, 202)
        self.assertEqual(replay.json["operation_id"], first.json["operation_id"])
        self.assertEqual(self.systemd.starts, 1)

    def test_stop_revokes_credentials_and_blocks_reveal(self) -> None:
        self.assertEqual(self.start_lab().status_code, 202)
        reveal = self.request("POST", "/management/v1/credentials/userA/reveal", self.operator, body={})
        self.assertEqual(reveal.status_code, 200)
        token = reveal.json["credential"]["token"]
        stopped = self.stop_lab()
        self.assertEqual(stopped.status_code, 202)
        self.assertEqual(self.store.status()["lifecycle"], "STOPPED")
        self.assertEqual({item["status"] for item in credential_statuses(self.state_dir)}, {"REVOKED"})
        self.assertEqual(self.request("POST", "/management/v1/credentials/userA/reveal", self.operator, body={}).status_code, 409)
        self.assertNotIn(token, self.request("GET", "/management/v1/credentials/audit", self.operator).get_data(as_text=True))

    def test_reset_prepares_replacement_then_start_activates_it(self) -> None:
        self.assertEqual(self.start_lab().status_code, 202)
        old_secret = read_private_json(state_path(self.state_dir, "manifest"))["signing_secret"]
        self.assertEqual(self.stop_lab().status_code, 202)
        reset = self.request(
            "POST", "/management/v1/reset", self.operator,
            body={"scenario": "S02", "token_ttl_seconds": 3600, "confirm_invalidate_tokens": True},
            headers=self.mutation_headers(self.store.status()["state_version"], "c" * 16),
        )
        self.assertEqual(reset.status_code, 202)
        self.assertEqual(self.store.status()["lifecycle"], "READY")
        self.assertNotEqual(old_secret, read_private_json(state_path(self.state_dir, "manifest"))["signing_secret"])
        self.assertEqual(self.request("GET", "/management/v1/credentials", self.operator).json, {"credentials": []})
        start = self.request("POST", "/management/v1/start", self.operator, body={}, headers=self.mutation_headers(self.store.status()["state_version"], "d" * 16))
        self.assertEqual(start.status_code, 202)
        self.assertEqual(self.store.status()["lifecycle"], "RUNNING")
        self.assertEqual({item["status"] for item in self.request("GET", "/management/v1/credentials", self.operator).json["credentials"]}, {"ACTIVE"})

    def test_stop_and_reset_are_blocked_by_unreleased_leases(self) -> None:
        self.assertEqual(self.start_lab().status_code, 202)
        lease = self.request("POST", "/management/v1/evaluation-leases", self.evaluator, body={"duration_seconds": 60})
        self.assertEqual(lease.status_code, 201)
        self.assertEqual(self.stop_lab().status_code, 409)
        self.assertEqual(self.request("DELETE", f"/management/v1/evaluation-leases/{lease.json['lease_id']}", self.evaluator).status_code, 204)
        self.assertEqual(self.stop_lab().status_code, 202)
        reset = self.request("POST", "/management/v1/reset", self.operator, body={"scenario": "S02", "token_ttl_seconds": 3600, "confirm_invalidate_tokens": True}, headers=self.mutation_headers(self.store.status()["state_version"], "e" * 16))
        self.assertEqual(reset.status_code, 202)

    def test_unknown_lifecycle_blocks_start_and_credential_reveal(self) -> None:
        self.systemd.start_result = "activating"
        start = self.start_lab()
        self.assertEqual(start.status_code, 202)
        self.assertEqual(self.store.status()["lifecycle"], "UNKNOWN")
        self.assertEqual(self.request("POST", "/management/v1/start", self.operator, body={}, headers=self.mutation_headers(self.store.status()["state_version"], "b" * 16)).status_code, 409)
        self.assertEqual(self.request("POST", "/management/v1/credentials/userA/reveal", self.operator, body={}).status_code, 409)

    def test_preconditions_and_concurrent_operation_interlocks_remain_enforced(self) -> None:
        missing = self.request("POST", "/management/v1/start", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600})
        self.assertEqual(missing.status_code, 428)
        stale = self.request("POST", "/management/v1/start", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600}, headers=self.mutation_headers("9"))
        self.assertEqual(stale.status_code, 412)
        self.store.begin_operation(self.operator.subject, "start", "c" * 16, "0", {"scenario": "S01"})
        with self.assertRaises(LeaseConflict):
            self.store.begin_operation(self.operator.subject, "reset", "d" * 16, "0", {"scenario": "S02"})

    def console_token(self, identity: ManagementIdentity) -> str:
        response = self.request("GET", "/management/console", identity)
        self.assertEqual(response.status_code, 200)
        match = re.search(r'data-csrf-token="([^"]+)"', response.get_data(as_text=True))
        self.assertIsNotNone(match)
        return html.unescape(match.group(1))

    def console_headers(self, identity: ManagementIdentity, token: str) -> dict[str, str]:
        return {"Origin": self.console_config.origin, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "X-Management-Console": "1", "X-CSRF-Token": token}

    def test_console_role_security_and_only_simplified_controls(self) -> None:
        reader = self.request("GET", "/management/console", self.reader).get_data(as_text=True)
        operator = self.request("GET", "/management/console", self.operator).get_data(as_text=True)
        self.assertNotIn('id="credentials"', reader)
        self.assertIn('id="start-form"', operator)
        self.assertIn('data-lifecycle="stop"', operator)
        self.assertIn('id="reset-form"', operator)
        self.assertNotIn('id="init-form"', operator)
        self.assertNotIn('data-lifecycle="validate"', operator)
        self.assertNotIn('credential-issue-form', operator)
        self.assertNotIn("signing_secret", operator)

    def test_console_csrf_and_security_headers(self) -> None:
        token = self.console_token(self.operator)
        allowed = self.request("POST", "/management/v1/start", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600}, headers=self.console_headers(self.operator, token) | self.mutation_headers())
        self.assertEqual(allowed.status_code, 202)
        bad = self.request("POST", "/management/v1/start", self.operator, body={}, headers=self.console_headers(self.operator, "0.nonce.***") | self.mutation_headers("1", "b" * 16))
        self.assertEqual(bad.status_code, 403)
        console = self.request("GET", "/management/console", self.reader)
        self.assertEqual(console.headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(console.headers["X-Frame-Options"], "DENY")
        self.assertNotIn("Access-Control-Allow-Origin", console.headers)

    def test_console_source_preserves_ephemeral_token_and_live_refresh_guarantees(self) -> None:
        root = Path(__file__).parents[1]
        script = (root / "bola_lab" / "static" / "management_console.js").read_text(encoding="utf-8")
        template = (root / "bola_lab" / "templates" / "management_console.html").read_text(encoding="utf-8")
        self.assertIn("refreshLiveState", script)
        self.assertIn("window.isSecureContext", script)
        self.assertIn("clearCredentialMemory", script)
        self.assertIn('cache: "no-store"', script)
        self.assertNotIn("localStorage", script)
        self.assertNotIn("sessionStorage", script)
        self.assertNotIn("IndexedDB", script)
        self.assertNotIn("credential-issue-form", template)
        self.assertNotIn("init-form", template)

    def test_control_journal_and_public_contract_keep_secrets_out(self) -> None:
        self.assertEqual(self.start_lab().status_code, 202)
        token = self.request("POST", "/management/v1/credentials/userA/reveal", self.operator, body={}).json["credential"]["token"]
        connection = sqlite3.connect(self.store.path)
        try:
            journal = "\n".join(str(value) for row in connection.execute("SELECT * FROM operations") for value in row)
        finally:
            connection.close()
        self.assertNotIn(token, journal)
        self.assertNotIn("token_ttl_seconds", journal)
        public_contract = (Path(__file__).parents[1] / "openapi_specs" / "bola-lab.openapi.json").read_text(encoding="utf-8")
        self.assertNotIn("management/v1", public_contract)
        self.assertNotIn("credential", public_contract)

    def test_console_config_rejects_non_https_or_weak_origins(self) -> None:
        with self.assertRaises(ConsoleConfigurationError):
            ConsoleConfig(origin="http://management.example.test", csrf_secret=b"c" * 32)
        with self.assertRaises(ConsoleConfigurationError):
            ConsoleConfig(origin="https://management.example.test", csrf_secret=b"short")


if __name__ == "__main__":
    unittest.main(verbosity=2)
