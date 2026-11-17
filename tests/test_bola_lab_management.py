"""Security and lifecycle coverage for the isolated BOLA management API."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from bola_lab.control.identity import IdentityError, MTLSIdentityProvider, ManagementIdentity, StaticTestIdentityProvider
from bola_lab.control.lifecycle import RunLifecycle
from bola_lab.control.store import ControlStore, LeaseConflict
from bola_lab.control.systemd import SupervisorError
from bola_lab.management import create_management_app


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
        self.app = create_management_app(
            store=self.store,
            lifecycle=RunLifecycle(str(self.state_dir), self.systemd),
            identity_provider=StaticTestIdentityProvider(),
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

    def test_missing_identity_and_bola_bearer_fail_closed(self) -> None:
        response = self.request("GET", "/management/v1/status", None, headers={"Authorization": "Bearer test-token"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json["code"], "unauthenticated")

    def test_untrusted_headers_do_not_create_identity(self) -> None:
        response = self.client.get("/management/v1/status", headers={"X-Client-Cert": "attacker", "X-Forwarded-For": "127.0.0.1"})
        self.assertEqual(response.status_code, 401)

    def test_production_identity_requires_verified_environ_and_mapped_role(self) -> None:
        provider = MTLSIdentityProvider({"spiffe://lab/operator": "operator"})
        identity = provider.identity_for(
            {
                "BOLA_MGMT_TLS_VERIFIED": "SUCCESS",
                "bola.mtls.identity": json.dumps({"subject": "spiffe://lab/operator", "fingerprint": "aa"}),
                "HTTP_X_CLIENT_CERT": "attacker",
            }
        )
        self.assertEqual(identity.role, "operator")
        with self.assertRaises(IdentityError):
            provider.identity_for({"bola.mtls.identity": json.dumps({"subject": "spiffe://lab/operator", "fingerprint": "aa"})})
        with self.assertRaises(IdentityError):
            provider.identity_for(
                {"BOLA_MGMT_TLS_VERIFIED": "SUCCESS", "bola.mtls.identity": json.dumps({"subject": "spiffe://lab/unknown", "fingerprint": "aa"})}
            )

    def test_reader_cannot_mutate(self) -> None:
        response = self.request("POST", "/management/v1/init", self.reader, body={"scenario": "S01", "token_ttl_seconds": 3600}, headers=self.mutation_headers())
        self.assertEqual(response.status_code, 403)

    def test_init_validation_start_leases_stop_and_reset_interlocks(self) -> None:
        init = self.request("POST", "/management/v1/init", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600}, headers=self.mutation_headers())
        self.assertEqual(init.status_code, 202)
        self.assertEqual(self.store.operation(init.json["operation_id"])["state"], "SUCCEEDED")
        self.assertEqual(self.store.status()["lifecycle"], "STOPPED")
        status_body = self.request("GET", "/management/v1/status", self.reader).get_data(as_text=True).lower()
        self.assertNotIn("signing_secret", status_body)
        self.assertNotIn("marker-", status_body)

        validate = self.request("POST", "/management/v1/validate", self.operator, body={}, headers=self.mutation_headers("1", "b" * 16))
        self.assertEqual(validate.status_code, 202)
        start = self.request("POST", "/management/v1/start", self.operator, body={}, headers=self.mutation_headers("2", "c" * 16))
        self.assertEqual(start.status_code, 202)
        self.assertEqual(self.systemd.starts, 1)

        lease = self.request("POST", "/management/v1/evaluation-leases", self.evaluator, body={"duration_seconds": 120})
        self.assertEqual(lease.status_code, 201)
        stop = self.request("POST", "/management/v1/stop", self.operator, body={}, headers=self.mutation_headers("3", "d" * 16))
        self.assertEqual(stop.status_code, 409)
        release = self.request("DELETE", f"/management/v1/evaluation-leases/{lease.json['lease_id']}", self.evaluator)
        self.assertEqual(release.status_code, 204)
        stop = self.request("POST", "/management/v1/stop", self.operator, body={}, headers=self.mutation_headers("3", "e" * 16))
        self.assertEqual(stop.status_code, 202)
        reset = self.request("POST", "/management/v1/reset", self.operator, body={"scenario": "S02", "token_ttl_seconds": 3600, "confirm_invalidate_tokens": True}, headers=self.mutation_headers("4", "f" * 16))
        self.assertEqual(reset.status_code, 202)
        self.assertEqual(self.store.status()["credential_generation"], 2)

    def initialize_validated_running_lab(self) -> None:
        init = self.request("POST", "/management/v1/init", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600}, headers=self.mutation_headers())
        self.assertEqual(init.status_code, 202)
        validate = self.request("POST", "/management/v1/validate", self.operator, body={}, headers=self.mutation_headers("1", "b" * 16))
        self.assertEqual(validate.status_code, 202)
        start = self.request("POST", "/management/v1/start", self.operator, body={}, headers=self.mutation_headers("2", "c" * 16))
        self.assertEqual(start.status_code, 202)

    def test_expired_unreleased_lease_blocks_stop_until_explicit_release(self) -> None:
        self.initialize_validated_running_lab()
        lease = self.request("POST", "/management/v1/evaluation-leases", self.evaluator, body={"duration_seconds": 60})
        self.assertEqual(lease.status_code, 201)
        connection = sqlite3.connect(self.store.path)
        try:
            connection.execute("UPDATE leases SET expires_at = 0 WHERE lease_id = ?", (lease.json["lease_id"],))
            connection.commit()
        finally:
            connection.close()
        status = self.request("GET", "/management/v1/status", self.reader)
        self.assertEqual(status.json["evaluation_leases"], {"active": 0, "expired_unreleased": 1})
        stop = self.request("POST", "/management/v1/stop", self.operator, body={}, headers=self.mutation_headers("3", "d" * 16))
        self.assertEqual(stop.status_code, 409)
        release = self.request("DELETE", f"/management/v1/evaluation-leases/{lease.json['lease_id']}", self.evaluator)
        self.assertEqual(release.status_code, 204)
        stop = self.request("POST", "/management/v1/stop", self.operator, body={}, headers=self.mutation_headers("3", "e" * 16))
        self.assertEqual(stop.status_code, 202)

    def test_replay_precedes_state_checks_and_reservation_blocks_new_lease(self) -> None:
        self.initialize_validated_running_lab()
        reservation, _ = self.store.begin_operation("spiffe://lab/operator", "stop", "e" * 16, "3", {})
        lease = self.request("POST", "/management/v1/evaluation-leases", self.evaluator, body={"duration_seconds": 60})
        self.assertEqual(lease.status_code, 409)
        self.store.fail_operation(reservation, "test_cleanup")

        headers = self.mutation_headers("3", "d" * 16)
        first = self.request("POST", "/management/v1/stop", self.operator, body={}, headers=headers)
        self.assertEqual(first.status_code, 202)
        replay = self.request("POST", "/management/v1/stop", self.operator, body={}, headers=headers)
        self.assertEqual(replay.status_code, 202)
        self.assertEqual(replay.json["operation_id"], first.json["operation_id"])

    def test_indeterminate_supervisor_transition_marks_control_state_unknown(self) -> None:
        init = self.request("POST", "/management/v1/init", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600}, headers=self.mutation_headers())
        self.assertEqual(init.status_code, 202)
        validate = self.request("POST", "/management/v1/validate", self.operator, body={}, headers=self.mutation_headers("1", "b" * 16))
        self.assertEqual(validate.status_code, 202)
        self.systemd.start_result = "activating"
        start = self.request("POST", "/management/v1/start", self.operator, body={}, headers=self.mutation_headers("2", "c" * 16))
        self.assertEqual(start.status_code, 202)
        self.assertEqual(self.store.operation(start.json["operation_id"])["state"], "UNKNOWN")
        self.assertEqual(self.store.status()["lifecycle"], "UNKNOWN")
        blocked = self.request("POST", "/management/v1/stop", self.operator, body={}, headers=self.mutation_headers("3", "d" * 16))
        self.assertEqual(blocked.status_code, 409)

    def test_supervisor_timeout_marks_control_state_unknown(self) -> None:
        init = self.request("POST", "/management/v1/init", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600}, headers=self.mutation_headers())
        self.assertEqual(init.status_code, 202)
        validate = self.request("POST", "/management/v1/validate", self.operator, body={}, headers=self.mutation_headers("1", "b" * 16))
        self.assertEqual(validate.status_code, 202)
        self.systemd.start_error = True
        start = self.request("POST", "/management/v1/start", self.operator, body={}, headers=self.mutation_headers("2", "c" * 16))
        self.assertEqual(start.status_code, 202)
        self.assertEqual(self.store.operation(start.json["operation_id"])["state"], "UNKNOWN")
        self.assertEqual(self.store.status()["lifecycle"], "UNKNOWN")

    def test_idempotent_replay_does_not_repeat_initialization(self) -> None:
        headers = self.mutation_headers()
        body = {"scenario": "S01", "token_ttl_seconds": 3600}
        first = self.request("POST", "/management/v1/init", self.operator, body=body, headers=headers)
        second = self.request("POST", "/management/v1/init", self.operator, body=body, headers=headers)
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.json["operation_id"], first.json["operation_id"])
        conflict = self.request("POST", "/management/v1/init", self.operator, body={"scenario": "S02", "token_ttl_seconds": 3600}, headers=headers)
        self.assertEqual(conflict.status_code, 409)

    def test_stale_version_and_missing_precondition_are_rejected(self) -> None:
        missing = self.request("POST", "/management/v1/init", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600})
        self.assertEqual(missing.status_code, 428)
        stale = self.request("POST", "/management/v1/init", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600}, headers=self.mutation_headers("9"))
        self.assertEqual(stale.status_code, 412)

    def test_interrupted_operation_becomes_unknown_and_blocks_writes(self) -> None:
        operation_id, replay = self.store.begin_operation("spiffe://lab/operator", "init", "a" * 16, "0", {"scenario": "S01"})
        self.assertFalse(replay)
        restarted = ControlStore(self.store.root)
        restarted.initialize()
        self.assertEqual(restarted.operation(operation_id)["state"], "UNKNOWN")
        self.assertEqual(restarted.status()["lifecycle"], "UNKNOWN")
        response = self.request("POST", "/management/v1/init", self.operator, body={"scenario": "S01", "token_ttl_seconds": 3600}, headers=self.mutation_headers("1", "b" * 16))
        self.assertEqual(response.status_code, 409)

    def test_running_operation_blocks_parallel_lifecycle_write(self) -> None:
        self.store.begin_operation("spiffe://lab/operator", "init", "a" * 16, "0", {"scenario": "S01"})
        with self.assertRaises(LeaseConflict):
            self.store.begin_operation("spiffe://lab/operator", "reset", "b" * 16, "0", {"scenario": "S02"})

    def test_control_journal_excludes_lifecycle_payload_and_private_state_path(self) -> None:
        body = {"scenario": "S01", "token_ttl_seconds": 3600}
        response = self.request("POST", "/management/v1/init", self.operator, body=body, headers=self.mutation_headers())
        self.assertEqual(response.status_code, 202)
        connection = sqlite3.connect(self.store.path)
        try:
            journal_text = "\n".join(str(item) for row in connection.execute("SELECT * FROM operations") for item in row)
        finally:
            connection.close()
        self.assertNotIn("token_ttl_seconds", journal_text)
        self.assertNotIn(str(self.state_dir), journal_text)
        self.assertNotIn("signing_secret", journal_text)

    def test_public_bola_contract_has_no_management_routes(self) -> None:
        public_contract = (Path(__file__).parents[1] / "openapi_specs" / "bola-lab.openapi.json").read_text(encoding="utf-8")
        self.assertNotIn("management/v1", public_contract)
        self.assertNotIn("credential-handoffs", public_contract)


if __name__ == "__main__":
    unittest.main(verbosity=2)
