"""Separate mTLS-authenticated management API for the Controlled BOLA Lab."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from flask import Flask, Response, g, render_template, request, send_from_directory

from .control.identity import IdentityError, IdentityProvider, ManagementIdentity, MTLSIdentityProvider
from .control.lifecycle import IndeterminateLifecycleError, LifecycleError, RunLifecycle
from .control.store import (
    ControlStore,
    ControlStoreError,
    IdempotencyConflict,
    LeaseConflict,
    PreconditionRequired,
    StaleVersion,
)
from .scenarios import SCENARIOS
from .storage import (
    StateError,
    read_private_json,
    state_path,
    active_claims_for_subject,
    credential_statuses,
    issue_initial_credentials,
    revoke_all_credentials,
)
from .tokens import issue_token


class ManagementStartupError(RuntimeError):
    """The isolated management service cannot be started safely."""


class ConsoleConfigurationError(ValueError):
    """The browser console cannot be configured safely."""


def _console_clock() -> int:
    return int(time.time())


@dataclass(frozen=True)
class ConsoleConfig:
    """Deployment-pinned browser-console protections."""

    origin: str
    csrf_secret: bytes
    csrf_ttl_seconds: int = 900
    clock: Callable[[], int] = _console_clock

    def __post_init__(self) -> None:
        parsed = urlsplit(self.origin)
        try:
            valid_port = parsed.port is None or 1 <= parsed.port <= 65535
        except ValueError:
            valid_port = False
        if (
            self.origin != f"https://{parsed.netloc}"
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname != parsed.hostname.lower()
            or parsed.port == 443
            or parsed.username is not None
            or parsed.password is not None
            or not valid_port
        ):
            raise ConsoleConfigurationError("Console origin must be an exact HTTPS origin.")
        if not isinstance(self.csrf_secret, bytes) or len(self.csrf_secret) < 32:
            raise ConsoleConfigurationError("Console CSRF secret is too short.")
        if not 300 <= self.csrf_ttl_seconds <= 1800:
            raise ConsoleConfigurationError("Console CSRF lifetime is outside the allowed range.")


def _response(payload: dict[str, Any], status: int = 200, headers: dict[str, str] | None = None) -> Response:
    response = Response(response=None, status=status, mimetype="application/json")
    response.set_data(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    if headers:
        response.headers.update(headers)
    return response


def _error(code: str, message: str, status: int) -> Response:
    return _response({"code": code, "message": message, "request_id": str(uuid.uuid4())}, status)


def _payload(required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    if set(data) - required - optional or not required.issubset(data):
        raise ValueError("Request body does not match the required schema.")
    return data


def _csrf_payload(identity: ManagementIdentity, issued_at: int, nonce: str) -> bytes:
    return f"{identity.subject}\x00{identity.certificate_fingerprint}\x00{issued_at}\x00{nonce}".encode()


def _issue_console_csrf_token(config: ConsoleConfig, identity: ManagementIdentity) -> str:
    issued_at = config.clock()
    nonce = secrets.token_urlsafe(18)
    payload = _csrf_payload(identity, issued_at, nonce)
    signature = hmac.new(config.csrf_secret, payload, hashlib.sha256).digest()
    return ".".join(
        (
            str(issued_at),
            nonce,
            base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
        )
    )


def _valid_console_csrf_token(config: ConsoleConfig, identity: ManagementIdentity, token: str | None) -> bool:
    if not token:
        return False
    try:
        issued_at_text, nonce, signature_text = token.split(".")
        issued_at = int(issued_at_text)
        now = config.clock()
        if issued_at > now or now - issued_at > config.csrf_ttl_seconds:
            return False
        supplied = base64.urlsafe_b64decode(f"{signature_text}{'=' * (-len(signature_text) % 4)}")
    except (ValueError, UnicodeEncodeError, binascii.Error):
        return False
    expected = hmac.new(config.csrf_secret, _csrf_payload(identity, issued_at, nonce), hashlib.sha256).digest()
    return hmac.compare_digest(supplied, expected)


def create_management_app(
    *,
    store: ControlStore,
    lifecycle: RunLifecycle,
    identity_provider: IdentityProvider | None = None,
    console_config: ConsoleConfig | None = None,
) -> Flask:
    """Create the management-only app; production uses deployment mTLS injection."""
    try:
        store.initialize()
    except ControlStoreError as exc:
        raise ManagementStartupError("Management state cannot be initialized safely.") from exc
    provider = identity_provider or MTLSIdentityProvider.from_environment()
    app = Flask(__name__, static_folder=None)
    app.config.update(JSON_AS_ASCII=False, PROPAGATE_EXCEPTIONS=False)
    console_static_root = Path(__file__).with_name("static")
    console_assets = {"management_console.css", "management_console.js"}

    def console_enabled() -> Response | None:
        if console_config is None:
            return _error("not_found", "Management console is unavailable.", 404)
        return None

    def browser_mutation_is_valid() -> bool:
        return request.headers.get("X-Management-Console") == "1" and request.method in {"POST", "DELETE"}

    def console_request_is_valid() -> bool:
        return (
            request.headers.get("Origin") == console_config.origin
            and request.headers.get("Sec-Fetch-Site") == "same-origin"
            and request.headers.get("Sec-Fetch-Mode") == "cors"
            and request.headers.get("Sec-Fetch-Dest") == "empty"
            and _valid_console_csrf_token(console_config, g.management_identity, request.headers.get("X-CSRF-Token"))
        )

    @app.get("/management/console")
    def console() -> Response | str:
        unavailable = console_enabled()
        if unavailable:
            return unavailable
        denied = require("reader", "operator", "evaluator")
        if denied:
            return denied
        return render_template(
            "management_console.html",
            role=identity().role,
            csrf_token=_issue_console_csrf_token(console_config, identity()),
        )

    @app.get("/management/console/static/<asset>")
    def console_static(asset: str) -> Response:
        unavailable = console_enabled()
        if unavailable:
            return unavailable
        if asset not in console_assets:
            return _error("not_found", "Management console asset was not found.", 404)
        return send_from_directory(console_static_root, asset, max_age=0)

    @app.get("/static/<path:_unused>")
    def reject_default_static(_unused: str) -> Response:
        return _error("not_found", "Management console asset was not found.", 404)

    @app.before_request
    def authenticate_management() -> Response | None:
        try:
            g.management_identity = provider.identity_for(request.environ)
        except IdentityError:
            return _error("unauthenticated", "Verified management identity is required.", 401)
        if browser_mutation_is_valid():
            if console_config is None or not console_request_is_valid():
                return _error("forbidden", "Console request protection is invalid.", 403)
        return None

    @app.after_request
    def apply_management_security_headers(response: Response) -> Response:
        response.headers.update(
            {
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
            }
        )
        return response

    def identity() -> ManagementIdentity:
        return g.management_identity

    def require(*roles: str) -> Response | None:
        if identity().role not in roles:
            return _error("forbidden", "Management role is not permitted for this operation.", 403)
        return None

    def signed_credential(claims: dict[str, Any]) -> dict[str, Any]:
        try:
            manifest = read_private_json(state_path(lifecycle.state_dir, "manifest"))
            secret = manifest["signing_secret"]
            if not isinstance(secret, str):
                raise StateError("Lab credential material is unavailable.")
            token = issue_token(claims["sub"], claims["role"], claims["jti"], secret, claims["exp"])
        except (KeyError, StateError) as exc:
            raise StateError("Lab credential material is unavailable.") from exc
        return {
            "username": claims["sub"],
            "role": claims["role"],
            "issued_at": claims["issued_at"],
            "expires_at": claims["exp"],
            "token": token,
        }

    def credential_error(action: str, result: str, status: int, message: str, *, subject: str | None = None) -> Response:
        store.record_credential_audit(identity().subject, action, result, subject=subject)
        return _error("state_conflict" if status == 409 else "invalid_request", message, status)

    def mutating(route: str, body: dict[str, Any], guard: Any = None) -> tuple[str, Response | None]:

        try:
            operation_id, replay = store.begin_operation(
                identity().subject,
                route,
                request.headers.get("Idempotency-Key"),
                request.headers.get("If-Match"),
                body,
                guard,
            )
        except PreconditionRequired as exc:
            return "", _error("precondition_required", str(exc), 428)
        except StaleVersion as exc:
            return "", _error("stale_state_version", str(exc), 412)
        except (IdempotencyConflict, ControlStoreError) as exc:
            return "", _error("state_conflict", str(exc), 409)
        if replay:
            return operation_id, _response({"operation_id": operation_id}, 202, {"Location": f"/management/v1/operations/{operation_id}"})
        return operation_id, None

    def run_transition(operation_id: str, action: str, callback: Any, success: dict[str, Any] | Any) -> Response:
        try:
            result = callback()
            store.finish_operation(operation_id, "ok", **(success(result) if callable(success) else success))
        except IndeterminateLifecycleError:
            store.mark_operation_unknown(operation_id, "transition_indeterminate")
        except LifecycleError:
            store.fail_operation(operation_id, "transition_rejected")
        return _response({"operation_id": operation_id}, 202, {"Location": f"/management/v1/operations/{operation_id}"})

    @app.get("/management/v1/status")
    def status() -> Response:
        denied = require("reader", "operator", "evaluator")
        if denied:
            return denied
        return _response(store.status())

    @app.get("/management/v1/scenarios")
    def scenarios() -> Response:
        denied = require("reader", "operator", "evaluator")
        if denied:
            return denied
        return _response({"scenarios": [{"code": code, "description": item.description} for code, item in SCENARIOS.items()]})

    @app.post("/management/v1/start")
    def start() -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            body = _payload(set(), {"scenario", "token_ttl_seconds"})
        except ValueError as exc:
            return _error("invalid_request", str(exc), 422)

        start_state: str | None = None

        def start_guard(connection: Any, state: Any) -> None:
            nonlocal start_state
            if state["lifecycle"] not in {"UNINITIALIZED", "READY"}:
                raise LeaseConflict("Start requires an uninitialized or prepared lab.")
            if state["lifecycle"] == "UNINITIALIZED":
                if set(body) != {"scenario", "token_ttl_seconds"} or not isinstance(body["token_ttl_seconds"], int) or isinstance(body["token_ttl_seconds"], bool):
                    raise LeaseConflict("Initial start requires a scenario and token lifetime.")
            elif body:
                raise LeaseConflict("A prepared lab starts without new configuration.")
            store.require_no_unreleased_leases(connection, state)
            start_state = state["lifecycle"]

        operation_id, error = mutating("start", body, start_guard)
        if error:
            return error

        def provision_and_start() -> None:
            if start_state == "UNINITIALIZED":
                lifecycle.provision(body["scenario"], body["token_ttl_seconds"])
                try:
                    claims = issue_initial_credentials(lifecycle.state_dir, body["token_ttl_seconds"], operation_id)
                except StateError as exc:
                    raise LifecycleError("Test credentials could not be provisioned safely.") from exc
                for claim in claims:
                    store.record_credential_audit(
                        identity().subject,
                        "issued",
                        "ok",
                        subject=claim["sub"],
                        role=claim["role"],
                    )
            else:
                lifecycle.validate()
            lifecycle.start()

        return run_transition(
            operation_id,
            "start",
            provision_and_start,
            {"lifecycle": "RUNNING", "validated": True, "scenario": body.get("scenario"), "rotate_generation": start_state == "UNINITIALIZED"},
        )

    @app.post("/management/v1/stop")
    def stop() -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            body = _payload(set())
        except ValueError as exc:
            return _error("invalid_request", str(exc), 422)
        operation_id, error = mutating("stop", body, store.require_no_unreleased_leases)
        if error:
            return error
        current = store.status()

        def revoke_and_stop() -> None:
            revoked = revoke_all_credentials(lifecycle.state_dir)
            if revoked:
                store.record_credential_audit(identity().subject, "revoked", "ok")
            lifecycle.stop()

        return run_transition(
            operation_id,
            "stop",
            revoke_and_stop,
            {"lifecycle": "STOPPED", "validated": current["validated"], "scenario": None},
        )

    @app.post("/management/v1/reset")
    def reset() -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            body = _payload({"scenario", "token_ttl_seconds", "confirm_invalidate_tokens"})
        except ValueError as exc:
            return _error("invalid_request", str(exc), 422)
        if body["confirm_invalidate_tokens"] is not True:
            return _error("invalid_request", "Token invalidation confirmation is required.", 422)

        def reset_guard(connection: Any, state: Any) -> None:
            if state["lifecycle"] not in {"UNINITIALIZED", "STOPPED"}:
                raise LeaseConflict("Reset requires stopped state.")
            store.require_no_unreleased_leases(connection, state)

        operation_id, error = mutating("reset", body, reset_guard)
        if error:
            return error
        def provision_reset() -> None:
            lifecycle.provision(body["scenario"], body["token_ttl_seconds"])
            try:
                claims = issue_initial_credentials(lifecycle.state_dir, body["token_ttl_seconds"], operation_id)
            except StateError as exc:
                raise LifecycleError("Test credentials could not be provisioned safely.") from exc
            for claim in claims:
                store.record_credential_audit(
                    identity().subject,
                    "issued",
                    "ok",
                    subject=claim["sub"],
                    role=claim["role"],
                )

        return run_transition(
            operation_id,
            "reset",
            provision_reset,
            {"lifecycle": "READY", "validated": True, "scenario": body["scenario"], "rotate_generation": True},
        )

    def current_running_lab() -> None:
        if store.status()["lifecycle"] != "RUNNING":
            raise StateError("A running lab is required for test credentials.")

    @app.get("/management/v1/credentials")
    def credentials() -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            current_running_lab()
            return _response({"credentials": credential_statuses(lifecycle.state_dir)})
        except StateError:
            return _response({"credentials": []})

    @app.post("/management/v1/credentials/<subject>/reveal")
    def reveal_credential(subject: str) -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            current_running_lab()
            claims = active_claims_for_subject(lifecycle.state_dir, subject)
            store.record_credential_audit(identity().subject, "revealed", "ok", subject=subject, role=claims["role"])
            return _response({"credential": signed_credential(claims)})
        except StateError:
            return credential_error("revealed", "unavailable", 409, "Active credential is unavailable.", subject=subject)

    @app.post("/management/v1/credentials/<subject>/copy-audit")
    def copy_credential_audit(subject: str) -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            current_running_lab()
            claims = active_claims_for_subject(lifecycle.state_dir, subject)
            store.record_credential_audit(identity().subject, "copy_requested", "ok", subject=subject, role=claims["role"])
            return Response(status=204)
        except StateError:
            return credential_error("copy_requested", "unavailable", 409, "Active credential is unavailable.", subject=subject)

    @app.get("/management/v1/credentials/audit")
    def credential_audit() -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            return _response({"events": store.credential_audit()})
        except ValueError:
            return _error("invalid_request", "Audit history is unavailable.", 422)

    @app.get("/management/v1/operations/<operation_id>")
    def operation(operation_id: str) -> Response:
        denied = require("reader", "operator", "evaluator")
        if denied:
            return denied
        item = store.operation(operation_id)
        if not item:
            return _error("not_found", "Operation was not found.", 404)
        return _response(item)

    @app.post("/management/v1/evaluation-leases")
    def acquire_lease() -> Response:
        denied = require("evaluator")
        if denied:
            return denied
        try:
            body = _payload({"duration_seconds"})
            item = store.acquire_lease(identity().subject, body["duration_seconds"])
        except (ValueError, LeaseConflict) as exc:
            return _error("state_conflict", str(exc), 409)
        return _response(item, 201)

    @app.post("/management/v1/evaluation-leases/<lease_id>/renew")
    def renew_lease(lease_id: str) -> Response:
        denied = require("evaluator")
        if denied:
            return denied
        try:
            body = _payload({"duration_seconds"})
            item = store.renew_lease(identity().subject, lease_id, body["duration_seconds"])
        except (ValueError, LeaseConflict) as exc:
            return _error("state_conflict", str(exc), 409)
        return _response(item)

    @app.delete("/management/v1/evaluation-leases/<lease_id>")
    def release_lease(lease_id: str) -> Response:
        denied = require("evaluator")
        if denied:
            return denied
        if not store.release_lease(identity().subject, lease_id):
            return _error("not_found", "Evaluation lease was not found.", 404)
        return Response(status=204)

    @app.errorhandler(404)
    def not_found(_: Exception) -> Response:
        return _error("not_found", "Management route was not found.", 404)

    @app.errorhandler(Exception)
    def unhandled(_: Exception) -> Response:
        return _error("service_unavailable", "Management service is unavailable.", 503)

    return app
