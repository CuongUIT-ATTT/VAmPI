"""Separate mTLS-authenticated management API for the Controlled BOLA Lab."""

from __future__ import annotations

import uuid
from typing import Any

from flask import Flask, Response, g, request

from .control.identity import IdentityError, IdentityProvider, ManagementIdentity, MTLSIdentityProvider
from .control.lifecycle import LifecycleError, RunLifecycle
from .control.store import (
    ControlStore,
    ControlStoreError,
    IdempotencyConflict,
    LeaseConflict,
    PreconditionRequired,
    StaleVersion,
)
from .scenarios import SCENARIOS


class ManagementStartupError(RuntimeError):
    """The isolated management service cannot be started safely."""


def _response(payload: dict[str, Any], status: int = 200, headers: dict[str, str] | None = None) -> Response:
    response = Response(response=None, status=status, mimetype="application/json")
    response.set_data(__import__("json").dumps(payload, sort_keys=True, separators=(",", ":")))
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


def create_management_app(*, store: ControlStore, lifecycle: RunLifecycle, identity_provider: IdentityProvider | None = None) -> Flask:
    """Create the management-only app; production uses deployment mTLS injection."""
    try:
        store.initialize()
    except ControlStoreError as exc:
        raise ManagementStartupError("Management state cannot be initialized safely.") from exc
    provider = identity_provider or MTLSIdentityProvider.from_environment()
    app = Flask(__name__)
    app.config.update(JSON_AS_ASCII=False, PROPAGATE_EXCEPTIONS=False)

    @app.before_request
    def authenticate_management() -> Response | None:
        try:
            g.management_identity = provider.identity_for(request.environ)
        except IdentityError:
            return _error("unauthenticated", "Verified management identity is required.", 401)
        return None

    def identity() -> ManagementIdentity:
        return g.management_identity

    def require(*roles: str) -> Response | None:
        if identity().role not in roles:
            return _error("forbidden", "Management role is not permitted for this operation.", 403)
        return None

    def mutating(route: str, body: dict[str, Any]) -> tuple[str, Response | None]:
        try:
            operation_id, replay = store.begin_operation(identity().subject, route, request.headers.get("Idempotency-Key"), request.headers.get("If-Match"), body)
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

    @app.post("/management/v1/init")
    def init() -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            body = _payload({"scenario", "token_ttl_seconds"})
        except ValueError as exc:
            return _error("invalid_request", str(exc), 422)
        operation_id, error = mutating("init", body)
        if error:
            return error
        return run_transition(operation_id, "init", lambda: lifecycle.init(body["scenario"], body["token_ttl_seconds"]), lambda expiry: {"lifecycle": "STOPPED", "validated": False, "scenario": body["scenario"], "token_expires_at": expiry, "rotate_generation": True})

    @app.post("/management/v1/validate")
    def validate() -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            body = _payload(set())
        except ValueError as exc:
            return _error("invalid_request", str(exc), 422)
        operation_id, error = mutating("validate", body)
        if error:
            return error
        def validate_transition() -> None:
            expiry = lifecycle.validate()
            store.finish_operation(operation_id, "ok", lifecycle="STOPPED", validated=True, scenario=None, token_expires_at=expiry)
        try:
            validate_transition()
        except LifecycleError:
            store.fail_operation(operation_id, "validation_failed")
        return _response({"operation_id": operation_id}, 202, {"Location": f"/management/v1/operations/{operation_id}"})

    @app.post("/management/v1/start")
    def start() -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            body = _payload(set())
        except ValueError as exc:
            return _error("invalid_request", str(exc), 422)
        current = store.status()
        if not current["validated"]:
            return _error("state_conflict", "Lab state must be validated before start.", 409)
        operation_id, error = mutating("start", body)
        if error:
            return error
        return run_transition(operation_id, "start", lifecycle.start, {"lifecycle": "RUNNING", "validated": True, "scenario": None, "token_expires_at": current["token_expires_at"]})

    @app.post("/management/v1/stop")
    def stop() -> Response:
        denied = require("operator")
        if denied:
            return denied
        try:
            body = _payload(set())
        except ValueError as exc:
            return _error("invalid_request", str(exc), 422)
        if store.active_leases():
            return _error("evaluation_busy", "Active evaluation leases block stop.", 409)
        operation_id, error = mutating("stop", body)
        if error:
            return error
        current = store.status()
        return run_transition(operation_id, "stop", lifecycle.stop, {"lifecycle": "STOPPED", "validated": current["validated"], "scenario": None, "token_expires_at": current["token_expires_at"]})

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
        if store.status()["lifecycle"] != "STOPPED" or store.active_leases():
            return _error("state_conflict", "Reset requires stopped state without active leases.", 409)
        operation_id, error = mutating("reset", body)
        if error:
            return error
        return run_transition(operation_id, "reset", lambda: lifecycle.reset(body["scenario"], body["token_ttl_seconds"]), lambda expiry: {"lifecycle": "STOPPED", "validated": False, "scenario": body["scenario"], "token_expires_at": expiry, "rotate_generation": True})

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

    @app.errorhandler(Exception)
    def unhandled(_: Exception) -> Response:
        return _error("service_unavailable", "Management service is unavailable.", 503)

    return app
