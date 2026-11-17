"""mTLS identity boundary for the BOLA management service.

A TLS terminator, not a client request header, is responsible for injecting the
verified identity into WSGI. The app deliberately rejects all other sources.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Mapping, Protocol


class IdentityError(RuntimeError):
    """The trusted mTLS deployment boundary did not provide a valid identity."""


@dataclass(frozen=True)
class ManagementIdentity:
    subject: str
    role: str
    certificate_fingerprint: str


class IdentityProvider(Protocol):
    def identity_for(self, environ: Mapping[str, object]) -> ManagementIdentity: ...


class MTLSIdentityProvider:
    """Read only deployment-injected identity data after verified mTLS."""

    environ_key = "bola.mtls.identity"

    def __init__(self, role_mapping: Mapping[str, str]) -> None:
        self._roles = dict(role_mapping)

    @classmethod
    def from_environment(cls) -> "MTLSIdentityProvider":
        raw = os.environ.get("BOLA_MGMT_ROLE_MAPPING")
        if not raw:
            raise IdentityError("Management role mapping is not configured.")
        try:
            roles = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise IdentityError("Management role mapping is invalid.") from exc
        if not isinstance(roles, dict) or not all(
            isinstance(subject, str) and isinstance(role, str) for subject, role in roles.items()
        ):
            raise IdentityError("Management role mapping is invalid.")
        return cls(roles)

    def identity_for(self, environ: Mapping[str, object]) -> ManagementIdentity:
        if environ.get("BOLA_MGMT_TLS_VERIFIED") != "SUCCESS":
            raise IdentityError("Verified mTLS identity is required.")
        value = environ.get(self.environ_key)
        if not isinstance(value, str):
            raise IdentityError("Verified mTLS identity is required.")
        try:
            item = json.loads(value)
        except json.JSONDecodeError as exc:
            raise IdentityError("Verified mTLS identity is invalid.") from exc
        if not isinstance(item, dict):
            raise IdentityError("Verified mTLS identity is invalid.")
        subject = item.get("subject")
        fingerprint = item.get("fingerprint")
        if not isinstance(subject, str) or not subject or not isinstance(fingerprint, str) or not fingerprint:
            raise IdentityError("Verified mTLS identity is invalid.")
        role = self._roles.get(subject)
        if role not in {"reader", "operator", "evaluator"}:
            raise IdentityError("Management identity is not authorized.")
        return ManagementIdentity(subject, role, fingerprint)


class StaticTestIdentityProvider:
    """Test-only injection seam; never used by the production launcher."""

    def identity_for(self, environ: Mapping[str, object]) -> ManagementIdentity:
        value = environ.get("bola.test.identity")
        if not isinstance(value, ManagementIdentity):
            raise IdentityError("Verified mTLS identity is required.")
        return value
