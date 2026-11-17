"""Run the separate mTLS-fronted BOLA management service on loopback."""

from __future__ import annotations

import os
import sys

from bola_lab.control.lifecycle import RunLifecycle
from bola_lab.control.store import ControlStore
from bola_lab.control.systemd import PinnedSystemdAdapter, SupervisorError
from bola_lab.management import ManagementStartupError, create_management_app


if __name__ == "__main__":
    try:
        state_dir = os.environ["BOLA_LAB_STATE_DIR"]
        control_dir = os.environ["BOLA_MGMT_STATE_DIR"]
        unit = os.environ["BOLA_MGMT_SYSTEMD_UNIT"]
        port = int(os.environ.get("BOLA_MGMT_PORT", "5443"))
        if not 1 <= port <= 65535:
            raise ValueError
        adapter = PinnedSystemdAdapter(unit)
        application = create_management_app(store=ControlStore(control_dir), lifecycle=RunLifecycle(state_dir, adapter))
    except (KeyError, ValueError, SupervisorError, ManagementStartupError):
        print("BOLA management service cannot start with the configured deployment boundary.", file=sys.stderr)
        raise SystemExit(2)
    application.run(host="127.0.0.1", port=port, debug=False)
