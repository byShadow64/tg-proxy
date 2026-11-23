"""Docker launch without a shell or copying a secret into process arguments."""
from __future__ import annotations

import os
import sys


def main():
    from . import tg_ws_proxy

    legacy_secret = os.environ.pop("TG_WS_PROXY_SECRET", "")
    secret_file = os.environ.get("TG_WS_PROXY_SECRET_FILE", "")
    if legacy_secret and secret_file:
        raise SystemExit("Choose TG_WS_PROXY_SECRET_FILE or the deprecated secret environment input, not both")
    extra = sys.argv[1:]
    if any(value == "--secret" or value.startswith("--secret=") for value in extra):
        raise SystemExit("Use TG_WS_PROXY_SECRET_FILE instead of a Docker command-line secret")
    arguments = ["tg-ws-proxy", "--host", os.environ.get("TG_WS_PROXY_HOST", "0.0.0.0"),
                 "--port", os.environ.get("TG_WS_PROXY_PORT", "1443")]
    for route in os.environ.get("TG_WS_PROXY_DC_IPS", "2:149.154.167.220 4:149.154.167.220").split():
        arguments.extend(("--dc-ip", route))
    if secret_file:
        arguments.extend(("--secret-file", secret_file))
    worker = os.environ.get("TG_WS_PROXY_CF_WORKER", "")
    if worker:
        arguments.extend(("--cfproxy-worker-domain", worker))
    sys.argv[:] = arguments + extra
    tg_ws_proxy.main(secret_override=legacy_secret or None)


if __name__ == "__main__":
    main()
