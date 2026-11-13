# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops-qa-service``: start the service, or ``redevops-qa-service healthcheck`` (what the container HEALTHCHECK runs)."""
from __future__ import annotations

import os
import signal
import sys
import urllib.error
import urllib.request

from .config import ENV_PORT, ConfigError, load_config


def healthcheck() -> int:
    port = os.environ.get(ENV_PORT) or "8080"
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{int(port)}/readyz", timeout=5) as resp:        # nosec: loopback only
            return 0 if resp.status == 200 else 1
    except (urllib.error.URLError, OSError, ValueError):
        return 1


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["healthcheck"]:
        return healthcheck()
    if argv:
        print("usage: redevops-qa-service [healthcheck]", file=sys.stderr)
        return 2
    try:
        cfg = load_config(os.environ)
    except ConfigError as exc:
        print(f"redevops-qa-service: not started: {exc}", file=sys.stderr)
        return 78                                          # EX_CONFIG
    from .server import QAServer
    server = QAServer(cfg)
    def _terminate(*_args):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _terminate)
    print(f"redevops-qa-service: listening on {cfg.bind}:{cfg.port}; data in {cfg.data_dir}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
