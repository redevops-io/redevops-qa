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


def _password_from(env, name_file: str, name_value: str):
    path, value = env.get(name_file), env.get(name_value)
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read().strip("\r\n")
        except OSError:
            return None
    return value or None


def bootstrap_admin(data_dir, env) -> str:
    """With an empty user table, create the first admin from QA_SERVICE_BOOTSTRAP_ADMIN_PASSWORD(_FILE) (name QA_SERVICE_BOOTSTRAP_ADMIN_NAME, default ``admin``). The password is never logged."""
    from .users import UserError, UserStore
    store = UserStore(data_dir)
    if store.count() > 0:
        return "users exist"
    password = _password_from(env, "QA_SERVICE_BOOTSTRAP_ADMIN_PASSWORD_FILE", "QA_SERVICE_BOOTSTRAP_ADMIN_PASSWORD")
    if not password:
        return "no user exists and no bootstrap password is set: sign-in is not possible until one is created (redevops-qa-service users add NAME --role admin --password-file FILE)"
    name = env.get("QA_SERVICE_BOOTSTRAP_ADMIN_NAME", "admin")
    try:
        store.add(name, "admin", password, created_by="bootstrap")
    except UserError as exc:
        return f"the bootstrap admin was not created: {exc}"
    return f"created the first admin '{name}' from the bootstrap password; create named users and remove the bootstrap setting"


def users_command(argv) -> int:
    """``users add NAME --role ROLE --password-file FILE`` and ``users list``: administration without a running service (the data directory is QA_SERVICE_DATA_DIR)."""
    import argparse
    from pathlib import Path
    from .users import ROLES, UserError, UserStore
    data = os.environ.get("QA_SERVICE_DATA_DIR", "")
    if not data.startswith("/"):
        print("QA_SERVICE_DATA_DIR must be an absolute path", file=sys.stderr)
        return 78
    ap = argparse.ArgumentParser(prog="redevops-qa-service users")
    sub = ap.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add")
    add.add_argument("name")
    add.add_argument("--role", choices=ROLES, required=True)
    add.add_argument("--password-file", required=True)
    sub.add_parser("list")
    args = ap.parse_args(argv)
    store = UserStore(Path(data))
    Path(data).mkdir(parents=True, exist_ok=True)
    if args.cmd == "list":
        for u in store.list():
            print(f"{u['name']}\t{u['role']}\t{'disabled' if u['disabled'] else 'enabled'}")
        return 0
    try:
        with open(args.password_file, encoding="utf-8") as fh:
            password = fh.read().strip("\r\n")
        store.add(args.name, args.role, password, created_by="cli")
    except (UserError, OSError) as exc:
        print(f"not created: {exc}", file=sys.stderr)
        return 1
    print(f"created {args.name} ({args.role})")
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["healthcheck"]:
        return healthcheck()
    if argv and argv[0] == "users":
        return users_command(argv[1:])
    if argv:
        print("usage: redevops-qa-service [healthcheck | users add|list ...]", file=sys.stderr)
        return 2
    try:
        cfg = load_config(os.environ)
    except ConfigError as exc:
        print(f"redevops-qa-service: not started: {exc}", file=sys.stderr)
        return 78                                          # EX_CONFIG
    from .server import QAServer
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    print("redevops-qa-service: " + bootstrap_admin(cfg.data_dir, os.environ), file=sys.stderr, flush=True)
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
