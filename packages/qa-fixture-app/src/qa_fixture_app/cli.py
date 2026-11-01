# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Command line: ``python -m qa_fixture_app`` and the console script ``redevops-qa-fixture-app``.

Standard output carries JSON lines only: one ``ready`` line when the socket is bound and the app answers, one ``stopped`` line on a
clean shutdown. Everything else (errors) goes to standard error. Exit status: 0 clean shutdown, 1 the address could not be bound,
2 refused or unusable options (including any address that is not loopback).
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from typing import List, Optional

from . import __version__
from .app import DEFECT_DESCRIPTIONS, DEFECTS
from .server import DEFAULT_HOST, NotLoopback, create_server

DEFAULT_PORT = 8765


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="qa_fixture_app", description="Deterministic local web app with one switchable, documented defect (loopback only).")
    p.add_argument("--defect", choices=DEFECTS, default="none", help="the one seeded defect to switch on (default: none)")
    p.add_argument("--host", default=DEFAULT_HOST, help="loopback address to bind: 127.0.0.1 (default), another 127.x.x.x address or ::1; nothing else is accepted")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP port; 0 picks a free port, reported in the ready line (default: %d)" % DEFAULT_PORT)
    p.add_argument("--request-log", metavar="FILE", help="write one JSON line per request to FILE (truncated at start)")
    p.add_argument("--shutdown-on-stdin-eof", action="store_true",
                   help="shut down cleanly when standard input reaches end of file (a parent that dies closes the pipe, so no process is left behind)")
    p.add_argument("--list-defects", action="store_true", help="print the defects and what each one changes, then exit")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_defects:
        _emit(DEFECT_DESCRIPTIONS)
        return 0
    if not 0 <= args.port <= 65535:
        sys.stderr.write("error: --port must be between 0 and 65535\n")
        return 2
    try:
        server = create_server(defect=args.defect, host=args.host, port=args.port, request_log=args.request_log)
    except NotLoopback as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except OSError as exc:
        sys.stderr.write("error: cannot start: %s\n" % exc)
        return 1

    def request_shutdown(*_: object) -> None:
        # server.shutdown() waits for the serving loop, so it must not run in the thread that serves (the signal handler runs there).
        threading.Thread(target=server.shutdown, name="qa-fixture-app-shutdown", daemon=True).start()

    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), request_shutdown)
    if args.shutdown_on_stdin_eof:
        def watch_stdin() -> None:
            try:
                while sys.stdin.buffer.read(4096):
                    pass
            except (OSError, ValueError):
                pass
            request_shutdown()
        threading.Thread(target=watch_stdin, name="qa-fixture-app-stdin", daemon=True).start()
    try:
        _emit({"defect": server.defect, "event": "ready", "host": server.host, "port": server.port, "url": server.url})
        server.serve_forever()
        _emit({"event": "stopped", "requests": server.request_count})
    except BrokenPipeError:
        pass            # the reader of standard output is gone; shut down all the same
    finally:
        server.close()
    return 0
