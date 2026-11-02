# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A TEST DOUBLE for the ``robot`` command (it replaces ``-m robot`` through ``RunOptions.robot_launcher``, started as ``python -I fake_robot.py MODE --outputdir ...``).
It exists only in the tests, to exercise what the parent does with an engine that finishes, fails, hangs, crashes or writes a report with a hostile tag, without
Robot Framework installed. The real engine runs the real, reviewed suite in ``tests/real``.

Modes: live (asks the REAL target for the four order totals, writes them as qa-observe tags and a PASS or FAIL like the suite's own checks would), hang, exit2, no-output,
tag-expected (an observation named like an expected value), pidfile:PATH (records its pid, then hangs, with a stray child)."""
import os
import subprocess
import sys
import time
import urllib.request
import json
from pathlib import Path

mode = sys.argv[1]
argv = sys.argv[2:]
outdir = Path(argv[argv.index("--outputdir") + 1])
GOOD = {"101": 9450, "102": 9999, "103": 9000, "104": 9005}


def write(values, status, extra=()):
    tags = "".join(f"<tag>qa-observe:order_{k}_total_cents={v}</tag>" for k, v in values.items()) + "".join(f"<tag>{t}</tag>" for t in extra)
    p, f = (1, 0) if status == "PASS" else (0, 1)
    (outdir / "output.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<robot generator="Robot 7.5 (Python 3.12.16 on linux)" generated="2026-11-01T13:34:05.196569" rpa="false" schemaversion="5">\n'
        '<suite id="s1" name="Order Discount" source="/x/order_discount.robot"><test id="s1-t1" name="Order Discount Rule" line="8">' + tags
        + f'<status status="{status}" start="2026-11-01T13:34:05.2" elapsed="0.001"/></test><status status="{status}" start="2026-11-01T13:34:05.1" elapsed="0.01"/></suite>'
        + f'<statistics><total><stat pass="{p}" fail="{f}" skip="0">All Tests</stat></total></statistics></robot>\n')
    sys.exit(0 if status == "PASS" else 1)


def live():
    base = os.environ["QA_BASE_URL"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    got = {k: json.loads(opener.open(f"{base}/api/orders/{k}", timeout=5).read())["total_cents"] for k in GOOD}
    return got


if mode == "live":
    got = live()
    write(got, "PASS" if got == GOOD else "FAIL")
elif mode == "hang":
    time.sleep(600)
elif mode == "exit2":
    sys.exit(2)
elif mode == "no-output":
    sys.exit(0)
elif mode == "tag-expected":
    write(GOOD, "PASS", extra=("qa-observe:expected=9450",))
elif mode.startswith("pidfile:"):
    Path(mode.split(":", 1)[1]).write_text(str(os.getpid()))
    subprocess.Popen([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"])
    time.sleep(600)
else:
    sys.exit(9)
