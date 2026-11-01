# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A TEST DOUBLE for the lane child process. It exists only in the tests, to exercise what the parent does with a child that finishes, fails, hangs, crashes or
spawns a stray process, without a browser. The product has no such mode: nothing in ``qa_runner`` can produce a result without running the engine.

usage: python fake_lane.py MODE INPUT.json [PIDFILE]     (modes: pass, env-fail, settings-bug, hang, exit7, garbage, orphan, disagree, native-fail-verified, unknown-field, junk-rows, forged-verdict)
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

mode, input_path = sys.argv[1], sys.argv[2]
cfg = json.loads(Path(input_path).read_text())
out = Path(cfg["out_dir"])
out.mkdir(parents=True, exist_ok=True)
origin = cfg["origin"]


def rows(notif=True):
    def row(aid, value):
        return {"assertion_id": aid, "resolution": "RESOLVED", "match_count": 1, "value": value, "value_digest": None}
    return [row("A-SAVED", "Settings saved"), row("A-NOTIF-ON", notif), row("A-URL", origin + "/settings?saved=1")]


def result(outcome, exit_code, verdicts, observations):
    doc = {"schema": "redevops-qa/lane-result", "schema_version": "1.0", "status": "COMPLETED", "outcome": outcome, "reason": None, "exit_code": exit_code,
           "sealed": True, "cancelled": False, "states": [], "browser": "test-double", "observations": observations,
           "harness_verdicts": [{"assertion_id": a, "verdict": v, "reason_code": None, "actual": None, "actual_digest": None} for a, v in verdicts],
           "gateway": {"events": 0, "allowed": 0, "denied": 0}, "seconds_milli": 1}
    (out / "lane-result.json").write_text(json.dumps(doc, sort_keys=True, indent=2) + "\n")
    (out / "run-record.json").write_text(json.dumps({"schema": "test-double"}) + "\n")


ALL_PASS = [("A-NOTIF-ON", "PASS"), ("A-SAVED", "PASS"), ("A-URL", "PASS")]
if mode == "pass":
    result("PASS", 0, ALL_PASS, rows())
elif mode == "settings-bug":
    result("PRODUCT_FAIL", 1, [("A-NOTIF-ON", "FAIL"), ("A-SAVED", "PASS"), ("A-URL", "PASS")], rows(notif=False))
elif mode == "native-fail-verified":
    result("PRODUCT_FAIL", 1, ALL_PASS, rows())            # the engine says fail, every observation satisfies the frozen assertions
elif mode == "env-fail":
    result("ENVIRONMENT_FAIL", 3, [], rows())             # the executor could not run the spec; observations that happen to look right must not matter
elif mode == "disagree":
    result("PASS", 0, [("A-NOTIF-ON", "FAIL"), ("A-SAVED", "PASS"), ("A-URL", "PASS")], rows())       # the in-run verifier said FAIL for what the recomputation verifies
elif mode == "unknown-field":
    r = rows()
    r[0]["verdict"] = "VERIFIED"
    result("PASS", 0, ALL_PASS, r)
elif mode == "junk-rows":
    result("PASS", 0, ALL_PASS, [1, "x", {"assertion_id": 7}])          # rows that are not rows
elif mode == "hang":
    time.sleep(600)
elif mode == "exit7":
    sys.exit(7)
elif mode == "garbage":
    (out / "lane-result.json").write_text("{not json")
elif mode == "orphan":
    # a stray grandchild that ignores SIGTERM and records its pid; the parent must end the whole process group
    code = "import os,signal,time,sys; signal.signal(signal.SIGTERM, signal.SIG_IGN); open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(600)"
    subprocess.Popen([sys.executable, "-c", code, sys.argv[3]])
    time.sleep(600)
else:
    sys.exit(9)
