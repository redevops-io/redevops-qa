# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The process the fake suite adapter starts. It plays one scenario named on the command line and writes a small native report
(``native.json``) into the output directory. It uses only the standard library and talks to nothing outside its output directory.

Usage: python fake_child.py SCENARIO OUTPUT_DIR
"""
import json
import os
import signal
import subprocess
import sys
import time

scenario, out = sys.argv[1], sys.argv[2]


def report(tests, artifacts=()):
    with open(os.path.join(out, "native.json"), "w", encoding="utf-8") as fh:
        json.dump({"tests": tests, "artifacts": list(artifacts)}, fh)


def t(i, status, message="", tags=("qa-assert:A-1",)):
    return {"id": f"T{i}", "name": f"test {i}", "status": status, "message": message, "tags": list(tags), "duration": 0.01}


if scenario == "pass":
    print("all good")
    report([t(1, "pass")])
elif scenario == "pass_two":
    report([t(1, "pass"), t(2, "pass", tags=("qa-assert:A-2",))])
elif scenario == "pass_untagged":
    report([t(1, "pass", tags=())])
elif scenario == "pass_wrong_tag":
    report([t(1, "pass", tags=("qa-assert:A-9",))])
elif scenario == "fail":
    report([t(1, "pass"), t(2, "fail", "expected 3 got 4", tags=("qa-assert:A-2",))])
    sys.exit(1)
elif scenario == "error":
    report([t(1, "error", "driver crashed")])
    sys.exit(1)
elif scenario == "skip":
    report([t(1, "skip", "not applicable")])
elif scenario == "unknown":
    report([t(1, "unknown")])
elif scenario == "empty":
    report([])
elif scenario == "pass_nonzero_exit":
    report([t(1, "pass")])
    sys.exit(3)
elif scenario == "hang":
    time.sleep(600)
elif scenario == "ignore_term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    print("ready", flush=True)
    time.sleep(600)
elif scenario == "child_tree":
    child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(600)"])
    with open(os.path.join(out, "grandchild.pid"), "w") as fh:
        fh.write(str(child.pid))
    print("spawned", flush=True)
    time.sleep(600)
elif scenario == "orphan_after_exit":
    child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(600)"])
    with open(os.path.join(out, "grandchild.pid"), "w") as fh:
        fh.write(str(child.pid))
    report([t(1, "pass")])
elif scenario == "spam":
    chunk = "x" * 65536
    for _ in range(200):
        sys.stdout.write(chunk)
        sys.stdout.flush()
elif scenario == "spam_stderr":
    chunk = "y" * 65536
    for _ in range(200):
        sys.stderr.write(chunk)
        sys.stderr.flush()
elif scenario == "malformed":
    with open(os.path.join(out, "native.json"), "w") as fh:
        fh.write("{not json")
elif scenario == "bad_shape":
    with open(os.path.join(out, "native.json"), "w") as fh:
        json.dump({"tests": [{"name": "no id", "status": "pass"}]}, fh)
elif scenario == "bad_status":
    report([t(1, "passed-ish")])
elif scenario == "framework_unverified":
    report([t(1, "unverified")])
elif scenario == "missing_artifact":
    report([t(1, "pass")], ["screens/missing.png"])
elif scenario == "good_artifact":
    os.makedirs(os.path.join(out, "screens"), exist_ok=True)
    with open(os.path.join(out, "screens", "a.txt"), "w") as fh:
        fh.write("evidence")
    report([t(1, "pass")], ["screens/a.txt"])
elif scenario == "traversal_artifact":
    report([t(1, "pass")], ["../escape.txt"])
elif scenario == "absolute_artifact":
    report([t(1, "pass")], ["/etc/hosts"])
elif scenario == "symlink_artifact":
    os.symlink(os.environ.get("QA_FAKE_TARGET", "/etc/hosts"), os.path.join(out, "link.txt"))
    report([t(1, "pass")], ["link.txt"])
elif scenario == "prohibited_artifact":
    os.makedirs(os.path.join(out, ".ssh"), exist_ok=True)
    with open(os.path.join(out, ".ssh", "id_rsa"), "w") as fh:
        fh.write("x")
    report([t(1, "pass")], [".ssh/id_rsa"])
elif scenario == "secret_print":
    value = os.environ.get("QA_APP_PASSWORD", "")
    print("password is", value)
    print("Authorization: Bearer abcdef0123456789")
    sys.stderr.write("secret=" + value + "\n")
    report([t(1, "fail", "login failed for " + value)])
    sys.exit(1)
elif scenario == "secret_in_artifact":
    with open(os.path.join(out, "log.txt"), "w") as fh:
        fh.write("token " + os.environ.get("QA_APP_PASSWORD", ""))
    report([t(1, "pass")], ["log.txt"])
elif scenario == "env_dump":
    with open(os.path.join(out, "env.json"), "w") as fh:
        json.dump(sorted(os.environ), fh)
    with open(os.path.join(out, "env-values.json"), "w") as fh:
        json.dump(dict(os.environ), fh)
    report([t(1, "pass")], ["env.json"])
elif scenario == "write_outside":
    target = os.environ.get("QA_FAKE_TARGET", "")
    with open(target, "w") as fh:
        fh.write("outside")
    report([t(1, "pass")])
elif scenario == "retry_marker":
    report([t(1, "pass")])
else:
    sys.exit(97)
