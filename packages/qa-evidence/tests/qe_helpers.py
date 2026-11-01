# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A small valid bundle built in the tests, and helpers that forge, mutate and re-chain it the way an attacker with the same tools would."""
from __future__ import annotations

import copy
import json

from qa_evidence.build import BuiltBundle, build_bundle
from qa_evidence.canon import dumps_canonical, sha256_bytes
from qa_evidence.constants import MANIFEST_NAME
from qa_evidence.report import assemble_report

BROWSER_NATIVE = b"browser native report\n"
BROWSER_OBS = b'{"final_url": "/settings?saved=1", "save_status": "Settings saved"}\n'
ROBOT_NATIVE = b"<robot generator='Robot 7.5'/>\n"
ROBOT_OBS_BAD = b'{"order_total_cents": 10500}\n'
ROBOT_OBS_GOOD = b'{"order_total_cents": 9450}\n'
LOG = b"orchestrator log line\n"
ENV = {"os": "linux", "arch": "x86_64", "python": "3.12.3"}
VERIFIER = {"id": "qa-verify", "version": "0.1.0"}
A1, A2, A3 = ("sha256:" + c * 64 for c in "123")


def lanes(browser_native=BROWSER_NATIVE, robot_native=ROBOT_NATIVE):
    return [
        {"lane_id": "browser", "run_id": "r0-test.browser", "engine": {"name": "playwright", "version": "1.64.1"},
         "native": {"status": "NATIVE_PASS", "raw_status": "passed", "exit_code": 0, "counts": {"passed": 2, "failed": 0, "errored": 0, "skipped": 0},
                    "artifacts": [{"path": "lanes/browser/native.txt", "digest": sha256_bytes(browser_native), "size": len(browser_native)}]}},
        {"lane_id": "robot", "run_id": "r0-test.robot", "engine": {"name": "robotframework", "version": "7.5"},
         "native": {"status": "NATIVE_PASS", "raw_status": "PASS", "exit_code": 0,
                    "artifacts": [{"path": "lanes/robot/output.xml", "digest": sha256_bytes(robot_native), "size": len(robot_native)}]}},
    ]


def inputs(robot_obs=ROBOT_OBS_BAD, robot_state="FAILED", robot_reason="EXPECTED_VALUE_DIFFERS"):
    """Two lanes. The robot engine's own check passed; the verifier, comparing the recorded observation with the frozen value, did not."""
    frozen = [{"assertion_id": "A-STATUS", "lane_id": "browser", "digest": A1}, {"assertion_id": "A-URL", "lane_id": "browser", "digest": A2},
              {"assertion_id": "A-TOTAL", "lane_id": "robot", "digest": A3}]
    results = [
        {"assertion_id": "A-STATUS", "native_status": "NATIVE_PASS", "state": "VERIFIED", "reason_code": "EQUALS_EXPECTED",
         "evidence": {"path": "lanes/browser/observations.json", "digest": sha256_bytes(BROWSER_OBS)}},
        {"assertion_id": "A-URL", "native_status": "NATIVE_PASS", "state": "VERIFIED", "reason_code": "EQUALS_EXPECTED",
         "evidence": {"path": "lanes/browser/observations.json", "digest": sha256_bytes(BROWSER_OBS)}},
        {"assertion_id": "A-TOTAL", "native_status": "NATIVE_PASS", "state": robot_state, "reason_code": robot_reason,
         "evidence": {"path": "lanes/robot/observations.json", "digest": sha256_bytes(robot_obs)}},
    ]
    report = assemble_report(run_id="r0-test", started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:09Z",
                             plan_digest="sha256:" + "a" * 64, environment=ENV, lanes=lanes(), frozen=frozen, results=results, verifier=VERIFIER,
                             redaction={"applied": True, "rules": [{"id": "env-values", "description": "environment variable values removed", "count": 3}],
                                        "notes": ["gateway log carries no query strings"]})
    files = {"lanes/browser/native.txt": (BROWSER_NATIVE, "native-artifact"), "lanes/browser/observations.json": (BROWSER_OBS, "observation"),
             "lanes/robot/output.xml": (ROBOT_NATIVE, "native-artifact"), "lanes/robot/observations.json": (robot_obs, "observation"),
             "logs/orchestrator.log": (LOG, "log")}
    return report, files, {"orchestrator": "0.1.0", "verifier": "0.1.0"}


def build_base(**kw) -> BuiltBundle:
    report, files, tools = inputs(**kw)
    return build_bundle(report=report, files=files, tools=tools, producer={"name": "qa-runner", "version": "0.1.0"})


def build_forged() -> BuiltBundle:
    """What someone with this library can do: the same bundle, but the robot assertion is VERIFIED over an observation that fits."""
    return build_base(robot_obs=ROBOT_OBS_GOOD, robot_state="VERIFIED", robot_reason="EQUALS_EXPECTED")


def load(files, path):
    return json.loads(files[path].decode("utf-8"))


def put(files, path, doc):
    files[path] = dumps_canonical(doc)


def rechain(files):
    """Rewrite the manifest so that every listed file's digest and size match what is now in ``files`` (the forger's last step)."""
    files = dict(files)
    man = load(files, MANIFEST_NAME)
    for entry in man["files"]:
        if entry["path"] in files:
            entry["digest"] = sha256_bytes(files[entry["path"]])
            entry["size"] = len(files[entry["path"]])
    put(files, MANIFEST_NAME, man)
    return files


def edit(files, path, fn):
    files = dict(files)
    doc = load(files, path)
    fn(doc)
    put(files, path, doc)
    return files


def codes(result):
    return sorted({f.code for f in result.findings})
