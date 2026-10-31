# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Scripted adapters for the shim tests. Each fake is written against ONE side's types and records the types of every
argument it was handed, so a test can prove no object of the other side ever reached it."""
import copy

from redevops_qa_bridge import convert


class _Side:
    """Builds values of one side from golden data. ``side`` is 'contracts' or 'neutral'."""

    def __init__(self, side, golden):
        self.side = side
        self.golden = golden
        self.reg = convert.registry()
        self.calls = []                      # (method, tuple of argument type modules)
        self.raise_on = {}

    def value(self, golden_name):
        entry = self.golden["values"][golden_name]
        c_cls, n_cls = self.reg.values[entry["type"]]
        return (c_cls if self.side == "contracts" else n_cls).from_json(copy.deepcopy(entry["input"]))

    def record(self, case_name):
        case = self.golden["cases"][case_name]
        data = copy.deepcopy(case["input"])
        if case.get("custody"):
            data["custody"] = case["custody"]
        c_cls, n_cls = self.reg.records[case["schema_id"]]
        return (c_cls if self.side == "contracts" else n_cls).from_json(data)

    def evidence_ref(self):
        c_cls, n_cls = self.reg.reused["EvidenceRef"]
        fields = dict(ref="shot-9", content_hash="sha256:" + "0" * 62 + "99", version="1", modality="image",
                      media_type="image/png", source="qa-playwright", ref_type="artifact")
        return (c_cls if self.side == "contracts" else n_cls)(**fields)

    def seen(self, method, *args):
        self.calls.append((method, tuple(type(a).__module__.split(".")[0] for a in args)))
        exc = self.raise_on.get(method)
        if exc is not None:
            raise exc


class FakeQAAdapter(_Side):
    adapter_id = "fake-qa"
    adapter_version = "0.0.1"
    api_version = "qa-adapter/1"

    def open_session(self, profile):
        self.seen("open_session", profile)
        return self.value("session_handle")

    def observe(self, s, req):
        self.seen("observe", s, req)
        return self.record("observation")

    def locate(self, s, target, *, mode):
        self.seen("locate", s, target, mode)
        return self.value("locate_result")

    def act(self, s, action, target):
        self.seen("act", s, action, target)
        return self.value("action_outcome")

    def assert_(self, s, subject):
        self.seen("assert_", s, subject)
        return self.record("observed_value_resolved")

    def capture(self, s, kinds):
        self.seen("capture", s, *kinds)
        return [self.evidence_ref()]

    def reset(self, s, scope):
        self.seen("reset", s, scope)
        return self.value("reset_result")

    def close_session(self, s):
        self.seen("close_session", s)
        return self.record("cleanup_report")


class FakeCheckAdapter(_Side):
    adapter_id = "fake-check"
    adapter_version = "0.0.1"
    api_version = "qa-check-adapter/1"

    def open_workspace(self, profile):
        self.seen("open_workspace", profile)
        return self.value("workspace_handle")

    def resolve(self, w, ref):
        self.seen("resolve", w, ref)
        return self.value("resolved_resource")

    def run_check(self, w, subject):
        self.seen("run_check", w, subject)
        return self.record("observed_value_resolved")

    def capture(self, w, kinds):
        self.seen("capture", w, *kinds)
        return [self.evidence_ref()]

    def reset(self, w, scope):
        self.seen("reset", w, scope)
        return self.value("reset_result")

    def close_workspace(self, w):
        self.seen("close_workspace", w)
        return self.record("cleanup_report")
