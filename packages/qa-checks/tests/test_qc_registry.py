# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The registry of hashed check programs: verification before execution, purity guard, no expected values, no verdicts."""
import inspect
import re

import pytest

import redevops_qa_checks.registry as reg
from qc_fixtures import good_set, write_tree
from redevops_qa_checks.errors import (ExpectedValueRefused, OutputRefused, ProgramHashMismatch, ProgramRefused,
                                       ProgramUnregistered)
from redevops_qa_checks.program_input import ProgramInput

HASH = re.compile(r"sha256:[0-9a-f]{64}")


def test_every_program_has_a_full_sha256_and_ids_and_hashes_are_unique(registry):
    entries = registry.entries()
    assert len(entries) == 44
    assert all(HASH.fullmatch(e.program_hash) for e in entries)
    assert len({e.id for e in entries}) == 44 and len({e.program_hash for e in entries}) == 44


def test_the_registry_satisfies_the_harness_program_registry_protocol(registry, neutral):
    from agent_harness.qa.specstore import ProgramRegistry
    assert isinstance(registry, ProgramRegistry)
    e = registry.entries()[0]
    assert registry.registered_program_hash(e.id, e.version) == e.program_hash
    assert registry.registered_program_hash(e.id, "9.9.9") is None
    assert registry.registered_program_hash("no.such", e.version) is None


def test_registry_is_immutable(registry):
    with pytest.raises(AttributeError):
        registry.anything = 1


def test_an_unregistered_program_is_refused_before_anything_runs(registry):
    with pytest.raises(ProgramUnregistered):
        registry.resolve({"id": "manifest.not-there", "version": "1.0.0", "program_hash": "sha256:" + "0" * 64})
    with pytest.raises(ProgramUnregistered):
        registry.resolve({"id": registry.entries()[0].id, "version": "2.0.0", "program_hash": registry.entries()[0].program_hash})


def test_a_hash_mismatch_is_refused(registry):
    spec = registry.entries()[0]
    wrong = "sha256:" + ("0" * 63 + "1")
    with pytest.raises(ProgramHashMismatch):
        registry.run({"id": spec.id, "version": spec.version, "program_hash": wrong}, ProgramInput())
    # a ref that is the right hash but for another program also mismatches
    other = registry.entries()[1]
    with pytest.raises(ProgramHashMismatch):
        registry.resolve({"id": spec.id, "version": spec.version, "program_hash": other.program_hash})


def test_verification_precedes_execution_even_for_a_spy_program():
    calls = []

    def spy(data):
        calls.append(1)
        return {}
    spec = reg.ProgramSpec(id="spy.one", version="1.0.0", description="", program_hash="sha256:" + "1" * 64, source_files=(), fn=spy)
    r = reg.ProgramRegistry([spec])
    with pytest.raises(ProgramHashMismatch):
        r.run({"id": "spy.one", "version": "1.0.0", "program_hash": "sha256:" + "2" * 64}, ProgramInput())
    assert calls == []
    r.run({"id": "spy.one", "version": "1.0.0", "program_hash": "sha256:" + "1" * 64}, ProgramInput())
    assert calls == [1]


def test_duplicate_registration_is_refused(registry):
    e = registry.entries()[0]
    with pytest.raises(ProgramRefused):
        reg.ProgramRegistry([e, e])


def test_the_hash_covers_the_program_every_support_file_and_the_framework(registry):
    spec = registry.resolve({"id": "manifest.probes", "version": "1.0.0",
                             "program_hash": registry.registered_program_hash("manifest.probes", "1.0.0")})
    assert "programs/probes.py" in spec.source_files and "programs/_common.py" in spec.source_files
    assert set(reg.FRAMEWORK_FILES) <= set(spec.source_files)
    files = {rel: (reg.PACKAGE_ROOT / rel).read_bytes() for rel in spec.source_files}
    base = reg.bundle_hash(files.items())
    for rel in files:
        changed = dict(files)
        changed[rel] = files[rel] + b"\n# changed\n"
        assert reg.bundle_hash(changed.items()) != base, rel


def test_line_endings_do_not_change_a_hash():
    a = reg.bundle_hash([("x.py", b"a\nb\n")])
    assert a == reg.bundle_hash([("x.py", b"a\r\nb\r\n")])


def test_the_program_id_and_entry_point_are_bound_into_the_hash(registry):
    assert registry.registered_program_hash("manifest.probes", "1.0.0") != registry.registered_program_hash("manifest.probes.counts", "1.0.0")


@pytest.mark.parametrize("source", [
    "import os\ndef run(data):\n    return {}\n",
    "import socket\ndef run(data):\n    return {}\n",
    "import subprocess\ndef run(data):\n    return {}\n",
    "import time\ndef run(data):\n    return {}\n",
    "import random\ndef run(data):\n    return {}\n",
    "import urllib.request\ndef run(data):\n    return {}\n",
    "from os import path\ndef run(data):\n    return {}\n",
    "from .. import manifests\ndef run(data):\n    return {}\n",
    "def run(data):\n    return open('x').read()\n",
    "def run(data):\n    return eval('1')\n",
    "def run(data):\n    return exec('x=1')\n",
    "def run(data):\n    return getattr(data, 'manifests')\n",
    "def run(data):\n    return __import__('os')\n",
    "def run(data):\n    return data.__class__\n",
    "def run(data):\n    f = open\n    return f\n",
    "X = 1\ndef run(data):\n    global X\n    return X\n",
])
def test_an_impure_program_is_refused_at_registration(source):
    with pytest.raises(ProgramRefused):
        reg.assert_pure_source("p.py", source.encode())


@pytest.mark.parametrize("source", [
    "def run(data, expected):\n    return {}\n",
    "def run(data, *args):\n    return {}\n",
    "def run(data, **kw):\n    return {}\n",
    "def run(data=None):\n    return {}\n",
    "def run(data, *, expected=None):\n    return {}\n",
    "def run(expected):\n    return {}\n",
    "def helper(data):\n    return {}\n",
])
def test_a_program_must_take_exactly_one_parameter_named_data(source):
    with pytest.raises(ProgramRefused):
        reg.assert_run_signature("p.py", source.encode())


def test_every_builtin_program_takes_only_the_input(registry):
    for spec in registry.entries():
        sig = inspect.signature(spec.fn)
        assert list(sig.parameters) == ["data"], spec.id
        assert not any(n in reg.FORBIDDEN_ARGUMENT_NAMES for n in sig.parameters)


def test_the_registry_run_has_no_place_for_an_expected_value(registry):
    assert list(inspect.signature(reg.ProgramRegistry.run).parameters) == ["self", "ref", "data"]
    spec = registry.entries()[0]
    with pytest.raises(TypeError):
        registry.run(spec.ref, ProgramInput(), expected="x")
    with pytest.raises(ExpectedValueRefused):
        registry.run(spec.ref, {"expected": "x"})                      # anything but a ProgramInput


@pytest.mark.parametrize("payload", [{"expected": 1}, {"a": {"b": [{"Expected_Value": 1}]}}, {"predicate": {"op": "EQUALS"}},
                                     {"verdict": "PASS"}, {"x": [{"passed": True}]}])
def test_refuse_expected_finds_expected_and_verdict_keys_at_any_depth(payload):
    with pytest.raises(ExpectedValueRefused):
        reg.refuse_expected(payload)


def test_refuse_expected_accepts_a_normal_subject():
    reg.refuse_expected({"check_program_ref": {"id": "a.b", "version": "1.0.0", "program_hash": "sha256:" + "0" * 64},
                         "inputs": [{"kind": "MANIFEST_PATH", "path": "x"}], "tier": "OFFLINE"})


@pytest.mark.parametrize("value", [{"verdict": "PASS"}, {"a": {"passed": True}}, {"rows": [{"ok": True}]}, {"expected": 1},
                                   {"findings": []}, {"compliant": True}, {"Severity": "high"}])
def test_an_output_that_looks_like_a_verdict_is_refused(value):
    with pytest.raises(OutputRefused):
        reg.validate_output(value)


@pytest.mark.parametrize("value", [{"a": 1.5}, {"a": {1, 2}}, {"a": b"x"}, {1: "a"}, {"a": object()}, {"a": float("nan")}])
def test_an_output_must_be_plain_json_without_floats(value):
    with pytest.raises(OutputRefused):
        reg.validate_output(value)


def test_no_builtin_program_output_has_a_verdict_shaped_key_on_a_rich_input(registry, tmp_path):
    from redevops_qa_checks.engine import CheckEngine
    docs = good_set()
    docs["40-odd.yaml"] = [{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "x", "labels": {"status": "ok", "pass": "1"}}}]
    root = write_tree(tmp_path / "c", docs)
    engine = CheckEngine(root, registry)
    for spec in (e for e in registry.entries() if e.tier == "OFFLINE"):
        out = engine.run_check({"check_program_ref": spec.ref, "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "tier": "OFFLINE"})
        assert out.resolution == "RESOLVED"
        reg.validate_output(out.value)


def test_a_program_cannot_mutate_what_it_is_given(registry, case_root):
    from redevops_qa_checks.manifests import load_tree
    data = ProgramInput(manifests=load_tree(case_root).manifests)
    with pytest.raises(TypeError):
        data.manifests[0].doc["kind"] = "x"
