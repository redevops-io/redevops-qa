# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The CheckAdapter over the engine, in the neutral form: protocol, typed errors, write discipline, evidence, verifier parity."""
import copy
import os
import stat

import pytest

from qc_fixtures import deployment, dump, good_set, write_tree
from redevops_qa_checks.adapter import ADAPTER_ID, API_VERSION, CheckAdapter
from redevops_qa_checks.engine import CheckEngine
from redevops_qa_checks.manifests import tree_digest

IMG = "manifest.image-references"


@pytest.fixture
def R(neutral):
    from agent_harness.qa import records
    return records


@pytest.fixture
def E(neutral):
    from agent_harness.qa import errors
    return errors


def profile(R, root, tier="OFFLINE", proof=None):
    return R.CheckProfile(case_root_digest=tree_digest(root), tier=R.CheckTier(tier), disposable_proof_ref=proof)


def subject(R, registry, pid=IMG, paths=(".",), tier="OFFLINE", program_hash=None):
    h = program_hash or registry.registered_program_hash(pid, "1.0.0")
    return R.CheckSubject(check_program_ref=R.CheckProgramRef(id=pid, version="1.0.0", program_hash=h),
                          inputs=tuple(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path=p) for p in paths), tier=R.CheckTier(tier))


@pytest.fixture
def adapter(case_root, registry, neutral):
    return CheckAdapter(case_root, registry=registry)


def test_the_adapter_satisfies_the_neutral_check_adapter_protocol(adapter, neutral):
    from agent_harness.qa.ports import NeutralCheckAdapter
    assert isinstance(adapter, NeutralCheckAdapter)
    assert (adapter.adapter_id, adapter.api_version) == (ADAPTER_ID, API_VERSION) and adapter.api_version == neutral.schemas.CHECK_ADAPTER_API_VERSION \
        if hasattr(neutral.schemas, "CHECK_ADAPTER_API_VERSION") else adapter.api_version == "qa-check-adapter/1"


def test_open_run_close_returns_an_observed_value_and_a_clean_cleanup_report(adapter, case_root, registry, R):
    w = adapter.open_workspace(profile(R, case_root))
    ov = adapter.run_check(w, subject(R, registry))
    assert ov.resolution is R.Resolution.RESOLVED and ov.match_count == 1 and ov.value["counts"]["containers"] == 1
    assert ov.value_digest.startswith("rcv1:") and len(ov.value_digest) == 5 + 64
    rep = adapter.close_workspace(w)
    assert rep.verified is True and rep.leaked == ()


def test_resolve_returns_a_content_digest_for_paths_and_objects(adapter, case_root, R):
    w = adapter.open_workspace(profile(R, case_root))
    r1 = adapter.resolve(w, R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="10-app.yaml"))
    assert r1.content_digest == tree_digest(case_root, "10-app.yaml")
    r2 = adapter.resolve(w, R.ResourceRef(kind=R.ResourceKind.NAMESPACE_OBJECT, api_version="apps/v1", object_kind="Deployment", name="app", namespace="demo"))
    assert r2.content_digest.startswith("sha256:")


def test_resolve_of_something_absent_is_a_typed_error(adapter, case_root, R, E):
    w = adapter.open_workspace(profile(R, case_root))
    with pytest.raises(E.EnvironmentUnhealthy):
        adapter.resolve(w, R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="nope.yaml"))
    with pytest.raises(E.EnvironmentUnhealthy):
        adapter.resolve(w, R.ResourceRef(kind=R.ResourceKind.IMAGE_DIGEST, digest="sha256:" + "0" * 64))


def test_without_an_image_store_an_image_reference_is_not_expressible(case_root, registry):
    from redevops_qa_checks.errors import Unsupported
    with pytest.raises(Unsupported):
        CheckEngine(case_root, registry).resolve({"kind": "IMAGE_DIGEST", "digest": "sha256:" + "0" * 64})


def test_a_missing_input_is_an_unresolved_subject_not_a_value(adapter, case_root, registry, R):
    w = adapter.open_workspace(profile(R, case_root))
    ov = adapter.run_check(w, subject(R, registry, paths=("nope",)))
    assert ov.resolution is R.Resolution.UNRESOLVED and ov.match_count == 0 and ov.value is None and ov.value_digest is None


def test_a_duplicate_object_identity_is_ambiguous(tmp_path, registry, R):
    root = write_tree(tmp_path / "c", {"a.yaml": [deployment()], "b.yaml": [deployment()]})
    a = CheckAdapter(root, registry=registry)
    w = a.open_workspace(profile(R, root))
    s = R.CheckSubject(check_program_ref=R.CheckProgramRef(id=IMG, version="1.0.0", program_hash=registry.registered_program_hash(IMG, "1.0.0")),
                       inputs=(R.ResourceRef(kind=R.ResourceKind.NAMESPACE_OBJECT, api_version="apps/v1", object_kind="Deployment", name="app", namespace="demo"),),
                       tier=R.CheckTier.OFFLINE)
    ov = a.run_check(w, s)
    assert ov.resolution is R.Resolution.AMBIGUOUS and ov.match_count == 2 and ov.value is None


def test_a_namespace_object_input_runs_the_program_over_that_object_only(adapter, case_root, registry, R):
    w = adapter.open_workspace(profile(R, case_root))
    s = R.CheckSubject(check_program_ref=R.CheckProgramRef(id=IMG, version="1.0.0", program_hash=registry.registered_program_hash(IMG, "1.0.0")),
                       inputs=(R.ResourceRef(kind=R.ResourceKind.NAMESPACE_OBJECT, api_version="apps/v1", object_kind="Deployment", name="app", namespace="demo"),),
                       tier=R.CheckTier.OFFLINE)
    assert adapter.run_check(w, s).value["counts"]["containers"] == 1


def test_an_unregistered_program_is_refused_before_any_input_is_read(adapter, case_root, registry, R, E, monkeypatch):
    w = adapter.open_workspace(profile(R, case_root))
    reads = []
    import redevops_qa_checks.engine as eng
    monkeypatch.setattr(eng.CheckEngine, "load_inputs", lambda *a, **k: reads.append(1))
    s = R.CheckSubject(check_program_ref=R.CheckProgramRef(id="manifest.nothing", version="1.0.0", program_hash="sha256:" + "0" * 64),
                       inputs=(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="."),), tier=R.CheckTier.OFFLINE)
    with pytest.raises(E.AssertionProgramUnregistered):
        adapter.run_check(w, s)
    assert reads == []


def test_a_hash_mismatch_is_refused_before_any_input_is_read(adapter, case_root, registry, R, E, monkeypatch):
    w = adapter.open_workspace(profile(R, case_root))
    reads = []
    import redevops_qa_checks.engine as eng
    monkeypatch.setattr(eng.CheckEngine, "load_inputs", lambda *a, **k: reads.append(1))
    with pytest.raises(E.AssertionProgramMismatch):
        adapter.run_check(w, subject(R, registry, program_hash="sha256:" + "f" * 64))
    assert reads == []


def test_an_expected_value_cannot_reach_a_check(adapter, case_root, registry, R, E):
    w = adapter.open_workspace(profile(R, case_root))

    class Fake:
        def __init__(self, data):
            self._d = data

        def to_json(self):
            return self._d
    good = subject(R, registry).to_json()
    for extra in ({"expected": 1}, {"predicate": {"op": "EQUALS", "expected": 1}}, {"verdict": "PASS"}):
        with pytest.raises(E.SpecInvalid):
            adapter.run_check(w, Fake({**good, **extra}))
    with pytest.raises(E.SpecInvalid):
        adapter.run_check(w, Fake({**good, "inputs": [{"kind": "MANIFEST_PATH", "path": ".", "expected": "x"}]}))


def test_a_subject_with_unknown_fields_is_refused(adapter, case_root, registry, R, E):
    w = adapter.open_workspace(profile(R, case_root))

    class Fake:
        def to_json(self):
            return {**subject(R, registry).to_json(), "extra_field": 1}
    with pytest.raises(E.UnsupportedOperation):
        adapter.run_check(w, Fake())


def test_the_case_root_digest_in_the_profile_must_match(adapter, case_root, R, E):
    bad = R.CheckProfile(case_root_digest="sha256:" + "0" * 64, tier=R.CheckTier.OFFLINE)
    with pytest.raises(E.EnvironmentUnhealthy):
        adapter.open_workspace(bad)


def test_tier_k_is_blocked_without_a_gate_and_so_is_a_k_subject(adapter, case_root, registry, R, E):
    with pytest.raises(E.ActionBlockedByPolicy):
        adapter.open_workspace(profile(R, case_root, "K", proof="sha256:" + "1" * 64))
    w = adapter.open_workspace(profile(R, case_root))
    with pytest.raises(E.ActionBlockedByPolicy):
        adapter.run_check(w, subject(R, registry, tier="K"))


def test_a_path_that_leaves_the_case_root_is_a_policy_block(adapter, case_root, registry, R, E):
    w = adapter.open_workspace(profile(R, case_root))
    with pytest.raises(E.ActionBlockedByPolicy):
        adapter.run_check(w, subject(R, registry, paths=("../outside",)))


def test_a_symlink_inside_the_case_is_a_policy_block(tmp_path, registry, R, E):
    root = write_tree(tmp_path / "c", good_set())
    os.symlink(root / "10-app.yaml", root / "x.yaml")
    a = CheckAdapter(root, registry=registry)
    with pytest.raises(E.ActionBlockedByPolicy):
        a.open_workspace(R.CheckProfile(case_root_digest="sha256:" + "0" * 64, tier=R.CheckTier.OFFLINE))


def test_an_unknown_or_closed_workspace_is_refused(adapter, case_root, registry, R, E):
    w = adapter.open_workspace(profile(R, case_root))
    adapter.close_workspace(w)
    with pytest.raises(E.EnvironmentUnhealthy):
        adapter.run_check(w, subject(R, registry))


def test_offline_reset_is_not_supported_because_there_is_nothing_to_reset(adapter, case_root, R, E):
    w = adapter.open_workspace(profile(R, case_root))
    with pytest.raises(E.UnsupportedOperation):
        adapter.reset(w, R.ResetScope.FIXTURE)


def test_an_over_large_observation_is_a_resource_limit_not_a_truncation(tmp_path, registry, R, E):
    big = [deployment(f"d{i}") for i in range(200)]
    root = write_tree(tmp_path / "c", {"a.yaml": big})
    a = CheckAdapter(root, registry=registry)
    w = a.open_workspace(profile(R, root))
    with pytest.raises(E.ResourceLimitExceeded):
        a.run_check(w, subject(R, registry, "manifest.structure"))
    ov = a.run_check(w, subject(R, registry, "manifest.structure.counts"))
    assert ov.value["counts"]["documents"] == 200


def test_the_runner_can_use_the_adapter_through_the_harness_verifier_end_to_end(case_root, registry, neutral, R):
    """The same observed value the adapter returns is compared by the harness verifier with a pinned predicate."""
    from agent_harness.qa import records, specstore, verifier
    a = CheckAdapter(case_root, registry=registry)
    w = a.open_workspace(profile(R, case_root))
    pid = "manifest.image-references.counts"
    ref = {"id": pid, "version": "1.0.0", "program_hash": registry.registered_program_hash(pid, "1.0.0")}
    expected = {"counts": {"containers": 1, "with_digest": 1, "tag_only": 0, "latest_tag": 0, "untagged_unpinned": 0, "image_missing": 0},
                "input_error_count": 0}
    doc = {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": "a-pinned", "executor": "SCRIPT",
           "check_program_ref": ref, "determinism": "DETERMINISTIC", "on_unresolvable": "INDETERMINATE",
           "predicate": {"op": "EQUALS", "expected": expected}, "requirement_ref": "REQ-X-1",
           "subject": {"kind": "RESOURCE_INPUTS", "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "subject_alternates": []},
           "verifier_id": verifier.VERIFIER_ID, "verifier_version_range": ">=0.0,<99"}
    spec = records.AssertionSpec.from_json(doc)
    pin = verifier.assertion_set_pin((spec,))
    store = specstore.InMemorySpecStore({pin: [doc]})
    v = verifier.DeterministicVerifier(programs=registry, check_adapter=a)
    results = v.verify_run(store, pin, lineage=verifier.ApprovedLineage([pin]), workspace=w)
    assert [r.check.verdict.value for r in results] == ["PASS"] and results[0].executor is records.Executor.SCRIPT
    # a differently authored expected value gives FAIL from the same observation: the verdict is the verifier's alone
    bad = copy.deepcopy(doc)
    bad["predicate"]["expected"]["counts"]["with_digest"] = 0
    bad_spec = records.AssertionSpec.from_json(bad)
    bad_pin = verifier.assertion_set_pin((bad_spec,))
    v2 = verifier.DeterministicVerifier(programs=registry, check_adapter=a)
    out = v2.verify_run(specstore.InMemorySpecStore({bad_pin: [bad]}), bad_pin, lineage=verifier.ApprovedLineage([bad_pin]), workspace=w)
    assert out[0].check.verdict.value == "FAIL"


def test_the_harness_verifier_refuses_an_unregistered_or_mismatched_program_with_the_real_registry(registry, neutral):
    from agent_harness.qa import errors, records, specstore, verifier
    pid = "manifest.probes.counts"
    for h, code in (("sha256:" + "0" * 64, "ASSERTION_PROGRAM_MISMATCH"), (None, "ASSERTION_PROGRAM_UNREGISTERED")):
        ref = {"id": pid if h else "manifest.not-registered", "version": "1.0.0", "program_hash": h or "sha256:" + "0" * 64}
        doc = {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": "a-1", "executor": "SCRIPT",
               "check_program_ref": ref, "determinism": "DETERMINISTIC", "on_unresolvable": "INDETERMINATE",
               "predicate": {"op": "EXISTS"}, "subject": {"kind": "RESOURCE_INPUTS", "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "subject_alternates": []},
               "verifier_id": verifier.VERIFIER_ID, "verifier_version_range": ">=0.0,<99"}
        pin = verifier.assertion_set_pin((records.AssertionSpec.from_json(doc),))
        with pytest.raises(errors.QAError) as exc:
            verifier.load_frozen_assertions(specstore.InMemorySpecStore({pin: [doc]}), pin, lineage=verifier.ApprovedLineage([pin]), programs=registry)
        assert exc.value.code == code


# -- write discipline ---------------------------------------------------------------------------------------------------------

def _snapshot(root):
    return sorted((str(p.relative_to(root)), p.stat().st_mtime_ns, p.stat().st_size, p.stat().st_ino) for p in root.rglob("*"))


def test_a_run_changes_nothing_in_the_case_tree_even_when_it_is_read_only(case_root, registry, R):
    before_digest = tree_digest(case_root)
    for p in sorted(case_root.rglob("*"), reverse=True):
        os.chmod(p, 0o555 if p.is_dir() else 0o444)
    os.chmod(case_root, 0o555)
    try:
        before = _snapshot(case_root)
        a = CheckAdapter(case_root, registry=registry)
        w = a.open_workspace(profile(R, case_root))
        for spec in registry.entries():
            a.run_check(w, R.CheckSubject(check_program_ref=R.CheckProgramRef(id=spec.id, version=spec.version, program_hash=spec.program_hash),
                                          inputs=(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="."),), tier=R.CheckTier.OFFLINE))
        a.resolve(w, R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="10-app.yaml"))
        a.close_workspace(w)
        assert _snapshot(case_root) == before
        assert tree_digest(case_root) == before_digest
    finally:
        for p in sorted(case_root.rglob("*")):
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.chmod(case_root, 0o755)


def test_no_write_mode_open_happens_during_a_run(case_root, registry, R, monkeypatch):
    import builtins
    opened = []
    real = builtins.open

    def spy(file, mode="r", *a, **k):
        if any(c in mode for c in "wax+"):
            opened.append((str(file), mode))
        return real(file, mode, *a, **k)
    monkeypatch.setattr(builtins, "open", spy)
    a = CheckAdapter(case_root, registry=registry)
    w = a.open_workspace(profile(R, case_root))
    a.run_check(w, subject(R, registry))
    a.close_workspace(w)
    assert opened == []


# -- evidence ---------------------------------------------------------------------------------------------------------------------

def test_capture_is_redacted_content_addressed_and_only_a_trace(case_root, registry, R, E, neutral):
    from agent_harness.qa.blobs import MemoryBlobSink
    from agent_harness.qa.redaction import PatternRedactor
    sink, red = MemoryBlobSink(), PatternRedactor()
    a = CheckAdapter(case_root, registry=registry, redactor=red, blobs=sink)
    w = a.open_workspace(profile(R, case_root))
    a.run_check(w, subject(R, registry))
    refs = a.capture(w, [R.CaptureKind.TRACE])
    assert len(refs) == 1 and refs[0].ref == refs[0].content_hash and sink.exists(refs[0].ref)
    body = sink.get(refs[0].ref)
    assert b"manifest.image-references" in body
    with pytest.raises(E.UnsupportedOperation):
        a.capture(w, [R.CaptureKind.SCREENSHOT])


def test_capture_without_a_redactor_never_produces_a_raw_artifact(case_root, registry, R, E):
    a = CheckAdapter(case_root, registry=registry)
    w = a.open_workspace(profile(R, case_root))
    with pytest.raises(E.RedactionFailed):
        a.capture(w, [R.CaptureKind.TRACE])


def test_a_secret_shaped_value_in_a_manifest_never_reaches_the_observed_value_or_the_evidence(tmp_path, registry, R, neutral):
    from agent_harness.qa.blobs import MemoryBlobSink
    from agent_harness.qa.redaction import PatternRedactor
    canary = "AKIA" + "ABCDEFGHIJKLMNOP"                       # built at run time; never committed as a literal
    token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    env = [{"name": "A", "value": canary}, {"name": "B", "value": token}]
    from qc_fixtures import container
    root = write_tree(tmp_path / "c", {"a.yaml": [deployment(containers=[container(env=env)])]})
    sink = MemoryBlobSink()
    a = CheckAdapter(root, registry=registry, redactor=PatternRedactor(), blobs=sink)
    w = a.open_workspace(profile(R, root))
    outs = [a.run_check(w, subject(R, registry, pid)) for pid in ("manifest.env-and-secret-refs", "manifest.structure", "manifest.security-context")]
    assert all(canary not in str(o.value) and token not in str(o.value) for o in outs)
    ref = a.capture(w, [R.CaptureKind.TRACE])[0]
    assert canary.encode() not in sink.get(ref.ref) and token.encode() not in sink.get(ref.ref)
