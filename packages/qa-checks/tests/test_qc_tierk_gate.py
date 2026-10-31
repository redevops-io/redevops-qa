# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Dry-run and admission drivers, the tier K programs and the adapter's route into the disposable cluster, against a fake runner."""
import json

import pytest

import qc_cluster as C
from qc_fixtures import container, deployment, good_set, namespace, write_tree
from redevops_qa_checks.adapter import CheckAdapter
from redevops_qa_checks.engine import CheckEngine
from redevops_qa_checks.errors import LimitExceeded, PolicyBlocked, Unsupported
from redevops_qa_checks.manifests import tree_digest
from redevops_qa_checks.not_expressible import NOT_EXPRESSIBLE
from redevops_qa_checks.tierk import drivers as D
from redevops_qa_checks.tierk.gate import TierKGate
from redevops_qa_checks.tierk.lanes import LaneReports

KYVERNO_DENIAL = ('Error from server: error when creating "STDIN": admission webhook "validate.kyverno.svc-fail" denied the request: \n\n'
                  'resource Pod/demo/web was blocked due to the following policies \n\nrequire-labels:\n  check-team: \'validation error: label team is required. '
                  'rule check-team failed at path /metadata/labels/team/\'\n')
PSA = ('Error from server (Forbidden): error when creating "STDIN": pods "web" is forbidden: violates PodSecurity "restricted:latest": '
       'allowPrivilegeEscalation != false (container "app" must set securityContext.allowPrivilegeEscalation=false), '
       'unrestricted capabilities (container "app" must set securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container "app" must set securityContext.runAsNonRoot=true)')
QUOTA = 'Error from server (Forbidden): error when creating "STDIN": pods "web" is forbidden: exceeded quota: q, requested: pods=1, used: pods=20, limited: pods=20'
LIMIT = 'Error from server (Forbidden): pods "web" is forbidden: maximum cpu usage per Container is 1, but limit is 2'
NOKIND = 'error: resource mapping not found for name: "x" namespace: "" from "STDIN": no matches for kind "Gateway" in version "x/v1"\nensure CRDs are installed first'
UNKNOWN = 'Error from server (BadRequest): error when creating "STDIN": Deployment in version "v1" cannot be handled as a Deployment: strict decoding error: unknown field "spec.bogus"'
INVALID = 'The Deployment "web" is invalid: spec.template.spec.containers[0].image: Required value'
NONS = 'Error from server (NotFound): error when creating "STDIN": namespaces "demo" not found'


@pytest.mark.parametrize("text,cls,layer", [(KYVERNO_DENIAL, "admission_denied", "kyverno"), (PSA, "pod_security_violation", "pod_security"),
                                            (QUOTA, "quota_exceeded", "resource_quota"), (LIMIT, "limit_range_violation", "limit_range"),
                                            (NOKIND, "kind_not_known", "apiserver"), (UNKNOWN, "schema_unknown_field", "apiserver"),
                                            (INVALID, "schema_invalid", "apiserver"), (NONS, "namespace_not_found", "apiserver"),
                                            ("Error from server (Forbidden): something else is forbidden", "forbidden_other", "apiserver"),
                                            ("connection refused", "other", "apiserver")])
def test_rejection_text_is_classified_by_the_layer_that_spoke(text, cls, layer):
    c = D.classify_rejection(text)
    assert (c["error_class"], c["layer"]) == (cls, layer) and len(c["message"]) <= D.MESSAGE_LIMIT


def test_policy_names_pod_security_checks_and_quota_names_are_extracted():
    assert D.classify_rejection(KYVERNO_DENIAL)["policies"] == ["require-labels"]
    p = D.classify_rejection(PSA)
    assert p["pod_security_level"] == "restricted:latest"
    assert p["pod_security_checks"] == ["allowPrivilegeEscalation != false", "runAsNonRoot != true", "unrestricted capabilities"]
    assert D.classify_rejection(QUOTA)["quota_name"] == "q"


def test_warnings_are_collected_from_a_successful_answer():
    assert D.warnings_from('Warning: would violate PodSecurity "restricted:latest": x\nfoo\nWarning: second one') == [
        'would violate PodSecurity "restricted:latest": x', "second one"]


def objs(*names):
    return [deployment(n) for n in names]


def test_dry_run_sends_one_server_side_dry_run_per_object_and_records_each_answer(tmp_path):
    s, fake, *_ = C.open_session(tmp_path, fake_kw={"dry_run": {"b": (1, KYVERNO_DENIAL), "c": (0, "Warning: heads up")}})
    rows = D.DryRunDriver(s).dry_run(objs("a", "b", "c"))
    assert [(r["name"], r["response"]) for r in rows] == [("a", "accepted"), ("b", "rejected"), ("c", "accepted")]
    assert rows[1]["layer"] == "kyverno" and rows[1]["policies"] == ["require-labels"] and rows[2]["warnings"] == ["heads up"]
    applies = [a for a, _ in fake.calls if a[0] == "apply"]
    assert len(applies) == 3 and all(a == ["apply", "--dry-run=server", "--validate=strict", "-f", "-", "-o", "json"] for a in applies)
    assert fake.mutating_calls() == []


def test_the_dry_run_object_count_is_bounded(tmp_path):
    s, *_ = C.open_session(tmp_path, max_commands=2000)
    with pytest.raises(LimitExceeded):
        D.DryRunDriver(s).dry_run(objs(*[f"d{i}" for i in range(D.MAX_OBJECTS + 1)]))


def test_status_driver_reads_gateway_route_policy_quota_and_limit_range(tmp_path):
    objects = {
        "gateway.gateway.networking.k8s.io": {"items": [{"metadata": {"namespace": "infra", "name": "public"}, "status": {
            "conditions": [{"type": "Accepted", "status": "True", "reason": "Accepted"}, {"type": "Programmed", "status": "True", "reason": "Programmed"}],
            "addresses": [{"value": "10.0.0.5"}], "listeners": [{"name": "https", "attachedRoutes": 1, "conditions": [{"type": "ResolvedRefs", "status": "True", "reason": "ResolvedRefs"}]}]}}]},
        "httproute.gateway.networking.k8s.io": {"items": [{"metadata": {"namespace": "demo", "name": "app"}, "status": {"parents": [{
            "parentRef": {"name": "public", "namespace": "infra", "sectionName": "https"}, "controllerName": "example.test/c",
            "conditions": [{"type": "Accepted", "status": "False", "reason": "NotAllowedByListeners"}]}]}}]},
        "clusterpolicy.kyverno.io": {"items": [{"metadata": {"name": "p1"}, "status": {"ready": True, "conditions": [{"type": "Ready", "status": "True", "reason": "Succeeded"}]}}]},
        "resourcequota": {"items": [{"metadata": {"namespace": "demo", "name": "q"}, "status": {"hard": {"pods": "20"}, "used": {"pods": "3"}}}]},
        "limitrange": {"items": [{"metadata": {"namespace": "demo", "name": "lr"}, "spec": {"limits": [{"type": "Container"}, {"type": "Pod"}]}}]}}
    s, fake, *_ = C.open_session(tmp_path, fake_kw={"objects": objects})
    gw = D.StatusDriver(s).gateway_status()
    pol = D.StatusDriver(s).policy_status()
    assert [r["section"] for r in gw] == ["gateway", "route"] and gw[0]["listeners"][0]["attached_routes"] == 1 and gw[1]["parents"][0]["conditions"][0]["reason"] == "NotAllowedByListeners"
    assert [r["section"] for r in pol] == ["limit_range", "policy", "quota"] and pol[0]["types"] == ["Container", "Pod"] and pol[2]["used"] == [["pods", "3"]]
    assert fake.mutating_calls() == []


def test_a_status_read_that_fails_or_is_not_json_is_an_environment_fault_never_an_empty_pass(tmp_path):
    from redevops_qa_checks.errors import EnvironmentFault
    s, fake, *_ = C.open_session(tmp_path)
    fake.objects = {"gateway.gateway.networking.k8s.io": "not-a-dict"}
    orig = fake.run

    def bad(args, **kw):
        if args[:2] == ["get", "gateway.gateway.networking.k8s.io"]:
            return C.KubectlResult(0, "<<not json>>")
        return orig(args, **kw)
    fake.run = bad
    with pytest.raises(EnvironmentFault):
        D.StatusDriver(s).gateway_status()


# -- the tier K programs through the adapter -----------------------------------------------------------------------------------------------------------

@pytest.fixture
def k_world(tmp_path, registry, neutral):
    from agent_harness.qa import records as R
    case = write_tree(tmp_path / "case", good_set())
    sess, fake, guard, state, entry = C.open_session(tmp_path)
    gate = TierKGate(sess)
    adapter = CheckAdapter(case, registry=registry, tier_k=gate)
    profile = R.CheckProfile(case_root_digest=tree_digest(case), tier=R.CheckTier.K, disposable_proof_ref=sess.proof_ref)

    class W:
        pass
    w = W()
    w.R, w.case, w.sess, w.fake, w.gate, w.adapter, w.profile, w.registry = R, case, sess, fake, gate, adapter, profile, registry
    return w


def k_subject(w, pid, paths=(".",), tier="K"):
    R = w.R
    return R.CheckSubject(check_program_ref=R.CheckProgramRef(id=pid, version="1.0.0", program_hash=w.registry.registered_program_hash(pid, "1.0.0")),
                          inputs=tuple(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path=p) for p in paths), tier=R.CheckTier(tier))


def test_a_tier_k_check_returns_the_dry_run_answers_with_the_lane_and_changes_nothing(k_world):
    w = k_world
    h = w.adapter.open_workspace(w.profile)
    ov = w.adapter.run_check(h, k_subject(w, "cluster.dry-run"))
    v = ov.value
    assert v["lane"]["id"] == "primary" and v["lane"]["kubernetes_version"] == "v1.37.0" and v["lane"]["disposable_proof"] == w.sess.proof_ref
    assert v["counts"]["objects"] == 9 and v["counts"]["accepted"] == 9 and v["counts"]["rejected"] == 0
    assert w.fake.mutating_calls() == []
    allowed = {"apply-dry-run", "get", "version"}
    from redevops_qa_checks.tierk.argv import validate_argv
    assert {validate_argv(a).rule for a, _ in w.fake.calls} <= allowed
    rep = w.adapter.close_workspace(h)
    assert rep.verified is True


def test_every_command_other_than_the_marker_read_is_preceded_by_a_marker_read(k_world):
    w = k_world
    h = w.adapter.open_workspace(w.profile)
    w.adapter.run_check(h, k_subject(w, "cluster.dry-run.counts"))
    calls = [a for a, _ in w.fake.calls]
    for i, a in enumerate(calls):
        if a[:3] != ["get", "configmap", "qa-disposable-marker"] and a != ["version", "-o", "json"]:
            assert calls[i - 1][:3] == ["get", "configmap", "qa-disposable-marker"], (i, a)


def test_rejections_by_each_admission_layer_are_observed_per_object(tmp_path, registry, neutral):
    from agent_harness.qa import records as R
    docs = [deployment("a"), deployment("b"), deployment("c"), deployment("d"), deployment("e")]
    case = write_tree(tmp_path / "case", {"x.yaml": docs})
    sess, fake, *_ = C.open_session(tmp_path, fake_kw={"dry_run": {"b": (1, KYVERNO_DENIAL), "c": (1, PSA), "d": (1, QUOTA), "e": (1, LIMIT)}})
    adapter = CheckAdapter(case, registry=registry, tier_k=TierKGate(sess))
    w = adapter.open_workspace(R.CheckProfile(case_root_digest=tree_digest(case), tier=R.CheckTier.K, disposable_proof_ref=sess.proof_ref))
    pid = "cluster.admission"
    s = R.CheckSubject(check_program_ref=R.CheckProgramRef(id=pid, version="1.0.0", program_hash=registry.registered_program_hash(pid, "1.0.0")),
                       inputs=(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="."),), tier=R.CheckTier.K)
    v = adapter.run_check(w, s).value
    assert v["counts"] == {"objects": 5, "kyverno_denials": 1, "other_webhook_denials": 0, "pod_security_denials": 1, "quota_denials": 1,
                           "limit_range_denials": 1, "warnings": 0}
    by = {r["name"]: r for r in v["objects"]}
    assert list(by["b"]["policies"]) == ["require-labels"] and by["c"]["pod_security_level"] == "restricted:latest" and by["d"]["quota_name"] == "q"
    assert by["a"]["response"] == "accepted" and by["a"]["layer"] == "none"


def test_status_programs_read_the_cluster_and_need_no_manifest_inputs(tmp_path, registry, neutral):
    from agent_harness.qa import records as R
    case = write_tree(tmp_path / "case", good_set())
    objects = {"gateway.gateway.networking.k8s.io": {"items": [{"metadata": {"namespace": "infra", "name": "public"}, "status": {"conditions": [
        {"type": "Accepted", "status": "True", "reason": "Accepted"}, {"type": "Programmed", "status": "True", "reason": "Programmed"}],
        "listeners": [{"name": "https", "attachedRoutes": 1, "conditions": [{"type": "ResolvedRefs", "status": "True", "reason": "ok"}]}]}}]},
        "httproute.gateway.networking.k8s.io": {"items": [{"metadata": {"namespace": "demo", "name": "app"}, "status": {"parents": [{
            "parentRef": {"name": "public", "namespace": "infra"}, "conditions": [{"type": "Accepted", "status": "True", "reason": "Accepted"},
                                                                                   {"type": "ResolvedRefs", "status": "True", "reason": "ok"}]}]}}]},
        "clusterpolicy.kyverno.io": {"items": [{"metadata": {"name": "p1"}, "status": {"ready": True}}, {"metadata": {"name": "p2"}, "status": {}}]}}
    sess, fake, *_ = C.open_session(tmp_path, fake_kw={"objects": objects})
    adapter = CheckAdapter(case, registry=registry, tier_k=TierKGate(sess))
    w = adapter.open_workspace(R.CheckProfile(case_root_digest=tree_digest(case), tier=R.CheckTier.K, disposable_proof_ref=sess.proof_ref))

    def run(pid):
        s = R.CheckSubject(check_program_ref=R.CheckProgramRef(id=pid, version="1.0.0", program_hash=registry.registered_program_hash(pid, "1.0.0")),
                           inputs=(), tier=R.CheckTier.K)
        return adapter.run_check(w, s).value
    g = run("cluster.gateway-status")
    assert g["counts"] == {"gateways": 1, "gateways_programmed": 1, "routes": 1, "route_parents": 1, "route_parents_accepted": 1, "route_parents_not_accepted": 0}
    assert g["gateways"][0]["listeners_resolved"] is True
    p = run("cluster.policy-status.counts")
    assert p["counts"]["policies"] == 2 and p["counts"]["policies_ready"] == 1 and p["counts"]["policies_not_ready"] == 1


def test_a_dry_run_program_with_no_inputs_is_unresolved_not_empty(k_world):
    w = k_world
    h = w.adapter.open_workspace(w.profile)
    R = w.R
    s = R.CheckSubject(check_program_ref=R.CheckProgramRef(id="cluster.dry-run", version="1.0.0", program_hash=w.registry.registered_program_hash("cluster.dry-run", "1.0.0")),
                       inputs=(), tier=R.CheckTier.K)
    assert w.adapter.run_check(h, s).resolution is R.Resolution.UNRESOLVED


def test_a_proof_that_is_not_this_clusters_is_refused_when_the_workspace_opens(k_world, neutral):
    from agent_harness.qa import errors as E
    w = k_world
    bad = w.R.CheckProfile(case_root_digest=tree_digest(w.case), tier=w.R.CheckTier.K, disposable_proof_ref="sha256:" + "5" * 64)
    with pytest.raises(E.ActionBlockedByPolicy):
        w.adapter.open_workspace(bad)


def test_a_tier_k_subject_needs_a_tier_k_workspace_and_a_tier_k_program(k_world, neutral):
    from agent_harness.qa import errors as E
    w = k_world
    offline = w.adapter.open_workspace(w.R.CheckProfile(case_root_digest=tree_digest(w.case), tier=w.R.CheckTier.OFFLINE))
    with pytest.raises(E.ActionBlockedByPolicy):
        w.adapter.run_check(offline, k_subject(w, "cluster.dry-run"))
    h = w.adapter.open_workspace(w.profile)
    with pytest.raises(E.ActionBlockedByPolicy):
        w.adapter.run_check(h, k_subject(w, "manifest.structure"))                       # an offline program is not a tier K program
    with pytest.raises(E.ActionBlockedByPolicy):
        w.adapter.run_check(h, k_subject(w, "cluster.dry-run", tier="OFFLINE"))          # a tier K program does not run offline


def test_an_unregistered_or_mismatched_tier_k_program_is_refused_before_the_cluster_is_touched(k_world, neutral):
    from agent_harness.qa import errors as E
    w = k_world
    h = w.adapter.open_workspace(w.profile)
    before = len(w.fake.calls)
    R = w.R
    bad = R.CheckSubject(check_program_ref=R.CheckProgramRef(id="cluster.dry-run", version="1.0.0", program_hash="sha256:" + "4" * 64),
                         inputs=(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="."),), tier=R.CheckTier.K)
    with pytest.raises(E.AssertionProgramMismatch):
        w.adapter.run_check(h, bad)
    none = R.CheckSubject(check_program_ref=R.CheckProgramRef(id="cluster.unknown", version="1.0.0", program_hash="sha256:" + "4" * 64),
                          inputs=(), tier=R.CheckTier.K)
    with pytest.raises(E.AssertionProgramUnregistered):
        w.adapter.run_check(h, none)
    assert len(w.fake.calls) == before


def test_an_expected_value_cannot_reach_a_tier_k_check(k_world, neutral):
    from agent_harness.qa import errors as E
    w = k_world
    h = w.adapter.open_workspace(w.profile)

    class Fake:
        def to_json(self_inner):
            return {**k_subject(w, "cluster.dry-run").to_json(), "expected": {"accepted": 9}}
    with pytest.raises(E.SpecInvalid):
        w.adapter.run_check(h, Fake())


def test_the_marker_object_disappearing_between_checks_blocks_the_next_check(k_world, neutral):
    from agent_harness.qa import errors as E
    w = k_world
    h = w.adapter.open_workspace(w.profile)
    w.adapter.run_check(h, k_subject(w, "cluster.dry-run.counts"))
    w.fake.marker = None
    with pytest.raises(E.ActionBlockedByPolicy):
        w.adapter.run_check(h, k_subject(w, "cluster.dry-run.counts"))


def test_reset_and_close_run_the_registered_cleanups_and_report_anything_left_behind(k_world, neutral):
    w = k_world
    h = w.adapter.open_workspace(w.profile)
    done = []
    w.gate.register_cleanup(lambda: done.append("a") or [])
    assert w.adapter.reset(h, w.R.ResetScope.ENVIRONMENT).ok is True and done == ["a"]
    w.gate.register_cleanup(lambda: ["probe-namespace-1"])
    rep = w.adapter.close_workspace(h)
    assert rep.verified is False and rep.leaked == ("probe-namespace-1",)


def test_two_lanes_give_separate_results_that_are_never_merged(tmp_path, registry, neutral):
    from agent_harness.qa import records as R
    case = write_tree(tmp_path / "case", good_set())
    state, entries = C.make_state(tmp_path, ("primary", "control"))
    guard = C.make_guard(state)
    from redevops_qa_checks.tierk.guard import GuardedSession, local_for_lane
    reports = LaneReports()
    pid = "cluster.dry-run"
    ref = {"id": pid, "version": "1.0.0", "program_hash": registry.registered_program_hash(pid, "1.0.0")}
    for lane, rejects in (("primary", {"app": (1, QUOTA)}), ("control", {})):
        fake = C.FakeCluster(entries[lane], dry_run=rejects)
        sess = GuardedSession(guard, local_for_lane(guard, lane), fake)
        a = CheckAdapter(case, registry=registry, tier_k=TierKGate(sess))
        w = a.open_workspace(R.CheckProfile(case_root_digest=tree_digest(case), tier=R.CheckTier.K, disposable_proof_ref=sess.proof_ref))
        s = R.CheckSubject(check_program_ref=R.CheckProgramRef(**ref), inputs=(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="."),), tier=R.CheckTier.K)
        v = a.run_check(w, s).value
        reports.add(lane, sess.kubernetes_version, ref, v)
    data = reports.as_data()
    assert [l["lane"] for l in data["lanes"]] == ["control", "primary"] and data["pooled"] is None
    assert not any(k in json.dumps(data) for k in ("total", "overall", "merged", "combined"))
    diff = reports.lane_difference("primary", "control")
    assert diff["attribution"] == "none" and diff["checks"][0]["equal"] is False


def test_a_result_cannot_be_filed_under_the_wrong_lane(tmp_path):
    from redevops_qa_checks.errors import CheckError
    r = LaneReports()
    with pytest.raises(CheckError):
        r.add("control", "v1.35.8", {"id": "x", "version": "1.0.0", "program_hash": "sha256:" + "0" * 64},
              {"lane": {"id": "primary", "kubernetes_version": "v1.37.0"}})
    with pytest.raises(CheckError):
        r.add("control", "v1.35.8", {"id": "x", "version": "1.0.0", "program_hash": "sha256:" + "0" * 64}, {"no": "lane"})


def test_the_gate_cannot_be_built_without_a_guarded_session():
    with pytest.raises(PolicyBlocked):
        TierKGate(object())


# -- what is not expressible ---------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("pid", sorted(NOT_EXPRESSIBLE))
def test_a_property_the_disposable_cluster_cannot_show_is_not_expressible_never_a_pass(k_world, neutral, pid):
    from agent_harness.qa import errors as E
    w = k_world
    R = w.R
    h = w.adapter.open_workspace(w.profile)
    off = w.adapter.open_workspace(R.CheckProfile(case_root_digest=tree_digest(w.case), tier=R.CheckTier.OFFLINE))
    s_k = R.CheckSubject(check_program_ref=R.CheckProgramRef(id=pid, version="1.0.0", program_hash="sha256:" + "3" * 64), inputs=(), tier=R.CheckTier.K)
    s_o = R.CheckSubject(check_program_ref=R.CheckProgramRef(id=pid, version="1.0.0", program_hash="sha256:" + "3" * 64),
                         inputs=(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="."),), tier=R.CheckTier.OFFLINE)
    for ws, s in ((h, s_k), (off, s_o)):
        with pytest.raises(E.UnsupportedOperation):
            w.adapter.run_check(ws, s)
    assert w.fake.non_marker_calls() == []


def test_the_not_expressible_list_names_the_documented_classes():
    assert {"closed-world.allow-list-completeness", "admission.signature-verification", "traffic.metadata-endpoint-proof"} <= set(NOT_EXPRESSIBLE)
    assert all(NOT_EXPRESSIBLE[k] for k in NOT_EXPRESSIBLE)


def test_the_offline_engine_refuses_a_tier_k_program(case_root, registry):
    spec = registry.resolve({"id": "cluster.dry-run", "version": "1.0.0", "program_hash": registry.registered_program_hash("cluster.dry-run", "1.0.0")})
    with pytest.raises(PolicyBlocked):
        CheckEngine(case_root, registry).run_check({"check_program_ref": spec.ref, "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "tier": "OFFLINE"})


def test_tier_k_program_hashes_cover_the_argv_allow_list_the_drivers_and_the_collectors(registry):
    spec = registry.resolve({"id": "cluster.admission", "version": "1.0.0", "program_hash": registry.registered_program_hash("cluster.admission", "1.0.0")})
    assert {"tierk/argv.py", "tierk/drivers.py", "tierk/collectors.py", "programs/_cluster.py"} <= set(spec.source_files)
    assert spec.tier == "K" and spec.collector == "dry-run"
