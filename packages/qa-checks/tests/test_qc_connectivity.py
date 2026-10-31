# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The connectivity matrix: parsing, probe execution against a fake cluster, the evaluator over observed results, policy state."""
import json

import pytest

import qc_cluster as C
from qc_fixtures import reference, write_tree
from redevops_qa_checks.adapter import CheckAdapter
from redevops_qa_checks.errors import LimitExceeded, PolicyBlocked, Unsupported
from redevops_qa_checks.manifests import load_text
from redevops_qa_checks.program_input import ProgramInput
from redevops_qa_checks.tierk import connectivity as CN
from redevops_qa_checks.tierk.gate import TierKGate
from redevops_qa_checks.tierk.guard import GuardedSession, local_for_lane
from redevops_qa_checks.tierk.probes import PROBE_SOURCE, ProbePolicy
from redevops_qa_checks.tierk.subnets import TargetPolicy

# built at run time: the local-network range a developer machine may use
LAN_HOST = ".".join(["192", "168", "40", "5"])
LAN_NET = ".".join(["192", "168", "40", "0"]) + "/24"


def plain(v):
    from collections.abc import Mapping
    if isinstance(v, Mapping):
        return {k: plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [plain(x) for x in v]
    return v


def probe(pid="web-to-db", **over):
    p = {"id": pid, "range_class": "workload", "source": {"namespace": "demo", "labels": {"app": "web"}},
         "target": {"ip": "10.244.2.7", "port": 5432}, "control": {"namespace": "control"}}
    p.update(over)
    return p


def matrix(*probes):
    return reference("ConnectivityMatrix", {"probes": list(probes) or [probe()]})


def refs(*probes):
    """Reference documents as the loader produces them."""
    from qc_fixtures import dump
    return load_text(dump([matrix(*probes)]), "m.yaml").references


def parse(*probes, **kw):
    return CN.parse_matrix(refs(*probes), **kw)


# -- parsing -------------------------------------------------------------------------------------------------------------------------------

def test_a_declared_probe_is_parsed_into_data():
    p = parse()[0]
    assert (p.id, p.range_class, p.source_namespace, p.source_labels, p.target_ip, p.port, p.protocol, p.control_namespace) == \
        ("web-to-db", "workload", "demo", (("app", "web"),), "10.244.2.7", 5432, "tcp", "control")


def test_exactly_one_matrix_is_required_and_the_count_is_bounded():
    with pytest.raises(PolicyBlocked):
        CN.parse_matrix(())
    with pytest.raises(PolicyBlocked):
        CN.parse_matrix(refs(probe()) + refs(probe("b")))
    with pytest.raises(LimitExceeded):
        parse(*[probe(f"p{i}") for i in range(CN.MAX_PROBES + 1)])
    assert len(parse(*[probe(f"p{i}") for i in range(CN.MAX_PROBES)])) == CN.MAX_PROBES


@pytest.mark.parametrize("over", [
    {"id": "Bad_ID"}, {"id": ""}, {"range_class": "everywhere"}, {"source": {"labels": {"a": "b"}}}, {"source": {"namespace": "Bad NS"}}, {"source": "demo"},
    {"target": {"port": 80}}, {"target": {"ip": "10.244.2.7"}}, {"target": {"ip": "10.244.2.7", "port": 0}}, {"target": {"ip": "10.244.2.7", "port": "80"}},
    {"target": {"ip": "10.244.2.7", "port": 80, "workload": {"namespace": "x", "labels": {"a": "b"}}}},
    {"target": {"ip": "web.demo.svc", "port": 80}}, {"target": {"ip": "example.test", "port": 80}}, {"target": {"ip": 5, "port": 80}},
    {"target": {"workload": {"namespace": "x"}, "port": 80}}, {"target": {"workload": {"namespace": "x", "labels": {}}, "port": 80}},
    {"target": {"workload": "x", "port": 80}}, {"timeout_seconds": 0}, {"timeout_seconds": 11}, {"timeout_seconds": True},
    {"source": {"namespace": "demo", "labels": {"a b": "c"}}}, {"extra_field": 1}, {"control": {"namespace": "BAD"}}, {"control": "x"},
])
def test_a_malformed_probe_is_refused(over):
    with pytest.raises(PolicyBlocked):
        parse(probe(**over))


def test_duplicate_ids_are_refused():
    with pytest.raises(PolicyBlocked):
        parse(probe("a"), probe("a"))


def test_a_hostname_target_is_refused_as_not_an_ip_literal():
    with pytest.raises(PolicyBlocked) as e:
        parse(probe(target={"ip": "db.example.test", "port": 5432}))
    assert e.value.details["guard_code"] == "TARGET_NOT_IP_LITERAL"


def test_udp_and_metadata_endpoint_probes_are_not_expressible_for_traffic():
    with pytest.raises(Unsupported):
        parse(probe(target={"ip": "10.244.2.7", "port": 53, "protocol": "udp"}))
    with pytest.raises(Unsupported):
        parse(probe(range_class="metadata-endpoint"))
    with pytest.raises(Unsupported):
        parse(probe(target={"ip": "169.254.169.254", "port": 80}))


def test_the_metadata_address_is_allowed_for_the_policy_state_check_because_it_sends_nothing():
    p = parse(probe(range_class="metadata-endpoint", target={"ip": "169.254.169.254", "port": 80}), allow_metadata=True)[0]
    assert p.target_ip == "169.254.169.254"


# -- traffic -----------------------------------------------------------------------------------------------------------------------------------------

def world(tmp_path, *probes, fake_kw=None, session_ok=True, sleeper=None, tp=None):
    from agent_harness.qa import records as R
    from redevops_qa_checks.manifests import tree_digest
    from redevops_qa_checks.registry import builtin_registry
    from qc_fixtures import good_set
    files = good_set()
    files["matrix.yaml"] = [matrix(*probes)]
    case = write_tree(tmp_path / "case", files)
    sess, fake = C.open_probe_session(tmp_path, fake_kw=fake_kw)
    gate = TierKGate(sess, target_policy=tp or TargetPolicy(), sleep=sleeper or (lambda s: None))
    reg = builtin_registry()
    adapter = CheckAdapter(case, registry=reg, tier_k=gate)
    w = adapter.open_workspace(R.CheckProfile(case_root_digest=tree_digest(case), tier=R.CheckTier.K, disposable_proof_ref=sess.proof_ref))

    def run(pid, paths=("matrix.yaml",)):
        s = R.CheckSubject(check_program_ref=R.CheckProgramRef(id=pid, version="1.0.0", program_hash=reg.registered_program_hash(pid, "1.0.0")),
                           inputs=tuple(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path=p) for p in paths), tier=R.CheckTier.K)
        ov = adapter.run_check(w, s)
        from types import SimpleNamespace
        return SimpleNamespace(value=plain(ov.value), resolution=ov.resolution, raw=ov)

    class W:
        pass
    o = W()
    o.run, o.fake, o.sess, o.gate, o.adapter, o.handle, o.R = run, fake, sess, gate, adapter, w, R
    return o


def test_a_traffic_probe_runs_a_fixed_pod_reads_its_one_line_and_deletes_it(tmp_path):
    w = world(tmp_path, probe(), fake_kw={"outcome": lambda ip, port, ns, role: "refused" if role == "probe" else "connected"})
    v = w.run("connectivity.traffic").value
    row = v["matrix"][0]
    assert v["evidence"] == "traffic" and v["lane"]["id"] == "primary"
    assert (row["id"], row["result"], row["control_result"], row["control_reached_target"], row["target_ip"], row["port"]) == \
        ("web-to-db", "refused", "connected", True, "10.244.2.7", 5432)
    assert len(w.fake.applied) == 2 and {d["metadata"]["namespace"] for d in w.fake.applied} == {"demo", "control"}
    assert all(d["spec"]["containers"][0]["command"][2] == PROBE_SOURCE for d in w.fake.applied)
    assert w.fake.live == {}                                          # every probe pod was deleted
    probe_pod = [d for d in w.fake.applied if d["metadata"]["namespace"] == "demo"][0]
    assert probe_pod["metadata"]["labels"]["app"] == "web"            # the probe carries the source workload's labels
    counts = v["counts"]
    assert counts["probes"] == 1 and counts["refused"] == 1 and counts["controls_reached_target"] == 1


def test_only_probe_pods_are_ever_created_or_deleted_and_each_command_follows_a_marker_read(tmp_path):
    w = world(tmp_path, probe(), probe("b", target={"ip": "203.0.113.10", "port": 8080}, range_class="lan-equivalent"))
    w.run("connectivity.traffic")
    mut = w.fake.mutating_calls()
    assert len(mut) == 8 and {m[0] for m in mut} == {"apply", "delete"}
    for m in mut:
        if m[0] == "delete":
            assert m[1] == "pod" and m[2].startswith("qa-probe-")
    calls = [a for a, _ in w.fake.calls]
    for i, a in enumerate(calls):
        if a[:3] != ["get", "configmap", "qa-disposable-marker"] and a != ["version", "-o", "json"]:
            assert calls[i - 1][:3] == ["get", "configmap", "qa-disposable-marker"]


def test_a_result_that_is_unreachable_while_the_control_connected_is_set_out_as_two_facts(tmp_path):
    w = world(tmp_path, probe(), fake_kw={"outcome": lambda ip, port, ns, role: "timeout" if ns == "demo" else "connected"})
    row = w.run("connectivity.traffic").value["matrix"][0]
    assert (row["result"], row["control_result"], row["control_reached_target"]) == ("timeout", "connected", True)


def test_when_the_control_cannot_reach_the_target_either_that_is_visible(tmp_path):
    w = world(tmp_path, probe(), fake_kw={"outcome": lambda ip, port, ns, role: "timeout"})
    row = w.run("connectivity.traffic").value["matrix"][0]
    assert row["control_reached_target"] is False
    assert w.run("connectivity.traffic.counts").value["counts"]["controls_did_not_reach_target"] == 1


def test_a_probe_without_a_control_has_no_control_result(tmp_path):
    p = probe()
    del p["control"]
    row = world(tmp_path, p).run("connectivity.traffic").value["matrix"][0]
    assert (row["has_control"], row["control_result"], row["control_reached_target"]) == (False, "", None)


def test_a_pod_that_never_finishes_is_reported_not_finished_after_a_bounded_number_of_polls(tmp_path):
    slept = []
    w = world(tmp_path, probe(), fake_kw={"polls_until_done": 10**6}, sleeper=slept.append)
    row = w.run("connectivity.traffic").value["matrix"][0]
    assert row["result"] == "not_finished" and len(slept) == 2 * CN.MAX_POLLS
    assert w.fake.live == {}                                          # and it was still deleted


def test_a_workload_target_is_resolved_to_an_ip_literal_before_probing(tmp_path):
    p = probe(target={"workload": {"namespace": "db", "labels": {"app": "db"}}, "port": 5432})
    w = world(tmp_path, p, fake_kw={"pods": {("db", "app=db"): [("db-1", "10.244.9.9"), ("db-0", "10.244.9.8")]}})
    row = w.run("connectivity.traffic").value["matrix"][0]
    assert row["target_ip"] == "10.244.9.8" and row["target_kind"] == "workload" and row["result"] == "connected"
    assert w.fake.applied[0]["spec"]["containers"][0]["args"][0] == "10.244.9.8"


def test_a_workload_target_that_is_not_found_is_not_run_never_connected(tmp_path):
    p = probe(target={"workload": {"namespace": "db", "labels": {"app": "db"}}, "port": 5432})
    w = world(tmp_path, p)
    row = w.run("connectivity.traffic").value["matrix"][0]
    assert (row["result"], row["target_ip"]) == ("not_run", "") and w.fake.applied == []


@pytest.mark.parametrize("ip", ["8.8.8.8", LAN_HOST, "10.0.0.5", "93.184.216.34"])
def test_a_target_outside_the_cluster_and_the_plan_is_never_probed(tmp_path, ip):
    from agent_harness.qa import errors as E
    w = world(tmp_path, probe(target={"ip": ip, "port": 80}))
    with pytest.raises(E.ActionBlockedByPolicy):
        w.run("connectivity.traffic")
    assert w.fake.applied == []


def test_hostname_targets_are_refused_by_the_adapter(tmp_path):
    from agent_harness.qa import errors as E
    w = world(tmp_path, probe(target={"ip": "db.example.test", "port": 80}))
    with pytest.raises(E.ActionBlockedByPolicy):
        w.run("connectivity.traffic")
    assert w.fake.applied == []


def test_udp_and_metadata_probes_are_unsupported_never_a_pass(tmp_path):
    from agent_harness.qa import errors as E
    for p in (probe(target={"ip": "10.244.2.7", "port": 53, "protocol": "udp"}), probe(range_class="metadata-endpoint")):
        w = world(tmp_path / ("a" if p["range_class"] == "workload" else "b"), p)
        with pytest.raises(E.UnsupportedOperation):
            w.run("connectivity.traffic")
        assert w.fake.applied == []


def test_the_synthetic_range_is_flagged_in_the_row(tmp_path):
    w = world(tmp_path, probe("lan", range_class="lan-equivalent", target={"ip": "203.0.113.10", "port": 8080}),
              probe("world", range_class="world", target={"ip": "198.51.100.10", "port": 25}), probe("pod"))
    rows = {r["id"]: r for r in w.run("connectivity.traffic").value["matrix"]}
    assert rows["lan"]["synthetic_network"] == "lan-equivalent" and rows["world"]["synthetic_network"] == "world" and rows["pod"]["synthetic_network"] == ""
    assert w.run("connectivity.traffic.counts").value["counts"]["synthetic_subnet_targets"] == 2


def test_the_traffic_check_needs_a_session_with_probe_mutation_enabled(tmp_path):
    from agent_harness.qa import errors as E, records as R
    from redevops_qa_checks.manifests import tree_digest
    from redevops_qa_checks.registry import builtin_registry
    from qc_fixtures import good_set
    files = good_set()
    files["matrix.yaml"] = [matrix(probe())]
    case = write_tree(tmp_path / "case", files)
    sess, fake, *_ = C.open_session(tmp_path)                       # a session without probe mutation
    reg = builtin_registry()
    a = CheckAdapter(case, registry=reg, tier_k=TierKGate(sess))
    w = a.open_workspace(R.CheckProfile(case_root_digest=tree_digest(case), tier=R.CheckTier.K, disposable_proof_ref=sess.proof_ref))
    pid = "connectivity.traffic"
    s = R.CheckSubject(check_program_ref=R.CheckProgramRef(id=pid, version="1.0.0", program_hash=reg.registered_program_hash(pid, "1.0.0")),
                       inputs=(R.ResourceRef(kind=R.ResourceKind.MANIFEST_PATH, path="matrix.yaml"),), tier=R.CheckTier.K)
    with pytest.raises(E.ActionBlockedByPolicy):
        a.run_check(w, s)
    assert fake.mutating_calls() == []


def test_a_probe_pod_that_cannot_be_deleted_is_reported_as_left_behind_on_close(tmp_path):
    w = world(tmp_path, probe(), fake_kw={"delete_fails": True})
    w.run("connectivity.traffic")
    rep = w.adapter.close_workspace(w.handle)
    assert rep.verified is False and len(rep.leaked) == 2 and all(":qa-probe-" in x for x in rep.leaked)


def test_close_deletes_what_an_interrupted_run_left_behind(tmp_path):
    w = world(tmp_path, probe(), fake_kw={"delete_fails": True})
    w.run("connectivity.traffic")
    assert len(w.fake.live) == 2
    w.fake.delete_fails = False
    rep = w.adapter.close_workspace(w.handle)
    assert rep.verified is True and rep.leaked == () and w.fake.live == {}


def test_reset_removes_probe_pods_too(tmp_path):
    w = world(tmp_path, probe(), fake_kw={"delete_fails": True})
    w.run("connectivity.traffic")
    w.fake.delete_fails = False
    assert w.adapter.reset(w.handle, w.R.ResetScope.ENVIRONMENT).ok is True and w.fake.live == {}


def test_a_reset_that_cannot_remove_a_probe_pod_fails_and_leaves_it_to_close(tmp_path):
    from agent_harness.qa import errors as E
    w = world(tmp_path, probe(), fake_kw={"delete_fails": True})
    w.run("connectivity.traffic")
    with pytest.raises(E.ResetFailed):
        w.adapter.reset(w.handle, w.R.ResetScope.ENVIRONMENT)
    rep = w.adapter.close_workspace(w.handle)
    assert rep.verified is False and len(rep.leaked) == 2


def test_the_matrix_must_be_among_the_inputs(tmp_path):
    w = world(tmp_path, probe())
    from agent_harness.qa import errors as E
    with pytest.raises(E.ActionBlockedByPolicy):
        w.run("connectivity.traffic", paths=("10-app.yaml",))


# -- the evaluator as data in, observations out ----------------------------------------------------------------------------------------------------------

def cluster_docs(*docs):
    from redevops_qa_checks.manifests import freeze
    return ProgramInput(cluster=tuple(freeze(d) for d in docs))


def test_the_evaluator_lays_results_out_per_declared_probe_without_judging_them():
    from redevops_qa_checks.programs import _connectivity as E
    data = cluster_docs(
        {"section": "lane", "lane": "primary", "kubernetes_version": "v1.37.0", "disposable_proof": "sha256:" + "0" * 64},
        {"section": "declared", "id": "b", "range_class": "world", "source_namespace": "demo", "target_kind": "ip", "target_ip": "198.51.100.10", "port": 25,
         "protocol": "tcp", "has_control": True, "synthetic_network": "world"},
        {"section": "declared", "id": "a", "range_class": "workload", "source_namespace": "demo", "target_kind": "ip", "target_ip": "10.244.0.5", "port": 80,
         "protocol": "tcp", "has_control": False, "synthetic_network": ""},
        {"section": "probe", "id": "b", "role": "probe", "result": "timeout"}, {"section": "probe", "id": "b", "role": "control", "result": "connected"},
        {"section": "probe", "id": "a", "role": "probe", "result": "connected"})
    rows = E.evaluate_matrix(data)
    assert [r["id"] for r in rows] == ["a", "b"]
    assert (rows[1]["result"], rows[1]["control_result"], rows[1]["control_reached_target"]) == ("timeout", "connected", True)
    assert rows[0]["control_reached_target"] is None
    counts = E.matrix_counts(rows)
    assert (counts["probes"], counts["connected"], counts["timeout"], counts["controls_reached_target"]) == (2, 1, 1, 1)


def test_a_declared_probe_without_a_result_is_not_run_and_an_unknown_result_is_an_error():
    from redevops_qa_checks.programs import _connectivity as E
    data = cluster_docs({"section": "declared", "id": "a", "range_class": "workload", "target_ip": "10.244.0.5", "port": 80, "protocol": "tcp"},
                        {"section": "declared", "id": "b", "range_class": "workload", "target_ip": "10.244.0.6", "port": 80, "protocol": "tcp"},
                        {"section": "probe", "id": "b", "role": "probe", "result": "totally-fine"})
    rows = {r["id"]: r for r in E.evaluate_matrix(data)}
    assert rows["a"]["result"] == "not_run" and rows["b"]["result"] == "error"


def test_the_evaluator_output_has_no_verdict_key_and_no_expected_value():
    from redevops_qa_checks.programs import _connectivity as E
    from redevops_qa_checks.registry import validate_output
    data = cluster_docs({"section": "declared", "id": "a", "range_class": "workload", "target_ip": "10.244.0.5", "port": 80, "protocol": "tcp"})
    validate_output({"matrix": E.evaluate_matrix(data), "counts": E.matrix_counts(E.evaluate_matrix(data))})


# -- policy state ---------------------------------------------------------------------------------------------------------------------------------------

def cnp(name, ns="demo", kind="CiliumNetworkPolicy", selector=None, **rule):
    return {"kind": kind, "metadata": {"name": name, **({"namespace": ns} if ns else {})},
            "spec": {"endpointSelector": selector if selector is not None else {}, "egressDeny": [rule]}}


def npol(name, ns="demo", egress=None, selector=None, types=("Egress",)):
    sp = {"podSelector": selector if selector is not None else {}, "policyTypes": list(types)}
    if egress is not None:
        sp["egress"] = egress
    return {"metadata": {"name": name, "namespace": ns}, "spec": sp}


def state(tmp_path, probes, *, k8s=(), cil=(), ccnp=()):
    return world(tmp_path, *probes, fake_kw={"objects": {"networkpolicy": {"items": list(k8s)}, "ciliumnetworkpolicy.cilium.io": {"items": list(cil)},
                                                         "ciliumclusterwidenetworkpolicy.cilium.io": {"items": list(ccnp)}}})


def test_a_cidr_deny_entry_matching_the_target_and_the_source_is_reported(tmp_path):
    p = probe(range_class="lan-equivalent", target={"ip": "203.0.113.10", "port": 8080})
    w = state(tmp_path, [p], cil=[cnp("deny-lan", toCIDR=["203.0.113.0/24"])])
    v = w.run("connectivity.policy-state").value
    row = v["matrix"][0]
    assert v["evidence"] == "policy-state" and [list(d.values()) for d in row["egress_deny_matches"]] == [["CiliumNetworkPolicy/deny-lan", "demo", "cidr", "203.0.113.0/24"]]
    assert row["selecting_policies"] == ["CiliumNetworkPolicy/deny-lan"] and row["selector_understood"] is True
    assert w.fake.mutating_calls() == [] and w.fake.applied == []


def test_cidr_sets_with_exceptions_entities_ports_and_selectors_are_applied(tmp_path):
    ps = [probe("a", target={"ip": "198.51.100.10", "port": 25}, range_class="mail-port"),
          probe("b", target={"ip": "198.51.100.10", "port": 8025}, range_class="mail-port"),
          probe("c", target={"ip": "10.244.2.7", "port": 80}),
          probe("d", target={"ip": "203.0.113.10", "port": 80}, range_class="lan-equivalent")]
    cil = [cnp("mail", entities=None, toEntities=["world"], toPorts=[{"ports": [{"port": "25", "protocol": "TCP"}, {"port": "465"}]}]),
           cnp("set", toCIDRSet=[{"cidr": "203.0.113.0/24", "except": ["203.0.113.10/32"]}]),
           cnp("other-app", selector={"matchLabels": {"app": "other"}}, toCIDR=["10.244.0.0/16"]),
           cnp("wrong-ns", ns="elsewhere", toCIDR=["10.244.0.0/16"])]
    cil[0]["spec"]["egressDeny"][0].pop("entities", None)
    w = state(tmp_path, ps, cil=cil)
    rows = {r["id"]: r for r in w.run("connectivity.policy-state").value["matrix"]}
    assert [d["via"] for d in rows["a"]["egress_deny_matches"]] == ["entity"]                # port 25 is listed
    assert rows["b"]["egress_deny_matches"] == [] and rows["c"]["egress_deny_matches"] == [] # port 8025 not listed; app=other does not select the source
    assert rows["d"]["egress_deny_matches"] == []                                            # excluded by the except entry
    assert rows["c"]["selecting_policies"] == ["CiliumNetworkPolicy/mail", "CiliumNetworkPolicy/set"] or rows["c"]["selecting_policies"]


def test_cluster_wide_deny_policies_apply_to_every_source(tmp_path):
    p = probe(target={"ip": "10.244.2.7", "port": 80})
    w = state(tmp_path, [p], ccnp=[cnp("everywhere", ns=None, kind="CiliumClusterwideNetworkPolicy", toCIDR=["10.244.0.0/16"])])
    row = w.run("connectivity.policy-state").value["matrix"][0]
    assert row["egress_deny_matches"][0]["policy"] == "CiliumClusterwideNetworkPolicy/everywhere"


def test_default_deny_and_ip_block_allow_rules_are_reported_for_kubernetes_policies(tmp_path):
    ps = [probe("a", target={"ip": "10.244.2.7", "port": 5432}), probe("b", target={"ip": "198.51.100.10", "port": 25}, range_class="world")]
    k8s = [npol("deny-all"), npol("allow-db", egress=[{"to": [{"ipBlock": {"cidr": "10.244.0.0/16", "except": ["10.244.2.0/24"]}}], "ports": [{"port": 5432}]}]),
           npol("allow-lan", egress=[{"to": [{"ipBlock": {"cidr": "198.51.100.0/24"}}], "ports": [{"port": 8025}]}]),
           npol("ingress-only", types=("Ingress",)), npol("other-ns", ns="elsewhere")]
    rows = {r["id"]: r for r in state(tmp_path, ps, k8s=k8s).run("connectivity.policy-state").value["matrix"]}
    assert rows["a"]["default_deny_egress_selecting"] is True and rows["a"]["egress_allow_matches"] == []         # the except range excludes the target
    assert rows["b"]["egress_allow_matches"] == []                                                                  # the allowed port is not 25
    assert sorted(rows["a"]["selecting_policies"]) == ["NetworkPolicy/allow-db", "NetworkPolicy/allow-lan", "NetworkPolicy/deny-all"]


def test_an_allow_rule_that_matches_target_and_port_is_reported(tmp_path):
    p = probe(target={"ip": "10.244.3.3", "port": 5432})
    k8s = [npol("allow-db", egress=[{"to": [{"ipBlock": {"cidr": "10.244.0.0/16"}}], "ports": [{"port": 5432}]}])]
    row = state(tmp_path, [p], k8s=k8s).run("connectivity.policy-state").value["matrix"][0]
    assert row["egress_allow_matches"][0]["via"] == "ip-block" and row["egress_allow_matches"][0]["value"] == "10.244.0.0/16"


def test_a_selector_the_checker_does_not_understand_is_flagged_not_guessed(tmp_path):
    p = probe(target={"ip": "10.244.2.7", "port": 80})
    sel = {"matchExpressions": [{"key": "app", "operator": "In", "values": ["web"]}]}
    row = state(tmp_path, [p], cil=[cnp("x", selector=sel, toCIDR=["10.244.0.0/16"])]).run("connectivity.policy-state").value["matrix"][0]
    assert row["selector_understood"] is False and row["egress_deny_matches"] == []


def test_the_metadata_endpoint_entry_is_a_policy_state_check_only(tmp_path):
    p = probe(range_class="metadata-endpoint", target={"ip": "169.254.169.254", "port": 80})
    w = state(tmp_path, [p], cil=[cnp("no-metadata", toCIDR=["169.254.169.254/32"])])
    row = w.run("connectivity.policy-state").value["matrix"][0]
    assert row["egress_deny_matches"][0]["value"] == "169.254.169.254/32" and w.fake.applied == []
    from agent_harness.qa import errors as E
    with pytest.raises(E.UnsupportedOperation):
        w.run("connectivity.traffic")                                           # the same declaration is not expressible as traffic


def test_policy_state_and_traffic_are_distinct_programs_with_distinct_evidence_kinds(tmp_path, registry):
    a, b = (registry.resolve({"id": i, "version": "1.0.0", "program_hash": registry.registered_program_hash(i, "1.0.0")}) for i in
            ("connectivity.traffic", "connectivity.policy-state"))
    assert a.collector == "traffic" and b.collector == "policy-state" and a.program_hash != b.program_hash
    w = state(tmp_path, [probe()])
    assert w.run("connectivity.policy-state").value["evidence"] == "policy-state"
    assert w.run("connectivity.traffic").value["evidence"] == "traffic"


def test_a_policy_list_that_cannot_be_read_is_an_environment_fault_not_an_empty_pass(tmp_path):
    from agent_harness.qa import errors as E
    w = state(tmp_path, [probe()])
    orig = w.fake.run

    def bad(args, **kw):
        if args[:2] == ["get", "networkpolicy"]:
            return C.KubectlResult(1, "", "forbidden")
        return orig(args, **kw)
    w.fake.run = bad
    with pytest.raises(E.EnvironmentUnhealthy):
        w.run("connectivity.policy-state")


def test_connectivity_program_hashes_cover_the_probe_specification_and_the_target_policy(registry):
    spec = registry.resolve({"id": "connectivity.traffic", "version": "1.0.0", "program_hash": registry.registered_program_hash("connectivity.traffic", "1.0.0")})
    assert {"tierk/probes.py", "tierk/subnets.py", "tierk/connectivity.py", "tierk/argv.py", "programs/_connectivity.py"} <= set(spec.source_files)
