# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The disposable-cluster guard: it accepts only a cluster this tool generated and refuses everything else, fail closed."""
import hashlib
import json
import os
from pathlib import Path

import pytest

import qc_cluster as C
from redevops_qa_checks.errors import LimitExceeded, PolicyBlocked
from redevops_qa_checks.tierk import guard as G


def code(exc):
    return exc.value.details["guard_code"]


def state_with(tmp_path, **kw):
    state, entries = C.make_state(tmp_path, **kw)
    return state, entries["primary"], C.make_guard(state)


# -- local checks ----------------------------------------------------------------------------------------------------------------

def test_the_generated_cluster_is_accepted(tmp_path):
    state, entry, guard = state_with(tmp_path)
    local = G.local_for_lane(guard, "primary")
    assert local.entry == entry and local.kubeconfig_path == (state / "primary.kubeconfig").resolve()


def test_a_session_on_the_generated_cluster_proves_it_and_the_proof_is_deterministic(tmp_path):
    s1, fake, guard, state, entry = C.open_session(tmp_path)
    ref = s1.proof_ref
    assert ref.startswith("sha256:") and len(ref) == 71
    s2 = G.GuardedSession(guard, G.local_for_lane(guard, "primary"), C.FakeCluster(entry))
    assert s2.proof_ref == ref
    rec = s1.proof_record
    assert rec["schema"] == G.PROOF_SCHEMA and rec["marker"]["lane"] == "primary" and entry.nonce not in json.dumps(rec)
    assert rec["marker_object_nonce_sha256"] == entry.nonce_sha256 and ref == G.proof_ref(rec)


def test_the_two_lanes_have_different_proofs(tmp_path):
    state, entries = C.make_state(tmp_path, ("primary", "control"))
    guard = C.make_guard(state)
    refs = {}
    for lane in ("primary", "control"):
        refs[lane] = G.GuardedSession(guard, G.local_for_lane(guard, lane), C.FakeCluster(entries[lane])).proof_ref
    assert refs["primary"] != refs["control"]


def test_an_unknown_lane_is_refused(tmp_path):
    state, entry, guard = state_with(tmp_path)
    with pytest.raises(PolicyBlocked) as e:
        guard.local_check("nope", state / "primary.kubeconfig", entry.context_name)
    assert code(e) == "LANE_UNKNOWN"
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(guard, "control")
    assert code(e) == "LANE_NOT_GENERATED"


@pytest.mark.parametrize("ctx", ["minikube", "docker-desktop", "prod-eu", "kind-kind", "kind-qa-tier-k-other", "", "kind-qa-tier-k-control"])
def test_a_context_that_is_not_on_the_allow_list_is_refused(tmp_path, ctx):
    state, entry, guard = state_with(tmp_path)
    with pytest.raises(PolicyBlocked) as e:
        guard.local_check("primary", state / "primary.kubeconfig", ctx)
    assert code(e) == "CONTEXT_NOT_ALLOWED"


def test_an_ambient_kubeconfig_is_never_used_even_if_it_is_set_in_the_environment(tmp_path, monkeypatch):
    state, entry, guard = state_with(tmp_path)
    ambient = tmp_path / "ambient.kubeconfig"
    ambient.write_bytes(C.kubeconfig_bytes("prod", "https://prod.example.test:6443"))
    monkeypatch.setenv("KUBECONFIG", str(ambient))
    local = G.local_for_lane(guard, "primary")                  # takes no kubeconfig argument at all
    assert local.kubeconfig_path == (state / "primary.kubeconfig").resolve()
    with pytest.raises(PolicyBlocked) as e:
        guard.local_check("primary", ambient, entry.context_name)
    assert code(e) == "KUBECONFIG_NOT_GENERATED"


def test_a_kubeconfig_elsewhere_with_identical_bytes_is_still_not_the_generated_file(tmp_path):
    state, entry, guard = state_with(tmp_path)
    copy = tmp_path / "copy.kubeconfig"
    copy.write_bytes((state / "primary.kubeconfig").read_bytes())
    with pytest.raises(PolicyBlocked) as e:
        guard.local_check("primary", copy, entry.context_name)
    assert code(e) == "KUBECONFIG_NOT_GENERATED"


def test_a_kubeconfig_that_was_edited_after_generation_is_refused(tmp_path):
    state, entry, guard = state_with(tmp_path)
    p = state / "primary.kubeconfig"
    p.write_bytes(p.read_bytes().replace(b"127.0.0.1", b"10.0.0.9"))
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(guard, "primary")
    assert code(e) == "KUBECONFIG_NOT_GENERATED"


def test_a_symlinked_kubeconfig_is_refused(tmp_path):
    state, entry, guard = state_with(tmp_path)
    p = state / "primary.kubeconfig"
    real = tmp_path / "real"
    real.write_bytes(p.read_bytes())
    p.unlink()
    os.symlink(real, p)
    with pytest.raises(PolicyBlocked):
        G.local_for_lane(guard, "primary")


@pytest.mark.parametrize("server", ["https://203.0.113.5:6443", "https://example.test:6443", "https://10.0.0.1:6443", "http://127.0.0.1:6443",
                                    "https://127.0.0.1", "https://user:pw@127.0.0.1:6443", "https://127.0.0.1:6443/extra", "https://192.168.1.9:6443",
                                    "https://[2001:db8::1]:6443", "127.0.0.1:6443", "https://0.0.0.0:6443", "https://localhost.example.test:6443",
                                    "https://127.0.0.1:99999"])
def test_a_server_outside_loopback_is_refused(tmp_path, server):
    state = G.write_state_dir(tmp_path / "state")
    entry, kc = C.make_entry("primary", server=server)
    G.register_cluster(state, entry, kc)
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(C.make_guard(state), "primary")
    assert code(e) == "SERVER_NOT_LOOPBACK"


@pytest.mark.parametrize("server", ["https://127.0.0.1:46443", "https://127.5.5.5:46443", "https://localhost:46443", "https://[::1]:46443"])
def test_loopback_servers_are_accepted(tmp_path, server):
    state = G.write_state_dir(tmp_path / "state")
    entry, kc = C.make_entry("primary", server=server)
    G.register_cluster(state, entry, kc)
    assert G.local_for_lane(C.make_guard(state), "primary")


def test_a_configured_sandbox_network_is_accepted_and_nothing_near_it_is(tmp_path):
    state = G.write_state_dir(tmp_path / "state")
    entry, kc = C.make_entry("primary", server="https://172.30.5.2:46443")
    G.register_cluster(state, entry, kc)
    assert G.local_for_lane(C.make_guard(state, sandbox_networks=["172.30.5.0/24"]), "primary")
    with pytest.raises(PolicyBlocked):
        G.local_for_lane(C.make_guard(state, sandbox_networks=["172.30.6.0/24"]), "primary")
    with pytest.raises(PolicyBlocked):
        G.local_for_lane(C.make_guard(state), "primary")


def test_a_sandbox_network_may_not_overlap_the_private_lan_range(tmp_path):
    with pytest.raises(PolicyBlocked) as e:
        G.check_server("https://127.0.0.1:1", ["192.168.0.0/16"])
    assert code(e) == "SANDBOX_NETWORK_REFUSED"
    with pytest.raises(PolicyBlocked):
        G.check_server("https://127.0.0.1:1", [".".join(["192", "168", "7", "0"]) + "/24"])


@pytest.mark.parametrize("kw", [{"extra_user": {"token": "abc"}}, {"extra_user": {"exec": {"command": "x"}}}, {"extra_user": {"auth-provider": {"name": "x"}}},
                                {"extra_user": {"username": "u", "password": "p"}}, {"extra_user": {"client-certificate": "/x"}},
                                {"extra_user": {"as": "admin"}}, {"extra_cluster": {"proxy-url": "http://x"}},
                                {"extra_cluster": {"insecure-skip-tls-verify": True}}, {"extra_cluster": {"certificate-authority": "/x"}},
                                {"extra_cluster": {"tls-server-name": "x"}}, {"extra_user": {"tokenFile": "/x"}}, {"extra_user": {"unknown": 1}},
                                {"extra_cluster": {"unknown": 1}}])
def test_credentials_other_than_embedded_client_certificate_data_are_refused(tmp_path, kw):
    state = G.write_state_dir(tmp_path / "state")
    l = C.PLAN.lane("primary")
    entry, kc = C.make_entry("primary", kubeconfig=C.kubeconfig_bytes(l["cluster_name"], f"https://127.0.0.1:{l['api_server_port']}", **kw))
    G.register_cluster(state, entry, kc)
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(C.make_guard(state), "primary")
    assert code(e) == "KUBECONFIG_CREDENTIAL_FORBIDDEN"


def test_a_kubeconfig_with_two_contexts_or_garbage_is_refused(tmp_path):
    state = G.write_state_dir(tmp_path / "state")
    l = C.PLAN.lane("primary")
    entry, kc = C.make_entry("primary", kubeconfig=C.kubeconfig_bytes(l["cluster_name"], f"https://127.0.0.1:{l['api_server_port']}", contexts=2))
    G.register_cluster(state, entry, kc)
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(C.make_guard(state), "primary")
    assert code(e) == "KUBECONFIG_NOT_SINGLE"
    with pytest.raises(PolicyBlocked):
        G.inspect_kubeconfig(b"not: [a kubeconfig")
    with pytest.raises(PolicyBlocked):
        G.inspect_kubeconfig(b"kind: Pod\n")


def test_register_cluster_refuses_an_entry_that_does_not_describe_the_kubeconfig(tmp_path):
    state = G.write_state_dir(tmp_path / "state")
    entry, kc = C.make_entry("primary")
    with pytest.raises(PolicyBlocked):
        G.register_cluster(state, entry, kc + b" ")


# -- the state directory and the marker list ---------------------------------------------------------------------------------------------------

def test_a_missing_or_foreign_state_directory_is_refused(tmp_path):
    with pytest.raises(PolicyBlocked) as e:
        G.check_state_dir(tmp_path / "nope")
    assert code(e) == "STATE_DIR_MISSING"
    plain = tmp_path / "plain"
    plain.mkdir(mode=0o700)
    with pytest.raises(PolicyBlocked) as e:
        G.check_state_dir(plain)
    assert code(e) == "STATE_SENTINEL_INVALID"
    (plain / G.STATE_SENTINEL).write_text(json.dumps({"schema": "something/else"}), encoding="utf-8")
    with pytest.raises(PolicyBlocked):
        G.check_state_dir(plain)


def test_a_state_directory_writable_by_others_or_a_link_is_refused(tmp_path):
    state, entry, guard = state_with(tmp_path)
    os.chmod(state, 0o777)
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(guard, "primary")
    assert code(e) == "STATE_DIR_WRITABLE_BY_OTHERS"
    os.chmod(state, 0o700)
    link = tmp_path / "link"
    os.symlink(state, link)
    with pytest.raises(PolicyBlocked) as e:
        G.check_state_dir(link)
    assert code(e) == "STATE_DIR_INVALID"


def test_the_state_directory_is_never_created_over_an_existing_path(tmp_path):
    (tmp_path / "s").mkdir()
    with pytest.raises(FileExistsError):
        G.write_state_dir(tmp_path / "s")


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema="x"), lambda d: d.update(created_by="someone"), lambda d: d.update(clusters="no"),
    lambda d: d["clusters"][0].pop("nonce"), lambda d: d["clusters"][0].update(extra="x"), lambda d: d["clusters"][0].update(cluster_name="prod"),
    lambda d: d["clusters"][0].update(context_name="kind-qa-tier-k-other"), lambda d: d["clusters"].append(dict(d["clusters"][0])),
    lambda d: d["clusters"][0].update(server=""), lambda d: d["clusters"][0].update(lane=5),
])
def test_a_malformed_or_foreign_marker_list_is_refused(tmp_path, mutate):
    state, entry, guard = state_with(tmp_path)
    p = state / G.MARKER_LIST_FILE
    d = json.loads(p.read_text(encoding="utf-8"))
    mutate(d)
    p.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(guard, "primary")
    assert code(e) == "MARKER_LIST_INVALID"


def test_a_missing_marker_list_is_refused(tmp_path):
    state, entry, guard = state_with(tmp_path)
    (state / G.MARKER_LIST_FILE).unlink()
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(guard, "primary")
    assert code(e) == "MARKER_LIST_MISSING"


def test_a_cluster_generated_from_another_plan_or_version_is_refused(tmp_path):
    state, entries = C.make_state(tmp_path, plan_sha256="sha256:" + "1" * 64)
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(C.make_guard(state), "primary")
    assert code(e) == "PLAN_MISMATCH"
    state2, _ = C.make_state(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path, version="v1.36.4")
    with pytest.raises(PolicyBlocked) as e:
        G.local_for_lane(C.make_guard(state2), "primary")
    assert code(e) == "LANE_MISMATCH"


def test_a_lane_whose_context_belongs_to_another_lane_is_refused(tmp_path):
    state, entries = C.make_state(tmp_path, ("primary", "control"))
    guard = C.make_guard(state)
    with pytest.raises(PolicyBlocked) as e:
        guard.local_check("primary", state / "control.kubeconfig", entries["control"].context_name)
    assert code(e) == "LANE_MISMATCH"


# -- the marker object in the cluster --------------------------------------------------------------------------------------------------------------

def test_a_cluster_without_the_marker_object_is_refused(tmp_path):
    with pytest.raises(PolicyBlocked) as e:
        C.open_session(tmp_path, fake_kw={"marker": None})
    assert code(e) == "MARKER_OBJECT_MISSING"


@pytest.mark.parametrize("mutate", [
    lambda m: m["data"].update(nonce_sha256="0" * 64), lambda m: m["data"].update(cluster_name="other"), lambda m: m["data"].update(lane="control"),
    lambda m: m["data"].update(plan_sha256="sha256:" + "2" * 64), lambda m: m["data"].update(created_by="someone"),
    lambda m: m["data"].update(schema="x"), lambda m: m["data"].update(extra="x"), lambda m: m["data"].pop("lane"),
])
def test_a_marker_object_that_differs_from_the_marker_list_is_refused(tmp_path, mutate):
    state, entries = C.make_state(tmp_path)
    marker = G.marker_object(entries["primary"])
    mutate(marker)
    guard = C.make_guard(state)
    with pytest.raises(PolicyBlocked) as e:
        G.GuardedSession(guard, G.local_for_lane(guard, "primary"), C.FakeCluster(entries["primary"], marker=marker))
    assert code(e) == "MARKER_OBJECT_MISMATCH"


@pytest.mark.parametrize("marker", [{}, {"kind": "Secret"}, {"kind": "ConfigMap", "metadata": {"name": "x", "namespace": "y"}, "data": {}},
                                    {"kind": "ConfigMap", "metadata": {"name": "qa-disposable-marker", "namespace": "default"}, "data": {}}, [], "x"])
def test_a_marker_object_at_the_wrong_place_or_of_the_wrong_kind_is_refused(tmp_path, marker):
    state, entries = C.make_state(tmp_path)
    guard = C.make_guard(state)
    with pytest.raises(PolicyBlocked):
        G.GuardedSession(guard, G.local_for_lane(guard, "primary"), C.FakeCluster(entries["primary"], marker=marker))


def test_a_server_version_that_is_not_the_lanes_is_refused(tmp_path):
    with pytest.raises(PolicyBlocked) as e:
        C.open_session(tmp_path, fake_kw={"server_version": "v1.36.4"})
    assert code(e) == "LANE_MISMATCH"


def test_the_marker_object_carries_the_nonce_hash_and_never_the_nonce(tmp_path):
    state, entries = C.make_state(tmp_path)
    m = G.marker_object(entries["primary"])
    assert m["data"]["nonce_sha256"] == hashlib.sha256(entries["primary"].nonce.encode()).hexdigest()
    assert entries["primary"].nonce not in json.dumps(m)


# -- the guarded session -----------------------------------------------------------------------------------------------------------------------------

def test_a_session_cannot_be_built_from_a_forged_local_cluster(tmp_path):
    state, entries = C.make_state(tmp_path)
    guard = C.make_guard(state)
    real = G.local_for_lane(guard, "primary")
    with pytest.raises(PolicyBlocked):
        G.LocalCluster(entry=real.entry, kubeconfig_path=real.kubeconfig_path, state_dir=real.state_dir, _seal=object())
    with pytest.raises(PolicyBlocked):
        G.GuardedSession(guard, object(), C.FakeCluster(entries["primary"]))


def test_every_command_is_checked_against_the_allow_list_before_the_runner_sees_it(tmp_path):
    s, fake, *_ = C.open_session(tmp_path)
    n = len(fake.calls)
    for bad in (["exec", "x"], ["get", "secret", "-n", "x", "-o", "json"], ["delete", "namespace", "default"], ["apply", "-f", "-"]):
        with pytest.raises(PolicyBlocked):
            s.run(bad)
    assert len(fake.calls) == n


def test_the_marker_object_is_read_again_before_every_command(tmp_path):
    s, fake, *_ = C.open_session(tmp_path)
    fake.calls.clear()
    s.run(["get", "pod", "-A", "-o", "json"])
    s.run(["get", "node", "-o", "json"])
    kinds = [a[:3] if a[:3] == ["get", "configmap", "qa-disposable-marker"] else a[:2] for a, _ in fake.calls]
    assert kinds == [["get", "configmap", "qa-disposable-marker"], ["get", "pod"], ["get", "configmap", "qa-disposable-marker"], ["get", "node"]]


def test_a_marker_object_removed_mid_session_stops_everything(tmp_path):
    s, fake, *_ = C.open_session(tmp_path)
    fake.marker = None
    n = len(fake.non_marker_calls())
    with pytest.raises(PolicyBlocked):
        s.run(["get", "pod", "-A", "-o", "json"])
    assert len(fake.non_marker_calls()) == n


def test_a_marker_object_replaced_mid_session_with_another_clusters_is_refused(tmp_path):
    s, fake, guard, state, entry = C.open_session(tmp_path)
    other, _ = C.make_entry("primary", nonce="z" * 32)
    fake.marker = G.marker_object(other)
    with pytest.raises(PolicyBlocked):
        s.run(["get", "pod", "-A", "-o", "json"])


def test_stdin_is_required_exactly_when_the_rule_takes_it(tmp_path):
    s, fake, *_ = C.open_session(tmp_path)
    with pytest.raises(PolicyBlocked):
        s.run(["apply", "--dry-run=server", "--validate=strict", "-f", "-", "-o", "json"])
    with pytest.raises(PolicyBlocked):
        s.run(["get", "pod", "-A", "-o", "json"], stdin="{}")


def test_persisting_commands_are_refused_unless_probe_mutation_was_enabled_with_a_policy(tmp_path):
    s, fake, *_ = C.open_session(tmp_path)
    for cmd in (["create", "namespace", "qa-probe-a"], ["delete", "namespace", "qa-probe-a", "--wait=true", "--timeout=60s"]):
        with pytest.raises(PolicyBlocked) as e:
            s.run(cmd)
        assert code(e) if "guard_code" in e.value.details else True
    with pytest.raises(PolicyBlocked):
        s.run(["apply", "-f", "-", "-n", "qa-probe-a"], stdin="{}")
    assert fake.mutating_calls() == []
    with pytest.raises(PolicyBlocked) as e:
        C.open_session(tmp_path / "again" if (tmp_path / "again").mkdir() is None else tmp_path, allow_probe_mutation=True)
    assert code(e) == "PROBE_POLICY_REQUIRED"


def test_probe_mutation_goes_through_the_probe_policy(tmp_path):
    seen = []

    def policy(doc):
        seen.append(doc)
        if doc.get("kind") != "Pod":
            raise PolicyBlocked("not a probe", guard_code="PROBE_SPEC_REFUSED")
    s, fake, *_ = C.open_session(tmp_path, allow_probe_mutation=True, probe_policy=policy)
    s.run(["create", "namespace", "qa-probe-a"])
    s.run(["apply", "-f", "-", "-n", "qa-probe-a"], stdin=json.dumps({"kind": "Pod", "metadata": {"name": "p"}}))
    with pytest.raises(PolicyBlocked):
        s.run(["apply", "-f", "-", "-n", "qa-probe-a"], stdin=json.dumps({"kind": "Deployment"}))
    assert len(seen) == 2 and len(fake.mutating_calls()) == 2


def test_the_command_budget_and_timeout_are_bounded(tmp_path):
    s, fake, *_ = C.open_session(tmp_path, max_commands=12)
    with pytest.raises(PolicyBlocked):
        s.run(["get", "pod", "-A", "-o", "json"], timeout_s=500)
    with pytest.raises(LimitExceeded):
        for _ in range(20):
            s.run(["get", "pod", "-A", "-o", "json"])


def test_the_session_does_not_expose_the_runner(tmp_path):
    s, fake, *_ = C.open_session(tmp_path)
    public = [n for n in dir(s) if not n.startswith("_")]
    assert sorted(public) == ["kubernetes_version", "lane", "proof_record", "proof_ref", "run", "verify"] or set(public) <= {
        "kubernetes_version", "lane", "proof_record", "proof_ref", "run", "verify"}
    assert not any(isinstance(getattr(s, n, None), C.FakeCluster) for n in public)
