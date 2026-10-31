# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The synthetic subnet plan, the target policy, and the fixed probe workloads (including the probe's own code, run on loopback)."""
import copy
import ipaddress
import json
import socket
import subprocess
import sys
import threading

import pytest

from redevops_qa_checks.errors import PolicyBlocked
from redevops_qa_checks.tierk import probes as PR
from redevops_qa_checks.tierk import subnets as SN

# built at run time: the local-network range a developer machine may use
LAN_HOST = ".".join(["192", "168", "40", "5"])
LAN_NET = ".".join(["192", "168", "40", "0"]) + "/24"


def code(e):
    return e.value.details["guard_code"]


# -- subnet plan ----------------------------------------------------------------------------------------------------------------

def test_the_plan_is_valid_and_uses_documentation_ranges_only():
    SN.validate_plan()
    nets = [ipaddress.ip_network(n["cidr"]) for n in SN.SUBNET_PLAN["networks"].values()]
    assert [str(n) for n in nets] == ["198.51.100.0/24", "203.0.113.0/24"]
    for n in nets:
        for bad in SN.FORBIDDEN_NETWORKS + SN.CLUSTER_NETWORKS:
            assert not n.overlaps(ipaddress.ip_network(bad))


def test_the_plan_never_names_the_reserved_local_network_range():
    text = json.dumps(SN.SUBNET_PLAN)
    assert ".".join(["192", "168"]) not in text


@pytest.mark.parametrize("cidr", [LAN_NET, "192.168.0.0/16", "10.1.0.0/16", "172.20.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                                  "10.244.0.0/16", "10.43.0.0/16"])
def test_a_plan_that_overlaps_a_forbidden_or_cluster_range_is_refused(cidr):
    plan = copy.deepcopy(SN.SUBNET_PLAN)
    plan["networks"]["lan-equivalent"] = {"cidr": cidr, "hosts": {}, "purpose": "x", "listening_ports": {}}
    with pytest.raises(PolicyBlocked) as e:
        SN.validate_plan(plan)
    assert code(e) == "SUBNET_FORBIDDEN"


def test_overlapping_synthetic_networks_and_hosts_outside_their_network_are_refused():
    plan = copy.deepcopy(SN.SUBNET_PLAN)
    plan["networks"]["lan-equivalent"]["cidr"] = "198.51.100.0/25"
    plan["networks"]["lan-equivalent"]["hosts"] = {"x": "198.51.100.5"}
    with pytest.raises(PolicyBlocked) as e:
        SN.validate_plan(plan)
    assert code(e) == "SUBNET_OVERLAP"
    plan = copy.deepcopy(SN.SUBNET_PLAN)
    plan["networks"]["world"]["hosts"]["world-target"] = "198.51.101.10"
    with pytest.raises(PolicyBlocked) as e:
        SN.validate_plan(plan)
    assert code(e) == "SUBNET_HOST"


def test_check_free_refuses_a_network_already_on_the_host_that_overlaps():
    SN.check_free(["10.0.0.0/8", "172.17.0.0/16", LAN_NET, "127.0.0.0/8"])
    for taken in ("198.51.100.0/25", "198.51.0.0/16", "203.0.113.128/25"):
        with pytest.raises(PolicyBlocked) as e:
            SN.check_free(["10.0.0.0/8", taken])
        assert code(e) == "SUBNET_IN_USE"
    with pytest.raises(PolicyBlocked):
        SN.check_free(["not a cidr"])


def test_the_plan_describes_isolation_and_the_two_kinds_of_evidence():
    iso = SN.SUBNET_PLAN["isolation"]
    assert "no route" in iso["container_network"] and iso["location"] == "isolated host only"
    assert set(SN.SUBNET_PLAN["evidence"]) == {"policy-state", "traffic"}


# -- target policy ------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("ip", ["10.244.3.4", "10.43.0.10", "198.51.100.10", "203.0.113.20", "203.0.113.255"])
def test_targets_inside_the_cluster_and_the_plan_are_allowed(ip):
    assert SN.TargetPolicy().check(ip) == ipaddress.ip_address(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34", LAN_HOST, "192.168.1.1", "10.0.0.5", "172.16.1.1", "198.51.101.1", "203.0.114.1",
                                "2001:db8::1", "::1"])
def test_targets_anywhere_else_are_refused(ip):
    with pytest.raises(PolicyBlocked) as e:
        SN.TargetPolicy().check(ip)
    assert code(e) in ("TARGET_OUTSIDE_PLAN", "TARGET_REFUSED")


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "169.254.1.1", "224.0.0.1", "0.0.0.0"])
def test_loopback_link_local_metadata_multicast_and_unspecified_are_never_targets(ip):
    with pytest.raises(PolicyBlocked) as e:
        SN.TargetPolicy(extra_networks=["8.8.8.0/24"]).check(ip)
    assert code(e) == "TARGET_REFUSED"


@pytest.mark.parametrize("name", ["example.test", "localhost", "web.demo.svc", "web", "", "10.244.0.1.example.test", None, 5])
def test_a_probe_target_is_never_a_name(name):
    with pytest.raises(PolicyBlocked) as e:
        SN.TargetPolicy().check(name)
    assert code(e) == "TARGET_NOT_IP_LITERAL"


def test_an_extra_network_declared_by_bring_up_is_allowed_but_not_a_dangerous_one():
    assert SN.TargetPolicy(["172.18.0.0/16"]).check("172.18.0.5")
    for bad in ("127.0.0.0/8", "169.254.0.0/16", "192.168.0.0/16", LAN_NET):
        with pytest.raises(PolicyBlocked) as e:
            SN.TargetPolicy([bad])
        assert code(e) == "TARGET_NETWORK_REFUSED"


def test_is_synthetic_names_the_plan_network():
    p = SN.TargetPolicy()
    assert p.is_synthetic("198.51.100.10") == "world" and p.is_synthetic("203.0.113.10") == "lan-equivalent" and p.is_synthetic("10.244.0.5") == ""


# -- the probe pod -----------------------------------------------------------------------------------------------------------------------

def pod(**kw):
    kw.setdefault("timeout_s", 5)
    return PR.probe_pod(kw.pop("ns", "demo"), kw.pop("ip", "10.244.1.5"), kw.pop("port", 5432), **kw)


def test_the_probe_pod_is_one_fixed_restricted_specification():
    p = pod(labels={"app": "web"})
    c = p["spec"]["containers"][0]
    assert c["image"] == PR.IMAGE and "@sha256:" in c["image"] and c["imagePullPolicy"] == "Never" and ":latest" not in c["image"]
    assert c["command"] == ["python", "-c", PR.PROBE_SOURCE] and c["args"] == ["10.244.1.5", "5432", "tcp", "5"]
    assert c["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    s = p["spec"]
    assert s["restartPolicy"] == "Never" and s["automountServiceAccountToken"] is False and s["activeDeadlineSeconds"] == 30
    assert s["securityContext"]["runAsNonRoot"] is True and "hostNetwork" not in s and "volumes" not in s and len(s["containers"]) == 1
    assert p["metadata"]["labels"]["app"] == "web" and p["metadata"]["labels"]["app.kubernetes.io/managed-by"] == PR.MANAGED_BY


def test_probe_names_are_deterministic_and_depend_on_every_parameter():
    base = pod()
    assert pod() == base and base["metadata"]["name"].startswith("qa-probe-") and len(base["metadata"]["name"]) == len("qa-probe-") + 12
    names = {pod(ip="10.244.1.6")["metadata"]["name"], pod(port=5433)["metadata"]["name"], pod(ns="other")["metadata"]["name"],
             pod(role="control")["metadata"]["name"], pod(timeout_s=6)["metadata"]["name"], base["metadata"]["name"]}
    assert len(names) == 6


@pytest.mark.parametrize("kw", [{"port": 0}, {"port": 65536}, {"port": "80"}, {"timeout_s": 0}, {"timeout_s": 11}, {"ip": "example.test"}, {"ip": "10.0.0"}])
def test_probe_bounds(kw):
    with pytest.raises((PolicyBlocked, ValueError)):
        pod(**kw)


def test_the_probe_policy_accepts_exactly_the_fixed_specification():
    pol = PR.ProbePolicy()
    for kw in ({}, {"role": "control"}, {"labels": {"app": "web", "tier": "a"}}, {"ns": "other", "ip": "203.0.113.10", "port": 8080, "timeout_s": 3}):
        pol(pod(**kw))                       # no exception


def mutated(path, value=None, delete=False):
    p = pod()
    cur = p
    for k in path[:-1]:
        cur = cur[k]
    if delete:
        del cur[path[-1]]
    else:
        cur[path[-1]] = value
    return p


@pytest.mark.parametrize("p", [
    mutated(["spec", "containers", 0, "image"], "docker.io/library/busybox:1"),
    mutated(["spec", "containers", 0, "image"], "python:3.12-slim"),
    mutated(["spec", "containers", 0, "command"], ["sh", "-c", "id"]),
    mutated(["spec", "containers", 0, "command"], ["python", "-c", "print(1)"]),
    mutated(["spec", "containers", 0, "args"], ["10.244.1.5", "5432", "tcp", "5", "extra"]),
    mutated(["spec", "containers", 0, "args"], ["example.test", "5432", "tcp", "5"]),
    mutated(["spec", "containers", 0, "args"], ["10.244.1.6", "5432", "tcp", "5"]),            # name no longer matches the parameters
    mutated(["spec", "containers", 0, "securityContext", "privileged"], True),
    mutated(["spec", "containers", 0, "securityContext", "allowPrivilegeEscalation"], True),
    mutated(["spec", "containers", 0, "imagePullPolicy"], "Always"),
    mutated(["spec", "hostNetwork"], True), mutated(["spec", "hostPID"], True),
    mutated(["spec", "volumes"], [{"name": "h", "hostPath": {"path": "/"}}]),
    mutated(["spec", "serviceAccountName"], "admin"),
    mutated(["spec", "automountServiceAccountToken"], True),
    mutated(["spec", "activeDeadlineSeconds"], 99999),
    mutated(["spec", "restartPolicy"], "Always"),
    mutated(["spec", "containers"], [pod()["spec"]["containers"][0], pod()["spec"]["containers"][0]]),
    mutated(["spec", "initContainers"], [{"name": "i", "image": "x"}]),
    mutated(["metadata", "name"], "web-0"), mutated(["metadata", "namespace"], "other"),
    mutated(["metadata", "annotations"], {"a": "b"}), mutated(["metadata", "ownerReferences"], []),
    mutated(["kind"], "Deployment"), mutated(["apiVersion"], "apps/v1"),
    mutated(["spec", "containers", 0, "resources", "limits", "cpu"], "64"),
    mutated(["spec", "containers", 0, "env"], [{"name": "A", "value": "b"}]),
    mutated(["spec", "containers", 0, "volumeMounts"], [{"name": "x", "mountPath": "/x"}]),
    mutated(["spec", "containers", 0, "ports"], [{"containerPort": 1}]),
    mutated(["spec", "tolerations"], [{"operator": "Exists"}]), mutated(["spec", "nodeName"], "node-1"),
    {}, {"kind": "Pod"}, {"kind": "Pod", "metadata": {}, "spec": {}}, [], "pod",
])
def test_the_probe_policy_refuses_anything_that_is_not_the_fixed_specification(p):
    with pytest.raises(PolicyBlocked) as e:
        PR.ProbePolicy()(p)
    assert code(e) == "PROBE_SPEC_REFUSED"


def test_a_probe_with_a_label_that_tries_to_claim_the_probe_role_is_refused():
    p = pod()
    p["metadata"]["labels"]["qa-checks/probe-role"] = "other"
    with pytest.raises(PolicyBlocked):
        PR.ProbePolicy()(p)


# -- the probe's own code, run on loopback --------------------------------------------------------------------------------------------------------

def run_probe(*args, timeout=15):
    r = subprocess.run([sys.executable, "-B", "-c", PR.PROBE_SOURCE, *map(str, args)], capture_output=True, text=True, timeout=timeout,
                       env={"PATH": "/usr/bin:/bin"})
    assert r.returncode == 0, r.stderr
    lines = r.stdout.strip().splitlines()
    assert len(lines) == 1
    return json.loads(lines[0])


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(4)
    yield s
    s.close()


def test_the_probe_code_reports_connected_for_an_open_loopback_port(listener):
    assert run_probe("127.0.0.1", listener.getsockname()[1], "tcp", 2)["result"] == "connected"


def test_the_probe_code_reports_refused_for_a_closed_loopback_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert run_probe("127.0.0.1", port, "tcp", 2)["result"] == "refused"


@pytest.mark.parametrize("args,result", [(("example.test", 80, "tcp", 1), "error"), (("localhost", 80, "tcp", 1), "error"), (("not-an-ip", 80, "tcp", 1), "error"),
                                          (("127.0.0.1", 80, "udp", 1), "unsupported"), (("127.0.0.1", "x", "tcp", 1), "error")])
def test_the_probe_code_never_resolves_a_name_and_refuses_udp(args, result):
    assert run_probe(*args)["result"] == result


def test_the_probe_code_prints_exactly_one_json_line_even_on_error():
    out = run_probe("999.1.1.1", 80, "tcp", 1)
    assert out["result"] == "error" and set(out) == {"result", "errno"}
