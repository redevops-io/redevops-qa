# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The allow-list of kubectl argument vectors: allowed shapes, and everything else refused."""
import pytest

from redevops_qa_checks.errors import PolicyBlocked
from redevops_qa_checks.tierk import argv as A

ALLOWED = [
    (["version", "-o", "json"], "version", False),
    (["get", "configmap", "qa-disposable-marker", "-n", "qa-disposable-system", "-o", "json"], "get", False),
    (["get", "pod", "-A", "-o", "json"], "get", False),
    (["get", "pod", "-n", "demo", "-l", "app=web,tier=a", "-o", "json"], "get", False),
    (["get", "gateway.gateway.networking.k8s.io", "-A", "-o", "json"], "get", False),
    (["get", "clusterpolicy.kyverno.io", "-o", "json"], "get", False),
    (["get", "resourcequota", "quota-a", "-n", "demo", "-o", "json"], "get", False),
    (["apply", "--dry-run=server", "--validate=strict", "-f", "-", "-o", "json"], "apply-dry-run", False),
    (["wait", "--for=condition=Ready", "pod/probe-a", "-n", "qa-probe-ab12", "--timeout=60s"], "wait", False),
    (["wait", "--for=condition=Programmed", "gateway.gateway.networking.k8s.io/public", "-n", "infra", "--timeout=300s"], "wait", False),
    (["create", "namespace", "qa-probe-ab12"], "create-probe-namespace", True),
    (["apply", "-f", "-", "-n", "qa-probe-ab12"], "apply-probe", True),
    (["delete", "namespace", "qa-probe-ab12", "--wait=true", "--timeout=60s"], "delete-probe-namespace", True),
    (["logs", "qa-probe-0123456789ab", "-n", "qa-probe-ab12"], "probe-logs", False),
    (["logs", "qa-probe-0123456789ab", "-n", "demo"], "probe-logs", False),
    (["apply", "-f", "-", "-n", "demo"], "apply-probe", True),
    (["delete", "pod", "qa-probe-0123456789ab", "-n", "demo", "--wait=true", "--timeout=60s"], "delete-probe-pod", True),
]


@pytest.mark.parametrize("args,rule,mutating", ALLOWED)
def test_allowed_shapes(args, rule, mutating):
    d = A.validate_argv(args)
    assert (d.rule, d.mutating) == (rule, mutating)


REFUSED = [
    [], ["get"], ["get", "pod"], ["get", "pod", "-o", "yaml"], ["get", "secret", "-n", "x", "-o", "json"], ["get", "secrets", "-A", "-o", "json"],
    ["get", "pod", "-A", "-n", "x", "-o", "json"], ["get", "pod", "x", "-A", "-o", "json"], ["get", "pod", "-o", "json", "-o", "json"],
    ["get", "pod", "-l", "a in (b)", "-o", "json"], ["get", "pod", "--all-namespaces", "-o", "json"], ["get", "pod", "-o", "json", "--raw", "/api"],
    ["get", "pod", "-n", "x", "-n", "y", "-o", "json"], ["get", "token", "-o", "json"], ["get", "serviceaccount", "-A", "-o", "json"],
    ["--kubeconfig", "/etc/hosts", "get", "pod", "-o", "json"], ["--context", "prod", "get", "pod", "-o", "json"],
    ["get", "pod", "--kubeconfig=/x", "-o", "json"], ["get", "pod", "--server=https://example.test", "-o", "json"],
    ["get", "pod", "-s", "https://example.test", "-o", "json"], ["get", "pod", "--token=x", "-o", "json"], ["get", "pod", "--as=admin", "-o", "json"],
    ["get", "pod", "--insecure-skip-tls-verify", "-o", "json"], ["get", "pod", "--proxy-url=http://x", "-o", "json"],
    ["exec", "-n", "x", "pod", "--", "sh"], ["port-forward", "pod/x", "80:80"], ["proxy"], ["run", "x", "--image=busybox"], ["cp", "a", "b"],
    ["config", "view"], ["config", "use-context", "x"], ["auth", "can-i", "*", "*"], ["debug", "pod"], ["attach", "pod"], ["edit", "pod", "x"],
    ["patch", "pod", "x", "-p", "{}"], ["label", "pod", "x", "a=b"], ["annotate", "pod", "x", "a=b"], ["scale", "deployment", "x", "--replicas=0"],
    ["rollout", "restart", "deployment/x"], ["replace", "-f", "-"], ["set", "image", "x"], ["drain", "node"], ["cordon", "node"], ["taint", "node"],
    ["apply", "-f", "-"], ["apply", "-f", "manifest.yaml"], ["apply", "--dry-run=client", "-f", "-", "-o", "json"],
    ["apply", "--dry-run=server", "-f", "manifest.yaml", "-o", "json"], ["apply", "--dry-run=server", "--validate=strict", "-f", "-", "-o", "yaml"],
    ["apply", "--dry-run=server", "--validate=strict", "-f", "-", "-o", "json", "--force"], ["apply", "-f", "-", "-n", "qa-probe-"], ["apply", "-f", "-", "-n", "kube-system"], ["apply", "-f", "-", "-n", "default"],
    ["apply", "-f", "-", "-n", "kyverno"], ["apply", "-f", "-", "-n", "cilium-secrets"], ["apply", "-f", "-", "-n", "qa-disposable-system"],
    ["apply", "-f", "-", "-n", "kube-public"], ["apply", "-f", "-", "-n", "envoy-gateway-system"], ["apply", "-f", "-", "-n", "metallb-system"],
    ["delete", "pod", "web-0", "-n", "demo", "--wait=true", "--timeout=60s"], ["delete", "pod", "qa-probe-xyz", "-n", "demo", "--wait=true", "--timeout=60s"],
    ["delete", "pod", "qa-probe-0123456789ab", "-n", "kube-system", "--wait=true", "--timeout=60s"],
    ["delete", "pod", "qa-probe-0123456789ab", "-n", "demo"], ["delete", "pod", "qa-probe-0123456789ab", "-n", "demo", "--force"],
    ["logs", "web-0", "-n", "demo"], ["logs", "qa-probe-0123456789ab", "-n", "kube-system"], ["apply", "-k", "dir"], ["apply", "--server-side", "-f", "-"],
    ["create", "namespace", "demo"], ["create", "namespace", "qa-probe-"], ["create", "namespace", "qa-probe-x", "--dry-run=client"],
    ["create", "deployment", "x", "--image=y"], ["create", "secret", "generic", "x"], ["create", "clusterrolebinding", "x"],
    ["delete", "pod", "x", "-n", "qa-probe-a"], ["delete", "namespace", "default", "--wait=true", "--timeout=60s"], ["delete", "namespace", "kube-system"],
    ["delete", "namespace", "qa-probe-a"], ["delete", "namespace", "qa-probe-a", "--wait=false", "--timeout=60s"],
    ["delete", "namespace", "qa-probe-a", "--wait=true", "--timeout=60s", "--all"], ["delete", "-f", "-"], ["delete", "namespace", "--all"],
    ["logs", "pod", "-n", "demo"], ["logs", "pod", "-n", "qa-probe-a", "-f"], ["logs", "-n", "qa-probe-a", "pod"], ["logs", "pod"],
    ["wait", "--for=delete", "pod/x", "-n", "x", "--timeout=10s"], ["wait", "--for=condition=Ready", "pod/x", "-n", "x", "--timeout=301s"],
    ["wait", "--for=condition=Ready", "secret/x", "-n", "x", "--timeout=10s"], ["wait", "--for=condition=Ready", "pod/x", "--timeout=10s"],
    ["wait", "--for=condition=Weird", "pod/x", "-n", "x", "--timeout=10s"], ["wait", "--for=condition=Ready", "pod/x", "-n", "x", "--timeout=10"],
    ["version"], ["version", "--client"], ["version", "-o", "yaml"], ["api-resources"], ["cluster-info"], ["top", "node"], ["certificate", "approve", "x"],
    ["get", "pod\n", "-o", "json"], ["get", "pod", "-o", "json\x00"], ["get", "pod", "", "-o", "json"], ["get", "pod", "A" * 300, "-o", "json"],
    ["get", "pod", "-n", "UPPER", "-o", "json"], ["get", "pod", "-n", "a_b", "-o", "json"], ["get", "pod", "x y", "-o", "json"],
]


@pytest.mark.parametrize("args", REFUSED, ids=[str(i) for i in range(len(REFUSED))])
def test_everything_else_is_refused(args):
    with pytest.raises(PolicyBlocked):
        A.validate_argv(args)


def test_a_non_list_or_non_string_argument_is_refused():
    for bad in ("get pod -o json", None, 5, ["get", 5], ["get", None], [b"get"], ("get", "pod", "-o", "yaml")):
        with pytest.raises(PolicyBlocked):
            A.validate_argv(bad)


def test_too_many_arguments_are_refused():
    with pytest.raises(PolicyBlocked):
        A.validate_argv(["get", "pod"] + ["-n", "x"] * 10 + ["-o", "json"])


def test_secrets_and_credentials_are_never_readable():
    assert not any("secret" in k or "token" in k or "serviceaccount" in k for k in A.READ_KINDS)


def test_the_refusal_names_the_rule_not_just_a_message():
    with pytest.raises(PolicyBlocked) as e:
        A.validate_argv(["exec", "pod"])
    assert e.value.details["rule_code"] == "ARGV_NOT_ALLOWED" and e.value.code == "POLICY_BLOCKED"


def test_only_the_probe_rules_can_persist_anything():
    persisting = {d.rule for args, _r, m in ALLOWED if m for d in [A.validate_argv(args)]}
    assert persisting == {"create-probe-namespace", "apply-probe", "delete-probe-namespace", "delete-probe-pod"}
    for args, rule, mutating in ALLOWED:
        if mutating:
            ns = A.validate_argv(args).namespace
            assert ns not in A.SYSTEM_NAMESPACES and not ns.startswith(A.SYSTEM_NAMESPACE_PREFIXES)
            if rule in ("create-probe-namespace", "delete-probe-namespace"):
                assert ns.startswith(A.PROBE_NAMESPACE_PREFIX)
            if rule == "delete-probe-pod":
                assert A.PROBE_POD_PATTERN.fullmatch(args[2])
