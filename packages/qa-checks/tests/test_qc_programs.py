# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The manifest check programs: a passing fixture and a known-bad fixture per class, as observed values.

Fixtures are synthetic. The programs return observations; the assertions below read them. Nothing here compares an
observation with an expected value inside a program, and no program is given one."""
import itertools

import pytest

from qc_fixtures import (DIGEST_A, DIGEST_B, REGISTRY, cilium_deny, container, deployment, gateway, good_set, httproute, kyverno_policy,
                         namespace, netpol, quota, reference, service, write_tree)
from redevops_qa_checks.engine import CheckEngine


@pytest.fixture
def observe(registry, tmp_path):
    counter = itertools.count()

    def _observe(pid, files, *, counts=False):
        root = write_tree(tmp_path / f"c{next(counter)}", files)
        full = pid + (".counts" if counts else "")
        ref = registry.resolve({"id": full, "version": "1.0.0", "program_hash": registry.registered_program_hash(full, "1.0.0")}).ref
        out = CheckEngine(root, registry).run_check({"check_program_ref": ref, "inputs": [{"kind": "MANIFEST_PATH", "path": "."}],
                                                     "tier": "OFFLINE"})
        assert out.resolution == "RESOLVED"
        return out.value
    return _observe


def one(files_docs):
    return {"a.yaml": files_docs}


# -- image references and naming ------------------------------------------------------------------------------------------

IMG = "manifest.image-references"


def test_images_pinned_by_digest_are_reported_as_pinned(observe):
    v = observe(IMG, one([deployment(containers=[container(image=f"{REGISTRY}/app@{DIGEST_A}")])]))
    c = v["containers"][0]
    assert (c["has_digest"], c["has_tag"], c["tag_is_latest"], c["digest"], c["repository"]) == (True, False, False, DIGEST_A, f"{REGISTRY}/app")
    assert v["counts"] == {"containers": 1, "with_digest": 1, "tag_only": 0, "latest_tag": 0, "untagged_unpinned": 0, "image_missing": 0}


@pytest.mark.parametrize("image,tag,digest,latest,unpinned", [
    (f"{REGISTRY}/app:1.2.3", "1.2.3", "", False, False),
    (f"{REGISTRY}/app:latest", "latest", "", True, False),
    (f"{REGISTRY}/app", "", "", False, True),
    (f"{REGISTRY}/app:1.2.3@{DIGEST_B}", "1.2.3", DIGEST_B, False, False),
    ("localhost:5000/app", "", "", False, True),
    ("app:2", "2", "", False, False),
])
def test_tag_digest_latest_and_implicit_latest_are_told_apart(observe, image, tag, digest, latest, unpinned):
    c = observe(IMG, one([deployment(containers=[container(image=image)])]))["containers"][0]
    assert (c["tag"], c["digest"], c["tag_is_latest"], c["untagged_unpinned"]) == (tag, digest, latest, unpinned)


def test_registry_with_a_port_is_not_mistaken_for_a_tag(observe):
    c = observe(IMG, one([deployment(containers=[container(image="host.example.test:5000/team/app")])]))["containers"][0]
    assert (c["registry"], c["repository"], c["tag"]) == ("host.example.test:5000", "host.example.test:5000/team/app", "")


def test_init_and_ephemeral_containers_and_cronjobs_and_pods_are_covered(observe):
    dep = deployment(pod_spec={"initContainers": [{"name": "init", "image": f"{REGISTRY}/init:1"}]})
    cron = {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": "j", "namespace": "demo"},
            "spec": {"schedule": "* * * * *", "jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "c", "image": "x:1"}]}}}}}}
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p", "namespace": "demo"}, "spec": {"containers": [{"name": "c", "image": "y:2"}]}}
    v = observe(IMG, one([dep, cron, pod]))
    assert sorted((r["workload_kind"], r["role"]) for r in v["containers"]) == [("CronJob", "main"), ("Deployment", "init"), ("Deployment", "main"), ("Pod", "main")]


def test_a_missing_image_is_reported(observe):
    c = container()
    del c["image"]
    v = observe(IMG, one([deployment(containers=[c])]))
    assert v["counts"]["image_missing"] == 1


NAME_MAP = "manifest.image-name-map"


def _map(*entries):
    return reference("ImageMap", {"images": list(entries)})


def test_a_declared_image_map_is_matched_by_repository(observe):
    files = one([deployment(containers=[container(image=f"{REGISTRY}/app:1.0")]),
                 _map({"name": "app", "repository": f"{REGISTRY}/app", "tag": "1.0"})])
    v = observe(NAME_MAP, files)
    r = v["containers"][0]
    assert (r["in_map"], r["declared_names"], r["declared_tag_equal"]) == (True, ["app"], True)
    assert v["counts"] == {"containers": 1, "in_map": 1, "not_in_map": 0, "tag_disagreements": 0, "digest_disagreements": 0, "entries_not_used": 0}


def test_a_name_that_differs_from_the_declared_map_is_observed(observe):
    files = one([deployment(containers=[container(image=f"{REGISTRY}/app-web:1.0"), container("side", image="other.example.test/app:2")]),
                 _map({"name": "app", "repository": f"{REGISTRY}/app", "tag": "1.0"}, {"name": "unused", "repository": f"{REGISTRY}/unused"})])
    v = observe(NAME_MAP, files)
    by = {r["container"]: r for r in v["containers"]}
    assert by["app"]["in_map"] is False and by["app"]["same_last_component_other_registry"] == []
    assert by["side"]["in_map"] is False and by["side"]["same_last_component_other_registry"] == ["app"]
    assert [e["name"] for e in v["entries_not_used"]] == ["app", "unused"]
    assert v["counts"]["not_in_map"] == 2 and v["counts"]["entries_not_used"] == 2


def test_a_declared_tag_that_disagrees_is_observed(observe):
    files = one([deployment(containers=[container(image=f"{REGISTRY}/app:1.1")]), _map({"name": "app", "repository": f"{REGISTRY}/app", "tag": "1.0"})])
    assert observe(NAME_MAP, files, counts=True)["counts"]["tag_disagreements"] == 1


def test_without_a_declared_map_the_program_says_so(observe):
    v = observe(NAME_MAP, one([deployment()]))
    assert v["map_present"] is False and v["containers"][0]["in_map"] is False


# -- privilege versus admission profile -------------------------------------------------------------------------------------

SEC = "manifest.security-context"


def test_a_hardened_workload_shows_non_root_no_escalation_no_host_access(observe):
    v = observe(SEC, good_set())
    c = v["containers"][0]
    assert (c["run_as_non_root"], c["run_as_user"], c["allow_privilege_escalation"], c["privileged"], c["capabilities_drop"],
            c["namespace_psa_enforce"]) == (True, 10001, False, None, ["ALL"], "restricted")
    p = v["pods"][0]
    assert p["host_network"] is None and p["host_path_volumes"] == []


def test_privileged_root_host_access_and_missing_fields_are_observed(observe):
    bad = container(secure=False)
    bad["securityContext"] = {"privileged": True, "runAsUser": 0, "capabilities": {"add": ["NET_ADMIN", "SYS_TIME"]}}
    dep = deployment(containers=[bad], pod_spec={"hostNetwork": True, "hostPID": True,
                                                 "volumes": [{"name": "h", "hostPath": {"path": "/var/run", "type": "Directory"}}]})
    v = observe(SEC, {"a.yaml": [namespace("demo", {"pod-security.kubernetes.io/enforce": "restricted"}), dep]})
    c, p = v["containers"][0], v["pods"][0]
    assert (c["privileged"], c["run_as_user"], c["capabilities_add"], c["allow_privilege_escalation"], c["run_as_non_root"]) == \
        (True, 0, ["NET_ADMIN", "SYS_TIME"], None, None)
    assert (p["host_network"], p["host_pid"], p["host_path_volumes"]) == (True, True, [{"volume": "h", "path": "/var/run", "type": "Directory"}])
    assert v["counts"]["privileged_true"] == 1 and v["counts"]["host_path_volumes"] == 1 and v["counts"]["privilege_escalation_not_false"] == 1
    assert c["namespace_psa_enforce"] == "restricted"


def test_pod_level_security_context_is_inherited_unless_the_container_overrides(observe):
    c1 = container("a", secure=False)
    c2 = container("b", secure=False)
    c2["securityContext"] = {"runAsNonRoot": False, "runAsUser": 0}
    dep = deployment(containers=[c1, c2], pod_spec={"securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "seccompProfile": {"type": "RuntimeDefault"}}})
    by = {r["container"]: r for r in observe(SEC, one([dep]))["containers"]}
    assert (by["a"]["run_as_non_root"], by["a"]["run_as_user"], by["a"]["seccomp_profile_type"]) == (True, 1000, "RuntimeDefault")
    assert (by["b"]["run_as_non_root"], by["b"]["run_as_user"]) == (False, 0)


def test_host_ports_are_listed(observe):
    c = container()
    c["ports"] = [{"containerPort": 80, "hostPort": 8081}, {"containerPort": 81}]
    assert observe(SEC, one([deployment(containers=[c])]))["containers"][0]["host_ports"] == [8081]


# -- resources --------------------------------------------------------------------------------------------------------------

RES = "manifest.resources"


def test_requests_limits_and_namespace_sums_are_integers(observe):
    v = observe(RES, good_set())
    c = v["containers"][0]
    assert (c["requests_cpu_milli"], c["requests_memory_bytes"], c["limits_cpu_milli"], c["limits_memory_bytes"]) == (100, 128 * 2**20, 500, 256 * 2**20)
    s = v["namespace_sums"][0]
    assert (s["namespace"], s["pods"], s["requests_cpu_milli"], s["requests_memory_bytes"], s["limits_cpu_milli"]) == ("demo", 2, 200, 256 * 2**20, 1000)
    q = v["resource_quotas"][0]
    assert (q["requests_cpu_milli"], q["limits_memory_bytes"], q["pods"]) == (4000, 16 * 2**30, "20")


@pytest.mark.parametrize("value,expected", [("1", 1000), ("250m", 250), ("0.5", 500), (2, 2000), ("1500u", 2), ("1e1", 10000)])
def test_cpu_quantities_are_parsed_exactly(observe, value, expected):
    c = container()
    c["resources"] = {"requests": {"cpu": value}}
    assert observe(RES, one([deployment(replicas=1, containers=[c])]))["containers"][0]["requests_cpu_milli"] == expected


@pytest.mark.parametrize("value,expected", [("1Gi", 2**30), ("512Mi", 512 * 2**20), ("1G", 10**9), ("1500k", 1500000), ("128974848", 128974848),
                                            ("129e6", 129000000), ("1Ei", 2**60)])
def test_memory_quantities_are_parsed_exactly(observe, value, expected):
    c = container()
    c["resources"] = {"limits": {"memory": value}}
    assert observe(RES, one([deployment(replicas=1, containers=[c])]))["containers"][0]["limits_memory_bytes"] == expected


def test_an_unparsable_quantity_is_flagged_not_guessed(observe):
    c = container()
    c["resources"] = {"requests": {"cpu": "lots", "memory": "1Gi"}}
    v = observe(RES, one([deployment(replicas=1, containers=[c])]))
    assert v["containers"][0]["requests_cpu_milli"] is None and v["containers"][0]["quantity_unparsable"] is True
    assert v["namespace_sums"][0]["quantity_unparsable"] == 1


def test_pod_requests_use_the_larger_of_the_main_sum_and_the_largest_init_container(observe):
    init = {"name": "i", "image": "x:1", "resources": {"requests": {"cpu": "2", "memory": "1Gi"}}}
    v = observe(RES, one([deployment(replicas=3, pod_spec={"initContainers": [init]})]))
    s = v["namespace_sums"][0]
    assert s["requests_cpu_milli"] == 6000 and s["requests_memory_bytes"] == 3 * 2**30


def test_a_declared_budget_is_set_beside_the_sums(observe):
    budget = reference("ResourceBudget", {"namespaces": [{"namespace": "demo", "requests_cpu": "150m", "requests_memory": "1Gi",
                                                          "limits_cpu": "4", "limits_memory": "1Gi", "pods": 1}]})
    v = observe(RES, one([deployment(), budget]))
    b = v["budget"][0]
    assert b["dimensions_over_budget"] == ["requests_cpu_milli", "pods"] and v["declared_budget_present"] is True
    within = reference("ResourceBudget", {"namespaces": [{"namespace": "demo", "requests_cpu": "4", "pods": 2}]})
    assert observe(RES, one([deployment(), within]))["budget"][0]["dimensions_over_budget"] == []


def test_workloads_without_requests_or_limits_are_counted(observe):
    v = observe(RES, one([deployment(containers=[container(resources=False)])]), counts=True)
    assert v["counts"]["main_without_requests"] == 1 and v["counts"]["main_without_limits"] == 1


def test_daemonset_replicas_are_unknown_not_guessed(observe):
    ds = deployment()
    ds["kind"] = "DaemonSet"
    del ds["spec"]["replicas"]
    s = observe(RES, one([ds]))["namespace_sums"][0]
    assert s["workloads_with_unknown_replicas"] == 1 and s["pods"] == 1


# -- env and secret references -----------------------------------------------------------------------------------------------

ENV = "manifest.env-and-secret-refs"


def test_env_names_and_sources_are_reported_and_values_never_are(observe):
    canary = "".join(["s3cr", "et-val", "ue-", "9f2c"])
    env = [{"name": "PLAIN", "value": canary}, {"name": "FROM_SECRET", "valueFrom": {"secretKeyRef": {"name": "creds", "key": "k"}}},
           {"name": "FROM_CM", "valueFrom": {"configMapKeyRef": {"name": "cfg", "key": "k"}}},
           {"name": "POD_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}}]
    v = observe(ENV, one([deployment(containers=[container(env=env, env_from=[{"secretRef": {"name": "bulk"}}, {"configMapRef": {"name": "cm2"}, "prefix": "X_"}])])]))
    assert canary not in str(v)
    by = {r["env_name"]: r for r in v["env"]}
    assert by["PLAIN"]["source"] == "value" and by["PLAIN"]["has_literal_value"] is True
    assert (by["FROM_SECRET"]["source"], by["FROM_SECRET"]["ref_name"], by["FROM_SECRET"]["ref_key"]) == ("secretKeyRef", "creds", "k")
    assert by["POD_IP"]["ref_name"] == "status.podIP"
    assert [(r["ref_kind"], r["ref_name"]) for r in v["env_from"]] == [("ConfigMap", "cm2"), ("Secret", "bulk")]
    assert v["counts"]["from_secret"] == 2 and v["counts"]["literal_values"] == 1


def test_declared_forbidden_prefixes_are_matched_by_name(observe):
    env = [{"name": "CLOUD_TOKEN_X", "value": "a"}, {"name": "CLOUD_REGION", "value": "b"}, {"name": "SAFE", "value": "c"}]
    pol = reference("EnvPolicy", {"forbidden_prefixes": ["CLOUD_TOKEN", "OTHER_"]})
    v = observe(ENV, one([deployment(containers=[container(env=env, env_from=[{"secretRef": {"name": "s"}, "prefix": "OTHER_A"}])]), pol]))
    assert [(m["env_name"], m["prefix"], m["via"]) for m in v["prefix_matches"]] == [("", "OTHER_", "envFrom-prefix"), ("CLOUD_TOKEN_X", "CLOUD_TOKEN", "env")]
    assert v["declared_prefixes"] == ["CLOUD_TOKEN", "OTHER_"]


def test_secret_and_config_volumes_are_listed(observe):
    dep = deployment(pod_spec={"volumes": [{"name": "s", "secret": {"secretName": "tls"}}, {"name": "c", "configMap": {"name": "conf"}}]})
    v = observe(ENV, one([dep]))
    assert [(r["ref_kind"], r["ref_name"]) for r in v["volume_references"]] == [("ConfigMap", "conf"), ("Secret", "tls")]


# -- gateway routes -----------------------------------------------------------------------------------------------------------

GW = "manifest.gateway-routes"


def test_a_route_from_a_selected_namespace_attaches_to_the_listener(observe):
    v = observe(GW, good_set())
    p = v["routes"][0]["parents"][0]
    assert p["gateway_in_input"] is True and p["listeners"][0]["namespace_allowed"] is True and p["listeners"][0]["kind_allowed"] is True
    assert v["routes"][0]["rules"][0]["all_matches_have_method"] is True and v["routes"][0]["rules_without_method"] == 0


def test_a_route_from_an_unselected_namespace_does_not_satisfy_the_selector(observe):
    files = good_set()
    files["00-namespaces.yaml"] = [namespace("demo", {"team": "x"}), namespace("infra")]
    v = observe(GW, files, counts=False)
    assert v["routes"][0]["parents"][0]["listeners"][0]["namespace_allowed"] is False
    assert observe(GW, files, counts=True)["counts"]["parents_namespace_not_allowed"] == 1


def test_selector_with_an_unknown_namespace_is_reported_as_unknown_not_false(observe):
    files = good_set()
    files["00-namespaces.yaml"] = [namespace("infra")]
    assert observe(GW, files)["routes"][0]["parents"][0]["listeners"][0]["namespace_allowed"] is None


@pytest.mark.parametrize("frm,ns_route,expected", [("All", "other", True), ("Same", "infra", True), ("Same", "other", False)])
def test_all_and_same_namespace_policies(observe, frm, ns_route, expected):
    gw = gateway(listeners=[{"name": "https", "port": 443, "protocol": "HTTPS", "allowedRoutes": {"namespaces": {"from": frm}}}])
    v = observe(GW, one([gw, httproute(ns=ns_route)]))
    assert v["routes"][0]["parents"][0]["listeners"][0]["namespace_allowed"] is expected


def test_a_missing_gateway_or_section_is_reported(observe):
    v = observe(GW, one([gateway(), httproute(gw="absent"), httproute("two", section="nope")]))
    r = {x["name"]: x for x in v["routes"]}
    assert r["app"]["parents"][0]["gateway_in_input"] is False
    assert r["two"]["parents"][0]["gateway_in_input"] is True and r["two"]["parents"][0]["listener_candidates"] == 0
    c = observe(GW, one([gateway(), httproute(gw="absent"), httproute("two", section="nope")]), counts=True)["counts"]
    assert (c["parents_gateway_not_in_input"], c["parents_without_listener"]) == (1, 1)


def test_method_restrictions_and_path_matches_and_rewrites_are_extracted(observe):
    rw = [{"type": "URLRewrite", "urlRewrite": {"path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/api"}}}]
    route = httproute(matches=[{"path": {"type": "PathPrefix", "value": "/v1"}, "method": "POST"}, {"path": {"type": "Exact", "value": "/x"}}], filters=rw)
    v = observe(GW, one([gateway(), namespace("demo", {"gateway-access": "true"}), route]))
    rule = v["routes"][0]["rules"][0]
    assert [(m["path_type"], m["path_value"], m["method"]) for m in rule["matches"]] == [("PathPrefix", "/v1", "POST"), ("Exact", "/x", "")]
    assert rule["all_matches_have_method"] is False and v["routes"][0]["rules_without_method"] == 1
    assert rule["filters"] == [{"type": "URLRewrite", "detail": "ReplacePrefixMatch:/api"}]


def test_listener_kind_and_hostname_relations(observe):
    gw = gateway(listeners=[{"name": "tcp", "port": 9, "protocol": "TCP"}, {"name": "h", "port": 80, "protocol": "HTTP", "hostname": "a.example.test",
                                                                           "allowedRoutes": {"namespaces": {"from": "All"}}}])
    v = observe(GW, one([gw, httproute(section=None, hostnames=["b.example.test"])]))
    ls = {x["listener"]: x for x in v["routes"][0]["parents"][0]["listeners"]}
    assert ls["tcp"]["kind_allowed"] is False and ls["h"]["hostname_intersects"] is False


# -- network policies ------------------------------------------------------------------------------------------------------

NP = "manifest.network-policies"


def test_default_deny_both_directions_is_detected_per_namespace(observe):
    v = observe(NP, one([deployment(), netpol("deny-all")]))
    n = v["namespaces"][0]
    assert (n["default_deny_ingress"], n["default_deny_egress"], n["policy_count"], n["workload_count"]) == (True, True, 1, 1)


def test_an_allow_all_rule_or_a_selector_is_not_default_deny(observe):
    files = one([deployment(), netpol("a", ingress=[{}], egress=[{}]), netpol("b", pod_selector={"matchLabels": {"app": "x"}})])
    n = observe(NP, files)["namespaces"][0]
    assert (n["default_deny_ingress"], n["default_deny_egress"]) == (False, False)
    c = observe(NP, files, counts=True)["counts"]
    assert c["namespaces_without_default_deny_ingress"] == 1 and c["namespaces_without_default_deny_egress"] == 1


def test_a_namespace_without_any_policy_is_reported(observe):
    n = observe(NP, one([deployment(ns="open")]))["namespaces"][0]
    assert (n["namespace"], n["policy_count"], n["default_deny_ingress"]) == ("open", 0, False)


def test_egress_rules_are_extracted_as_data(observe):
    eg = [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8", "except": ["10.1.0.0/16"]}}, {"namespaceSelector": {}, "podSelector": {"matchLabels": {"a": "b"}}}],
           "ports": [{"port": 53, "protocol": "UDP"}, {"port": 443}]}]
    p = observe(NP, one([netpol("e", types=["Egress"], egress=eg)]))["policies"][0]
    rule = p["egress_rules"][0]
    assert rule["to"][0] == {"ip_block": "10.0.0.0/8", "except": ["10.1.0.0/16"], "pod_selector": "none", "namespace_selector": "none"}
    assert rule["to"][1]["pod_selector"] == "set" and rule["to"][1]["namespace_selector"] == "empty"
    assert rule["ports"] == [{"port": 53, "end_port": None, "protocol": "UDP"}, {"port": 443, "end_port": None, "protocol": "TCP"}]
    assert p["policy_types"] == ["Egress"]


def test_cilium_deny_rules_are_extracted(observe):
    v = observe(NP, one([cilium_deny("deny", cidrs=["203.0.113.0/24"], entities=["world"], ports=[(25, "TCP"), (587, "TCP")])]))
    p = v["policies"][0]
    assert p["engine"] == "cilium"
    d = p["deny_rules"][0]
    assert (d["direction"], d["cidr"], d["entities"]) == ("egress", ["203.0.113.0/24"], ["world"])
    assert [x["port"] for x in d["ports"]] == ["25", "587"]
    assert observe(NP, one([cilium_deny("deny", cidrs=["203.0.113.0/24"])]), counts=True)["counts"]["deny_rules"] == 1


# -- kyverno ------------------------------------------------------------------------------------------------------------------

KY = "manifest.kyverno-policies"


def test_kyverno_policies_are_listed_with_their_action_and_rule_types(observe):
    v = observe(KY, one([kyverno_policy("p1"), kyverno_policy("p2", action="Audit", rule_type="verifyImages")]))
    assert [(p["name"], p["validation_failure_action"]) for p in v["policies"]] == [("p1", "Enforce"), ("p2", "Audit")]
    assert v["policies"][0]["rules"][0]["types"] == ["validate"] and v["policies"][0]["rules"][0]["match_kinds"] == ["Pod"]
    assert observe(KY, one([kyverno_policy("p1"), kyverno_policy("p2", action="Audit", rule_type="verifyImages")]), counts=True)["counts"] == \
        {"policies": 2, "enforce": 1, "audit": 1, "verify_images_rules": 1}


def test_an_unrelated_kind_or_group_is_not_a_kyverno_policy(observe):
    other = {"apiVersion": "example.test/v1", "kind": "Policy", "metadata": {"name": "x"}, "spec": {}}
    assert observe(KY, one([other]))["policies"] == []
    assert observe(KY, one([deployment()]), counts=True)["counts"]["policies"] == 0


# -- probes -------------------------------------------------------------------------------------------------------------------

PR = "manifest.probes"


def test_declared_probes_and_ports(observe):
    c = observe(PR, one([deployment()]))["containers"][0]
    assert c["readiness"]["handler"] == "httpGet" and c["readiness"]["path"] == "/ready" and c["readiness"]["port_declared"] is True
    assert c["liveness"]["port"] == "http" and c["liveness"]["port_declared"] is True and c["startup"]["present"] is False


def test_missing_probe_and_undeclared_probe_port_are_observed(observe):
    none = observe(PR, one([deployment(containers=[container(probes=False)])]))
    assert none["counts"] == {"containers": 1, "with_liveness": 0, "with_readiness": 0, "with_startup": 0}
    c = container()
    c["readinessProbe"] = {"httpGet": {"path": "/r", "port": 9999}}
    r = observe(PR, one([deployment(containers=[c])]))["containers"][0]["readiness"]
    assert r["port_declared"] is False
    ex = container()
    ex["readinessProbe"] = {"exec": {"command": ["true"]}}
    assert observe(PR, one([deployment(containers=[ex])]))["containers"][0]["readiness"]["handler"] == "exec"


# -- cross references -----------------------------------------------------------------------------------------------------------

XR = "manifest.cross-references"


def test_selectors_ports_and_references_resolve_inside_the_input(observe):
    v = observe(XR, good_set())
    assert v["workload_selectors"][0]["selector_matches_template_labels"] is True
    s = v["services"][0]
    assert s["matched_workloads"] == ["Deployment/app"] and s["ports"][0]["target_declared_by_matched_workloads"] is True
    assert v["counts"]["references_not_in_input"] == 0 and [r["ref_name"] for r in v["references"]] == ["app"]


def test_a_service_selector_that_matches_nothing_and_a_wrong_target_port_are_observed(observe):
    v = observe(XR, one([deployment(), service(selector={"app": "nope"}), service("b", target=9999)]))
    by = {s["name"]: s for s in v["services"]}
    assert by["app"]["matched_workloads"] == [] and by["app"]["ports"][0]["target_declared_by_matched_workloads"] is None
    assert by["b"]["ports"][0]["target_declared_by_matched_workloads"] is None
    v2 = observe(XR, one([deployment(), service(target=9999)]))
    assert v2["services"][0]["ports"][0]["target_declared_by_matched_workloads"] is False


def test_a_workload_selector_that_does_not_match_its_template_is_observed(observe):
    dep = deployment(selector={"app": "other"})
    assert observe(XR, one([dep]))["workload_selectors"][0]["selector_matches_template_labels"] is False


def test_references_to_absent_objects_are_flagged(observe):
    env = [{"name": "A", "valueFrom": {"secretKeyRef": {"name": "missing", "key": "k"}}}]
    dep = deployment(containers=[container(env=env)], pod_spec={"serviceAccountName": "sa", "volumes": [{"name": "d", "persistentVolumeClaim": {"claimName": "pvc"}}]})
    sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "sa", "namespace": "demo"}}
    v = observe(XR, one([dep, sa, httproute(backend="gone")]))
    present = {(r["ref_kind"], r["ref_name"]): r["present_in_input"] for r in v["references"]}
    assert present == {("Secret", "missing"): False, ("ServiceAccount", "sa"): True, ("PersistentVolumeClaim", "pvc"): False, ("Service", "gone"): False}
    assert v["counts"]["references_not_in_input"] == 3


# -- structure --------------------------------------------------------------------------------------------------------------

ST = "manifest.structure"


def test_structure_reports_missing_identity_duplicates_and_load_errors(observe, tmp_path, registry):
    files = one([deployment(), deployment(), {"kind": "Thing", "metadata": {"name": "x"}}])
    v = observe(ST, files)
    assert v["duplicate_identities"] == [{"api_version": "apps/v1", "kind": "Deployment", "namespace": "demo", "name": "app", "count": 2}]
    assert v["counts"]["missing_identity"] == 1 and v["counts"]["documents"] == 3
    root = write_tree(tmp_path / "bad", one([deployment()]))
    (root / "broken.yaml").write_text("a: [unterminated\n", encoding="utf-8")
    ref = registry.resolve({"id": ST, "version": "1.0.0", "program_hash": registry.registered_program_hash(ST, "1.0.0")}).ref
    out = CheckEngine(root, registry).run_check({"check_program_ref": ref, "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "tier": "OFFLINE"})
    assert out.value["input_errors"] == [{"source": "broken.yaml", "code": "YAML_REFUSED"}] and out.value["counts"]["load_errors"] == 1


def test_an_empty_input_directory_resolves_to_an_empty_observation(observe, tmp_path, registry):
    (tmp_path / "empty").mkdir()
    ref = registry.resolve({"id": IMG, "version": "1.0.0", "program_hash": registry.registered_program_hash(IMG, "1.0.0")}).ref
    out = CheckEngine(tmp_path / "empty", registry).run_check({"check_program_ref": ref, "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "tier": "OFFLINE"})
    assert out.resolution == "RESOLVED" and out.value["counts"]["containers"] == 0


def test_the_counts_projection_equals_the_counts_of_the_full_program(observe):
    for pid in ["manifest.image-references", "manifest.security-context", "manifest.resources", "manifest.probes", "manifest.network-policies",
                "manifest.gateway-routes", "manifest.kyverno-policies", "manifest.cross-references", "manifest.structure",
                "manifest.env-and-secret-refs", "manifest.image-name-map"]:
        full = observe(pid, good_set())
        compact = observe(pid, good_set(), counts=True)
        assert compact == {"counts": full["counts"], "input_error_count": len(full["input_errors"])}, pid
