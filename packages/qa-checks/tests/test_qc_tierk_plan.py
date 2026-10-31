# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The bring-up plan as data: it reproduces the inventory's pin list exactly, pins every image by digest and has no floating tag."""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from redevops_qa_checks.tierk import plan as P

PKG = Path(__file__).resolve().parents[1]

# the machine-readable pin list as the component inventory states it
INVENTORY_PIN_LIST = """
tierK:
  kind: {version: v0.33.0}
  nodeImage: {primary: "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
             control: "kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"}
  cilium: {chart: "1.19.6", mode: real}
  envoyGateway: {chart: "v1.9.2", crds: gateway-api-v1.6.1-experimental+envoy-gateway, mode: real}
  metallb: {manifest: "v0.16.0", mode: real}
  kyverno: {chart: "3.9.2", app: "v1.19.2", cli: "v1.19.2", mode: real}
  certManager: {crds: "v1.21.2", mode: crd-only}
  externalSecrets: {crds: "v2.14.0", mode: crd-only}
"""

PLAN = P.build_plan()
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def test_the_plan_reproduces_the_inventory_pin_list_exactly():
    assert PLAN.pin_list() == yaml.safe_load(INVENTORY_PIN_LIST)


def test_the_node_images_in_the_pin_list_are_the_lanes_images_and_the_kind_configs_use_them():
    for lane in PLAN.document["lanes"]:
        key = {"primary": "primary", "control": "control"}[lane["id"]]
        assert lane["node_image"] == PLAN.pin_list()["tierK"]["nodeImage"][key]
        cfg = yaml.safe_load((P.DATA / lane["kind_config"]).read_text(encoding="utf-8"))
        assert {n["image"] for n in cfg["nodes"]} == {lane["node_image"]} and cfg["name"] == lane["cluster_name"]
        assert cfg["networking"]["apiServerAddress"] == "127.0.0.1" and cfg["networking"]["apiServerPort"] == lane["api_server_port"]


def test_every_image_is_pinned_by_digest_and_none_has_a_floating_tag():
    for i in PLAN.images():
        assert DIGEST.fullmatch(i["digest"]), i["component"]
        assert not i["ref"].endswith(":latest") and ":latest" not in i["ref"], i["component"]
    text = json.dumps(PLAN.document)
    assert "latest" not in text.replace("the chart default tag is floating", "")
    assert not re.search(r":latest\b", text)


def test_the_plan_contains_no_latest_tag_anywhere_including_the_data_files():
    for p in P.DATA.iterdir():
        assert ":latest" not in p.read_text(encoding="utf-8")
    assert not re.search(r"(?<![A-Za-z])latest(?![A-Za-z])", json.dumps(PLAN.images()))


def test_the_floating_hook_image_is_recorded_by_digest_only_and_is_not_deployed():
    hook = [i for i in PLAN.images() if i["component"] == "kyverno-hook"][0]
    assert hook["deployed"] is False and ":" not in hook["ref"].rsplit("/", 1)[-1]


def test_the_two_lanes_are_separate_and_on_the_stated_versions():
    lanes = {l["id"]: l for l in PLAN.document["lanes"]}
    assert set(lanes) == {"primary", "control"}
    assert lanes["primary"]["kubernetes_version"] == "v1.37.0" and lanes["control"]["kubernetes_version"] == "v1.35.8"
    assert len({l["cluster_name"] for l in lanes.values()}) == 2 and len({l["api_server_port"] for l in lanes.values()}) == 2
    assert PLAN.lane_versions() == {"primary": "v1.37.0", "control": "v1.35.8"}


def test_cluster_names_follow_the_generated_naming_the_guard_requires():
    for l in PLAN.document["lanes"]:
        assert l["cluster_name"].startswith("qa-tier-k-") and l["context_name"] == "kind-" + l["cluster_name"]


def test_the_nine_readiness_gates_are_present_in_order_and_every_apply_step_ends_at_one():
    assert [g["n"] for g in PLAN.document["gates"]] == list(range(1, 10))
    assert [s["step"] for s in PLAN.document["apply_order"]] == list(range(1, 10))
    assert [s["gate"] for s in PLAN.document["apply_order"]] == list(range(1, 10))


def test_dry_run_returns_every_step_as_data_and_executes_nothing(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a process was started")
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    steps = PLAN.dry_run("primary")
    assert len(steps) == 10 and all(s["executed"] is False for s in steps)
    assert steps[0]["action"].startswith("create the kind cluster") and steps[-1]["action"].startswith("apply the disposable marker object")
    assert steps[-1]["step"] == 10 and all(s["lane"] == "primary" for s in steps)
    with pytest.raises(KeyError):
        PLAN.dry_run("nope")


def test_the_data_files_are_hashed_into_the_plan_and_a_change_changes_the_plan_hash():
    assert set(PLAN.document["files"]) == set(P.FILES)
    for name, digest in PLAN.document["files"].items():
        assert digest == "sha256:" + hashlib.sha256((P.DATA / name).read_bytes()).hexdigest()
    changed = dict(PLAN.document)
    changed["files"] = {**PLAN.document["files"], "cilium-values.yaml": "sha256:" + "0" * 64}
    assert P.BringUpPlan(changed).plan_sha256 != PLAN.plan_sha256


def test_helm_values_carry_the_settings_the_inventory_states():
    cilium = yaml.safe_load((P.DATA / "cilium-values.yaml").read_text(encoding="utf-8"))
    assert cilium["kubeProxyReplacement"] is True and cilium["ipam"]["mode"] == "kubernetes" and cilium["routingMode"] == "tunnel"
    assert cilium["operator"]["replicas"] == 1 and cilium["envoy"]["enabled"] is False and cilium["hubble"]["enabled"] is False
    assert cilium["gatewayAPI"]["enabled"] is False
    eg = yaml.safe_load((P.DATA / "envoy-gateway-values.yaml").read_text(encoding="utf-8"))
    assert eg == {"crds": {"enabled": True}}
    ky = yaml.safe_load((P.DATA / "kyverno-values.yaml").read_text(encoding="utf-8"))
    assert ky["admissionController"]["replicas"] == 1 and all(ky[k]["enabled"] is False for k in ("backgroundController", "cleanupController", "reportsController", "webhooksCleanup"))


def test_kind_configs_disable_the_default_cni_and_kube_proxy_and_set_the_subnets_and_topology():
    for name in ("kind-primary.yaml", "kind-control.yaml"):
        cfg = yaml.safe_load((P.DATA / name).read_text(encoding="utf-8"))
        net = cfg["networking"]
        assert net["disableDefaultCNI"] is True and net["kubeProxyMode"] == "none"
        assert net["serviceSubnet"] == "10.43.0.0/16" and net["podSubnet"] == "10.244.0.0/16"
        assert [n["role"] for n in cfg["nodes"]] == ["control-plane", "worker", "worker"]


def test_the_control_lane_config_differs_from_the_primary_only_in_name_port_and_image():
    a = yaml.safe_load((P.DATA / "kind-primary.yaml").read_text(encoding="utf-8"))
    b = yaml.safe_load((P.DATA / "kind-control.yaml").read_text(encoding="utf-8"))
    for d in (a, b):
        d["name"] = ""
        d["networking"]["apiServerPort"] = 0
        for n in d["nodes"]:
            n["image"] = ""
    assert a == b


def test_cert_manager_and_external_secrets_are_crd_only_and_kyverno_runs_admission_only():
    pins = PLAN.pin_list()["tierK"]
    assert pins["certManager"]["mode"] == "crd-only" and pins["externalSecrets"]["mode"] == "crd-only"
    for i in PLAN.images():
        if i["component"].startswith(("cert-manager", "external-secrets")):
            assert i["deployed"] is False
    for c in ("kyverno-background", "kyverno-cleanup", "kyverno-reports", "kyverno-hook"):
        assert [i for i in PLAN.images() if i["component"] == c][0]["deployed"] is False


def test_the_inventory_digests_are_reproduced_verbatim():
    by = {i["component"]: i["digest"] for i in PLAN.images()}
    assert by["cilium-agent"] == "sha256:0df5b2750b64c49843aba1d649e9eaf61467cb0645ad3171db6f6962c095ac92"
    assert by["envoy-gateway"] == "sha256:9d67017c442a70e6ae9f1a358e6c80eb653c67c2e40823d9a991e0daf37ba926"
    assert by["kyverno-admission"] == "sha256:c8c4dd09e720d2cd7fd24ca73ac28e46651001372f988e0cba3f2f612f04b955"
    assert by["metallb-speaker"] == "sha256:70e7f83255af2e96acfd574ac9f049745639deb2746d35e988008afcc0b80dbd"
    assert by["stand-in-base"] == "sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"
    arts = {a["component"]: a for a in PLAN.document["artifacts"]}
    assert arts["cert-manager-crds"]["file_sha256"] == "sha256:262fef78478492cd35b73a1b227106b7802f9c056361d1f561d04b32d751337f"
    assert arts["external-secrets-crds"]["file_sha256"] == "sha256:21d51ab38bf7016a3d01e1259a92d40c23e83e68182ae6c4ca816af18717cb55"
    assert arts["kyverno-chart"]["tarball_sha256"] == "sha256:f6fe7184544d5e2ee33a77808c09e67aa603ce6560cc197038fde31d727c861e"
    assert arts["cilium-chart"]["manifest_digest"] == "sha256:b8d600c542c97dc8652429e12487ecce922d73de9785505457a8f653833e75f9"


def test_a_digest_the_inventory_records_only_in_part_is_flagged_not_invented():
    assert PLAN.unresolved_digests() == ["metallb-manifest"]
    assert [a for a in PLAN.document["artifacts"] if a["component"] == "metallb-manifest"][0]["manifest_sha256"] is None


def test_the_stand_in_base_is_the_pinned_python_slim_digest():
    assert PLAN.document["stand_in_base"] == {"image": "python:3.12-slim", "digest": "sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}


def test_run_time_inputs_and_determinism_requirements_are_listed():
    assert len(PLAN.document["determinism"]) >= 8 and len(PLAN.document["runtime_inputs"]) == 3


def test_the_plan_hash_is_identical_across_processes_and_hash_seeds():
    code = "from redevops_qa_checks.tierk.plan import build_plan; print(build_plan().plan_sha256)"
    outs = set()
    for seed in ("0", "1", "random"):
        r = subprocess.run([sys.executable, "-B", "-c", code], env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": seed, "PYTHONPATH": str(PKG / "src")},
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        outs.add(r.stdout.strip())
    assert outs == {PLAN.plan_sha256}


def test_no_file_in_the_plan_data_names_the_reserved_subnet_or_a_credential():
    for p in P.DATA.iterdir():
        text = p.read_text(encoding="utf-8")
        assert "".join(["192.", "168.", "40."]) not in text and "password" not in text.lower() and "token" not in text.lower()
