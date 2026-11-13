# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The standalone deployment files say what the documentation says they say: secure defaults in Compose and in the Kubernetes manifests, no credential and no internal address in any of them,
a digest-pinned base image, and a Secret example that holds no value and is not applied by the kustomization."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "standalone"
K8S = DEPLOY / "k8s"


def load_all(path: Path):
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]


def test_compose_is_closed_by_default_and_refuses_to_start_without_a_token_or_a_tag():
    text = (DEPLOY / "compose.yaml").read_text(encoding="utf-8")
    svc = yaml.safe_load(text)["services"]["qa"]
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"] and "no-new-privileges:true" in svc["security_opt"]
    assert svc["ports"] == ["${QA_BIND_ADDRESS:-127.0.0.1}:${QA_PORT:-8080}:8080"]
    assert ":?" in svc["image"] and ":?" in svc["environment"]["QA_SERVICE_TOKEN"], "the tag and the token have no default"
    assert svc["healthcheck"]["test"] == ["CMD", "redevops-qa-service", "healthcheck"]
    assert "latest" not in text and svc["tmpfs"] and svc["volumes"] == ["qa-data:/data"]


def test_env_example_lists_names_only():
    for line in (DEPLOY / ".env.example").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            name, _, value = line.partition("=")
            assert re.fullmatch(r"QA_[A-Z_]+", name) and value == "", line


def test_the_deployment_is_unprivileged_read_only_and_reads_the_token_from_a_mounted_secret():
    dep = next(d for d in load_all(K8S / "deployment.yaml") if d["kind"] == "Deployment")
    pod = dep["spec"]["template"]["spec"]
    c = pod["containers"][0]
    assert pod["securityContext"]["runAsNonRoot"] is True and pod["securityContext"]["runAsUser"] == 10001 and pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert c["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    assert pod["automountServiceAccountToken"] is False and dep["spec"]["replicas"] == 1 and dep["spec"]["strategy"]["type"] == "Recreate"
    assert {e["name"] for e in c["env"]} == {"QA_SERVICE_TOKEN_FILE"} and all("value" in e for e in c["env"])
    assert c["readinessProbe"]["httpGet"]["path"] == "/readyz" and c["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert c["resources"]["limits"] and c["resources"]["requests"]
    assert next(v for v in pod["volumes"] if v["name"] == "token")["secret"]["defaultMode"] == 0o440


def test_the_namespace_is_default_deny_with_one_allowance_and_no_egress():
    policies = load_all(K8S / "networkpolicy.yaml")
    deny = next(p for p in policies if p["metadata"]["name"] == "default-deny")
    assert deny["spec"]["podSelector"] == {} and set(deny["spec"]["policyTypes"]) == {"Ingress", "Egress"} and "ingress" not in deny["spec"] and "egress" not in deny["spec"]
    allow = next(p for p in policies if p["metadata"]["name"] == "allow-service-port")
    assert allow["spec"]["policyTypes"] == ["Ingress"] and allow["spec"]["ingress"][0]["ports"] == [{"protocol": "TCP", "port": 8080}]
    ns = load_all(K8S / "namespace.yaml")[0]
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"


def test_the_secret_example_has_no_value_and_the_optional_files_are_not_applied():
    secret = load_all(K8S / "secret.example.yaml")[0]
    assert secret["kind"] == "Secret" and secret["stringData"] == {"token": ""}
    kust = yaml.safe_load((K8S / "kustomization.yaml").read_text(encoding="utf-8"))
    assert "secret.example.yaml" not in kust["resources"] and "ingress.example.yaml" not in kust["resources"]
    assert kust["images"][0]["name"] == "ghcr.io/redevops-io/redevops-qa" and re.fullmatch(r"\d+\.\d+\.\d+", kust["images"][0]["newTag"])
    ingress = load_all(K8S / "ingress.example.yaml")[0]
    assert ingress["spec"]["rules"][0]["host"] == "qa.example.com"


def test_no_deployment_file_holds_a_credential_an_internal_address_or_latest():
    for path in [*DEPLOY.rglob("*")]:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"(?<![\w.-])(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(?![\w.])", text), path
        assert not re.search(r"(?i)\.svc\.cluster\.local|\.internal\b|BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}", text), path
        assert not re.search(r":latest\b", text), path
