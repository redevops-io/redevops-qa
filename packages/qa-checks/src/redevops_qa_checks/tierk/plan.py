# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The bring-up plan for the disposable cluster, as data.

Components, versions and digests come from the component inventory (pins and digests, the machine-readable pin list); the plan
adds the apply order, the nine readiness gates, the determinism requirements and the two node lanes. The Helm values files and
the kind configurations are committed under ``data/`` and hashed into the plan. Nothing here fetches anything or starts a
cluster; ``BringUpPlan.dry_run`` returns the steps a bring-up would take, as data.

Rules the tests hold the plan to: every container image is pinned by digest, no tag is ``latest``, the primary lane
(1.37.0) and the control lane (1.35.8) are separate, and the plan hash is the same on every run.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ..canonical import canonical_bytes, sha256_ref

DATA = Path(__file__).resolve().parent / "data"

#: the machine-readable pin list, as the inventory states it
PIN_LIST: Dict[str, Any] = {
    "tierK": {
        "kind": {"version": "v0.33.0"},
        "nodeImage": {"primary": "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
                      "control": "kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"},
        "cilium": {"chart": "1.19.6", "mode": "real"},
        "envoyGateway": {"chart": "v1.9.2", "crds": "gateway-api-v1.6.1-experimental+envoy-gateway", "mode": "real"},
        "metallb": {"manifest": "v0.16.0", "mode": "real"},
        "kyverno": {"chart": "3.9.2", "app": "v1.19.2", "cli": "v1.19.2", "mode": "real"},
        "certManager": {"crds": "v1.21.2", "mode": "crd-only"},
        "externalSecrets": {"crds": "v2.14.0", "mode": "crd-only"},
    }
}

STAND_IN_BASE = {"image": "python:3.12-slim", "digest": "sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}


def _img(component: str, ref: str, digest: str, *, deployed: bool = True, note: str = "") -> Dict[str, Any]:
    return {"component": component, "kind": "image", "ref": ref, "digest": digest, "deployed": deployed, "note": note}


#: every image, by digest. A reference with a floating tag is recorded without its tag and marked as not deployed.
IMAGES: Tuple[Dict[str, Any], ...] = (
    _img("kind-node-primary", "kindest/node:v1.37.0", "sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"),
    _img("kind-node-control", "kindest/node:v1.35.8", "sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"),
    _img("cilium-agent", "quay.io/cilium/cilium:v1.19.6", "sha256:0df5b2750b64c49843aba1d649e9eaf61467cb0645ad3171db6f6962c095ac92"),
    _img("cilium-operator", "quay.io/cilium/operator-generic:v1.19.6", "sha256:0db4ca4e06969d8904ee036617795d0e9c3228cf7b8d902ba74fc2bb98d2d665"),
    _img("cilium-envoy", "quay.io/cilium/cilium-envoy:v1.36.9-1782267392-edeb3f2af56c37c407efa1f63f0b32f595399bbc",
         "sha256:767101fb8a5e38f055778cb43b7aa8eed80450b37f8121effac3d9de9e06dc99", deployed=False, note="disabled in the values"),
    _img("envoy-gateway", "docker.io/envoyproxy/gateway:v1.9.2", "sha256:9d67017c442a70e6ae9f1a358e6c80eb653c67c2e40823d9a991e0daf37ba926"),
    _img("envoy-proxy", "docker.io/envoyproxy/envoy:distroless-v1.39.1", "sha256:eb2c01c13125d1629637cb4e4cce7207009fb7cc2c8027f9742758549d15b6f4"),
    _img("envoy-ratelimit", "docker.io/envoyproxy/ratelimit:0482748e", "sha256:5fdd8e3ae335ab6d64316f8d2fd9a886830075cbbb40a1d8065c869275909162",
         deployed=False, note="no route uses rate limiting"),
    _img("metallb-controller", "quay.io/metallb/controller:v0.16.0", "sha256:615b454c45e424e61d1f82c916ad7ab8c11ef2ba09d3ec4b0b64458e4058ff2b"),
    _img("metallb-speaker", "quay.io/metallb/speaker:v0.16.0", "sha256:70e7f83255af2e96acfd574ac9f049745639deb2746d35e988008afcc0b80dbd"),
    _img("kyverno-admission", "reg.kyverno.io/kyverno/kyverno:v1.19.2", "sha256:c8c4dd09e720d2cd7fd24ca73ac28e46651001372f988e0cba3f2f612f04b955"),
    _img("kyverno-init", "reg.kyverno.io/kyverno/kyvernopre:v1.19.2", "sha256:27f3cc52e628559b56d08363b85316819802086c9808606914f7805a244148f4"),
    _img("kyverno-background", "reg.kyverno.io/kyverno/background-controller:v1.19.2",
         "sha256:c46e124f21ef8a6bb4b48de57106808b1007edcd5ddd4ff7df5d23b9efa60ce2", deployed=False, note="disabled in the values"),
    _img("kyverno-cleanup", "reg.kyverno.io/kyverno/cleanup-controller:v1.19.2",
         "sha256:d7340aa7c9315080c3dafa7b765d090ced37353e89e5cd7a3f9ac69e8fb532b2", deployed=False, note="disabled in the values"),
    _img("kyverno-reports", "reg.kyverno.io/kyverno/reports-controller:v1.19.2",
         "sha256:5fb6d3e738050dbce84f60ecabaede7665fbe0578d07c1e8c912443b035e79c3", deployed=False, note="disabled in the values"),
    _img("kyverno-hook", "ghcr.io/kyverno/readiness-checker", "sha256:f0dd96c93f434e4fe9d47ade05f37fd39958264273550ce563a6c18f143115c0",
         deployed=False, note="the chart default tag is floating; the hook is disabled and recorded by digest only so nobody enables it unpinned"),
    _img("cert-manager-controller", "quay.io/jetstack/cert-manager-controller:v1.21.2",
         "sha256:70f532fd9cfde0b09d55687200942399d89838bc2d5d5b45152eb799a15912b8", deployed=False, note="CRD-only; optional real-controller lane"),
    _img("cert-manager-webhook", "quay.io/jetstack/cert-manager-webhook:v1.21.2",
         "sha256:a60e2dac46dbb8a7f3df95c54ce941012f54c2fe022f0ee55aaa1ab40ed957ae", deployed=False, note="CRD-only; optional real-controller lane"),
    _img("cert-manager-cainjector", "quay.io/jetstack/cert-manager-cainjector:v1.21.2",
         "sha256:c85268c64f2e0e76684bf5fe8906caff34b82523561c6affe0fae3546bd87562", deployed=False, note="CRD-only; optional real-controller lane"),
    _img("cert-manager-startupapicheck", "quay.io/jetstack/cert-manager-startupapicheck:v1.21.2",
         "sha256:46e75b6866359ffb5d82624f41e3ed1c70b2994982702ced547ce5edb418a8f5", deployed=False, note="CRD-only; optional real-controller lane"),
    _img("external-secrets", "ghcr.io/external-secrets/external-secrets:v2.14.0",
         "sha256:10608eb53e636e744903d5f3657a4d9c44e28d9d9c181b73e07bc7dd2e6884dc", deployed=False, note="CRD-only; optional real-controller lane"),
    _img("stand-in-base", STAND_IN_BASE["image"], STAND_IN_BASE["digest"], note="base of the stand-in workload images"),
)

#: charts, manifests and tool downloads, each by digest or checksum. ``None`` marks a digest the inventory records only in part.
ARTIFACTS: Tuple[Dict[str, Any], ...] = (
    {"component": "cilium-chart", "kind": "chart", "source": "oci://quay.io/cilium/charts/cilium", "version": "1.19.6",
     "manifest_digest": "sha256:b8d600c542c97dc8652429e12487ecce922d73de9785505457a8f653833e75f9",
     "blob_digest": "sha256:21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179", "values": "cilium-values.yaml"},
    {"component": "envoy-gateway-chart", "kind": "chart", "source": "oci://docker.io/envoyproxy/gateway-helm", "version": "v1.9.2",
     "manifest_digest": "sha256:be034275b55deeddd6b7bc1f4da6eeb02b8efc418a4a29e2b1977851b24b1e63",
     "blob_digest": "sha256:1079cad009e0885f6e10e5f712257d8e5fdaf911d2ceb3fa1b78632c8f29bbf9", "values": "envoy-gateway-values.yaml"},
    {"component": "kyverno-chart", "kind": "chart", "source": "https://kyverno.github.io/kyverno", "version": "3.9.2",
     "tarball_sha256": "sha256:f6fe7184544d5e2ee33a77808c09e67aa603ce6560cc197038fde31d727c861e", "values": "kyverno-values.yaml"},
    {"component": "metallb-manifest", "kind": "manifest", "source": "native manifest", "version": "v0.16.0", "manifest_sha256": None,
     "manifest_sha256_note": "the inventory records only the first and last digits (b0b9be28 ... 2b69); the full digest is recorded at the first verified fetch"},
    {"component": "cert-manager-crds", "kind": "crd-bundle", "source": "release asset cert-manager.crds.yaml", "version": "v1.21.2",
     "file_sha256": "sha256:262fef78478492cd35b73a1b227106b7802f9c056361d1f561d04b32d751337f", "expected_crds": 6},
    {"component": "external-secrets-crds", "kind": "crd-bundle", "source": "release asset external-secrets.yaml (CRDs extracted)", "version": "v2.14.0",
     "file_sha256": "sha256:21d51ab38bf7016a3d01e1259a92d40c23e83e68182ae6c4ca816af18717cb55",
     "chart_tarball_sha256": "sha256:0a6d9e91b1ff50adfdbf24b50b582babfa7c5b7df42b21974ca4b3fb88ee5e34", "expected_crds": 25},
    {"component": "gateway-api-and-envoy-gateway-crds", "kind": "crd-bundle", "source": "shipped by the Envoy Gateway chart (crds.enabled)",
     "version": "gateway-api-v1.6.1-experimental + envoy-gateway", "expected_crds": 18, "note": "10 Gateway API and 8 Envoy Gateway CRDs"},
)

TOOLS: Tuple[Dict[str, Any], ...] = (
    {"component": "kind", "version": "v0.33.0", "sha256": {"darwin-arm64": "0c8c7dbe5e23594a198b786c4bc13dacc101fa6196b0cb0b23a1ca44e61f4b4f",
                                                          "linux-amd64": "aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d"}},
    {"component": "helm", "version": "v3.22.1", "sha256": {"darwin-arm64": "e73da8a0b0d5193774fdff17ce6319c7436bb22ee229b45fd64f3c40368c753a",
                                                           "linux-amd64": "896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea"}},
    {"component": "kyverno-cli", "version": "v1.19.2", "sha256": {"linux-amd64": "357eaf1df8bc24ddd5a73979fadeaae6a032e8710f11af264229756e4956bf4a",
                                                                  "linux-arm64": "250f2a02f143d5c6425e686b13c130d3a3ba7372dba6a7210d599d1b0dd12e92",
                                                                  "darwin-arm64": "7915c03c613c22363a100adb3da8d06f2e2626d9d21a98b97f921795ffdc536f"}},
    {"component": "kubectl", "version": "v1.37.2", "sha256": {}, "note": "client within one minor of the 1.37.0 server; no checksum is recorded"},
)

LANES: Tuple[Dict[str, Any], ...] = (
    {"id": "primary", "kubernetes_version": "v1.37.0", "cluster_name": "qa-tier-k-primary", "context_name": "kind-qa-tier-k-primary",
     "kind_config": "kind-primary.yaml", "node_image": PIN_LIST["tierK"]["nodeImage"]["primary"], "api_server_port": 46443,
     "role": "the Kubernetes minor the infrastructure code targets"},
    {"id": "control", "kubernetes_version": "v1.35.8", "cluster_name": "qa-tier-k-control", "context_name": "kind-qa-tier-k-control",
     "kind_config": "kind-control.yaml", "node_image": PIN_LIST["tierK"]["nodeImage"]["control"], "api_server_port": 46444,
     "role": "separates a manifest problem from an untested version combination; run once per stack change"},
)

NETWORKING = {"service_subnet": "10.43.0.0/16", "pod_subnet": "10.244.0.0/16", "topology": "1 control-plane + 2 workers",
              "alternate_topology": "1 control-plane + 1 worker on a small runner"}

#: apply order; each phase ends at the named readiness gate before the next starts
APPLY_ORDER: Tuple[Dict[str, Any], ...] = (
    {"step": 1, "action": "create the kind cluster from the lane's kind configuration", "components": ["kind"], "gate": 1},
    {"step": 2, "action": "install Cilium (chart values committed and hashed)", "components": ["cilium-chart"], "gate": 2},
    {"step": 3, "action": "apply CRDs: Gateway API and Envoy Gateway (chart), cert-manager and External Secrets (CRD-only), Cilium, Kyverno",
     "components": ["gateway-api-and-envoy-gateway-crds", "cert-manager-crds", "external-secrets-crds"], "gate": 3},
    {"step": 4, "action": "install Envoy Gateway and apply the GatewayClass", "components": ["envoy-gateway-chart"], "gate": 4},
    {"step": 5, "action": "install MetalLB and apply the address pool", "components": ["metallb-manifest"], "gate": 5},
    {"step": 6, "action": "apply the local TLS secrets and the Gateway", "components": [], "gate": 6},
    {"step": 7, "action": "install Kyverno (admission controller only) and apply the policies", "components": ["kyverno-chart"], "gate": 7},
    {"step": 8, "action": "apply the namespace objects: quota, limit range, network policies, policy sets", "components": [], "gate": 8},
    {"step": 9, "action": "load the stand-in images by digest and apply the workloads, probes and routes", "components": ["stand-in-base"], "gate": 9},
)

GATES: Tuple[Dict[str, Any], ...] = (
    {"n": 1, "name": "nodes", "conditions": ["every node Ready", "CoreDNS Available"]},
    {"n": 2, "name": "cni", "conditions": ["Cilium agent DaemonSet and operator Available", "cilium status clean",
                                           "a throwaway pair of pods reaches each other (positive control)"]},
    {"n": 3, "name": "crds", "conditions": ["Gateway API CRDs Established (10)", "Envoy Gateway CRDs Established (8)", "cert-manager CRDs Established (6)",
                                           "External Secrets CRDs Established (25 in the bundle)", "Cilium CRDs Established", "Kyverno CRDs Established"]},
    {"n": 4, "name": "gateway-controller", "conditions": ["Envoy Gateway controller Available", "GatewayClass Accepted=True"]},
    {"n": 5, "name": "load-balancer", "conditions": ["MetalLB controller and speaker Ready", "address pool applied"]},
    {"n": 6, "name": "gateway", "conditions": ["Gateway Accepted=True and Programmed=True", "every listener ResolvedRefs=True",
                                               "proxy Deployment Available", "Service has an external address"]},
    {"n": 7, "name": "admission", "conditions": ["Kyverno admission controller Ready", "webhook configurations present",
                                                 "each ClusterPolicy ready (status.ready or the Ready condition)"]},
    {"n": 8, "name": "namespace-objects", "conditions": ["quota and limit range visible in status", "policies listed"]},
    {"n": 9, "name": "workloads", "conditions": ["stand-in workloads Available", "probes pass",
                                                 "routes show Accepted and ResolvedRefs before any request is sent"]},
)

DETERMINISM: Tuple[str, ...] = (
    "versions and digests in this plan are identical on every run",
    "Helm values files and kind configurations are committed and hashed (node count, subnets, no default CNI, no kube-proxy)",
    "cluster, context, node and namespace names, network names and subnets are fixed",
    "the apply order and the rendered manifest set come from the same renderer at the same source revision",
    "all images are fetched once into a local cache keyed by digest and loaded into the cluster; a run never depends on a registry",
    "chart tarballs and CRD files are fetched once, checksum-verified and kept in the cache",
    "secret and certificate material is generated from fixed inputs (names and subjects fixed; key bytes may differ and are never compared)",
    "single-replica settings (Cilium operator, Kyverno admission) so readiness does not depend on leader election timing",
)

#: values the bring-up derives at run time and the plan therefore cannot hash
RUNTIME_INPUTS: Tuple[str, ...] = (
    "Cilium k8sServiceHost and k8sServicePort (the lane's control-plane container and port 6443)",
    "the MetalLB address pool (a free range at the end of the kind network; it must not overlap the synthetic connectivity subnet)",
    "the generated nonce recorded in the marker list and, hashed, in the marker object",
)

FILES: Tuple[str, ...] = ("kind-primary.yaml", "kind-control.yaml", "cilium-values.yaml", "envoy-gateway-values.yaml", "kyverno-values.yaml")


def file_hashes() -> Dict[str, str]:
    return {n: sha256_ref((DATA / n).read_bytes().replace(b"\r\n", b"\n")) for n in FILES}


@dataclass(frozen=True)
class BringUpPlan:
    document: Mapping[str, Any]

    @property
    def plan_sha256(self) -> str:
        return sha256_ref(canonical_bytes(self.document))

    def lane(self, lane_id: str) -> Mapping[str, Any]:
        for l in self.document["lanes"]:
            if l["id"] == lane_id:
                return l
        raise KeyError(lane_id)

    def lane_versions(self) -> Dict[str, str]:
        return {l["id"]: l["kubernetes_version"] for l in self.document["lanes"]}

    def pin_list(self) -> Dict[str, Any]:
        return self.document["pin_list"]

    def images(self) -> Tuple[Mapping[str, Any], ...]:
        return tuple(self.document["images"])

    def unresolved_digests(self) -> List[str]:
        return [a["component"] for a in self.document["artifacts"] if a.get("manifest_sha256", "x") is None]

    def dry_run(self, lane_id: str) -> List[Dict[str, Any]]:
        """The steps a bring-up of one lane would take, in order, as data. Nothing is executed."""
        lane = self.lane(lane_id)
        steps = []
        for s in self.document["apply_order"]:
            steps.append({"step": s["step"], "lane": lane["id"], "cluster": lane["cluster_name"], "action": s["action"],
                          "components": list(s["components"]), "readiness_gate": next(g for g in self.document["gates"] if g["n"] == s["gate"]),
                          "executed": False})
        steps.append({"step": 10, "lane": lane["id"], "cluster": lane["cluster_name"], "executed": False,
                      "action": "apply the disposable marker object and record the cluster in the marker list", "components": [], "readiness_gate": None})
        return steps


def build_plan() -> BringUpPlan:
    doc = {"schema": "qa-checks/tier-k-plan/1", "pin_list": PIN_LIST, "images": [dict(i) for i in IMAGES], "artifacts": [dict(a) for a in ARTIFACTS],
           "tools": [dict(t) for t in TOOLS], "lanes": [dict(l) for l in LANES], "networking": dict(NETWORKING),
           "apply_order": [dict(s) for s in APPLY_ORDER], "gates": [dict(g) for g in GATES], "determinism": list(DETERMINISM),
           "runtime_inputs": list(RUNTIME_INPUTS), "files": file_hashes(), "stand_in_base": dict(STAND_IN_BASE)}
    return BringUpPlan(document=doc)
