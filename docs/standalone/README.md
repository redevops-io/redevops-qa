# redevops-qa standalone (container image, Docker Compose, Kubernetes)

`redevops-qa` runs frozen test specifications against its bundled fixture app and keeps hash-chained evidence that `redevops-qa verify` re-checks offline. This directory documents the
container image that packages it: the command line and a small authenticated HTTP service around it, with a Compose file for one host and Kustomize manifests for a cluster.

Licence: source-available under the family licence (AGPL-3.0-or-later with the Commons Clause); see [LICENSE.md](../../LICENSE.md). The public licence of the finished product is not final.

## What it is, and what it is not

* **It is** the product as it exists: `doctor`, `freeze`, `run`, `demo`, `verify`, `report`, `inspect` and `anchor` of the `redevops-qa` command, plus `redevops-qa-service`
  ([packages/qa-service](../../packages/qa-service/README.md)), which starts one of the shipped plans, keeps the evidence bundle it writes, and serves its report and verification.
* **It runs against the fixture app only.** `run` and `demo` start the fixture app that ships with the runner on the container's loopback; no external application can be pointed at
  the product yet (audit item P2-1 is design work, see [P2_1_EXTERNAL_TARGET_DESIGN.md](../P2_1_EXTERNAL_TARGET_DESIGN.md)). The service has no way to name a target or a file.
* **It has no web interface.** The product never had one. The only HTML it produces is the static report of `redevops-qa report --format html` (no script, a content-security policy), which
  the service returns as it is. The fixture app is the test target, not a user interface. Nothing in this image is a UI that was added for the occasion.
* **Engines in the image (linux/amd64):** Playwright 1.64.1 with the pinned Chromium (checked against `bundle/browser.lock.json` by the installer and by `doctor`), and Robot Framework 7.5.
  **Not in the image:** Selenium with Chrome, and Appium. They are outside the product's release claim (`bundle/README.md`); the Android lane needs an emulator or a device and the iOS adapter
  reports `UNAVAILABLE`. A container cannot offer them honestly, so it does not.
* **linux/arm64:** the product's bundle is for CPython 3.12 on Linux x86_64 only and its browser pin names x86_64 archives only, so the arm64 image carries the repository's own packages
  (installed from the same hash-checked bundle) **without** the browser and Robot wheels. `verify`, `report`, `inspect`, `freeze` and the service work (an arm64 host can verify evidence made on amd64);
  `run` and `demo` cannot start a lane: `/v1/info` lists every plan as `available: false` with `unavailable.code` `ARCHITECTURE_UNSUPPORTED` and the reason, and starting one is refused with 422. `doctor` reports failures there because the image is not a bundle installation.

## Published release

`v0.6.2`, built from commit `d86219f5c3053ecb1659ea80975132922bc08ebc` by `.github/workflows/oci-release.yml` (run 43503888890):

| Reference | Digest |
|---|---|
| `ghcr.io/redevops-io/redevops-qa:0.6.2` and `:0.6.2-d86219f5c305` (the same index) | `sha256:fa99c66bd94e64a871200eb36f4c242fa839bddca4c626f701e8df036d620065` |
| linux/amd64 image | `sha256:4c65abb941d488e03c0685fcf7cd3f8fce0eb631803d9b365bb9faf37707d998` |
| linux/arm64 image | `sha256:88f778e2867c7552c131ed82f42ba2f9eb899c57da28db1a7751bdb9237d44fe` |

The index and both images carry a keyless cosign signature by the identity `https://github.com/redevops-io/redevops-qa/.github/workflows/oci-release.yml@refs/heads/main` (issuer
`https://token.actions.githubusercontent.com`); the index also carries a GitHub build-provenance attestation, and BuildKit attached an SBOM and a provenance attestation per architecture.
These checks were run against the published tags with no registry credentials: the anonymous pull, `cosign verify` on the index and both images, and `gh attestation verify` on the index.
Install check from the published image only (the digest-pinned reference above, `compose.yaml` and a `.env` in an empty directory, a new Compose project, a clean Docker configuration, linux/amd64):
probes open and the other paths 401 without or with a wrong token; a `browser` run ended `VERIFIED`; a `browser` run with the `settings` defect ended `FAILED` (exit status 1); both bundles were
accepted by `redevops-qa verify` in a second container with `--network none`; the two runs survived a restart and `down` followed by `up`. The `demo` plan with the Robot lane's kernel layers was not part
of that check (it needs a native x86_64 host); the `standalone` CI job runs it on every change.

## Requirements

* Docker Engine with Compose v2 (tested with Docker 29.9.3 and Compose 5.7.0), or a Kubernetes cluster (tested on a throwaway `kind` cluster, Kubernetes 1.37; only core resources are used: Namespace, PersistentVolumeClaim,
  Deployment, Service, NetworkPolicy; k3s itself was not used for the test). The image is about 2.1 GB uncompressed on amd64 (Chromium and its libraries).
* For real runs: a linux/amd64 host. For the **Robot lane with its kernel layers** (what `demo` and the `robot` plan ask for): Linux 6.7 or later with Landlock enabled on a native x86_64 host, in a container whose
  seccomp profile allows seccomp user notification and the Landlock calls (Docker's default does). On a host without them (macOS or Windows with Docker Desktop, an emulated amd64 container, an older kernel) `demo` and the `robot`
  plan are refused before anything starts (`ROBOT_EGRESS_UNAVAILABLE`, nothing is written); use the `browser` plan, or `robot-not-enforced`, whose report states that the lane's traffic is not limited.

## Install with Docker Compose (one host)

Files: [deploy/standalone/compose.yaml](../../deploy/standalone/compose.yaml) and [deploy/standalone/.env.example](../../deploy/standalone/.env.example). Nothing else is needed.

```bash
mkdir redevops-qa && cd redevops-qa
# copy compose.yaml and .env.example from deploy/standalone/ into this directory, then:
cp .env.example .env && chmod 600 .env
openssl rand -hex 32          # put the output after QA_SERVICE_TOKEN= in .env
# set QA_IMAGE_TAG= in .env to the version you install, for example 0.6.2
docker compose up -d --wait
```

Compose refuses to start while `QA_IMAGE_TAG` or `QA_SERVICE_TOKEN` is empty. The port is published on `127.0.0.1:8080` only; set `QA_BIND_ADDRESS` (and put TLS in front) to change that.
To pin by digest instead of by tag, set `QA_IMAGE_TAG=<version>@sha256:<index digest>` (the digest of each release is in its release notes).

The Compose file defines the health check itself (it calls `redevops-qa-service healthcheck`, which asks `/readyz` on the container's loopback); the Dockerfile has the same `HEALTHCHECK`, but an image pushed in the OCI format does not carry one, so nothing relies on it. The container runs as user 10001 on a read-only root file system with all capabilities dropped and `no-new-privileges`; `/tmp` and `/dev/shm` are memory file systems and `/data` is the named volume `qa-data`.

## Install on Kubernetes (k3s or any cluster)

Manifests: [deploy/standalone/k8s](../../deploy/standalone/k8s): Namespace (Pod Security `restricted`), PersistentVolumeClaim (5 Gi, ReadWriteOnce), Deployment (one replica, `Recreate`), Service (ClusterIP),
and two NetworkPolicies (default deny for ingress and egress, then the service port from the same namespace and from namespaces labelled `redevops-qa/access=true`). The service needs no outbound traffic: the lanes talk to the
fixture app on the pod's own loopback. [secret.example.yaml](../../deploy/standalone/k8s/secret.example.yaml) (no value) and [ingress.example.yaml](../../deploy/standalone/k8s/ingress.example.yaml) (placeholder host) are not applied by the kustomization.

```bash
# set the version in deploy/standalone/k8s/kustomization.yaml (images: newTag), or pin a digest there, then:
kubectl apply -f deploy/standalone/k8s/namespace.yaml
kubectl -n redevops-qa create secret generic redevops-qa-token --from-literal=token="$(openssl rand -hex 32)"
kubectl apply -k deploy/standalone/k8s
kubectl -n redevops-qa rollout status deploy/redevops-qa
kubectl -n redevops-qa port-forward svc/redevops-qa 8080:80      # then use http://127.0.0.1:8080
```

The Deployment mounts the Secret as a file (`QA_SERVICE_TOKEN_FILE=/run/secrets/qa/token`, mode 0440, group 10001) instead of an environment variable. Without the Secret the pod does not start. The PVC uses the cluster's default
storage class unless you set one. Pods are not exposed outside the cluster by these manifests; for an Ingress, copy the example, replace the placeholder host and TLS secret, and label your ingress controller's namespace `redevops-qa/access=true`.
What was run: the manifests were applied to a throwaway `kind` cluster (arm64 image): the pod reached Ready under Pod Security `restricted`, the root file system was read-only with no capabilities, requests without the token got 401,
a pod in an unlabelled namespace could not reach the service and one in a labelled namespace could, and data survived a pod deletion. The lanes were run through Compose, not in the cluster.

## First run

```bash
TOKEN=...   # the value you generated
curl -s http://127.0.0.1:8080/healthz ; curl -s http://127.0.0.1:8080/readyz            # open probes
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/info                   # plans and whether each can start here
curl -s -H "Authorization: Bearer $TOKEN" -X POST -d '{"plan":"browser","defect":"none"}' http://127.0.0.1:8080/v1/runs
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/runs/<id>              # state, exit code, outcome
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8080/v1/runs/<id>/report?format=html" -o report.html   # open it in a browser
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/runs/<id>/bundle.tar -o bundle.tar
```

Plans: `demo` (the browser lane, then the Robot lane, one run), `browser`, `robot`, `robot-not-enforced`. `defect` seeds a fault into the fixture app so you can see a failing verdict: `none` ends `VERIFIED`, `discount`
fails the Robot lane, `settings` fails the browser lane (`FAILED`, exit status 1, with evidence that still verifies). A run takes seconds to about a minute. Only one run goes at a time (409 otherwise).
The outcomes are the runner's exit-status table ([packages/qa-runner/README.md](../../packages/qa-runner/README.md)): `VERIFIED`, `FAILED`, `REFUSED`, `NOT_COMPLETED`, `INCONCLUSIVE`, `EVIDENCE_REJECTED`, `RUNNER_ERROR`.
Verify a downloaded bundle anywhere the command is installed, offline: `redevops-qa verify <unpacked bundle directory>`; for example in a second container with `--network none`.
A passing verification is internal consistency of the evidence; without an external anchor it does not show the bundle was not rewritten, and it never shows the application under test is correct (the report says so).

## Authentication

There is no default credential. `redevops-qa-service` exits with status 78 and a message (never the value) unless `QA_SERVICE_TOKEN_FILE` or `QA_SERVICE_TOKEN` holds a token of at least 32 characters from
`A-Z a-z 0-9 . _ ~ + / = -`, with at least 8 distinct characters, that does not look like a placeholder. Generate one with `openssl rand -hex 32`. Everything but `/healthz` and `/readyz` answers 401 without
`Authorization: Bearer <token>`. The token is read once at start: to rotate it, change the value and recreate the container (`docker compose up -d`) or restart the Deployment. The token is not passed to the lanes. One token, no
users, no roles: anyone holding it can start runs and read every result. Put TLS in front before you expose the port beyond the host.

## Configuration reference

| Compose variable (`.env`) | Default | Service variable it sets |
|---|---|---|
| `QA_IMAGE_TAG` | none, required | the image tag |
| `QA_SERVICE_TOKEN` | none, required | `QA_SERVICE_TOKEN` |
| `QA_BIND_ADDRESS` | `127.0.0.1` | the host address the port is published on |
| `QA_PORT` | `8080` | the host port |
| `QA_RUN_TIMEOUT` | `1800` | `QA_SERVICE_RUN_TIMEOUT` (seconds, 10 to 86400; a run is killed after it) |
| `QA_IMAGE` | `ghcr.io/redevops-io/redevops-qa` | the image name |

The other service variables are set by the image and rarely need changing: `QA_SERVICE_BIND=0.0.0.0` (inside the container), `QA_SERVICE_PORT=8080`, `QA_SERVICE_DATA_DIR=/data`,
`QA_SERVICE_PLANS_DIR=/opt/redevops-qa/share/plans`, `QA_SERVICE_TOKEN_FILE` (see [packages/qa-service](../../packages/qa-service/README.md)).

## Persistence

`/data` (the volume `qa-data`, or the PVC) holds `runs/<run id>/`: `status.json`, `output.txt` and `evidence/<run id>/` (the evidence bundle: manifest, assertion lock, logs, the engines' native results, browser artefacts).
Nothing else is written outside `/tmp`. Results survive `docker compose restart`, `down` followed by `up`, and a pod deletion (all run). `docker compose down -v` deletes the volume. A run that was going when the container stopped is marked
`interrupted` at the next start. Runs are never deleted automatically: `DELETE /v1/runs/<id>` removes one.

## Backup and restore

Backup (the volume name is `<project>_qa-data`, `redevops-qa_qa-data` for the default project name):

```bash
docker run --rm -v redevops-qa_qa-data:/data:ro -v "$PWD":/backup alpine tar czf /backup/qa-data.tgz -C /data .
```

Restore into a new volume, then point Compose at it or copy it in: `docker volume create restored && docker run --rm -v restored:/data -v "$PWD":/backup:ro alpine sh -c 'tar xzf /backup/qa-data.tgz -C /data && chown -R 10001:10001 /data'`.
A restored bundle verifies with `redevops-qa verify` (run in this way, and with `--network none`, with the result `ACCEPTED`). On Kubernetes, snapshot or copy the PVC with your storage's tools.

## Upgrade

Set `QA_IMAGE_TAG` (or the `newTag` in `kustomization.yaml`) to the new version, then `docker compose pull && docker compose up -d` (or `kubectl apply -k deploy/standalone/k8s`). Data stays in the volume. There is one data layout today and no
migration step. Tags are never moved: `<version>` and `<version>-<12 characters of the source commit>` both name the same published build, and the exact source commit is in the image label
`org.opencontainers.image.revision`. To go back, set the previous tag. Before you rely on an image, verify it:

```bash
cosign verify ghcr.io/redevops-io/redevops-qa@sha256:<index digest> \
  --certificate-identity 'https://github.com/redevops-io/redevops-qa/.github/workflows/oci-release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/redevops-io/redevops-qa@sha256:<index digest> --repo redevops-io/redevops-qa
```

## Security notes

* Non-root (10001), read-only root file system, no capabilities, `no-new-privileges`, memory and process limits in Compose, resource limits and `seccompProfile: RuntimeDefault` in Kubernetes. No secret, token or internal address is in the image.
* Chromium runs without its own sandbox (the default of the product's browser driver); the container is the boundary, and the browser's traffic is forced through the product's egress gateway, which allows only the fixture app. The Robot lane's limits are the kernel layers described in `bundle/README.md`; the report states what they do not stop.
* The service is authenticated by one bearer token and speaks plain HTTP. It binds to loopback on the host and is a ClusterIP in the cluster; add TLS before exposing it.
* The base image is pinned by digest. The build applies the Debian security updates available on the build date (`apt-get upgrade`) and removes the virtual X server that Playwright's dependency installer adds.
  Vulnerability scans of each release are in its release notes; the Debian packages with no upstream fix yet are reported as they are, not hidden.
* The image does not contain `ssh-keygen`: the optional signed anchor (`anchor sign`, `verify --anchor-sig`) is not available in it. An unsigned run behaves as documented.

## Troubleshooting

| Symptom | Cause and remedy |
|---|---|
| `docker compose up` says a required variable is missing | `QA_IMAGE_TAG` or `QA_SERVICE_TOKEN` is empty in `.env`. |
| the container exits with status 78 | no usable token: read its log line; generate one with `openssl rand -hex 32`. |
| 401 on every call | the `Authorization: Bearer` header is missing or the token differs from the one the container started with. |
| 409 `busy` | a run is going; wait for it (`GET /v1/runs`). |
| 422 `plan_unavailable` | the plan cannot run here; the response and `/v1/info` carry `unavailable.code` (`ARCHITECTURE_UNSUPPORTED`, `LANE_ENGINE_MISSING`, `BROWSER_UNAVAILABLE`, `ROBOT_EGRESS_LAYERS_UNAVAILABLE`, `PLAN_FILE_MISSING`), the reason and a remedy. Nothing was started. |
| the run ends `NOT_COMPLETED` and the output says `ROBOT_EGRESS_UNAVAILABLE` | the host cannot provide the Robot lane's kernel layers (see Requirements); use `browser` or `robot-not-enforced`. |
| `Permission denied` on `/data` with a bind mount | give the directory to user 10001 (`chown 10001:10001`), or use the named volume. |
| the browser lane does not start | run `docker compose exec qa redevops-qa doctor`; each check names its remedy. |

## rAIlsApps compatibility

This change is packaging. It does not alter what rAIlsApps or any other consumer may rely on, and tests pin that ([tests/test_standalone_compat.py](../../tests/test_standalone_compat.py)): the pinned upstream releases (runtime-contracts
v0.3.15 and v0.3.16, which own the `qa/v1` schemas and golden vectors, and agent-harness v0.2.0) in `pins.toml`; the command-line commands and the exit-status table; the bundle installer, its locks and the capability and profile schemas;
the set of packages the bundle ships (the service is not in it); and that the image installs the product with the bundle's own scripts. `agentic-os` (its main line and release/0.6.0) holds no code, API path or variable that calls
`redevops-qa`; it names the product only in release and licensing records. The HTTP service is new and additive; nothing depends on it.
