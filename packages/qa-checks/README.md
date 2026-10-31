# qa-checks

Read-only checks over resources: rendered manifests, image metadata and, only inside a disposable cluster that this tool
generated, server-side dry-run and fixed probe workloads. The checks are the `executor = SCRIPT` side of a test specification:
each one is an individually hashed, versioned program that **observes** a value. It never receives an expected value and never
returns a verdict; the harness verifier compares the observation with the value frozen in the assertion.

Licence: the family licence of this repository (see `LICENSE.md`).

## What is here

| Area | Module | Notes |
|---|---|---|
| Loading | `manifests` | safe YAML and JSON loading (no aliases, no duplicate keys, no custom tags, size and depth caps), deep-frozen documents, a render helper that loads already-rendered manifests from a directory, symbolic links refused |
| Programs | `programs/*.py` | one module per program; each is pure over parsed manifests and returns plain JSON without floats |
| Registry | `registry` | `{id, version, program_hash}` lookup, hash verified before any program runs, purity lint at registration |
| Engine | `engine` | resolves `MANIFEST_PATH`, `NAMESPACE_OBJECT` and `IMAGE_DIGEST` references inside a case root and runs one program |
| Adapter | `adapter` | `CheckAdapter` (`qa-check-adapter/1`) in the harness neutral form: `open_workspace`, `resolve`, `run_check`, `capture`, `reset`, `close_workspace` |
| Command line | `cli` | `redevops-qa-checks list` and `run`; the program hash is a required argument |

The library, the adapter and the command line all go through `CheckEngine`, so a scripted executor runs exactly the same code
as the adapter.

## Programs (manifest checks)

| Id (version 1.0.0) | Observes |
|---|---|
| `manifest.image-references` | registry, repository, tag, digest, latest and untagged images, per container |
| `manifest.image-name-map` | each container image against a declared image map (reference document `ImageMap`) |
| `manifest.security-context` | effective `securityContext` per container, host namespaces, `hostPath` volumes, namespace admission labels |
| `manifest.resources` | requests and limits in millicores and bytes, per-namespace sums, `ResourceQuota` and `LimitRange`, sums beside a declared budget (`ResourceBudget`) |
| `manifest.env-and-secret-refs` | env var names and where values come from (never values), `envFrom`, secret and config volumes, matches against declared prefixes (`EnvPolicy`) |
| `manifest.gateway-routes` | Gateway listeners, route parent references, namespace selectors, allowed kinds, method and path matches, filters, backends |
| `manifest.network-policies` | default-deny shape per namespace, ingress and egress rule extraction, Cilium deny rules |
| `manifest.kyverno-policies` | Kyverno policy presence, action, rule types, matched kinds |
| `manifest.probes` | liveness, readiness and startup probe declarations and whether the probed port is declared |
| `manifest.cross-references` | selectors, service ports and referenced objects resolved inside the input |
| `manifest.structure` | identity fields, duplicate identities, kinds, files that did not load |

Image metadata programs read image documents built from files in the case root (see "Image metadata" below):

| Id (version 1.0.0) | Observes |
|---|---|
| `image.user-and-runtime` | `User` (empty, root, numeric, by name), entrypoint, command, working directory, variable names, volumes |
| `image.ports-and-health` | exposed ports and the declared health check (present, disabled) |
| `image.labels-and-base` | labels, annotations, reference names, declared base image digest and name |
| `image.layers` | layer count, sizes, media types, diff ids, config digest, platform, index children |
| `image.attestations` | SBOM and provenance presence among the files provided, and how it was found |

Every program above also has a compact projection registered as `<id>.counts` (its own hash): a gating assertion compares one
observed value with one expected value, and a small value of counts is what can be named in an assertion.

Reference documents (`apiVersion: qa-checks/reference-1`) carry declared context the program reads next to the manifests, such
as an image map or a budget. A key that looks like an expected value or a verdict (`expected`, `predicate`, `verdict` ...) in
a reference document is a load error.

## Image metadata

`image_store.ImageStore` reads, inside the case root and never over a network: OCI image layout directories (manifest, index
and configuration blobs are verified against the digest in their file name; layer blobs are not read), loose manifest, index
and configuration files, and `image inspect` output. An `IMAGE_DIGEST` reference is the manifest digest (or the index digest, or
the digest an `inspect` document reports). Two documents answering to one digest are `AMBIGUOUS`, never first-wins. Variable
values and build commands are not kept (names and counts only). There is no registry access, no daemon call and no network.

## Disposable-cluster tier (`tierk`)

No persistent write happens outside a disposable, isolated cluster that this tool generated. Inside one, only server-side
dry-run (persists nothing) and fixed probe workloads are allowed. **The real cluster lane is disabled by default and nothing in
this package starts a cluster**; every test uses a fake runner.

| Part | What it does |
|---|---|
| `guard` | accepts only a cluster this tool generated, proven locally (state directory sentinel, marker list with fixed cluster and context names per lane, the kubeconfig that was generated: exactly one cluster, context and user, embedded client certificate data only, https on loopback or a configured sandbox network) and in the cluster (a marker object carrying the nonce hash, names, lane and plan hash, and the server version the lane declares). An ambient kubeconfig, a context not on the allow-list, a non-loopback server, a missing or different marker object are all refused. `disposable_proof_ref` is the sha256 of a canonical proof record, recomputed from the live cluster. |
| `argv` | the allow-list of kubectl commands, structural and exact; secrets are not readable; no flag selects another kubeconfig, context, server, user or proxy; only the probe rules persist anything and only in `qa-probe-` namespaces |
| `runner` | `KubectlRunner` protocol; the real runner needs the real lane enabled, a valid disposable-host acknowledgement for this host, an absolute kubectl path and the guard's local result; it runs with an empty environment and a timeout |
| `GuardedSession` | the only handle drivers get: every command is checked against the allow-list, the marker object is re-read before each one, the number of commands is bounded |
| `plan` | the bring-up plan as data: components, digests, charts, CRD bundles, tool checksums, apply order, nine readiness gates, determinism requirements, two node lanes; Helm values and kind configurations under `tierk/data/` are hashed into it |
| `drivers`, `collectors` | server-side dry-run per object, rejection classification (webhook policy, Pod Security, quota, limit range, schema, unknown kind), Gateway, route, policy and quota status |
| `gate`, `lanes` | the adapter's route into the cluster; per-lane result sets that are never merged (no pooled count, no attribution of a lane difference) |
| `not_expressible` | properties the disposable cluster cannot show (closed-world completeness, signature admission, metadata-endpoint traffic proof, certificate issuance, secret sync, background scans, name-based unreachable probes, volume write semantics) are refused with `UnsupportedOperation`, never answered with a pass |

Tier K programs (`cluster.dry-run`, `cluster.admission`, `cluster.gateway-status`, `cluster.policy-status`, each with `.counts`)
are registered like any other program; their hash also covers the allow-list, the drivers and the collectors. A tier K subject
must name a tier K program and an offline subject must not.

## Connectivity (`tierk.connectivity`, `tierk.probes`, `tierk.subnets`, `standin`)

A check declares its probes in a reference document (`kind: ConnectivityMatrix`): a source namespace and workload labels, a target
(an IP literal, or a workload whose pod IP is read from the cluster and then used as a literal), a TCP port, an optional control
namespace, a range class. Names are never probed; targets must be inside the cluster's pod and service networks or the synthetic
plan; metadata-address traffic and UDP are refused as not expressible; the count and the timeout are bounded.

| Program | Evidence | What it does |
|---|---|---|
| `connectivity.traffic` | traffic | creates one fixed probe pod per probe (and per control), reads its one JSON line, deletes it; rows set the probe result beside the control result |
| `connectivity.policy-state` | policy-state | reads Kubernetes and Cilium network policy objects, reports which select each source and match each target; sends nothing |

* The probe pod is one constant specification (`probes.probe_pod`): the stand-in base image by digest (never pulled, never
  pushed), a constant command that makes one TCP connection to an IP literal, a restricted security context, small resources and
  a deadline. `ProbePolicy` accepts a manifest only if it equals what `probe_pod` builds for the values it carries.
* The synthetic subnet plan uses two documentation ranges (never routed): one for a "world" container and one standing in for a
  local-network range. It is data, validated against private, loopback, link-local, carrier-grade and cluster ranges; `check_free`
  refuses it if the host already has an overlapping network. Policy-state checks on the real local-network range come first and
  are reported as policy-state; traffic against the synthetic range is reported as traffic, never as proof about the real range.
* `standin.server` is a minimal stdlib server: a configured port, a configured health path, and an echo of method, path and
  headers for everything else. `standin.builder` turns `{name, tag, port, health_path}` entries into deterministic build contexts
  (a Dockerfile on the pinned base digest, the server, a config file) with a context hash; it has no build, registry or network
  code, so nothing can be pushed.

## What a program hash covers

`program_hash` is the sha256 of a source bundle: a header naming the program id, version and entry point, the program module,
each support file it declares, and the loader, serialisation and input modules every program depends on. Changing any of them
changes the hash of every program that includes it. Line endings are normalised before hashing.

## Rules the code keeps

* A check takes parsed data only. There is no parameter for an expected value; a subject or reference document that carries
  one is refused, and a result with a verdict-shaped key is refused.
* The program reference is verified before any input is read: an unregistered program and a hash that differs from the
  registered one are refused.
* The case workspace is read-only. Symbolic links, absolute paths and `..` are refused. The only write is evidence appended
  through the injected `Redactor` and `BlobSink`.
* A subject that does not resolve is reported as `UNRESOLVED` or `AMBIGUOUS` with no value. An observed value larger than the
  observed-value bound is a `ResourceLimitExceeded`, never a truncation.
* Offline checks need no network, no daemon and no cluster. Nothing here talks to a registry.

## Tests

The package tests run with the repository's test configuration (scrubbed environment, pinned harness tree from `pins.toml`).
They include a passing and a known-bad fixture per check class, determinism across hash seeds, a read-only filesystem audit,
secret-shape and wording scans (patterns assembled at run time), and mutation tests that remove each guard and require the
suite to fail.
