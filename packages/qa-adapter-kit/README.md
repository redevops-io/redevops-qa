# qa-adapter-kit

Product-local protocol, typed models and a shared process supervisor for the optional ReDevOps QA execution adapters (Selenium,
Robot Framework, Appium). Standard library only: it imports no framework, no harness module and no contracts package, and it is not
part of the frozen qa/v1 surface. Adapter manifests defined here are product-local.

Licence: the family licence of this repository (source-available; see `LICENSE.md`). Frameworks are optional, separately installed
and listed in `third_party/adapter-license-matrix.yaml`.

## Two adapter classes

| Class | What it does | What it never does |
|---|---|---|
| `suite` | Starts an existing test suite as one supervised process and imports the framework's native report afterwards (`SuiteAdapter.build_command`, `import_report`). | Steer a test while it runs. A suite manifest that declares `steer`, `click`, `navigate`, `inject`, `pause` or any other action capability is refused. |
| `interactive` | Performs one bounded action at a time and returns an observation (`InteractiveAdapter.perform`). The runner owns the step, retry and deadline budgets. | Run without a step limit, a retry limit and a deadline. |

## Models

`AdapterManifest`, `SuiteRunRequest`, `InteractiveActionRequest`, `AdapterResult`, `NativeAssertion` and `EvidenceArtifact` (plus
`Limits`, `FrameworkRef`, `PinnedFile`, `InteractiveObservation`). Each is immutable, validates on construction, rejects unknown
fields in `from_dict` and round-trips through `to_dict`. A serialised request never contains a secret value. An `AdapterResult` has
`authority = "native"`; it cannot be `UNVERIFIED` and it cannot be `ERROR` without an `error_code`.

Statuses: `PASS`, `FAIL`, `ERROR`, `SKIP`, `UNKNOWN`, `UNVERIFIED`. A framework can report the first five; `UNVERIFIED` is assigned
only by the mapping step.

## Native PASS is not an oracle PASS

`map_to_canonical(result, required_assertions, mapping)` returns one `CanonicalEvidence` per required assertion. A native test counts as
evidence for an assertion only when the request maps it explicitly **and** the test itself declares the same assertion id. A required
assertion with no such mapping is `UNVERIFIED`, whatever the suite reported. Even mapped evidence leaves `canonical_status(...)` at
`UNVERIFIED` until an independent verifier supplies an `OracleVerdict` that cites the digest of that exact evidence; an adapter cannot
verify its own result. Evidence cannot be constructed with an oracle status.

## Supervisor

| Control | Behaviour |
|---|---|
| Deadline, output limit, cancellation | Each ends the whole process group (terminate, a grace period, kill). A group member that outlives the leader is killed too. Output is cut at the per-stream limit. |
| Limits | A request may ask for less than its manifest allows, never more (`Limits.clamp`). |
| Retries | Only a run that failed to start is retried, up to the limit and inside the same deadline. A failing run and a timeout are never retried. |
| Executable allowlist | `argv[0]` must be an absolute path listed in the manifest (compared after symlink resolution). No shell. |
| Path allowlist | Workspace, suite, output directory and every artifact are resolved through symlinks and must lie inside the allowed roots; credential directories, `/etc`, `/proc`, `/run` and container sockets are refused even inside a root. |
| Environment | Built from nothing. Only names the manifest allows pass; credential-like, cloud, code-hosting, container and loader variables are refused. A secret goes through `secret_env` and only if the manifest names it. |
| Secret redaction | Known secret values and credential-shaped assignments are redacted from output tails, messages and observations. A text artifact that contains a secret value is refused as evidence. |
| Docker | No container engine as an executable and no container socket as an argument. |
| Sealed runs | The pinned files in the manifest are hashed first; installers and downloaders (`pip`, `npm`, `curl`, `git`, `python -m pip`, ...) cannot start; an adapter that declares `downloads` is refused. |

Not enforced here: network isolation (`AdapterManifest.network` is a declaration for the worker) and confinement of file writes by
the started process. POSIX only (process groups). An interactive action is bounded by a worker thread and its deadline: a timed-out
action cannot be pre-empted, so the adapter is asked to `abort()` and the session is closed.

## Fakes and tests

`qa_adapter_kit.testing` has a fake suite adapter (it runs `fake_child.py` scenarios and imports the JSON report) and a fake
interactive adapter. They produce every status, a cancel, a timeout, a malformed result, a missing artifact, a prohibited path and a
secret leak on demand, offline, with no framework installed. Run `python -m pytest packages/qa-adapter-kit/tests` from the repository
root. Secret-looking test values are generated at run time.
