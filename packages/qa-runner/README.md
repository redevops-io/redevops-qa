# qa-runner

The `redevops-qa` command: it checks a machine (`doctor`), freezes a test plan (`freeze`), runs a frozen plan against the fixture app and writes an evidence bundle (`run`),
re-verifies a finished run from its bundle alone (`verify`), reports and inspects a bundle (`report`, `inspect`) and does all of that in one step for the built-in two-lane plan (`demo`).
A plan holds a Playwright Chromium lane (`examples/golden-plan.json`), a Robot Framework lane (`examples/robot-plan.json`) or both, run one after the other
(`examples/demo-plan.json`).

Licence: the family licence of this repository (source-available, not open source; see `LICENSE.md`). Standard library and the repository's own packages
only (plus the OpenSSH client `ssh-keygen`, called only for the optional signed anchor); the two pinned upstreams (`runtime-contracts`, `agent-harness`) are found through `pins.toml`, as the bridge does it, and are neither installed nor
copied.

Scope of this release line: Linux x86_64, Playwright Chromium and Robot Framework. macOS runs are development evidence only (`doctor` says so). Selenium and
Appium are not part of this workflow. Nothing here has been run on any other platform.

Installing: from a checkout, as the tests and the CI jobs do (the `src` directories on `PYTHONPATH`, the pinned trees fetched into `.pinned`); or from the pinned bundle (`bundle/README.md`,
built by `tools/build_bundle.py`): a wheelhouse with a hash for every wheel, installed with `pip install --no-index --find-links wheelhouse --require-hashes -r requirements.lock` into a new
directory, for CPython 3.12 on Linux x86_64 only. A bundle install keeps `pins.toml` and the pinned trees under `<prefix>/share/redevops-qa/` and the pin check runs against those copies
(`REDEVOPS_QA_PINS` still overrides; a checkout above the environment is not used instead). Chromium is downloaded by the bundle's separate browser step and checked against `browser.lock.json` (`qa_runner.browser_pin`): in a bundle installation `doctor` and `run` compare the installed Chromium tree with the pin, and a browser lane is not started against a tree that differs or against an installation whose pin is missing. In a source checkout there is no pin: `doctor` says so (`WARN`) and no browser check is made.

## The public CI demo

Every push to this repository runs `redevops-qa demo` three times (the `demo` jobs of `tests.yml`), from the bundle that the `bundle` job built, installed with the commands of its README on a
clean `ubuntu-24.04` runner: `--defect none` must end `VERIFIED` (exit 0), `--defect discount` must fail in the Robot Framework lane (exit 1) and `--defect settings` in the Playwright Chromium lane (exit 1);
`tools/check_demo_outcome.py` checks the outcome, the lane that failed, that every other assertion was verified and the printed manifest digest. Each evidence bundle is kept as a workflow artifact
(`demo-evidence-<defect>`) and its anchor, the sha256 of its `bundle-manifest.json`, is printed in the job log and kept beside it (`demo-anchor-<defect>`). A second job (`demo-verify`) starts from nothing but
those artifacts, installs the bundle into a new directory and runs `redevops-qa verify --anchor ... --plan-digest ... --require-anchor --require-plan-digest`; the same command on a copy with one byte added,
and with a wrong anchor, must exit 5. The anchor is recorded where the demo job's own machine cannot change it after the fact (the workflow log and artifact of a finished run); nothing in the bundle
authenticates it, and a match shows only that the bundle is the one the value was taken from.

## Commands

```text
redevops-qa doctor [--plan PLAN] [--json]
redevops-qa freeze PLAN --out LOCK
redevops-qa run PLAN_OR_LOCK --out DIR [--defect none|discount|settings] [--run-id ID] [--lane-deadline SECONDS]
redevops-qa verify BUNDLE [--anchor sha256:HEX] [--plan-digest sha256:HEX] [--require-anchor] [--require-plan-digest] [--json]
                          [--anchor-sig FILE --anchor-pub FILE] [--require-signed-anchor]
redevops-qa demo [--out DIR] [--defect none|discount|settings] [--run-id ID] [--lane-deadline SECONDS]
redevops-qa report BUNDLE [--format text|json|html] [-o FILE] [--anchor sha256:HEX] [--plan-digest sha256:HEX] [--anchor-sig FILE --anchor-pub FILE] [--require-signed-anchor]
redevops-qa inspect BUNDLE [--anchor sha256:HEX] [--plan-digest sha256:HEX] [--anchor-sig FILE --anchor-pub FILE] [--require-signed-anchor]
redevops-qa anchor statement BUNDLE
redevops-qa anchor sign BUNDLE --key PATH [--agent] [--out FILE]
```

On a host where the Robot lane's kernel layers cannot be provided (macOS, Windows, a kernel without Landlock network rules, an emulated `amd64` container) `demo` and any plan whose Robot lane says `origin-only` are refused before anything starts; `redevops-qa doctor` names the reason, and `examples/robot-plan-not-enforced.json` is the Robot plan for such hosts (no limit on that lane's traffic; the report says so). Nothing falls back to it by itself.

`python -m qa_runner ...` is the same command from a checkout (`PYTHONPATH` set to the `src` directories of the packages; the tests and the CI job show how).

**`doctor`** reports Python, platform, the temporary directory, the pinned dependencies (commits, tree digests and vector files against `pins.toml`),
Playwright 1.64.1 and a real headless Chromium launch, Robot Framework 7.5, the kernel layers of the Robot lane (measured in a throwaway process), the fixture app and the egress gateway. Each check is `OK`, `WARN` (works, outside
what this release claims: any platform but Linux x86_64) or `FAIL`, with the command that fixes it. It never installs, downloads or changes anything. A
protection that cannot be provided is a `FAIL`: the egress gateway that every browser lane depends on must start, the browser launch configuration must be available, and it must be complete and closed
(`qa_runner.egress.launch_config_problems`: only the arguments `qa-egress` itself produces, none twice; the explicit proxy, Chromium's implicit loopback bypass removed, no name resolution in the browser, no QUIC, no WebRTC traffic outside the proxy). The
browser lane applies the same check before it starts a browser. The `robot egress layers` check installs the layers around a synthetic allow-list in a child process and tries what must pass and what must be refused; it fails where they cannot be provided (and `run` and `demo` then refuse a plan whose Robot lane says `origin-only` before anything starts), and it is not needed by a plan whose Robot lane says `not-enforced`. Exit status 0, or 3 if a check failed.

**`freeze`** validates a plan (the strict runtime-contracts parser first, then the harness mirror; unknown fields refused at every level), computes every assertion's digest, the
assertion lock and the plan digest, and writes the lock (`redevops-qa/plan-lock` 1.0: the plan, the digests, the pins, the suite file hashes). A lock is never overwritten. The plan
digest it prints is what `verify --plan-digest` will compare a bundle with; record it where whoever runs the plan cannot rewrite it (without it a removed assertion would not be
noticed). `run` accepts a plan (frozen on the spot, with a note on standard error) or a lock; a lock is re-frozen from the plan it carries and refused if any digest, pin, tool version,
suite hash or expected value differs.

The summary `run` prints says in its second line that integrity against deliberate re-forging is NOT established (no external anchor).

**`demo`** is `freeze` and `run` on the built-in plan (browser lane, then Robot lane, one target, one run id) followed by the full report. It prints no plan digest comparison: a digest
computed by the process that ran the plan would only match itself.

**`report`** and **`inspect`** read a bundle (directory or archive) through ONE snapshot taken by a killable child process (`isolated.snapshot_bundle`; `REDEVOPS_QA_BUNDLE_READ_TIMEOUT`, default 120 s; a
cancel ends with exit 3) and run `verify` over that same snapshot. For a bundle that `verify` accepts, what they print starts with the result of the recomputation (the first line of `report`, the second
of `inspect`, a banner of the HTML, `recomputation` and `verdicts_recomputed` in the JSON). For a bundle that `verify` rejects they exit 5 and show NOTHING of what the bundle says: no "Verification: OK", no
outcome, no summary; the JSON carries `content_trusted: false`, `verification: {ok: false}` and the findings. 2 if the location cannot be opened. Every string that came from the bundle is escaped. `report`
renders text, JSON or one HTML file with no script and a content-security policy; `inspect` lists the files with roles and digests, the tool versions, the lanes and the heads of the chains inside each
harness run record.

**`verify`** re-verifies a finished run from its bundle alone, offline, in a process of its own (see "What verification does and does not prove" below). Exit status: for an accepted bundle
the same table as `run` (0 VERIFIED, 1 FAILED, 3 a lane did not complete, 4 inconclusive); **5 when any finding rejects the evidence**; 2 when the bundle cannot be opened; 7 when the verifier itself cannot run here. `run` and
`demo` end by calling `verify` in a separate interpreter (fresh environment, no state shared) and exit 5 if it does not accept what they just wrote. That second pass is a RE-verification in a fresh process by the SAME code the run uses (`judge_lane`, `finalize_results`, the `native_from_*` functions are shared): it catches what was written wrongly or changed on the way to disk, it is not an independent implementation of the verdicts. The word "independent" in this package means independent of the ENGINE's own status and, for the probes, of the engines' code (the reference check), nothing more.

**`anchor`** and the signature options of `verify`, `report` and `inspect` are an OPTIONAL signed anchor. A run that is not signed behaves and reads exactly as before (the text of `verify` for an
unsigned bundle is unchanged; the JSON gains one key, `anchor_signature`, with state `absent`). What the signed anchor is:

* `anchor statement BUNDLE` verifies the bundle and prints the statement to be signed: canonical JSON of the run id, the manifest digest (the sha256 of `bundle-manifest.json`) and the plan digest, schema
  `redevops-qa/anchor-statement` 1.0. It refuses (exit 5) a bundle that does not verify. The statement can be taken to another machine: `ssh-keygen -Y sign -n redevops-qa-anchor@v1 -f <private key> FILE`
  writes `FILE.sig` (an OpenSSH SSHSIG signature in the namespace `redevops-qa-anchor@v1`).
* `anchor sign BUNDLE --key PATH [--agent] [--out FILE]` does the same in one step by calling `ssh-keygen -Y sign` (with `--agent`, `--key` names the PUBLIC key file and the ssh-agent named by `SSH_AUTH_SOCK`
  signs, and only the key named by `--key` signs). Without `--agent` no ssh-agent is used: `SSH_AUTH_SOCK` and `SSH_AGENT_PID` are removed from the environment of `ssh-keygen`. `anchor sign` keeps the operator's own environment otherwise, `SSH_ASKPASS` and the terminal included, so that a passphrase can be asked for; `verify` runs `ssh-keygen` with a fixed environment and ignores `SSH_ASKPASS`. The signature is written outside the bundle
  (default `<bundle path>.anchor.sig`, never overwritten, created before `ssh-keygen` is started so that an unusable location fails before a passphrase or a touch is asked for, and removed again if signing fails) and printed. For a
  bundle `DIR/r0-<id>` the default signature is a sibling `DIR/r0-<id>.anchor.sig` inside the evidence directory: a script that globs `DIR/r0-*` after signing would match it too (give `--out` to put it elsewhere). A signature by any key type but `ssh-ed25519` is refused and nothing is written.
  **Keys are the operator's: this package never generates, stores or reads a private key.** The path is handed to `ssh-keygen` as an argument and nothing else (a test watches every `open` of the process and
  signs with a key file that nothing but the agent can read). `run` and `demo` do not sign and take no key option; a host that runs lanes should not hold the signing key.
* `verify BUNDLE --anchor-sig FILE --anchor-pub FILE [--require-signed-anchor]` rebuilds the statement from the bundle it has just read (the manifest digest it recomputed, the run id and the plan digest of its
  report), writes a one-line `allowed_signers` file for ONE public key (a single `ssh-ed25519` line, no options, no certificate) that you supply and calls `ssh-keygen -Y verify` with the fixed namespace. A key
  that travels with the bundle or beside the signature is never consulted; `--anchor-sig` without `--anchor-pub` is a usage error (exit 2). The state is in the `anchor_signature` block of the JSON:
  `verified` (the assurance becomes `signed-anchor-verified`, the key fingerprint is printed), `invalid` (a signature file that was named and is missing, damaged, in another namespace, by another key type or
  another key, or over another statement: finding `ANCHOR_SIGNATURE_INVALID`, exit 5, with or without `--require-signed-anchor`), `unavailable` (`ssh-keygen` is missing, older than OpenSSH 8.0 (no `-Y`), does
  not answer within 20 seconds or does not answer as a verifier: finding `ANCHOR_SIGNATURE_UNAVAILABLE`, exit 7, never accepted) or `absent` (nothing was supplied; with `--require-signed-anchor` it is the finding
  `ANCHOR_SIGNATURE_REQUIRED`, exit 5, so an unsigned or stripped run cannot be accepted where a signature is demanded). `--anchor` alone never gives `signed-anchor-verified`.
  `ssh-keygen` runs with a fixed `PATH` (`/usr/bin:/bin`: a host that has it elsewhere gets exit 7), a temporary `HOME` and no ssh-agent; only its exit status and one expected line of its output count. The check trusts the OpenSSH client of the
  host it runs on: a host whose `ssh-keygen` has been replaced can make it say anything, which is not detectable here. Needs OpenSSH 8.0 or later.

When the state is `verified` the text says: "The manifest digest of this evidence bundle (run `<run id>`, plan digest `<plan digest>`) carries a valid OpenSSH Ed25519 signature made with the private key belonging
to the public key with fingerprint `<fingerprint>`, which was supplied to this verification. A bundle rewritten after signing would not verify. This does not show who holds that key, that the key was not exposed, when
the signature was made, that the run was executed on an uncompromised host, or that the application under test is correct." A signature is only as trustworthy as the channel through which you obtained the public key.
The existing limits stay: the hash chain inside a bundle is unkeyed, a signature carries no time (an old signed bundle can be presented as the latest run), there is no revocation or key rotation (one public key per
verification), and a bundle forged before it was signed carries a valid signature. FIDO (`sk-`) keys and other key types are not accepted by this release. The tests in `tests/test_qr_anchor_sig.py` rewrite and re-chain a
whole bundle after it was signed (the dropped lane, the weakened assertion, the engine's files rewritten to say the rule held): plain `verify` accepts each of them, `--anchor` with the digest of the rewrite accepts it, and the
signature check refuses it with exit 5; the signing keys of those tests are throwaway keys generated into the test's temporary directory. The public CI demo is not signed (no key is held there); its `demo-verify` job
only checks that `--require-signed-anchor` refuses the unsigned demo bundle with `ANCHOR_SIGNATURE_REQUIRED`, which authenticates nothing.

**External target (P2-1, v1).** A plan whose `target` is `{"kind": "external-origin", "origin": "http://127.0.0.1:<port>", "declared_by": "operator", "credential_refs": [], "mutating": false}` (see `examples/edge-sentinel-fixture-plan.json`) is run
against an Edge Sentinel started with `EDGE_SENTINEL_DEMO=1`: before any lane the runner reads the target's `/health` and refuses (`NOT_FIXTURE_MODE`, exit status 3, nothing written) unless it reports `demo.enabled=true`; no fixture app is started; the
Playwright lane goes through the egress gateway whose allow-list is exactly that origin (the origin IS the egress scope); every assertion's probe is `ui-only` (there is no reference check) and the evidence of the target having been reached is the
gateway's own record; the report carries `verification_ceiling: CORROBORATED`, the run level is `CORROBORATED` (reason `ALL_ASSERTIONS_CORROBORATED`, exit status 8) and the bundle states that nothing independent backs it. `redevops-qa estimate PLAN` prints,
without contacting anything, what a plan would do and every reason a run would refuse. `verify` refuses a bundle whose ceiling is not the one its plan's target gives (`CEILING_MISMATCH`).

**`run`** freezes the plan (or reads a lock), starts the fixture app on loopback with the defect you name, runs each lane as a supervised child process, stops
the app, and writes the bundle to `DIR/<run id>` (a directory that must not exist; it is reserved before anything runs and the bundle is renamed into place, so a reader sees no bundle or a whole one). It prints the outcome, what each engine reported, what the independent
verdicts are, the plan digest (the value to give `verify --plan-digest`) and the manifest digest (the value an external anchor should hold).

| Exit | Meaning |
|---|---|
| 0 | the run is `VERIFIED`: every lane `NATIVE_PASS` and every frozen assertion verified |
| 1 | at least one frozen assertion `FAILED` |
| 2 | the plan, the lock or an option was refused before anything ran |
| 3 | a lane did not run to completion (error, timeout, cancelled, unavailable), or the environment cannot provide what the run needs |
| 4 | inconclusive: every lane completed but not every assertion is verified, or an engine and the verifier disagree (`NATIVE_FAIL_VERIFIED_ASSERTIONS`) |
| 5 | `verify` rejected the evidence (any finding), including the verification a run does of its own bundle |
| 6 | an internal error of the runner (a crash is never reported as a product failure) |
| 7 | `verify` only: the verifier itself cannot run here (a pinned dependency or git is missing, or, when a signature was supplied, the OpenSSH client `ssh-keygen`); nothing was verified, which says nothing about the bundle (the JSON is still printed, with `assurance: not-verified`) |
| 8 | the run is `CORROBORATED`: an external-target run whose every lane passed and whose every assertion is verified by the engines' record, capped because nothing independent backs it (the fixture app is the only target that can print `VERIFIED`) |

## The plan

A plan (`redevops-qa/plan` 1.0, see `examples/`) names lanes; a lane carries a runtime-contracts `qa/v1` `TestSpec` whose assertions hold the
expected values. Freezing:

* refuses a plan or lane field it does not know, and a spec field the **runtime-contracts parser** does not know. The parser runs before the harness
  mirror because the mirror tolerates unknown spec fields and they change the spec hash (`tests/test_qr_plan.py` shows both);
* gives every assertion a digest (sha256 of its canonical JSON, expected value included) together with a binding to everything else that defines the lane: the
  whole spec (steps included), the egress profile, the deadline, the request expectations and probes below, the plan id and the target. The assertion lock and
  the plan digest follow the conventions of `qa-evidence`, so the plan digest covers all of it, and the contracts and the harness must agree on the assertion-set pin;
* needs, per lane, the `requests` the target must have seen (`required`) and may see (`allowed`) as `METHOD /path` strings, and names, for EVERY assertion, a probe: a fact of the independent reference
  check (`settings-persistence`, `discount-rule`) that must not contradict a verified verdict, or `ui-only` (the assertion is about what the browser shows; nothing independent backs it). A lane with an
  assertion that names no probe is refused at freeze, so a plan cannot reach VERIFIED on a fixture-app assertion nobody said anything about; the assertions declared `ui-only` are listed in the report
  (`extensions.no_independent_probe`) and in the summary `run` prints;
* refuses an assertion id that appears in two lanes (every assertion is accounted exactly once).

A step value may start with `{origin}`; the origin of this start of the target is substituted when the lane runs, so one frozen plan serves every start of
the app (a different port each time).

## The Robot lane

A Robot lane names a reviewed suite shipped with this package (`"suite": "order-discount"`: `src/qa_runner/robot_suite/order_discount.robot` and the library `OrderApi.py`).
The plan PINS the sha256 of each suite file (`"suite_sha256"`, the digests of `examples/robot-plan.json`, which a reviewer reads as a diff) and the registered check program; freezing
refuses a plan whose pins are not the files this runner ships (`SUITE_MISMATCH`, before anything runs) and the pins are part of the plan digest. The run copies the files into a fresh workspace, requires the copies to hash as frozen, and
gives the Robot adapter the library's hash as the only reviewed library (the adapter refuses any other library file, any library not on its allowlist and any construct that
loads code at run time). The suite runs under the kit supervisor with `QA_BASE_URL` as the only variable it is given.

* **Robot records, the verifier judges.** The suite reads the order totals from the target's API and records them as `qa-observe:<name>=<value>` tags; its own
  `Should Be Equal` lines are the engine's native check. The runner keeps the raw `output.xml` as a native artifact and derives the observation record from it
  (`qa_robot.parse_observations`). The frozen assertion (`executor = SCRIPT`, `EQUALS`) holds the expected values and pins the hash of the check program
  `evidence.robot-observations`; the harness `DeterministicVerifier` runs that program (through the `qa-checks` adapter, over a case root that holds the record and nothing else)
  and compares its observation with the frozen value. The program is never given the expected value and the record carries none.
* **Native result and verdict stay apart.** `NATIVE_PASS`/`NATIVE_FAIL` is what Robot said; the verdict is the comparison. A native PASS with a record that does not satisfy the
  frozen assertion is not VERIFIED; a native FAIL whose record satisfies it is INCONCLUSIVE (`NATIVE_FAIL_VERIFIED_ASSERTIONS`).
* **The record must be what the importer derives from the engine's own report that is in the bundle** (same run id, same lane, same digest of `output.xml`, canonical bytes): a
  hand-written record, one from another run or one that does not belong to the report next to it is unusable evidence (`EVIDENCE_UNUSABLE`).
* **A Robot lane's egress is limited by kernel layers, or by nothing, and the plan says which.** `"egress": "origin-only"` asks for the layers of the section Egress below (the same one-origin
  allow-list as the browser lane's); the lane does not start if they cannot be installed. `"egress": "not-enforced"` asks for nothing: a Robot library then opens its own sockets, the lane's
  egress profile says so and so does the report (the limitation `egress-not-enforced-robot`). A browser lane must use `origin-only`.
* **Same supervision as the browser lane:** the Robot lane runs in a child process too (the same deadline, cancel, process-group kill, and a parent-death watchdog), and the engine runs
  under its own supervisor inside it.
* **A suite that records a value it did not observe is caught outside the record.** Three things hold it: the pinned hashes of the suite and library (above); the target's own request
  log for the lane (`lanes/robot/target-requests.jsonl`), which must show `GET /api/orders/101` to `104` and nothing the plan does not allow, or the lane's assertions are `INCONCLUSIVE`
  (`EVIDENCE_UNUSABLE`); and the independent reference check of the target, which vetoes a verified verdict when it finds the discount rule deviating (or is missing).
* **The engine's files must hold together.** `robot-summary.json` and `adapter-result.json` must name the `output.xml` of the bundle by hash, agree on every test's status, belong to this run,
  and the suite files in the bundle must be the pinned ones; otherwise the lane's assertions are `INCONCLUSIVE`.
* **The engine itself also runs under a guard** (`robot_guard.py`, started instead of `-m robot`): when the lane child is killed the guard ends the engine and everything it started. The temporary
  directory of a killed run stays: nothing is left alive to remove it.
* **`output.xml` names the temporary workspace** (Robot writes the absolute path of the suite into the report's `source` attribute), so the bundle shows the path of the temporary directory of the
  machine that ran it. Set `TMPDIR` to a neutral location when that matters. The report is kept as the engine wrote it; it is not rewritten.

## What a run does

1. The fixture app starts as a child process (`--shutdown-on-stdin-eof`, its own process group) and is stopped in a `finally` block. One target serves every lane.
2. Lanes run one after the other, in plan order, under one run id (lane run ids are `<run id>.<lane id>`). A lane that fails, times out or crashes does not stop the next one: its
   result is recorded and the next lane still runs, so a run always accounts for every frozen assertion of every lane exactly once. After a cancel the remaining lanes are
   recorded as `NATIVE_SKIPPED`.
3. Each lane runs as a child process under the kit supervisor: a deadline, an output limit and cancellation end the whole process group, the browser (or the Robot process)
   included. SIGINT and SIGTERM to `redevops-qa` cancel the run: the lane is ended, the remaining lanes are skipped, the target is stopped, a bundle with outcome `INCONCLUSIVE` is
   still written and the exit status is 3. If the orchestrator is killed without warning (SIGKILL), each lane child notices that its parent is gone within a fraction of a second
   and ends its own process group (and, for the Robot lane, the engine it started); the target ends when its standard input closes. The end-to-end tests check, with a process
   table, that no process survives a cancel and a SIGKILL of the parent, and fail when the watchdog is removed. The environment of a child is built from nothing (fixed `PATH` and `HOME`; the import path, the pins and the browser location are passed
   explicitly; no other variable of the parent).
4. The browser lane wires the harness executor (`QARunner`) to the real `PlaywrightAdapter` over real Chromium, with the egress gateway in front of the
   browser and the adapter's request gate behind it, an action policy that allows only the plan's origin, and attestations answered from facts (the
   target's `/health`; declared preconditions or fixtures that nothing can attest are *unknown*, which blocks a pass).
5. Everything the lane wrote is collected as native artifacts. The observed values the harness verifier read are recorded in an observation file.
6. The verdicts are computed by `judge_lane` over the observation file and the frozen assertions, using the harness `DeterministicVerifier`. Before a value
   counts, what the lane claims is checked against what the run itself recorded (`corroborate.py`): the harness run record passes the harness integrity check, is sealed
   and not cancelled, belongs to this run, names the frozen assertion set and the frozen spec, and agrees with every observation; the target's own request
   log for the lane shows the required requests and none the plan does not allow; and an assertion tied to a probe is not verified when the independent reference
   check (run against the target after the lanes) finds that fact deviating, or when there is no reference check. Anything that does not hold leaves the lane's
   assertions `INCONCLUSIVE` (`EVIDENCE_UNUSABLE`). The in-run verifier's verdicts are a cross-check: a disagreement certifies nothing.
   One rule for incomplete evidence (`bundle.finalize_results`, used by the builder here and by `verify` in the next part): when the evidence budget kept ANYTHING out, a run-level file included (the
   target's own request log belongs to no lane), the report says `extensions.evidence_incomplete` and every VERIFIED assertion becomes `INCONCLUSIVE` with the reason `EVIDENCE_INCOMPLETE`; the run is
   never VERIFIED and exits 3. A FAILED assertion rests on evidence that was kept and stays.
   A lane produced by a test double (`RunOptions.lane_command`, used by tests only) carries only `INCONCLUSIVE` with the reason `TEST_DOUBLE` and the report says so
   (`extensions.test_double`).
7. The bundle is built by a pure function (`bundle.build_run_bundle`, no clock, no environment, no file system) with `qa-evidence`, which checks its own output.

Every lane and every frozen assertion is accounted for whatever happens. A lane that cannot start, times out, is cancelled or crashes is recorded with a
native status that says so; its assertions are `INCONCLUSIVE`; the run is never `VERIFIED`. The engine's own status (`lanes[].native`) and the verdict
(`accounting.results[].verdict`) are separate fields with disjoint vocabularies. For the browser lane the native status is the harness executor's outcome
(`PASS` becomes `NATIVE_PASS`, `PRODUCT_FAIL` becomes `NATIVE_FAIL`, anything else `NATIVE_ERROR` or `NATIVE_TIMEOUT`); it is never converted into a verdict.

## Egress

* **Browser lane: the gateway is the browser's only way out.** The lane starts the egress gateway, builds the launch configuration for it and checks the configuration (`launch_config_problems`) before it
  starts Chromium. If the gateway cannot start, the launch configuration is unavailable or incomplete, or the gateway is lost before the lane ends (`GatewayLost`: the gateway no longer answers),
  the lane fails closed: no verdict, the lane's native status is an engine error, the run is INCONCLUSIVE (exit status 3). A browser is never started with a way around the gateway as a fallback.
* **Robot lane: kernel layers, not the gateway.** A Robot library is arbitrary Python (it can load native code, start processes, call system calls itself), so an allow-list inside the interpreter would
  not hold and none is used. The lane child installs two layers on itself BEFORE it starts the engine (`qa_runner.netfence`; `prctl`, `seccomp` and the Landlock calls through `ctypes`: no helper
  program, no privilege), and everything the engine starts inherits them: (1) a seccomp filter with a supervising thread of the lane child lets `connect` through only to the plan's allow-list (one
  loopback address and port; anything else is refused with `EACCES` and recorded), allows only TCP over IPv4 and local stream sockets as socket kinds (UDP, raw, packet, netlink, IPv6, SCTP, MPTCP and
  the rest are refused), refuses `listen` (nothing in the lane accepts an inbound connection), `connect` to a local socket path and TCP Fast Open (measured below) and, not measured by an experiment of their own,
  `sendto` with an address (UDP and datagram sockets are already refused at creation), `io_uring` setup, `ptrace`, `process_vm_*` and `pidfd_getfd` (a container's own filter may refuse some of them first);
  (2) Landlock limits TCP `connect` to the allowed port, in the kernel, after the supervisor's decision, and refuses every TCP `bind` (the implicit bind of a `connect` is not a `bind` call and works).
  The lane child also marks itself not dumpable (`PR_SET_DUMPABLE`) and a subreaper: see "The record and the supervisor" below. The layers are installed with `PR_SET_NO_NEW_PRIVS`, cannot be removed by the
  process that carries them, and are followed by a self-test (a listener that is not allowed must refuse this very thread, a UDP socket must be refused). If either layer is unavailable or the self-test
  fails, the engine is not started (`NATIVE_UNAVAILABLE`, `egress-unavailable`, exit status 3), and `run`/`demo` refuse before anything starts ("Nothing was started and no evidence directory was made").
  There is no weaker mode and no automatic fallback.
  The lane's `egress-profile.json` is the allow-list (as for the browser lane), `egress-log.jsonl` is the audit file (the layers installed and what the self-test measured, then every refusal and the
  allowed connects up to a cap; what is not written is counted in a closing `summary` record, and a refusal is never what is dropped), and the report carries the limitation `egress-layers-robot` (JSON, text and
  HTML), which `verify` requires, with the same text, from a plan whose Robot lane says `origin-only`.
  **A refused attempt ends the lane as an engine error** (`NATIVE_ERROR`, `egress-denied`; `egress-fence-lost` if the supervisor was lost), whatever Robot itself said: the lane carries no verdict, the run is
  INCONCLUSIVE (exit status 3), and `verify` rejects a bundle whose log records a refusal while the lane is reported as completed (`EGRESS_DENIAL_NOT_REFLECTED`), a status of `egress-denied` without a
  refusal in the log, a log whose layers or allow-list are not the plan's, an allowed connect outside the allow-list, or a malformed log.
  **What the layers do not stop** is part of the report's statement and of the matrix below:
  * **Against a hostile library the allow-list is enforced at the level of the PORT, not of the address.** The supervisor reads the address of a `connect` from the caller's memory and the kernel then reads it
    again, so a second thread (or a process that shares the memory) that changes the address between the two can reach ANOTHER IPv4 ADDRESS on the allowed port. Landlock keeps it to that port. Measured: about a fifth
    of the attempts of such a library did (aarch64 Docker, development measurement); the CI experiment counts them and asserts that the unfenced control and Landlock alone reach another address and that
    the audit log shows a clean `127.0.0.1` allowed connect for each, whichever address it reached. The address half of the allow-list holds for honest code and for code that does not race it (measured: `127.0.0.2` on
    the allowed port, from one thread, is refused). It was not closed because the ways to close it are not usable: connecting on the caller's behalf needs `pidfd_getfd`, which Docker's default profile refuses
    (measured on Docker Desktop), and replacing the caller's socket (`SECCOMP_IOCTL_NOTIF_ADDFD`) loses the options and the blocking mode the caller set on it.
  * Files, pipes, FIFOs and processes reachable without a socket are not confined; a TCP simultaneous open is not excluded; names do not resolve over the network (UDP is refused), only `/etc/hosts` resolves
    and its address is checked like any other.
  * A caller with `CAP_SYS_PTRACE`, and a kernel bug, defeat the layers. This is not a sandbox of the library: the library allowlist remains a guard, not a sandbox.

  **The record and the supervisor.** The supervisor is a thread of the lane child; the engine is a separate child process. (a) The lane child is not dumpable, so a same-user engine cannot read or write
  its memory through `/proc` or attach to it, with or without a Yama policy on the host (the experiment checks the dumpable bit itself, which a Yama policy would hide); the ENGINE stays dumpable, because the
  supervisor needs to read its address argument, and the dependency on the host's ptrace policy is therefore only that of `CAP_SYS_PTRACE`. (b) The lane child is a subreaper and ends every process that is its
  descendant, in whatever session or group, BEFORE it writes the lane's result; so a process the library detaches (`setsid`) cannot rewrite the result files (measured: it could, 3 times of 3, before this was
  added). (c) The log also reaches the runner over the lane child's standard output, which nothing the engine started can reach; that copy replaces the one in the output directory and the refusals in it decide
  the lane's status, so a rewritten file cannot hide a refusal even from a process that survives (a lane whose child sent no log, or a malformed one, is an engine error). (d) A process of the same user that
  signals the lane child can stop (`SIGSTOP`) or kill it and with it the supervisor: every connect then fails or waits (no connection is made) until the lane's deadline ends it. That is a denial of service that fails
  closed, not an opening. A supervisor that fails while it decides closes the notification descriptor, so a waiting call fails at once, and the lane ends `egress-fence-lost`.

### Egress matrix by engine

| | Playwright Chromium (browser lane) | Robot Framework (Robot lane, `origin-only`) |
|---|---|---|
| What limits the traffic | the egress gateway (the browser's explicit proxy; loopback not bypassed; no name resolution, QUIC or WebRTC traffic outside it) and the adapter's in-browser request gate | the kernel layers of `qa_runner.netfence` (seccomp user notification, Landlock) on the lane process and everything it starts |
| Policy | the plan's `origin-only` allow-list: one http loopback origin | the same allow-list: one IPv4 loopback address and port; **against a hostile library only the port is enforced** (see above) |
| Default | deny | deny |
| Inbound | not applicable | `listen` refused, TCP `bind` refused (measured) |
| Fails closed when the protection is unavailable | yes: the gateway or the launch configuration cannot be provided, or the gateway is lost during the lane | yes: the layers cannot be installed or fail their self-test (the lane is not started), or the supervisor is lost during the lane |
| Refusals recorded | `gateway-log.jsonl`, `browser-guard-log.jsonl` | `egress-log.jsonl` (refusals never dropped; allowed connects up to a cap) |
| A refusal changes the lane's result | the lane's request is refused; the page may fail | the lane ends as an engine error (`egress-denied`), never a pass, whatever the library does to the lane's files |
| Measured by | the runner egress job (`tests/egress`), a hostile page on loopback | the Robot egress job (`tests/robot_egress`), a hostile Robot library on loopback |
| Does not stop | the browser lane has no other network path; see "What is not shown" below | another address on the allowed port (race), anything reachable without a socket (files, pipes, processes), a TCP simultaneous open, `CAP_SYS_PTRACE`, kernel bugs; a stopped or killed supervisor ends in no connection, not an open network |

Measured by the Robot egress experiments (a hostile library inside the real lane child, hostile LOOPBACK listeners that count what reaches them; nothing leaves this machine). `reached` and `blocked`
are the listeners' counts, not what the library says; the same attempts run with no layer (the control: every one that can reach does) and with each layer alone:

| Attempt | no layer | seccomp alone | Landlock alone | both (the lane) |
|---|---|---|---|---|
| direct connect to a forbidden loopback port; by IP literal in a URL; by a redirect from the allowed origin; through a proxy variable the library sets itself | reached | blocked | blocked | blocked |
| a name resolved by a hostile resolver (UDP) to a forbidden address, then connect; the same resolver over TCP | reached | blocked | blocked (the connect; the UDP query itself reached) | blocked |
| the allowed port on another loopback address (127.0.0.2), from one thread; `0.0.0.0` | reached | blocked | reached | blocked |
| the same, with the address flipped by a second process while `connect` runs (race) | reached | may reach (counted, not asserted) | reached (asserted) | may reach (counted, not asserted; the log shows the allowed address) |
| the allowed port flipped to a forbidden PORT by a second process | reached | may reach (not asserted) | blocked (asserted) | blocked (asserted) |
| IPv6 loopback (TCP) | reached | blocked | blocked | blocked |
| UDP datagram (IPv4 and IPv6); a unix-domain datagram to a path (also from `socketpair`); a unix-domain stream connect | reached | blocked | reached | blocked |
| raw socket (not asserted: it needs root to succeed even with no layer) | root only | refused | not covered | refused |
| TCP Fast Open (data sent with the connection attempt), by `sendto` and by `sendmsg` | reached | blocked | reached | blocked |
| `listen` after `bind` on every address (inbound) | reached | blocked | blocked | blocked |
| `listen` on a socket that was never bound (the kernel picks the port: no `bind` call) | reached | blocked | reached | blocked |
| an MPTCP or SCTP stream socket (not asserted with no layer or with Landlock alone: the kernel may not offer them) | depends | refused | not covered | refused |
| `curl`, `python`, `bash` (`/dev/tcp`) started by the library; `ctypes` `connect`; a raw `syscall`; a thread; a module that connects when it is imported | reached | blocked | blocked | blocked |
| `io_uring` setup | depends on the host | refused (a container's own filter may refuse first, so no audit record is required) | not covered | refused |
| a `connect` whose address is not memory | refused by the kernel | refused, recorded, the supervisor goes on | refused by the kernel | refused, recorded, the supervisor goes on |
| the lane child's `/proc/<pid>/mem` and dumpable bit, seen from the engine | depends on the host's ptrace policy | not exposed | not exposed | not exposed |
| a process left behind in a session of its own | survives (asserted) | ended before the result is written | ended before the result is written | ended before the result is written |
| the allowed origin, by the library's normal route | works | works | works | works |

Every refusal of the seccomp layer is also an entry of `egress-log.jsonl` (checked per attempt, with the allowed origin recorded as allowed). What is **not** shown: a kernel without Landlock network rules, an
architecture other than the two tables, a container whose own filter blocks `seccomp` user notification or the Landlock calls (the lane does not start there; the experiments cannot make it), HTTPS, and anything
about a library that talks to a process that is already running through the file system. Equivalent mutants, stated as such: the notification identity check (`ID_VALID`) after the supervisor read the address
is a race that no deterministic test reaches; the `socketpair` and local-socket type rules and the `sendto`-with-address rule are belt and braces while `connect` and the socket kinds are filtered.

**What was measured on the supported platform, before the layers were chosen** (GitHub-hosted `ubuntu-24.04`, x86_64, kernel 7.0.0-1017-azure; and in an `ubuntu:24.04` container on it, as root and as `nobody`):
unprivileged user namespaces are restricted (`kernel.apparmor_restrict_unprivileged_userns=1`; `unshare -Urn` fails with `Operation not permitted`, also as root in the container), no `bwrap` is installed, so a
network namespace around the lane is not available without root or a new program and was not used; seccomp user notification and Landlock (ABI 8) work in all three places, and Docker's default seccomp profile
does not stop either; Docker's default profile does stop `pidfd_getfd` (measured in Docker Desktop, not on the runner), which a supervisor would need to connect on the caller's behalf, so the supervisor
continues the call after checking the address instead (the race above, and why Landlock is the second layer). An in-process guard (a patched `socket`)
was not built: it is bypassed by `ctypes`, raw system calls and child processes, and adds nothing over the layers above. `doctor` probes each layer ALONE in a throwaway process before both together (the self-test of a lane
runs with both installed, where the seccomp layer refuses a forbidden connect first, so it cannot tell whether Landlock enforces by itself; the probe and the experiments do).
`verify` checks the header's layers, allow-list, self-test and that the Landlock ABI is a number of at least 4; the kernel release and architecture it names, and the presence of the `egress_fence_denied` extension, are
informational (a bundle without the extension is accepted; a bundle whose extension is present must carry the logs' count).

**Hosts that are refused.** The demo and the committed examples ask for `origin-only`, so on macOS, Windows, a kernel without Landlock network rules and an emulated `amd64` container (Docker Desktop on Apple silicon
running the `linux/amd64` platform reports Landlock ABI 0) `doctor` fails the `robot egress layers` check with the reason and `run` and `demo` exit 3 before anything starts; a native arm64 Linux container works
but is development evidence only and nothing is claimed for it. For such hosts `examples/robot-plan-not-enforced.json` is the same plan with `"egress": "not-enforced"` (no limit on the Robot lane's traffic, and the report
says so): `redevops-qa run examples/robot-plan-not-enforced.json --out DIR`. There is no automatic fallback. On macOS 23 offline tests of this package fail closed for the same reason (the doubled lanes install the
real layers): run the suite on Linux or in the Linux container the CI job uses.
* **What is tested** (the runner egress CI job, `tests/egress`, real Chromium; the same tests ran on macOS arm64 while they were written, which is development evidence only): a hostile page on the allowed
  origin tries to reach a hostile TCP origin and a UDP listener on loopback in fifteen ways (image, prefetch, iframe, script, fetch by number, by the name `localhost`, by decimal and hex spellings,
  a redirect from the allowed origin, a beacon, a WebSocket, an EventSource, a worker, `window.open`, a form post, plus WebRTC and an IPv6 literal). With the launch configuration of `qa-egress` the hostile
  origin sees nothing and the gateway refuses every attempt as not listed; with Chromium's defaults, and with `--proxy-server` alone (what a driver that only adds a proxy flag does), it is reached by every
  path, so the protected result is not an empty one. The same page is given to the orchestrated lane (both layers on). The gateway is stopped after the first page of a real run: the lane fails closed and
  the target never sees a later request.
* **What is not shown:** HTTPS interception, DNS rebinding at browser level, headed mode, other browsers (Selenium's driver does not apply the launch configuration), other platforms than the one
  that runs the job. "The hostile origin sees nothing" is counted in HTTP request lines AND in accepted TCP connections (a bare connect, a TLS ClientHello); rows exist for an image over https and a
  secure WebSocket, with controls that must open a connection. A `<link rel=preconnect>` opened no connection in the pinned Chromium even with every protection off, so there is no row for it.
  Removing a single flag from the launch configuration (the DNS, QUIC or proxy flags) is not detectable at browser level with cleartext HTTP on loopback; only the WebRTC flag changed results.
* **A page that opens a WebSocket to a refused origin** keeps the page from finishing its load in the orchestrated lane (both egress layers on): the navigation step times out and the lane ends
  INCONCLUSIVE, never a pass. The lane child returns 0 with a COMPLETED result file (the lane's own exit code is 4); the exit status 3 of the run comes from the orchestrator.
* **A lane child that crashed on ubuntu-24.04 (found by the egress tests, understood from CI runs, fixed).** After the timed-out navigation of that page the lane child process was killed by SIGSEGV
  in 24 of 24 CI runs (Python 3.12.15, Playwright 1.64.1, greenlet 3.5.6), in the same way with `-X dev`. It happened AFTER `main` had returned and the result file was complete (the crash is in
  interpreter shutdown: faulthandler shows no Python frame and the extension module `greenlet`); it did not happen in 24 of 24 runs that left through `os._exit`. The child now flushes its streams
  and leaves with `os._exit`. What is guaranteed either way: a child killed by a signal is a lane error (`child-signal-N`), never a verdict; nothing it wrote is kept as the engine's own record (so
  `verify` accepts the bundle as honest rather than refusing a relabelled status); every process it started is ended with its process group. What is not known: why greenlet fails in shutdown after
  a timed-out navigation (a defect of the pinned Playwright/greenlet pair is the likely cause; not investigated further), and whether other Python or platform builds are affected.

## Bounded reads

Two mechanisms, for two kinds of files.

* **Paths a user supplies** (a plan or lock, and a bundle to `verify`, `report` or `inspect`) are read by a child process (`isolated.py`, `read_worker.py`): the parent holds nothing but what
  came through a pipe, stops taking bytes at the cap (and kills the child), stops waiting at a wall-clock deadline (`REDEVOPS_QA_READ_TIMEOUT`, default 30 s; bundles `REDEVOPS_QA_BUNDLE_READ_TIMEOUT`, default
  120 s) and kills the child, and on SIGINT, SIGTERM or SIGHUP kills the child and ends with exit 3. The child opens the path without blocking (`O_NONBLOCK`), `fstat`s the same descriptor and refuses anything
  that is not a regular file (a FIFO, a device, a directory: never read, `/dev/zero` included), refuses a file above the cap before reading, and reads with a running total (a growing file stops at the cap).
  The child never outlives its parent: it is told the parent's pid and its deadline, and a watchdog thread ends it (`os._exit`, which works while the main thread is blocked in a system call) when the
  parent is gone (SIGKILL, a crash) or when the deadline plus a margin has passed. Memory: a bundle snapshot is held in the parent as the stream and again as the per-file copies; at the caps
  (about 330 MB of bundle) that is about 1 GB of resident memory for `verify`, `report` and `inspect` (measured by the retest at 819 MB for a 240 MiB bundle), not a smaller number.
* **Files a lane or the target wrote** (in the run's own temporary directory) are read in this process through `safe_read.read_regular` with the same rules (one descriptor, regular files only, no symbolic
  link, byte cap, deadline checked between chunks: a single system call blocked in the kernel, a temporary directory on a hung mount, is not interrupted; only the isolated path above is killable) and under one **evidence budget** for the whole run (`REDEVOPS_QA_MAX_EVIDENCE_BYTES` or `RunOptions.max_evidence_bytes`, default 128 MiB, half the cap of
  a bundle): a file that does not fit is neither read nor kept, its name is logged, the lane becomes an engine error `evidence-over-cap`, the report says `extensions.evidence_incomplete`, the run is never
  VERIFIED (exit 3), and everything that fit is in the bundle. If the bundle format still refuses what was collected, the run is rebuilt without the blobs instead of ending as a crash.
* The reference check of the target: no answer above 1 MiB, a total deadline of 30 s for the whole check (a watcher ends the connection; a server that sends a byte every few seconds does not stretch it),
  and the run's cancel ends it.

* The limits from the environment (`REDEVOPS_QA_READ_TIMEOUT`, `REDEVOPS_QA_BUNDLE_READ_TIMEOUT`: 1 to 3600 seconds; `REDEVOPS_QA_MAX_EVIDENCE_BYTES`: 1024 to 8 GiB) are parsed strictly: anything else (`abc`, `nan`,
  `inf`, `0`, a negative or a huge number) is refused with exit 2 and a message that names the variable, before anything starts; never a traceback and never "no limit".
* The core of the in-process read lives in the adapter kit (`qa_adapter_kit.boundedread`) so that the adapters use it too (the Robot adapter's `output.xml` and suite files, the kit's artifact collection). With a
  root (the run's temporary directory) every component below it is opened with `O_NOFOLLOW` relative to its parent's descriptor: a `blobs` directory replaced by a symbolic link is refused, not followed.
* A probe fact is tied to what it speaks for: `settings-persistence` only for the browser assertion on the 'Email notifications' checkbox, `discount-rule` only for a Robot lane's assertion read by the
  evidence program; any other pairing is refused at freeze (`BAD_PROBES`).

**Tested** (each in a child with a hard timeout and, where the platform enforces one, an address-space cap; none opens an unbounded source): a reading child that never answers is killed at the deadline and is
gone; a child that writes without end is stopped at the byte cap; SIGINT, SIGTERM, SIGHUP end the wait and the child; refusals of a FIFO with no writer, a FIFO with a capped writer (nothing is consumed), a
character device, a symlink, a sparse plan or lock of 300 MiB, a sparse bundle archive of 3 GiB and a sparse bundle member of 400 MiB (a finding, never read), a size that lies at the open and a growing file; the same for `run`, `doctor --plan`, `verify`, `report` and `inspect` (a stalled bundle read ends at the deadline, a cancel during it ends with exit 3); the evidence budget and its fallback (a run over the cap is an incomplete result, exit 3, that its own re-verification and `verify` accept as such: both real engines at seven caps, the Robot lane cut at the lowest ones); the reference check against a
capped 64 MiB answer, a one-byte-at-a-time body, dripped headers and a cancel during a stall.
**Not tested, only inferred:** a child blocked in UNINTERRUPTIBLE kernel I/O on a hard-hung network or FUSE mount. SIGKILL is sent and the parent does not wait for the child past a short grace, but the
process itself may stay until the kernel returns the I/O (a subprocess timeout does not guarantee that every blocked kernel operation ends). No test has a stalled mount; the "never answers" child is a stand-in.
`RLIMIT_AS` is enforced on Linux and ignored by macOS; on macOS the hard timeouts and the capped writers are the protection.

## Bundle contents

```
plan.lock.json                         the frozen plan, its digests and the pins (record)
lanes/browser/native/run-record.json   the harness run record: manifest, event chain, receipts, classification (native)
lanes/browser/native/lane-result.json  what the lane child reported, including the in-run verdicts (native)
lanes/browser/native/blobs/<sha256>    artifacts captured by the browser, redacted by the harness redactor (native)
lanes/browser/observations.json        the observed values the verdicts are computed from (observation)
lanes/browser/egress-profile.json      the allow-list the lane ran under, as data (record)
lanes/browser/gateway-log.jsonl        decisions of the egress gateway: scheme, host, port, verdict; no path, query or header (log)
lanes/browser/browser-guard-log.jsonl  decisions of the adapter's in-browser request gate, the second layer (log)
lanes/robot/native/output.xml          the Robot engine's own report; also robot-summary.json and adapter-result.json (native)
lanes/robot/observations.json          the observation record derived from output.xml: what the check program reads (observation)
lanes/robot/suite/*                    the reviewed suite files the engine ran, as hashed in the lock (record)
lanes/robot/egress-profile.json        the allow-list the lane ran under (origin-only), or the statement that egress is not enforced for it (record)
lanes/robot/egress-log.jsonl           origin-only Robot lanes: the layers installed, the self-test, every decision of the supervisor (log)
lanes/<lane>/target-requests.jsonl     the target's own log of the requests it served while that lane ran (log)
logs/                                  orchestration log, tails of the lane output, the reference check of the target (log)
```

Plus the files `qa-evidence` writes: `report.json`, `bundle-manifest.json`, `assertion-lock.json`, `BUNDLE-FORMAT.txt`.

## What verification does and does not prove

`redevops-qa verify BUNDLE` (a directory or the canonical archive) takes nothing from the run: it reads the bundle ONCE into a snapshot (a child process, killed at the deadline) and computes everything from that snapshot, so a writer that changes the files while it runs cannot make two checks see two bundles; it opens no socket and imports no browser or Robot Framework package. It is not
dependency-free: it needs the pinned runtime-contracts and agent-harness trees (checked with `git`, so `git` and clean checkouts of the pins), PyYAML (the check-program registry imports it), and its
output depends on `PATH` and the `REDEVOPS_QA_*` / `QA_PIN_*` variables that name the pins; the pinned harness imports the standard library's HTTP client modules when it is imported (a test shows
that nothing connects). It re-computes, and reports a finding for any difference:

1. every file digest and size, the manifest and the report schema, the accounting (every frozen assertion exactly once), the lane ids and run ids, and the external anchor and plan digest if you
   supply them (`qa-evidence`);
2. the frozen plan: `plan.lock.json` is re-frozen with the pinned runtime-contracts and harness parsers (unknown fields refused) and must equal itself, the report's frozen set and the
   assertion lock, with every expected value, digest, assertion-set pin and check-program hash recomputed; the suite files in the bundle must be the ones THE PLAN pins (`suite_sha256`, part of the
   plan digest) and the pins must name exactly the files of the suite (a lock with no pins, or other pins, is `LOCK_REJECTED`); a version of the runner that ships other suite files than the plan
   pins is a note, not a finding (an older run used older files);
3. **every verdict**, from the files in the bundle: the recorded browser observations against the frozen assertions, and for the Robot lane the hash-pinned check program over a record that
   must be exactly what the importer derives from the engine's own `output.xml` in the bundle. A report that says something else is `VERDICT_RECOMPUTE_MISMATCH`;
4. each lane's **native status**, re-derived from the engine's own files (the harness outcome and exit code, the Robot adapter result and the test statuses of `output.xml`); a native FAIL
   written as a PASS is `NATIVE_STATUS_RELABELLED`; an engine status this verifier does not map is never read as a pass;
5. each browser lane's **harness run record**: the event and receipt chains, the manifest, the blobs it refers to (a missing or altered blob is `RUN_RECORD_MISSING_BLOB` / `RUN_RECORD_BLOB_CONTENT`),
   the run id, the frozen assertion pin, the executed spec (rebuilt from the frozen template and the allowed origin), that the `AssertionResult` events are the results its manifest lists and
   that the seal and the manifest carry the classification the record states (`RUN_RECORD_CONTRADICTS_ITSELF`), and that every observation equals what the record says was read;
6. the **egress profile** of a browser lane is exactly the one the plan's profile gives for the origin it names, the lock's tool versions and runner version are well-formed, and the bundle holds no
   file that no run of its plan writes (`UNEXPECTED_FILE`: a lane directory that is not in the plan, a hidden log).

A bundle whose report says a test double produced a lane is rejected (`TEST_DOUBLE_BUNDLE`): a double carries no verdict. Whatever else goes wrong inside the verification, on a bundle built to cause it,
is `VERIFY_INCOMPLETE` and exit 5, never an internal error.

An observation row or record that carries a field an adapter has no business writing (a verdict, a `verified` claim, an expected value) is unusable evidence: the assertion is `INCONCLUSIVE`.

What an accepted bundle means, and what it does not:

* **Without `--anchor`, accepted means INTERNALLY CONSISTENT, nothing more.** The hashes and the manifest are unkeyed. They detect accidental changes and partial edits. They do not detect a bundle
  that was rewritten consistently from start to finish by someone who can rewrite all of it: the product's own builder would produce the same bytes from forged inputs, and the tamper suite shows
  it (`tests/test_qr_tamper_suite.py`): the failing lane dropped, an assertion weakened, or the engine's own report rewritten to say the rule held, with every digest recomputed, is accepted as
  internally consistent and says so (the engine's report now has to be rewritten together with the engine's summary, the adapter result that names both by hash, the observation record and the
  target's reference check: more work than before, not a different class of forgery). Only a manifest digest obtained from a place the forger cannot write (`--anchor`; the CI artifact attestation planned for the release job publishes it), or a valid signature of the manifest digest by a key the forger does not hold
  (`--anchor-sig` with `--anchor-pub`, optional, see `anchor` above), rejects those. `verify` never calls a match with a value you supplied proof that the value is trustworthy.
* **A signed anchor (optional) detects a rewrite made after signing, for the key you supplied.** `--anchor-sig` with `--anchor-pub` shows that the manifest digest of the bundle carries a valid signature by the supplied
  Ed25519 key (see `anchor` above for the exact claim and what it does not show). Measured: three bundles rewritten and re-chained after signing are accepted by plain `verify` and refused by the signature check. Without a signature, or
  without `--anchor`, the paragraph above applies unchanged.
* **`--plan-digest` closes the gaps in the PLAN and no other.** The plan digest printed by `freeze` (record it outside the bundle) covers every assertion, its expected value and, bound into each
  assertion's digest, the whole definition of its lane: the spec with its steps, the egress profile, the deadline, the request expectations and probes, the reviewed Robot suite and the sha256 of its
  files, and the plan id and target. A bundle whose plan was changed in any of those fails with it. It cannot reject a forgery that left the plan alone.
* **Two partial backstops that need no anchor:** an engine that said FAIL while every assertion verifies makes the run `INCONCLUSIVE` (`NATIVE_FAIL_VERIFIED_ASSERTIONS`), so weakening an assertion
  without also rewriting the engine's files does not give a VERIFIED run; and the harness run record is checked against itself (chains, seal, manifest, blobs, and the events against the manifest), so
  a forger must rewrite the manifest, the seal and every event that contradicts them, not only recompute the chain.
* **It does not establish that the application is correct.** It shows that the frozen assertions hold (or fail) over the recorded observations, and that the bundle is what it says. It does not re-drive the
  browser or the application and it does not show that a suite recorded what it observed (the target's request log and the frozen suite hashes are the only evidence of that).
* **Not covered:** verification with other pinned versions of runtime-contracts or agent-harness than the ones that wrote the bundle is reported as a note (every digest is re-derived with the tools loaded
  here, and they must agree); a check program changed since the run makes older bundles fail to verify (`PROGRAM_HASH_MISMATCH`), by design; a reviewed suite changed since the run does not (the plan carries its own pins), and `verify` says so
  in a note.
* **The offline mutation suite cannot reach the end-to-end tests** (`-m e2e` is an unknown marker under its strict configuration), so no mutant covers process cleanup end to end; the end-to-end job
  runs those tests unmutated.

### A run that hit the evidence cap

A run whose lanes' files did not fit `REDEVOPS_QA_MAX_EVIDENCE_BYTES` is an explicit INCOMPLETE result: the lane that lost files is an engine error `evidence-over-cap`, the report says `extensions.evidence_incomplete`,
the bundle lists what it did not keep (`logs/evidence-not-kept.json`), the run is never VERIFIED and its exit status is 3. `verify` (and the run's own re-verification) accepts exactly that, with a note, and the
same exit status 3. What it tolerates, and nothing else: a lane the report itself declares `evidence-over-cap` (and only when `evidence_incomplete` is there too) may differ from what its files say, because it can
only LOWER the result; a file the list names may be absent (a reviewed suite file, a blob the run record points at: matched by name, one finding per blob); a blob that is missing and not listed, a lane reported as
completed that its files contradict, a VERIFIED run that says its evidence is incomplete, a changed file that was kept, a list that is not of the shape the runner writes, or a list in a bundle that does not say
it is incomplete are findings. Round 3 tightened the tolerance: a lane declared `evidence-over-cap` must really have lost something (a file of that lane is listed and absent, or the lane's own result file is missing), the count in
`extensions.evidence_incomplete` must equal the length of the list (`EVIDENCE_OVER_CAP_NOT_SUPPORTED` otherwise), the list must be in the sorted, unique form the runner writes, and every file a run of the
plan always writes must be in the bundle or listed (`EXPECTED_FILE_MISSING`): the orchestrator's log and the target's request log; for a lane that completed or is over the cap, its egress profile, its
request-log window, the browser lane's gateway and guard logs, the Robot lane's suite copies (and, for a completed lane, the engine's own files; for an `origin-only` Robot lane that completed or was ended by the egress layers, its `egress-log.jsonl`). A lane that did not complete for another reason (a
timeout, a cancel, a target that never started) wrote whatever it got to: nothing is required of it.
Round 4: ONE rule covers every way the budget can keep something out. `bundle.finalize_results` (the builder and `verify` call the same function) turns every VERIFIED assertion into `INCONCLUSIVE`
with the reason `EVIDENCE_INCOMPLETE` whenever the report says `evidence_incomplete`, so a cap that drops only a run-level file (the target's own request log belongs to no lane) gives an INCONCLUSIVE run with
exit 3, never VERIFIED; `verify` recomputes the same downgrade and accepts it. A name in the list must be a file a run of the plan can write (the expected set, or a blob of a browser lane); a fabricated
name is `NOT_KEPT_MALFORMED`; a listed blob must also be one the lane's kept run record refers to (its digest appears in the record), so a made-up hex name does not count as something the lane lost.

Limits of this tolerance, stated plainly (each needs a rewrite of the whole bundle; only `--anchor` (a manifest digest supplied from outside) or a valid signature of the manifest digest by a key the forger does not hold (`--anchor-sig` with `--anchor-pub`) rejects all of them; `--plan-digest` does NOT, because these forgeries leave the plan untouched and its digest matches):
* A bundle that is rebuilt consistently by the product's own builder can declare a lane `evidence-over-cap` (or any non-complete status) with a matching list and thereby lower a FAILED or VERIFIED run to
  INCONCLUSIVE, exit 3, without an anchor or a signature. The result can only be lower; the orchestrator's log is not used to corroborate it (the Robot lane's over-cap label can come from the parent's budget, which the
  child's log lines do not carry), so it is documented rather than checked.
* Files an over-cap lane's own run wrote and that are not in the required set can be deleted without being listed: the browser lane's `lane-result.json` and `run-record.json`, the stdout and stderr tails
  (`logs/<lane>.stdout.txt`, `.stderr.txt`) and `observations.json`. A missing `lane-result.json` or `run-record.json` makes the lane's assertions inconclusive anyway; the tails and the observations
  are not read by a verdict of an incomplete lane.
* A run-level declaration (`evidence_incomplete` with a legal name that is in fact present) is not checked against an absence: only a lane declared over the cap must have lost something. It can only lower
  a VERIFIED run to INCONCLUSIVE/3; a FAILED run stays FAILED.
* `EVIDENCE_INCOMPLETE` was added to qa-evidence's closed list of INCONCLUSIVE reasons without a format version (as `TEST_DOUBLE` and `NATIVE_FAIL_VERIFIED_ASSERTIONS` were before): an older qa-evidence
  refuses a bundle that uses it. Note it when the format is frozen.
The list is written by the same run as everything else: without an anchor (or a signature) it shows nothing a forger could not also write, but with one a forger gains no higher status.

## Reading limits: tested and inferred (summary)

Tested: the byte cap, the deadline, the refusals and the cancel paths of every read of a user-supplied path (`freeze`, `run`, `doctor --plan`, `report`, `inspect`, `verify`), the kill of a reading child that
never answers, the evidence budget, the single snapshot (a writer that swaps the files after it was taken changes nothing). Inferred, not tested: a child stuck in uninterruptible kernel I/O on a hard-hung mount
may outlive its SIGKILL (the parent does not wait for it past a short grace); a subprocess timeout does not guarantee that every blocked kernel operation ends. See "Bounded reads".

## What this does not show

* The hash chain and the bundle manifest are unkeyed. They detect accidental changes and partial edits, not deliberate re-forging by anyone who can rewrite the
  whole bundle; only a manifest digest published somewhere that party cannot write (an external anchor), or a signature of that digest by a key that party does not hold (the optional signed anchor), changes that. This part prints the digests; it
  does not publish or attest them.
* A verified verdict says the frozen assertions hold over the recorded observations. It does not say the application is correct.
* The harness run record, the gateway log and the logs are not passed through the redactor (only browser artifacts are). Do not put a secret in a plan that
  is run for evidence.
* Egress: the gateway and the request gate are exercised against Chromium on the machines named in the tests. Nothing here claims that all traffic of every
  engine passes the gateway; Robot Framework lanes never do. A Robot lane that asks for `origin-only` is limited by kernel layers instead (the egress matrix above states what they stop, what
  they do not, and by which layer each attempt was measured); a Robot lane that says `not-enforced` is limited by nothing.
* The browser and Robot lanes have run on macOS arm64 (development) and in the CI jobs named in the pull requests; no other platform.

## Tests

```text
python -m pytest -q packages/qa-runner/tests                                   # offline: no browser; the lane child is a test double in fake_lane.py
python -m pytest -q -m browser packages/qa-runner/tests/browser                # real Chromium (Playwright 1.64.1 and a browser installed)
python -m pytest -q -m robot_real packages/qa-runner/tests/real                # real Robot Framework 7.5 (no browser needed)
python -m pytest -q -m e2e packages/qa-runner/tests/e2e                        # both real engines in one run, cancellation and a killed parent
python -m pytest -q -m egress packages/qa-runner/tests/egress                  # real Chromium: the hostile-page egress table, the orchestrated lane, the gateway killed mid-run
python -m pytest -q -m robot_egress packages/qa-runner/tests/robot_egress      # Linux, real Robot Framework 7.5: the hostile-library egress experiments of the Robot lane's kernel layers
```

The offline tests include a mutation suite (`test_qr_mutations.py`): each removes one guard from a copy of the source and requires a named test to fail. The
browser tests start the fixture app and the gateway and drive a real browser: clean target, each seeded defect, a forbidden navigation, a page that tries to reach
another origin, a deadline (and a check that no process of the lane's group is left), and the command line in a scrubbed environment.
