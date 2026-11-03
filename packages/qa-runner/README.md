# qa-runner

The `redevops-qa` command: it checks a machine (`doctor`), freezes a test plan (`freeze`), runs a frozen plan against the fixture app and writes an evidence bundle (`run`),
re-verifies a finished run from its bundle alone (`verify`), reports and inspects a bundle (`report`, `inspect`) and does all of that in one step for the built-in two-lane plan (`demo`).
A plan holds a Playwright Chromium lane (`examples/golden-plan.json`), a Robot Framework lane (`examples/robot-plan.json`) or both, run one after the other
(`examples/demo-plan.json`).

Licence: the family licence of this repository (source-available, not open source; see `LICENSE.md`). Standard library and the repository's own packages
only; the two pinned upstreams (`runtime-contracts`, `agent-harness`) are found through `pins.toml`, as the bridge does it, and are neither installed nor
copied.

Scope of this release line: Linux x86_64, Playwright Chromium and Robot Framework. macOS runs are development evidence only (`doctor` says so). Selenium and
Appium are not part of this workflow. Nothing here has been run on any other platform.

Installing: from a checkout, as the tests and the CI jobs do (the `src` directories on `PYTHONPATH`, the pinned trees fetched into `.pinned`); or from the pinned bundle (`bundle/README.md`,
built by `tools/build_bundle.py`): a wheelhouse with a hash for every wheel, installed with `pip install --no-index --find-links wheelhouse --require-hashes -r requirements.lock` into a new
directory, for CPython 3.12 on Linux x86_64 only. A bundle install keeps `pins.toml` and the pinned trees under `<prefix>/share/redevops-qa/` and the pin check runs against those copies
(`REDEVOPS_QA_PINS` still overrides; a checkout above the environment is not used instead). Chromium is downloaded by the bundle's separate browser step and is recorded, not hashed, by the bundle.

## Commands

```text
redevops-qa doctor [--plan PLAN] [--json]
redevops-qa freeze PLAN --out LOCK
redevops-qa run PLAN_OR_LOCK --out DIR [--defect none|discount|settings] [--run-id ID] [--lane-deadline SECONDS]
redevops-qa verify BUNDLE [--anchor sha256:HEX] [--plan-digest sha256:HEX] [--require-anchor] [--require-plan-digest] [--json]
redevops-qa demo [--out DIR] [--defect none|discount|settings] [--run-id ID] [--lane-deadline SECONDS]
redevops-qa report BUNDLE [--format text|json|html] [-o FILE] [--anchor sha256:HEX] [--plan-digest sha256:HEX]
redevops-qa inspect BUNDLE [--anchor sha256:HEX] [--plan-digest sha256:HEX]
```

`python -m qa_runner ...` is the same command from a checkout (`PYTHONPATH` set to the `src` directories of the packages; the tests and the CI job show how).

**`doctor`** reports Python, platform, the temporary directory, the pinned dependencies (commits, tree digests and vector files against `pins.toml`),
Playwright 1.64.1 and a real headless Chromium launch, Robot Framework 7.5, the fixture app and the egress gateway. Each check is `OK`, `WARN` (works, outside
what this release claims: any platform but Linux x86_64) or `FAIL`, with the command that fixes it. It never installs, downloads or changes anything. A
protection that cannot be provided is a `FAIL`: the egress gateway that every browser lane depends on must start, the browser launch configuration must be available, and it must be complete and closed
(`qa_runner.egress.launch_config_problems`: only the arguments `qa-egress` itself produces, none twice; the explicit proxy, Chromium's implicit loopback bypass removed, no name resolution in the browser, no QUIC, no WebRTC traffic outside the proxy). The
browser lane applies the same check before it starts a browser. Exit status 0, or 3 if a check failed.

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
| 7 | `verify` only: the verifier itself cannot run here (a pinned dependency or git is missing); nothing was verified, which says nothing about the bundle (the JSON is still printed, with `assurance: not-verified`) |

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
* **Egress is not enforced for a Robot lane.** A Robot library opens its own sockets. The lane's egress profile says `not-enforced` and the plan must say so (`"egress": "not-enforced"`;
  a browser lane must use `origin-only`).
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
* **Robot lane: egress is NOT enforced.** A Robot library opens its own sockets; the egress gateway is not in its path and the library allowlist is a guard, not a sandbox. The lane's
  `egress-profile.json` says `not-enforced`, and the report of a run with a Robot lane carries the limitation `egress-not-enforced-robot` (in the JSON, the text and the HTML), which `verify`
  requires from a plan that has a Robot lane (`EGRESS_STATEMENT_MISSING`, `EGRESS_STATEMENT_WRONG`). Nothing in a report shows that a Robot lane's traffic was limited to the allowed origin.
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
lanes/robot/egress-profile.json        says that egress is not enforced for this lane (record)
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
  target's reference check: more work than before, not a different class of forgery). Only a manifest digest obtained from a place the forger cannot write (`--anchor`; the CI artifact attestation planned for the release job publishes it) rejects
  those. `verify` never calls a match with a value you supplied proof that the value is trustworthy.
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
request-log window, the browser lane's gateway and guard logs, the Robot lane's suite copies (and, for a completed lane, the engine's own files). A lane that did not complete for another reason (a
timeout, a cancel, a target that never started) wrote whatever it got to: nothing is required of it.
Round 4: ONE rule covers every way the budget can keep something out. `bundle.finalize_results` (the builder and `verify` call the same function) turns every VERIFIED assertion into `INCONCLUSIVE`
with the reason `EVIDENCE_INCOMPLETE` whenever the report says `evidence_incomplete`, so a cap that drops only a run-level file (the target's own request log belongs to no lane) gives an INCONCLUSIVE run with
exit 3, never VERIFIED; `verify` recomputes the same downgrade and accepts it. A name in the list must be a file a run of the plan can write (the expected set, or a blob of a browser lane); a fabricated
name is `NOT_KEPT_MALFORMED`; a listed blob must also be one the lane's kept run record refers to (its digest appears in the record), so a made-up hex name does not count as something the lane lost.

Limits of this tolerance, stated plainly (each needs a rewrite of the whole bundle; only `--anchor`, a manifest digest supplied from outside, rejects all of them; `--plan-digest` does NOT, because these forgeries leave the plan untouched and its digest matches):
* A bundle that is rebuilt consistently by the product's own builder can declare a lane `evidence-over-cap` (or any non-complete status) with a matching list and thereby lower a FAILED or VERIFIED run to
  INCONCLUSIVE, exit 3, without an anchor. The result can only be lower; the orchestrator's log is not used to corroborate it (the Robot lane's over-cap label can come from the parent's budget, which the
  child's log lines do not carry), so it is documented rather than checked.
* Files an over-cap lane's own run wrote and that are not in the required set can be deleted without being listed: the browser lane's `lane-result.json` and `run-record.json`, the stdout and stderr tails
  (`logs/<lane>.stdout.txt`, `.stderr.txt`) and `observations.json`. A missing `lane-result.json` or `run-record.json` makes the lane's assertions inconclusive anyway; the tails and the observations
  are not read by a verdict of an incomplete lane.
* A run-level declaration (`evidence_incomplete` with a legal name that is in fact present) is not checked against an absence: only a lane declared over the cap must have lost something. It can only lower
  a VERIFIED run to INCONCLUSIVE/3; a FAILED run stays FAILED.
* `EVIDENCE_INCOMPLETE` was added to qa-evidence's closed list of INCONCLUSIVE reasons without a format version (as `TEST_DOUBLE` and `NATIVE_FAIL_VERIFIED_ASSERTIONS` were before): an older qa-evidence
  refuses a bundle that uses it. Note it when the format is frozen.
The list is written by the same run as everything else: without an anchor it shows nothing a forger could not also write, but with it a forger gains no higher status.

## Reading limits: tested and inferred (summary)

Tested: the byte cap, the deadline, the refusals and the cancel paths of every read of a user-supplied path (`freeze`, `run`, `doctor --plan`, `report`, `inspect`, `verify`), the kill of a reading child that
never answers, the evidence budget, the single snapshot (a writer that swaps the files after it was taken changes nothing). Inferred, not tested: a child stuck in uninterruptible kernel I/O on a hard-hung mount
may outlive its SIGKILL (the parent does not wait for it past a short grace); a subprocess timeout does not guarantee that every blocked kernel operation ends. See "Bounded reads".

## What this does not show

* The hash chain and the bundle manifest are unkeyed. They detect accidental changes and partial edits, not deliberate re-forging by anyone who can rewrite the
  whole bundle; only a manifest digest published somewhere that party cannot write (an external anchor) changes that. This part prints the digests; it
  does not publish or attest them.
* A verified verdict says the frozen assertions hold over the recorded observations. It does not say the application is correct.
* The harness run record, the gateway log and the logs are not passed through the redactor (only browser artifacts are). Do not put a secret in a plan that
  is run for evidence.
* Egress: the gateway and the request gate are exercised against Chromium on the machines named in the tests. Nothing here claims that all traffic of every
  engine passes the gateway; Robot Framework lanes will not.
* The browser and Robot lanes have run on macOS arm64 (development) and in the CI jobs named in the pull requests; no other platform.

## Tests

```text
python -m pytest -q packages/qa-runner/tests                                   # offline: no browser; the lane child is a test double in fake_lane.py
python -m pytest -q -m browser packages/qa-runner/tests/browser                # real Chromium (Playwright 1.64.1 and a browser installed)
python -m pytest -q -m robot_real packages/qa-runner/tests/real                # real Robot Framework 7.5 (no browser needed)
python -m pytest -q -m e2e packages/qa-runner/tests/e2e                        # both real engines in one run, cancellation and a killed parent
python -m pytest -q -m egress packages/qa-runner/tests/egress                  # real Chromium: the hostile-page egress table, the orchestrated lane, the gateway killed mid-run
```

The offline tests include a mutation suite (`test_qr_mutations.py`): each removes one guard from a copy of the source and requires a named test to fail. The
browser tests start the fixture app and the gateway and drive a real browser: clean target, each seeded defect, a forbidden navigation, a page that tries to reach
another origin, a deadline (and a check that no process of the lane's group is left), and the command line in a scrubbed environment.
