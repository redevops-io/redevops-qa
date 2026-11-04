# ReDevOps QA: a real run of the demo

The output below is copied from a CI run on the main branch, not written by hand: the `demo` and `demo-verify` jobs of [run 41591460007](https://github.com/redevops-io/redevops-qa/actions/runs/41591460007) of `tests.yml`,
head commit `d856bab` of `main`, on a GitHub-hosted `ubuntu-24.04` runner (Linux x86_64, CPython 3.12.15, Playwright 1.64.1 with Chromium, Robot Framework 7.5). The same jobs run on every push; run ids,
timestamps and anchors differ from run to run, the plan digest, the outcomes, the counts and the exit statuses do not.

**This page quotes a run from before the Robot lane's kernel layers.** In that run the plan froze the Robot lane with the egress profile `not-enforced`, and the plan digest below is that plan's. The demo plan of the
current source names `origin-only` for the Robot lane (a different plan digest): the Robot lane then runs under seccomp and Landlock layers (the report's limitation `egress-layers-robot` says what they stop and what
they do not; `lanes/robot/egress-log.jsonl` is their audit file), and `demo` refuses to start, before anything runs, on a host where `doctor` cannot measure them. The next run on the main branch replaces the numbers
on this page; until then none of them describes the layers.

## What was run

The bundle the `bundle` job had just built was installed with the commands of its own README (`install.sh`, then the separate browser step), and then:

```text
redevops-qa demo --defect none --out evidence
```

The demo starts a small fixture web app on loopback, runs a Playwright Chromium lane (sign in, open Settings, tick "Email notifications", save) and a Robot Framework lane (an order total with a 10 percent
discount) one after the other under one run id, writes one evidence bundle, and re-verifies it in a fresh process. `--defect discount` and `--defect settings` start the same app with a seeded defect.

## The output for the correct app ([job 125769400806](https://github.com/redevops-io/redevops-qa/actions/runs/41591460007/job/125769400806))

```text
run r0-20261103T064317Z-az64eenm2ehm4: VERIFIED (ALL_ASSERTIONS_VERIFIED)
  external anchor: no external anchor: integrity against deliberate re-forging NOT established (a manifest digest published where this machine cannot rewrite it is an anchor)
  lane browser: engine reported NATIVE_PASS (PASS); independent verdicts: 3 verified, 0 failed, 0 inconclusive, 0 unaccounted
  lane robot: engine reported NATIVE_PASS (PASS); independent verdicts: 1 verified, 0 failed, 0 inconclusive, 0 unaccounted
  egress: the gateway denied 0 request(s), the in-browser request gate denied 0 (details in the lane's logs)
  no independent probe (declared ui-only in the plan; the verdict rests on the engine's record and the target's request log): browser:A-SAVED,browser:A-URL
  assertions: frozen 4 = verified 4 + failed 0 + inconclusive 0 + unaccounted 0
  plan digest: sha256:3e53d5b170e6541bd7fb37188a17c99c766af1d161d5aed452af68a56e68b943   (the value to give `verify --plan-digest`)
  manifest digest: sha256:023ccf463df60bfae8b4f188abfd548262a3eea7be6dd44aaba91ba7ba780c27   (an anchor only if published where this machine cannot rewrite it)
  re-verification in a fresh process (the same code as the run, not independent code): ACCEPTED as internally consistent; 4 of 4 verdict(s) recomputed from the bundle alone agree with the report; no external anchor
```

The report that follows it lists each frozen assertion with the engine's native status and the verifier's verdict side by side:

```text
  A-NOTIF-ON [browser] native=NATIVE_PASS verdict=VERIFIED (EQUALS_EXPECTED) evidence=lanes/browser/observations.json
  A-ORDER-RULE [robot] native=NATIVE_PASS verdict=VERIFIED (EQUALS_EXPECTED) evidence=lanes/robot/observations.json
  A-SAVED [browser] native=NATIVE_PASS verdict=VERIFIED (EQUALS_EXPECTED) evidence=lanes/browser/observations.json
  A-URL [browser] native=NATIVE_PASS verdict=VERIFIED (PREDICATE_HOLDS) evidence=lanes/browser/observations.json
```

## The three outcomes

| `--defect` | Exit status | Outcome | Lane that failed | Anchor (sha256 of `bundle-manifest.json`) | Demo job | Verified again in a second job |
|---|---|---|---|---|---|---|
| `none` | 0 | `VERIFIED` | none: 3 browser and 1 Robot assertions verified | `sha256:023ccf463df60bfae8b4f188abfd548262a3eea7be6dd44aaba91ba7ba780c27` | [125769400806](https://github.com/redevops-io/redevops-qa/actions/runs/41591460007/job/125769400806) | [125769764235](https://github.com/redevops-io/redevops-qa/actions/runs/41591460007/job/125769764235): accepted, exit 0 |
| `discount` | 1 | `FAILED` (`ASSERTION_FAILED`) | Robot Framework: engine `NATIVE_FAIL`, 0 of 1 verified; the browser lane verified 3 of 3 | `sha256:f5d6a17a05c0b26b3980f9f3d8e5887702e3adfd5deddb3180d6408ce648f145` | [125769400825](https://github.com/redevops-io/redevops-qa/actions/runs/41591460007/job/125769400825) | [125769764661](https://github.com/redevops-io/redevops-qa/actions/runs/41591460007/job/125769764661): accepted, exit 1 |
| `settings` | 1 | `FAILED` (`ASSERTION_FAILED`) | Playwright Chromium: engine `NATIVE_FAIL (PRODUCT_FAIL)`, 2 of 3 verified; the Robot lane verified 1 of 1 | `sha256:ec0af491eb0138a56fe774970be460508441200c42996ff3e4fed8b184599c9e` | [125769400895](https://github.com/redevops-io/redevops-qa/actions/runs/41591460007/job/125769400895) | [125769764369](https://github.com/redevops-io/redevops-qa/actions/runs/41591460007/job/125769764369): accepted, exit 1 |

All three runs froze the same plan: plan digest `sha256:3e53d5b170e6541bd7fb37188a17c99c766af1d161d5aed452af68a56e68b943`. A seeded defect fails exactly its own lane, and the other lane's result is still recorded.

The second job starts from nothing but the artifacts the demo job kept: it installs the bundle into a new directory, downloads the evidence bundle and the anchor, and runs
`redevops-qa verify --anchor <the anchor above> --plan-digest <the plan digest above> --require-anchor --require-plan-digest`. For all three bundles the result was accepted, with the exit status the run had.
The same command on a copy with one byte added to `report.json`, and with a wrong anchor, exited 5 (the evidence is not accepted) in all three jobs.

## Running it as root

Run as root with the default `HOME=/root`, the demo of an installation under `/root` ends `INCONCLUSIVE`, not `VERIFIED`: the Robot lane is refused with `PROHIBITED_PATH`, because the command line of that lane names the
interpreter of the installation (`/root/redevops-qa/venv/bin/python`) and the adapter path policy refuses every path under `/root` (and under `/etc`, `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, `/boot`, and any path with a
component such as `.config`). The browser lane is not affected. `install.sh` now refuses such a prefix (exit status 2, the rule named; the list is read from the adapter kit inside the bundle), `doctor` has a check that names the
interpreter, the guard script or a `TMPDIR` under a refused path (the paths that are on the lane's command line) with the rule, exit status 3, and `run` and `demo` make the same check and refuse to start, and the bundle's CI job runs these cases as root. The refused-path list is not relaxed. As root use a prefix such as `/opt/redevops-qa`; `HOME` and the evidence directory may stay under `/root` (measured: the demo ends `VERIFIED`).

## What this does not show

* A verified run means that frozen assertions were evaluated over recorded observations; it does not show that an application is correct. The target here is a fixture app written to have two known defects.
* The hash chain inside an evidence bundle is unkeyed. Someone who can rewrite a whole bundle can rewrite its digests too. The anchor above is a value printed in a CI log and kept as an artifact of a finished run; a match
  shows that a bundle is the one the value was taken from, and nothing in the tool authenticates where the value came from.
* The demo is not signed: no key is held in CI. `redevops-qa verify` can also check an optional detached OpenSSH signature of the manifest digest against ONE Ed25519 public key you supply (`--anchor-sig`, `--anchor-pub`;
  `redevops-qa anchor statement` and `anchor sign` produce it with a key you hold; see `packages/qa-runner/README.md`). That shows the manifest digest was signed by the holder of the matching private key and that a bundle
  rewritten after signing does not verify; it does not show who holds that key, that the key was not exposed, when the signature was made, or that the run was executed on an uncompromised host. The `demo-verify` job
  only checks that `--require-signed-anchor` refuses the unsigned demo bundle (exit 5, `ANCHOR_SIGNATURE_REQUIRED`), which authenticates nothing.
* `verify` is a recomputation by the same code the run used, in a separate process; it is not an independent implementation of the verdicts. "Independent" in the output means independent of the engine's own status.
* Two assertions of the browser lane (`A-SAVED`, `A-URL`) are about what the browser shows and have no independent probe; the output says so.
* One platform, one Python minor, two engines: Linux x86_64, CPython 3.12, Playwright Chromium and Robot Framework. Chromium is downloaded by the bundle's browser step and checked against the pin `browser.lock.json` (archives by sha256 before unpacking, the unpacked tree file by file; the operating system libraries and the download host are not covered). The Robot lane's
  traffic does not pass the egress gateway (in the run quoted here nothing limited it; since then the plan can ask for kernel layers, whose limits are in the runner's README).
* The bundle is source-available under the family licence (AGPL-3.0-or-later with the Commons Clause), not open source; the harness it carries is plain AGPL-3.0-or-later, and the third-party wheels keep their own licences
  (see the bundle's README).
