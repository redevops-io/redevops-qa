# qa-robot

The Robot Framework suite adapter of ReDevOps QA, built on the shared `qa-adapter-kit`. Robot Framework is an optional, pinned extra
(`robotframework==7.5`, Apache-2.0; see `third_party/adapter-license-matrix.yaml`). It is not bundled and nothing is installed or downloaded.

```text
SuiteRunner -> RobotSuiteAdapter -> supervised `python -I -m robot --outputdir <throwaway> --log NONE --report NONE ...`
            -> output.xml (schema version 5) -> native assertions + robot-summary.json
```

Licence: the family licence of this repository (source-available; see `LICENSE.md`).

## What it does

* Runs an existing suite as one supervised process. It does not steer a test. Selectors are test names (`--test`) or `tag:<name>` (`--include`).
* **Allowlist of libraries.** Before the run the `.robot` and `.resource` files are scanned: a library that is not on the allowlist is refused (default
  `BuiltIn`, `Collections`, `DateTime`, `String`, `XML`; no `OperatingSystem`, `Process`, `Remote`, `Dialogs`, `Screenshot`, `Telnet`), an alias cannot
  launder one, a library file needs a reviewed SHA-256, a resource must be a file inside the workspace, a variable file must be YAML or JSON, and the
  constructs that load or evaluate code at run time (`Evaluate`, `Import Library`, `Import Resource`, `Import Variables`, `Get Library Instance`,
  `Set Library Search Order`, `${{ }}`) are refused. After the run, a report whose keywords belong to a library that was not allowed, or that called one of
  those dynamic keywords (for example by building the name at run time), is refused. Nothing is ever installed: no code path runs a package installer, and
  a sealed run cannot start one.
* **Strict import.** Only test-level facts are read: status, message, tags, duration and the suite path. A tag `qa-assert:<id>` declares the canonical
  assertion id a test is evidence for. A DOCTYPE or entity declaration, an oversized file, another schema version, an RPA run, a test without a PASS, FAIL or
  SKIP status and statistics that disagree with the tests (a truncated file) are refused. Exit codes above 250 mean the report is not trusted.
* **No secrets in evidence.** Keyword arguments and log messages are never copied. The raw `output.xml` stays in the run's throwaway directory; the evidence
  artifact is `robot-summary.json` (no messages, no arguments, the digest of the raw file). `RobotConfig.keep_raw_output` copies the raw file too, and the
  runner refuses it if it holds a known secret.
* Native PASS is never promoted: mapping needs an explicit mapping and a declared id, and the canonical status stays `UNVERIFIED`.

This is a guard, not a sandbox. A static scan cannot see every way a Python-capable keyword could load code, and the suite is only bounded by the
supervisor (deadline, output limit, environment, process group). A hostile suite is contained by the worker, not by the allowlist.

## Tests

* **Offline (default).** `python -m pytest packages/qa-robot/tests`: the importer against `output.xml` files recorded from real Robot Framework 7.5 runs and
  against hostile ones, the allowlist scan and run check, and the adapter through the supervisor with a stand-in for `python -m robot` that writes a recorded
  file. Robot Framework is not installed and nothing touches the network.
* **Real framework.** `tests/real`, every test marked `robot_real`, run only by the `robot-real` CI job (Robot Framework 7.5 pinned, no browser, no secret). It
  fails, never skips, when Robot Framework is missing, and is not a required check until it has been shown to pass in CI.
