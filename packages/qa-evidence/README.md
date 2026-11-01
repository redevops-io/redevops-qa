# qa-evidence

The portable evidence bundle for a ReDevOps QA run: the on-disk layout, the run-report schema, a reader and an offline verifier.
Standard library only (Python 3.11 or later); it imports no framework, no harness module and no contracts package, reads no clock, host
or environment variable, and opens no network connection.

Licence: the family licence of this repository (source-available, not open source; see `LICENSE.md`).

This package is the evidence format and its checks. It does not run a test engine and it does not produce verdicts: a producer (the
runner and the independent verifier, in other packages) hands it a report and the files the report refers to.

## What a verified bundle does and does not show

* **Unkeyed hashes.** The file digests and the manifest are plain SHA-256. They detect accidental changes and partial edits. They do
  **not** detect deliberate re-forging: anyone who can rewrite the whole bundle can recompute every digest and the manifest, and the
  result still verifies as internally consistent. The bundle says so in `bundle-manifest.json` (`integrity.statement`), in the
  `BUNDLE-FORMAT.txt` it carries, in the report's required limitations, and in every verification result and rendering.
* **External anchor.** Integrity against deliberate re-forging exists only when the digest of `bundle-manifest.json` is compared with a
  value published outside the bundle. The format provides the slot and the check; it does not create or verify any attestation.
  A CI job computes `python -m qa_evidence digest BUNDLE`, publishes that value through its own artifact-attestation step, and a
  consumer later supplies the published value with `--anchor`. Signed bundles are not part of this format version.
* **Native result versus verdict.** A lane's native result is the engine's own report (`NATIVE_PASS`, `NATIVE_FAIL`, ...). A verdict
  (`VERIFIED`, `FAILED`, `INCONCLUSIVE`, `UNACCOUNTED`) is produced by an independent verifier over recorded observations and frozen
  assertions, with provenance. The two live in different fields with disjoint vocabularies; a native pass never becomes `VERIFIED`, and
  a verdict may not name a native artifact as its evidence.
* **Not correctness.** A verified verdict says the frozen assertions were evaluated over the recorded observations. It does not say the
  application under test is correct.

## Layout

A bundle is a directory or a single-file archive holding the same relative paths.

```
bundle-manifest.json   every other file: path, sha256, size, role; run id, lanes (engine and version), tool versions, OS and
                       architecture, assertion-set digest(s), the integrity statement and an explicit anchor block
report.json            the run report (schema qa-evidence/run-report)
BUNDLE-FORMAT.txt      fixed text of this format version (listed in the manifest, compared byte for byte)
anchor.json            optional, data only: anchor type, anchor reference, manifest digest; NOT covered by the manifest
<everything else>      native artifacts, observations, logs, ... (each listed with a role)
```

Determinism: entries sorted by path (code-point order); canonical JSON (UTF-8 bytes, ASCII escapes, sorted keys, two-space indent, one
trailing newline, integers only); no clock, no user or host information; paths relative, NFC, `/` separators. The archive is an
uncompressed ustar archive written by this package with generated headers (mode 0644, uid and gid 0, no names, time 0, regular files,
names of at most 100 bytes, padded to 10240 bytes). Rebuilding from the same inputs gives byte-identical output on every host; the tests
pin golden digests that must be equal on macOS and on the Linux CI runner. Standard tools (`tar -tf`, `tarfile`) read the archive.

Path rules: components of letters, digits and `. _ - + = @ ,` (Unicode letters and digits allowed, NFC required); no `..`, no
absolute path, no drive letter or colon, no backslash, no empty or dot component, no leading or trailing dot, no Windows device name, no
control, format or separator character. Names that differ only in case or normalisation collide and are refused (also as directory
prefixes), as is a path that is both a file and a directory. Symbolic links, Windows reparse points (junctions), devices, pipes and
sockets are refused and never followed; in an archive, anything but a canonical regular-file header is refused.

### Caps (`Limits`, overridable by the caller)

| Cap | Default |
|---|---|
| files in a bundle | 4096 |
| one file | 64 MiB |
| all files | 256 MiB |
| path length / component length | 100 / 64 bytes |
| a JSON document (manifest, report, anchor) | 8 MiB |
| JSON nesting / items / one string | 24 / 20000 / 8192 characters |

A file over the cap is refused by its actual size and by the size the manifest declares; JSON documents are not parsed past the cap.

## Schemas and compatibility

The checked-in schemas are in `src/qa_evidence/schemas/` (`bundle-manifest-1`, `run-report-1`, `anchor-1`; JSON Schema 2020-12
vocabulary). `qa_evidence.minischema` validates them with no third-party code and refuses any schema keyword it does not implement.

Versioning: `schema_version` is `MAJOR.MINOR`; this reader supports major 1, minor 0.

| Situation | Result |
|---|---|
| unknown major version | refused (`UNSUPPORTED_MAJOR_VERSION`) before anything else is read |
| newer minor version | read under the same rules; a note `NEWER_MINOR_VERSION` is added to the result |
| unknown field in a **security-sensitive** object | refused (`UNKNOWN_FIELD`) |
| unknown field in an **informational** object | tolerated and listed in `informational_fields`; never used for a decision |

Informational objects are only `environment` (beyond `os`, `arch`, `python`), `producer` and `extensions`, and their extra properties
must have short lowercase names and scalar values. Everything else is security-sensitive: files, digests, run and lane ids, assertion
accounting, native results, verdicts, provenance, anchor data. Duplicate JSON keys, floats, `NaN`, a byte-order mark, lone surrogates and
non-canonical bytes are refused.

### Run report (`qa-evidence/run-report`)

`run_id`, `started_at`, `finished_at` (supplied by the producer), `plan_digest`, `environment`, then:

* `lanes[]`: `lane_id`, `run_id`, `engine {name, version}` and `native {status, raw_status, exit_code, counts?, artifacts[{path, digest, size}]}`.
* `assertion_set`: the frozen assertions `{assertion_id, lane_id, digest}` and their digest.
* `accounting`: `frozen = verified + failed + inconclusive + unaccounted`, and `results[]`, one per frozen assertion exactly once, each with the
  engine's `native_status` (or null) and a `verdict {state, reason_code, provenance}`. Provenance names the verifier (id and version), the
  assertion digest and the evidence (`path`, `digest`); it is null only for `UNACCOUNTED`, and a `VERIFIED` verdict must name its evidence.
* `verdict`: the run outcome, which must equal what the accounting gives (any `FAILED` fails; anything not `VERIFIED`, or nothing frozen, is
  `INCONCLUSIVE`), bound to the assertion-set digest and an evidence-set digest.
* `redaction` (rules and notes) and `limitations` (the three required statements, unchanged, plus any of your own).

Cross-checks between manifest and report: run id, lanes with engine versions, environment, assertion-set digest, every native artifact and
every evidence file present in the manifest with the same digest, native artifacts with role `native-artifact`, evidence with role
`observation` or `record`.

## Verification

`verify_bundle(location, anchor=None)` (offline) recomputes every hash and returns a `VerifyResult`: findings (stable codes), the
anchor result, the manifest digest, tolerated informational fields and notes. Finding codes include `DIGEST_MISMATCH`, `SIZE_MISMATCH`,
`MISSING_FILE`, `EXTRA_FILE`, `DUPLICATE_PATH`, `DUPLICATE_LANE_ID`, `PATH_TRAVERSAL`, `PATH_ABSOLUTE`, `PATH_UNSAFE`, `PATH_NOT_NFC`,
`PATH_TOO_LONG`, `CASE_COLLISION`, `FILE_DIR_CONFLICT`, `SYMLINK_REFUSED`, `JUNCTION_REFUSED`, `SPECIAL_FILE`, `OVERSIZE_ENTRY`,
`OVERSIZE_BUNDLE`, `TOO_MANY_FILES`, `ARCHIVE_NONCANONICAL`, `UNSUPPORTED_MAJOR_VERSION`, `UNKNOWN_FIELD`, `SCHEMA_INVALID`,
`MANIFEST_NOT_CANONICAL`, `MANIFEST_REPORT_MISMATCH`, `ACCOUNTING_*`, `VERDICT_*`, `PROVENANCE_RULE`, `EVIDENCE_ROLE`, `ANCHOR_MISMATCH`.

The anchor result has one of five states:

| State | Meaning | Establishes integrity against deliberate re-forging |
|---|---|---|
| `absent` | no anchor value and no `anchor.json` | no |
| `declared` | `anchor.json` present and matching, no external value supplied | no (the sidecar can be rewritten with the bundle) |
| `verified` | a supplied value equals the recomputed manifest digest | yes, to the extent the supplied value came from a channel the forger cannot write; this tool does not check that |
| `mismatch` | the supplied value, or the digest named in `anchor.json`, differs | verification fails |
| `invalid` | the supplied value or `anchor.json` is malformed | verification fails |

`ok` means no findings. It is not folded together with the anchor state: a result can be `ok` and still say
`no external anchor: integrity against deliberate re-forging NOT established`.

## Command line

```
python -m qa_evidence inspect BUNDLE [--json] [--anchor sha256:HEX] [--require-anchor]
python -m qa_evidence verify  BUNDLE [--json] [--anchor sha256:HEX] [--require-anchor]
python -m qa_evidence html    BUNDLE [-o FILE] [--anchor sha256:HEX]
python -m qa_evidence digest  BUNDLE          # the manifest digest an external anchor should hold (only for a bundle that verifies)
python -m qa_evidence anchor  BUNDLE --type ci-artifact-attestation --reference REF    # anchor.json data on stdout; no attestation is made
```

Exit status: 0 clean, 1 findings, 2 usage or the location cannot be opened, 3 `--require-anchor` and no verified anchor. The HTML is one
file: inline style, no script, no image, no external reference, a Content-Security-Policy that forbids loading anything, and every value
from the bundle escaped (control, bidirectional and zero-width characters shown as `\uXXXX`).

## Building (library)

```python
from qa_evidence.report import assemble_report
from qa_evidence.build import build_bundle

report = assemble_report(run_id=..., started_at=..., finished_at=..., plan_digest=..., environment={...}, lanes=[...],
                         frozen=[...], results=[...], verifier={"id": ..., "version": ...})
bundle = build_bundle(report=report, files={"lanes/robot/output.xml": (data, "native-artifact"), ...}, tools={"orchestrator": "0.1.0"})
bundle.write_archive("evidence.tar")          # or bundle.write_directory("evidence/")
print(bundle.manifest_digest)                 # hand to the CI job's attestation step
```

`assemble_report` computes the digests, counts and outcome instead of trusting the caller; `build_bundle` validates the report and the
files and runs the verifier over its own output before returning.

## Tests

`python -m pytest -q packages/qa-evidence/tests` (no network, no skip). Includes the tamper matrix, determinism and golden vectors,
schema positive and negative tests, hostile-string HTML tests and a mutation suite (`test_qe_mutations.py`) that removes one guard of the
verifier at a time and requires a named test to fail.
