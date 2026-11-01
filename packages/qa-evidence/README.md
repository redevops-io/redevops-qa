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
  consumer later supplies the published value with `--anchor`. A match means "equals the supplied value" (`matches_supplied_value`),
  never "integrity established": a digest taken from the same bundle always matches, and the tool does not know where a supplied value came
  from. `digest` and `anchor` print that caveat on standard error. Signed bundles are not part of this format version (the anchor type
  `signed-bundle` is refused).
* **The frozen assertion set is declared by the producer.** `assertion-lock.json` holds the frozen assertions; its sha256 is the
  assertion-set digest and, in this format version, the plan digest, and the report, the manifest and the verdict provenance must all
  carry that same value. A forger who removes a failing assertion and recomputes every digest, the lock and the plan digest included,
  produces a bundle that verifies internally; only a plan digest obtained from outside the bundle (`--plan-digest sha256:HEX`, the value
  the freeze step printed) shows the difference. Without one, every result says "frozen assertion set not checked against an external
  plan digest".
* **Native result versus verdict.** A lane's native result is the engine's own report (`NATIVE_PASS`, `NATIVE_FAIL`, ...). A verdict
  (`VERIFIED`, `FAILED`, `INCONCLUSIVE`, `UNACCOUNTED`) is produced by an independent verifier over recorded observations and frozen
  assertions, with provenance. The two live in different fields with disjoint vocabularies and a native pass never becomes `VERIFIED`.
  What the verifier enforces about evidence, and what it cannot:
  * enforced: a verdict's evidence file must be listed in the manifest with the digest the report names and the role `observation` or
    `record`; its digest must not equal the digest of any `native-artifact` file, of any artifact the lanes list, or of any file under
    `lanes/<lane>/native/`; its path must not be under `lanes/*/native/`; everything under `lanes/<lane>/native/` must carry the role
    `native-artifact`, and a native artifact must live under its own lane's native directory. Copying engine bytes into an observation
    file, or labelling them differently, is therefore refused.
  * not enforced, and not claimed: that an observation file really is what the independent verifier saw, or that it was derived from
    the engine report by the importer and not written by hand. Roles are labels written by the producer. The authenticity of a Robot
    observation file depends on the importer that wrote it and on the external anchor and CI provenance of the bundle.
  * not enforced, and not claimed: that the verifier is independent. `verifier` is a name and a version the producer wrote; the
    manifest must list the same verifier version under `tools`, and that is all that is checked.
* **Run outcome.** `VERIFIED` needs every frozen assertion verified, every lane to have run to completion (`NATIVE_PASS` or `NATIVE_FAIL`;
  an error, timeout, unavailable or skipped lane makes the run `INCONCLUSIVE`) and every lane to have at least one frozen assertion.
* **Not correctness.** A verified verdict says the frozen assertions were evaluated over the recorded observations. It does not say the
  application under test is correct.

## Layout

A bundle is a directory or a single-file archive holding the same relative paths.

```
bundle-manifest.json   every other file: path, sha256, size, role; run id, plan digest, lanes (engine and version), tool versions,
                       OS and architecture, assertion-set digest(s), the integrity statement and an explicit anchor block
report.json            the run report (schema qa-evidence/run-report)
assertion-lock.json    the frozen assertions (id, lane, digest); its sha256 is the assertion-set digest and the plan digest
BUNDLE-FORMAT.txt      fixed text of this format version (listed in the manifest, compared byte for byte)
anchor.json            optional, data only: anchor type, anchor reference, manifest digest; NOT covered by the manifest
lanes/<lane>/native/   what the lane's engine wrote (role native-artifact); nothing else may be there
<everything else>      observations, records, logs, ... (each listed with a role)
```

Determinism: entries sorted by path (code-point order); canonical JSON (UTF-8 bytes, ASCII escapes, sorted keys, two-space indent, one
trailing newline, integers only); no clock, no user or host information; paths relative, ASCII, `/` separators. The archive is an
uncompressed ustar archive written by this package with generated headers (mode 0644, uid and gid 0, no names, time 0, regular files,
names of at most 100 bytes, zero padding after every entry, padded to 10240 bytes). Rebuilding from the same inputs gives byte-identical
output on every host; the tests pin golden digests that must be equal on macOS and on the Linux CI runner. Standard tools (`tar -tf`,
`tarfile`) can read the archive, but the format is one-way: an archive re-created by another tool, even from the same files, is refused
(`ARCHIVE_NONCANONICAL`); only this package writes the canonical form. Every single-byte change of the archive is detected when the
manifest digest is supplied as the anchor; without it, the only changes that still verify are inside the manifest's descriptive metadata
(`producer`, tool names and versions, the minor schema version), which is exactly what the anchor exists to catch.

Path rules: components of ASCII letters, digits and `. _ - + = @ ,` only; no `..`, no absolute path, no empty or dot component, no leading
or trailing dot, no Windows device name. ASCII only is deliberate: the accept/reject decision never depends on the Unicode database of the
interpreter (a character unassigned in one Python release and assigned in the next would make one bundle verify on one host and fail on
another), and NFC, case folding and confusable names stop being a question. Backslash, colon (drive letters, alternate streams), space,
wildcards and every control, format or separator character are refused by the same rule, a non-ASCII name with `PATH_NOT_ASCII`. Names that
differ only in case collide and are refused (also as directory prefixes), as is a path that is both a file and a directory. Symbolic links,
Windows reparse points (junctions), devices, pipes, sockets and empty directories are refused and never followed; in an archive, anything but
a canonical regular-file header is refused.

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

`run_id`, `started_at`, `finished_at` (supplied by the producer), `plan_digest` (required), `environment`, then:

* `lanes[]`: `lane_id`, `run_id` (must be `<run id>.<lane id>`), `engine {name, version}` and
  `native {status, raw_status, exit_code, counts?, artifacts[{path, digest, size}]}`. A `NATIVE_PASS` lane may not report failed or errored
  tests or a non-zero exit code; a `NATIVE_FAIL` lane may not exit 0 and, when counts are given, must report a failure.
* `assertion_set`: the frozen assertions `{assertion_id, lane_id, digest}` and their digest. Every lane needs at least one.
* `accounting`: `frozen = verified + failed + inconclusive + unaccounted`, and `results[]`, one per frozen assertion exactly once, each with the
  engine's `native_status` (or null) and a `verdict {state, reason_code, provenance}`. The reason code comes from a closed list per state
  (`VERIFIED`: `EQUALS_EXPECTED`, `PREDICATE_HOLDS`; `FAILED`: `EXPECTED_VALUE_DIFFERS`, `PREDICATE_VIOLATED`; `INCONCLUSIVE`:
  `EVIDENCE_MISSING`, `EVIDENCE_UNUSABLE`, `ASSERTION_INTEGRITY`, `VERIFIER_ERROR`; `UNACCOUNTED`: `NO_RESULT_RECORDED`). Provenance names
  the verifier (id and version), the assertion digest and the evidence (`path`, `digest`); it is null only for `UNACCOUNTED`, and a
  `VERIFIED` verdict must name its evidence.
* `verdict`: the run outcome, which must equal what the accounting and the lanes give (any `FAILED` fails; anything not `VERIFIED`, nothing
  frozen, or a lane that did not run to completion is `INCONCLUSIVE`) with the one reason code for that outcome
  (`ALL_ASSERTIONS_VERIFIED`, `ASSERTION_FAILED`, `NOT_ALL_ASSERTIONS_VERIFIED`, `ENGINE_DID_NOT_COMPLETE`), bound to the plan digest, the
  assertion-set digest and an evidence-set digest.
* `redaction` (rules and notes; rules need `applied: true`) and `limitations` (the three required statements, unchanged, plus any of your own).

The format is not released; changes made after review of the first version (non-null plan digest, assertion lock, lane run id relation,
native directory, closed reason codes, ASCII paths) are made in schema version 1.0 and the three required limitation texts are unchanged.

Cross-checks between manifest and report: run id, lane run ids, lanes with engine versions, environment, plan digest, assertion-set digest,
the assertion lock, the verifier named by the report listed in `tools` with its version, every native artifact and every evidence file
present in the manifest with the same digest, the native and evidence rules above. Ids that differ only in case (lanes, assertions) are a
finding (`DUPLICATE_ID_CASE`).

## Verification

`verify_bundle(location, anchor=None, plan_digest=None)` (offline) recomputes every hash and returns a `VerifyResult`: findings (stable
codes), the anchor result, the plan result, the manifest digest, tolerated informational fields and notes. `ok` is false unless both the
manifest and the report were read, parsed as JSON objects and schema-valid (`complete`); a document that is `null`, an array or any other
non-object is `MANIFEST_UNREADABLE` / `REPORT_UNREADABLE` / `ANCHOR_UNREADABLE`. Finding codes include `DIGEST_MISMATCH`, `SIZE_MISMATCH`,
`MISSING_FILE`, `EXTRA_FILE`, `EMPTY_DIRECTORY`, `DUPLICATE_PATH`, `DUPLICATE_LANE_ID`, `DUPLICATE_ID_CASE`, `PATH_TRAVERSAL`, `PATH_ABSOLUTE`,
`PATH_UNSAFE`, `PATH_NOT_ASCII`, `PATH_TOO_LONG`, `CASE_COLLISION`, `FILE_DIR_CONFLICT`, `SYMLINK_REFUSED`, `JUNCTION_REFUSED`,
`SPECIAL_FILE`, `OVERSIZE_ENTRY`, `OVERSIZE_BUNDLE`, `TOO_MANY_FILES`, `ARCHIVE_NONCANONICAL`, `UNSUPPORTED_MAJOR_VERSION`, `UNKNOWN_FIELD`,
`SCHEMA_INVALID`, `INCOMPLETE_VERIFICATION`, `MANIFEST_NOT_CANONICAL`, `MANIFEST_REPORT_MISMATCH`, `LANE_WITHOUT_ASSERTIONS`,
`LANE_RUN_ID_MISMATCH`, `NATIVE_STATUS_INCONSISTENT`, `NATIVE_ARTIFACT_LOCATION`, `REASON_CODE_STATE_MISMATCH`, `REDACTION_INCONSISTENT`,
`TOOLS_VERIFIER_MISMATCH`, `ASSERTION_LOCK_MISSING`, `ASSERTION_LOCK_MISMATCH`, `PLAN_DIGEST_MISMATCH`, `ACCOUNTING_*`, `VERDICT_*`,
`PROVENANCE_RULE`, `EVIDENCE_ROLE`, `EVIDENCE_IS_NATIVE_BYTES`, `EVIDENCE_IN_NATIVE_DIRECTORY`, `ANCHOR_MISMATCH`.

The anchor result has one of five states:

| State | Meaning | Establishes integrity against deliberate re-forging |
|---|---|---|
| `absent` | no anchor value and no `anchor.json` | no |
| `declared` | `anchor.json` present and matching, no external value supplied | no (the sidecar can be rewritten with the bundle) |
| `verified` | a supplied value equals the recomputed manifest digest (`matches_supplied_value: true`) | only if the supplied value came from a channel the forger cannot write; this tool does not check that, and a digest taken from the same bundle always matches |
| `mismatch` | the supplied value, or the digest named in `anchor.json`, differs | verification fails |
| `invalid` | the supplied value or `anchor.json` is malformed | verification fails |

The plan result has the states `absent` (no `--plan-digest` supplied: the assertion set is the producer's word), `verified`, `mismatch` and
`invalid`, with the same caveat about where the supplied value came from.

`ok` means no findings and a complete read. It is not folded together with the anchor or plan state: a result can be `ok` and still say
`no external anchor: integrity against deliberate re-forging NOT established`.

## Command line

```
python -m qa_evidence inspect BUNDLE [--json] [--anchor sha256:HEX] [--require-anchor] [--plan-digest sha256:HEX]
python -m qa_evidence verify  BUNDLE [--json] [--anchor sha256:HEX] [--require-anchor] [--plan-digest sha256:HEX]
python -m qa_evidence html    BUNDLE [-o FILE] [--anchor sha256:HEX] [--plan-digest sha256:HEX]
python -m qa_evidence digest  BUNDLE          # the manifest digest an external anchor should hold (only for a bundle that verifies)
python -m qa_evidence anchor  BUNDLE --type ci-artifact-attestation --reference REF    # anchor.json data on stdout; no attestation is made
```

Exit status: 0 clean, 1 findings, 2 usage or the location cannot be opened, 3 `--require-anchor` and no matching anchor value, 4 an internal
error (a crash is never reported as a finding). Every string that comes from a bundle is escaped before it is printed (control, bidirectional,
zero-width, separator and non-plain space characters shown as `\uXXXX`), in the text output, the error messages and the HTML. The HTML is one
file: inline style, no script, no image, no external reference, and a Content-Security-Policy that forbids loading anything.

## Building (library)

```python
from qa_evidence.report import assemble_report, assertion_set_digest
from qa_evidence.build import build_bundle

report = assemble_report(run_id=..., started_at=..., finished_at=..., plan_digest=assertion_set_digest(frozen), environment={...},
                         lanes=[...], frozen=[...], results=[...], verifier={"id": ..., "version": ...})
bundle = build_bundle(report=report, files={"lanes/robot/native/output.xml": (data, "native-artifact"), ...}, tools={"orchestrator": "0.1.0"})
bundle.write_archive("evidence.tar")          # or bundle.write_directory("evidence/")
print(bundle.manifest_digest)                 # hand to the CI job's attestation step
```

`assemble_report` computes the digests, counts, outcome and reason codes instead of trusting the caller; `build_bundle` validates the
report and the files, writes `assertion-lock.json`, lists the verifier under `tools`, and runs the verifier over its own output before
returning.

## Tests

`python -m pytest -q packages/qa-evidence/tests` (no network, no skip). Includes the tamper matrix, determinism and golden vectors,
schema positive and negative tests, hostile-string text and HTML tests, regression tests for every finding of the independent review
(`test_qe_review.py`, including an exhaustive one-byte-change test over the golden archive) and a mutation suite
(`test_qe_mutations.py`) that removes one guard at a time and requires a named test to fail.
