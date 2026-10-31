# qa-bridge

The only package in `redevops-qa` that imports both sides of the QA data contract:

* **contracts**: `runtime_contracts.qa` from `runtime-contracts`, the canonical `qa/v1` schemas (hash spelling `rcv1:<hex>`);
* **neutral**: `agent_harness.qa` from `agent-harness`, a standalone mirror of the same records, protocols and hashing
  (hash spelling `canon-v1:<hex>`). It imports nothing from contracts.

For equal payloads the 64 hex digits are equal; the bridge maps the prefix and refuses to return anything on which the two
sides disagree. Contracts is canonical; on a conflict the neutral mirror is corrected, never the other way round.

Licence: the family licence of this repository (source-available; see `LICENSE.md`).

## What crosses the boundary: data only

A conversion is `object.to_json()` on the source side, a pure dictionary transformation, and `from_json` on the destination
side. No class instance of one side is handed to the other, and `assert_data_only` refuses anything that is not plain JSON
(class instances, enums, floats, mappings that are not `dict`).

**Verify on convert.** After the destination object exists, the digest it computes for itself must equal the digest the
source computed. A difference raises `HashDisagreement` (`HASH_DISAGREEMENT`); the converted object is never returned.
The checked-in tests and the conformance suite use this to surface places where the two implementations differ.

## API (`redevops_qa_bridge`)

| Area | Functions and classes |
|---|---|
| Conversion | `from_contracts(obj)`, `to_contracts(obj)` for every record, value, reused repository type (`Check`, `EvidenceRef`, `SecretRef`) and enum; `contracts_data_to_neutral(data)`, `neutral_data_to_contracts(data)` at the dictionary level; `registry()` lists the type pairs found in the pinned packages |
| Hashes | `to_contracts_hash` (`canon-v1:` to `rcv1:`), `to_neutral_hash`, `contracts_digest`, `neutral_digest` |
| Plans | `validate_plan(plan)` and `runnable_items(plan)` reject `coverage_contract != FULL` (`UNSUPPORTED_COVERAGE_CONTRACT`) before any item is released; the harness never sees a plan |
| Adapters | `NeutralQAAdapterFromContracts`, `ContractsQAAdapterFromNeutral`, `NeutralCheckAdapterFromContracts`, `ContractsCheckAdapterFromNeutral`, blob store and redactor shims: one component, both protocol forms |
| Errors | `neutral_error_for_contracts`, `contracts_error_for_neutral`, `contracts_to_neutral()` / `neutral_to_contracts()` context managers; only the stable `code` crosses |
| Stores | `ContractsSpecStore` (loads contracts specs, pins `assertion_set_hash` with `rcv1`, cross-checks it with `canon-v1`, serves frozen assertions by hash, read-only), `EvidenceSink` (harness `EvidenceStream` over a contracts-side appender) |
| Policy | `PolicyPlaneActionPolicy`: data-only adapter from a policy-plane provider to the neutral `ActionPolicy`; fails closed |

### Typed errors and their codes

Every bridge error subclasses `BridgeError` and carries a stable `code`:
`DEPENDENCY_UNAVAILABLE`, `PINS_INVALID`, `PIN_MISMATCH`, `DATA_ONLY_VIOLATION`, `UNKNOWN_SCHEMA`, `UNKNOWN_TYPE`,
`HASH_DISAGREEMENT`, `HASH_FORMAT`, `CONVERSION_REFUSED` (with `details["cause_code"]` set to the destination's own code),
`ERROR_CODE_UNMAPPED`, `ADAPTER_REFUSED`, `SPEC_STORE_REFUSED`, `EVIDENCE_REFUSED`, `POLICY_REFUSED`, `BLOB_STORE_FAULT`.
Plan refusals keep the contracts reason code (`UNSUPPORTED_COVERAGE_CONTRACT`, `UNKNOWN_FIELD`, `PLAN_INVALID`, ...).

## Pins

`pins.toml` at the repository root is the single configuration of what the bridge is tied to. It holds named **pin sets**
(`[sets.c3]`, `[sets.c4]`; `default_set` is used unless `REDEVOPS_QA_PIN_SET` or `--pin-set` selects one). For `contracts`
and `harness_qa` a pin set lists the repository, version, git tag (empty while the pin is a draft `TEMP-PIN`), full commit sha, the
source tree to import from, the sha256 of the distribution tree and the sha256 of every vector file. Nothing about a
dependency is hard-coded elsewhere.

* `redevops_qa_bridge.deps.prepare_paths(pins)` puts the pinned trees first on `sys.path`.
* `redevops_qa_bridge.deps.verify_pins(pins)` fails (`PIN_MISMATCH`) unless the imported packages live in the pinned trees,
  the distribution digest and every vector file digest match, no vector file matching an addendum glob is unlisted, the
  tree's declared version is the pinned one and, for a git checkout, `HEAD` is the pinned commit.
* A missing or unimportable dependency raises `DEPENDENCY_UNAVAILABLE`. It is a failure, never a skip.
* `python -m redevops_qa_bridge.pins [--forbid-temp-pin]` checks the file (CI runs the strict form on `main`).

This package's `pyproject.toml` declares **no** runtime dependency on `runtime-contracts` or `agent-harness`. At test time
the pinned trees are imported from the paths in `pins.toml` (`.pinned/runtime-contracts`, `.pinned/agent-harness` by
default; `QA_PIN_CONTRACTS_PATH` and `QA_PIN_HARNESS_QA_PATH` override the paths per machine, never the digests). A real
installation pins exact tags instead, for example:

```text
pip install "runtime-contracts @ git+https://github.com/redevops-io/runtime-contracts@<exact tag>"
pip install "agent-harness @ git+https://github.com/redevops-io/agent-harness@<exact tag>"
```

and then sets `tag`, `commit`, `temp_pin = false`, `distribution_sha256` and the vector file digests in `pins.toml` to the
values of those tags. A floating install is a failure of the conformance suite, not a warning.

## Tests

From the repository root, in a scrubbed environment with the pinned trees available:

```text
env -i HOME="$(mktemp -d)" PATH="$PATH" LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 python -m pytest -q
```

`tools/check_junit.py` turns a JUnit report into a failure on zero collected tests or any skip (CI uses it).

## Conformance suite (release-critical)

`tests/conformance/` makes the contracts `qa/v1` schemas and the harness neutral mirror one contract (ADR A.2.5). It runs
against the **exact** pinned versions, fails (never skips) when either dependency is unavailable or inexact, and a run is
only valid with a nonzero collected count and zero skips. Seven checks, one test per item:

| id | check |
|---|---|
| CHK1 | hash equality, contracts to neutral: every golden case and value, assertion sets and relations, every vector of every pinned canonical vector file (the 97 frozen vectors and any addendum), predicate and value digests, set ordering |
| CHK2 | hash equality, neutral to contracts: the harness vector files and neutral parses of the golden inputs; a contracts vector without a matching harness vector fails |
| CHK3 | identity and custody field parity per schema, schema ids and versions |
| CHK4 | enum parity |
| CHK5 | protocol parity (`QAAdapter`, `CheckAdapter`, `BlobStore`, `Redactor`), a reference adapter against both forms, `qa-playwright` once configured |
| CHK6 | mutation-refusal parity (every refusal fixture, same reason code on both sides) and error-code parity |
| CHK7 | round trip, contracts to neutral to contracts is the identity |

Derived variants (legal payloads built from golden cases) cover the optional fields of the three reused repository types.
The allow-lists the parity checks accept (contracts-only schemas, enums and error codes) are in `[conformance]` of
`pins.toml`; anything not listed fails.

```text
python -m redevops_qa_bridge.conformance.cli run --pin-set c4 --receipt compat-receipt.json \
    --report divergence-report.json --report-md divergence-report.md
python -m redevops_qa_bridge.conformance.cli verify compat-receipt.json --pin-set c4
```

`run` writes one `compat-receipt/1` JSON (fields per ADR A.2.7; `receipt_hash` is the sha256 of the canonical JSON of every
other field) and exits 0 only if its `result` is `PASS`. `verify` re-checks the hash and the receipt's own consistency and
reports `VALID`, `STALE` (some pin differs from what the receipt was made against; exit 2), `TAMPERED`, `INVALID` or
`FAILED`. A receipt is evidence for exactly the pins and the `redevops-qa` commit it records.
