# third_party

`adapter-license-matrix.yaml` records the licence facts for the optional execution-adapter frameworks (Selenium, Robot
Framework, Appium, Playwright) and the toolchains around them: project, pinned release and tag, SPDX licence, licence URL and file
hash, artifacts, bundled and direct dependencies, notices, trademark constraints and the redistribution status.

This is technical triage, not legal advice. Each fact says how it was checked (`verified` against the upstream file at the pinned tag,
`registry-metadata`, or `unverified`); an unverified fact never supports a redistribution claim.

`python tools/check_adapter_licenses.py` fails on an unknown or incompatible redistributable, on a package that an adapter package or
workflow installs without a matrix entry, and on a pin that differs from the matrix. `--verify-upstream` re-fetches each licence file
at its tag and compares hashes (network; not part of the offline test run). Commercial SDKs and Apple toolchains are listed as
`excluded_by_default` and are never bundled or downloaded.

The pinned bundle (`bundle/`, built by `tools/build_bundle.py`) carries unmodified wheels of Playwright, Robot Framework, PyYAML, greenlet, pyee and typing_extensions, named with
their digests in `bundle/third-party.lock.json`. Every one of them is recorded in the matrix under `shipped_wheels` with the licence and notice files the wheel itself carries, and the
status `staged_unmodified`: **private staging only; public distribution requires an owner decision.** `tools/check_adapter_licenses.py` fails when a wheel of the lock has no such entry
(same name, version, file name and sha256), when a recorded wheel is not in the lock, or when a shipped wheel sits under any other status.

What the two large wheels contain, from unpacking them: the Playwright wheel holds a Node.js runtime binary (`playwright/driver/node`, licence file `playwright/driver/LICENSE`), the
Playwright driver with 79 distinct npm packages inlined into it (`lib/utilsBundle.js` and `lib/serverRegistry.js`; 81 sidecar notice sections, because two packages appear in both files) and libwebp
(`lib/webp_codec.LICENSE`). The Robot Framework wheel holds five report assets in `robot/htmldata/lib` and an inlined JavaScript bundle in `robot/htmldata/libdoc/libdoc.html`.

What is established about them is recorded per component under `third_party_evidence` in the matrix, with the URL, the retrieval date and the sha256 of everything that was fetched, and only
where the exact component and version were identified from the shipped bytes and the licence text of that version was fetched from the primary source: the Node.js runtime (Node.js 24.22.1, byte
for byte the official release executable, with the release's `LICENSE`, whose 44 listed libraries are tabulated in `third_party/evidence/node-24.22.1-licence-sections.json`), the inlined npm packages
(`third_party/evidence/playwright-1.64.1-inlined-npm-packages.json`: per notice section, the registry entry and the published tarball of the exact version), minimatch (Blue Oak Model License 1.0.0),
jQuery 3.5.1 with Sizzle, and the libraries inlined in `libdoc.html` (Handlebars 4.7.9, mark.js 8.11.1, source-map 0.6.1, the Parcel runtime; the file was reproduced byte for byte from Robot Framework's
own build inputs). Two items have no licence text in any primary source that was looked at and stay open as `declared_only` (a licence is declared, no text exists): `proxy-agent-negotiate` 1.1.0
(declared MIT) and jQuery tablesorter 2.30.5 (declared `(MIT OR GPL-2.0)`); each lists the options the owner has and is named under `public_distribution_blockers`. A `verified` item records facts; it is
never a clearance, `public_distribution` stays `owner_decision_required`, and the checker fails on a `verified` item that lacks its evidence fields.

The licence and notice texts that ship are listed in `third_party/notices/notices.lock.json` (the licence files of the shipped wheels, read from those wheels, and the texts fetched from upstream, kept
under `third_party/notices/upstream/`, each with its sha256). `tools/build_bundle.py` writes them into the bundle as `THIRD_PARTY_NOTICES/` with an `INDEX.json`, refuses a file whose sha256 is not the
locked one, and also packs them as a wheel that installs `share/redevops-qa/THIRD_PARTY_NOTICES`; `tools/check_bundle.py` and `redevops-qa doctor` check the tree against its index.
`python tools/check_adapter_licenses.py --wheelhouse DIR [--notices DIR/../THIRD_PARTY_NOTICES]` re-checks the recorded digests, licence files, the notice breakdown, the two evidence tables and the notices tree
against the wheels of a built bundle (the `bundle` CI job does). `tools/collect_licence_evidence.py` makes the two evidence tables from a Playwright wheel. Nothing here is a clearance.
