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
own build inputs). 
<!-- evidence-status:begin -->
At this head the matrix has 29 evidence items: 19 `verified`, 9 `declared_only` (`pw-proxy-agent-negotiate`, `pw-vite-browser-logos`, `pw-vite-codicon`, `rf-asserts-unittest`, `rf-highlighting-burgaud`, `rf-jquery-highlight`, `rf-jquery-tmpl`, `rf-jsxcompressor`, `rf-tablesorter-2.30.5`) and 1 `unverified` (`rf-htmldog-tabs`). Every item that is not `verified` is named under `public_distribution_blockers` of its entry. 5 items carry a recorded owner decision and 29 shipped items (the evidence items and components without a settled decision) still say `none yet`. This paragraph is checked against the matrix by `tests/test_third_party_evidence.py`; a `verified` item records facts, never a clearance, `public_distribution` stays `owner_decision_required`, and the checker fails on a `verified` item that lacks its evidence fields.
<!-- evidence-status:end -->

The licence and notice texts that ship are listed in `third_party/notices/notices.lock.json` (the licence files of the shipped wheels, read from those wheels, and the texts fetched from upstream, kept
under `third_party/notices/upstream/`, each with its sha256). `tools/build_bundle.py` writes them into the bundle as `THIRD_PARTY_NOTICES/` with an `INDEX.json`, refuses a file whose sha256 is not the
locked one, and also packs them as a wheel that installs `share/redevops-qa/THIRD_PARTY_NOTICES`; `tools/check_bundle.py` and `redevops-qa doctor` check the tree against its index.
`python tools/check_adapter_licenses.py --wheelhouse DIR [--notices DIR/../THIRD_PARTY_NOTICES]` re-checks the recorded digests, licence files, the notice breakdown, the two evidence tables and the notices tree
against the wheels of a built bundle (the `bundle` CI job does). `tools/collect_licence_evidence.py` makes the two evidence tables from a Playwright wheel. Nothing here is a clearance.

## How the inventory is derived, and what it cannot show

"What third-party material do the shipped wheels contain" is not answered by any one file, so the matrix derives it from several sources and says where each stops (the same text is in the `inventory`
block of the matrix, which the checker requires):

1. **Each wheel's own notice files**: the licence and notice files the wheel carries (Playwright's `ThirdPartyNotices.txt`, the sidecar `*.LICENSE` files, `driver/LICENSE`; Robot Framework's
   `LICENSE.txt` and `AUTHORS.rst`; the dist-info licence files of the Python wheels). They name what their authors chose to name.
2. **Node.js's LICENSE sections**: the externally maintained libraries the LICENSE of the exact Node.js release lists (`third_party/evidence/node-*-licence-sections.json`).
3. **Playwright's lock file and import statements at the pinned tag** for what the vite bundles and `coreBundle.js` resolve: `tools/collect_licence_evidence.py import-candidates` reads the repository
   tarball of the tag, takes the bare package names imported by the sources of the packages that end up in the wheel (tests excluded) and keeps those the lock file resolves
   (`third_party/evidence/playwright-*-import-candidates.json`). Each candidate must be among the inlined npm packages of the sidecar notices, named in an evidence item (`packages`), or listed under
   `inventory.excluded_packages` with the reason it is not in the wheel (build tools, development-only dependencies, a package required at run time by path but not shipped).
4. **A licence and copyright header scan of every text file of the Playwright and Robot Framework wheels** (`scan_wheel_inventory` in `tools/check_adapter_licenses.py`; `python tools/collect_licence_evidence.py inventory --wheel
   WHEEL` prints the candidates and which are covered): a file that names a copyright holder other than the product's own (`inventory.own_holders`), or carries a licence marker ("Licensed under", "Permission is
   hereby granted", SPDX identifier, "Dual licensed", "All rights reserved") without a holder, is a candidate. `tools/check_adapter_licenses.py --wheelhouse` FAILS when a candidate is not covered by an
   evidence item (its `shipped_members`, `inlined_in` or `covers_paths`) or a recorded licence file.
5. **Reading by hand** for what 1 to 4 leave open (for example the codicon font, whose licence is not in the file, and the logo packages that declare none).

**Limits.** This is best effort: it cannot prove that the inventory is complete, and the checker does not claim completeness. What it cannot find: a minified file whose comments were stripped, a library with no notice or header, data inlined as an
opaque string (the logo data URIs, a font), code reached through a path the import scan does not follow, and anything a bundler inlined that no source of Playwright imports by a bare package name are
not found by 3 or 4. Several items of this matrix were found by hand after the first lists were written; the scans exist so that the next such item fails the check instead of waiting for a reviewer,
not to show that no further item exists. Quotes of declaring sources are checked against the stored bytes where the source is pinned in `THIRD_PARTY_NOTICES` (same URL) or is a member of the shipped wheel
(`wheel_member`); the other quotes are checked only for presence and format.

**Owner decisions.** The wording of the owner's decisions of 2026-11-03 (the decision, its date, the elected licence and the minimum conditions) is kept in the checker as `REQUIRED_DECISIONS`, so deleting or
weakening a condition in the record is a finding (`OWNER_CONDITION_WEAKENED`); the record may state more than the owner required, never less. The checker cannot know that the owner took a decision: it keeps the
recorded wording from being edited away, it does not authenticate the decision.

**Known limits of the header scan** (listed, not closed; each was found by a reviewer or by reading the scan's own code):
* a file whose only marker is an Apache-2.0 header and that has no copyright line is skipped by design (it is taken to be the product's own);
* `.map` files, files that start with NUL bytes and non-text assets (SVG, PNG, fonts, icons, favicons, data URIs) are not scanned; the logo and icon data inlined as `data:` URIs are tied to their packages by hand;
* `covers_paths` globs can be wide (the vite items cover `lib/vite/**`), so a new foreign header under a covered glob is accepted;
* `inventory.own_holders` is editable data: adding a name to it silences that holder; a holder is judged by its own text, not by the file mentioning an own holder elsewhere (a file with a foreign holder next to "Microsoft Corporation" is still a candidate);
* small snippets taken from public Q&A and recipe sites and credited only in a comment (`log.js`, `common/storage.js`, `dialogs_py.py` and the stylesheets link stackoverflow answers; `running/timeouts/windows.py` cites an ActiveState recipe) are not licence-bearing headers and are not inventoried;
* an unpinned declaring quote (a `package.json`, a `composer.json`, a registry document) is checked for presence and format only; the pinned ones are checked against the stored bytes.
