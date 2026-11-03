# THIRD_PARTY_NOTICES

The licence and notice texts of the third-party software this bundle ships, as they were published or as they travel inside the shipped wheels. Nothing in this tree was written by
the ReDevOps authors except this file. Every other file is a whole file, byte for byte, of a shipped wheel or of an upstream source, EXCEPT the files whose `INDEX.json` label says
`EXCERPT`: those are line excerpts of an upstream file (the licence comment block of a source file, or the lines of a README that state a licence) and are not whole files. `INDEX.json`
gives the sha256, size, origin and, where a file needs one, a label saying whose text it is. The installed copy is checked against `INDEX.json` by `redevops-qa doctor`.

* `wheels/<name>-<version>/...`: the licence and notice files the shipped third-party wheels carry (Playwright, Robot Framework, pyee, greenlet, typing_extensions, PyYAML), at the path
  they have inside the wheel. For Playwright this includes the Node.js licence file (`playwright/driver/LICENSE`, which lists the libraries compiled into or bundled with the Node.js
  runtime), the notices of the npm packages inlined into the Playwright driver and the notice of the WebP codec (libwebp and Emscripten).
* `upstream/<component>-<version>/...`: texts fetched from the upstream source of the exact version found in the shipped files, for components whose shipped files carry no licence text:
  the jQuery 3.5.1 and Sizzle files of the Robot Framework report pages; the libraries inlined in the Robot Framework `libdoc.html` (Handlebars, mark.js, source-map, the Parcel bundler);
  minimatch (its licence text and its `package.json`, shipped because it names the author the Blue Oak text does not); React, CodeMirror and xterm.js of the Playwright trace viewer
  bundles; and the licence comment blocks (excerpts) of the third-party source files vendored in Playwright's repository.
* Texts of a RELATED project, each labelled in `INDEX.json` with whose it is, and not a licence of the shipped bytes: the MIT text of the ORIGINAL tablesorter repository (christianbach/tablesorter),
  not of the Mottie fork that Robot Framework ships; the Apache-2.0 text of the JSXGraph project's JSXCompressor directory; the candidate texts of the codicon icon font (a Visual Studio Code MIT text from
  Playwright's folder, and the CC BY 4.0 and MIT texts of the upstream vscode-codicons project); the MIT text of the browser-logos repository, which by its README does not cover the logos. For
  jQuery tablesorter 2.30.5, jQuery Templates and jQuery Highlight only the licence statements of their upstream sources exist (excerpts of the source header or the README).
* `INDEX.json`: every file with its sha256, size and origin (the wheel and member, or the URL, the date it was fetched and the component version it belongs to).

Known gaps, recorded in `third_party/adapter-license-matrix.yaml` of the source repository: `proxy-agent-negotiate` 1.1.0 (inlined in the Playwright driver; declared MIT, and its notice section says "no
license text found; declared licenses: MIT") has no licence text in any source that was looked at; jQuery tablesorter, jQuery Templates, jQuery Highlight and JSXCompressor have declarations and no licence
text tied to the shipped file; the codicon font has two candidate licences; the browser logo SVGs have no licence for the artwork. This tree states what the texts say. It is not legal advice and it decides
nothing about distribution.
