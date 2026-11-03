# THIRD_PARTY_NOTICES

The licence and notice texts of the third-party software this bundle ships, as they were published or as they travel inside the shipped wheels. Nothing in this tree was written by
the ReDevOps authors except this file; every other file is byte for byte a file of an upstream source or of a shipped wheel, and `INDEX.json` gives the sha256 of each (the installed
copy is checked against it by `redevops-qa doctor`).

* `wheels/<name>-<version>/...`: the licence and notice files the shipped third-party wheels carry (Playwright, Robot Framework, pyee, greenlet, typing_extensions, PyYAML), at the path
  they have inside the wheel. For Playwright this includes the Node.js licence file (`playwright/driver/LICENSE`, which lists the libraries compiled into or bundled with the Node.js
  runtime) and the notices of the npm packages inlined into the Playwright driver.
* `upstream/<component>-<version>/...`: licence texts fetched from the upstream source of the exact version found in the shipped files (an upstream repository tag or the published npm
  package), for components whose shipped files carry no licence text: the jQuery 3.5.1 and Sizzle files used by the Robot Framework report pages, the libraries inlined into the Robot
  Framework `libdoc.html` (Handlebars, mark.js, source-map and the Parcel bundler), and minimatch. For jQuery tablesorter 2.30.5 only the licence statements of its upstream
  repository exist (an excerpt of the source header and of the README): upstream publishes no licence text for it.
* `INDEX.json`: every file with its sha256, size and origin (the wheel and member, or the URL, the date it was fetched and the component version it belongs to).

No licence text exists, in any primary source that was looked at, for `proxy-agent-negotiate` 1.1.0 (inlined in the Playwright driver; its notice section says "no license text found;
declared licenses: MIT") and for the jQuery tablesorter licence itself (only a dual-licence statement, MIT or GPL-2.0, in the README and the source header). Those two gaps are recorded in
`third_party/adapter-license-matrix.yaml` of the source repository and are decisions for the owner of the distribution. This tree states what the texts say. It is not legal advice and it
does not approve the distribution of any component.
