# redevops-qa

QA runner that executes versioned test specifications against a target, checks
immutable assertions deterministically, and keeps reproducible evidence.

Status: private development repository. Nothing here is released.

Planned layout: product packages (`qa-api`, `qa-ui`, `qa-runner`,
`qa-playwright`, `qa-evidence`, `qa-bridge`, `qa-egress`), deployment
(`deploy/`), examples and benchmarks. It depends on pinned releases of
`runtime-contracts`, `agent-harness` and `context-runtime`; it does not vendor them.

Licence: see [LICENSE.md](LICENSE.md).

Configuration of the pinned upstream versions: [pins.toml](pins.toml). The contracts bridge is in
[packages/qa-bridge](packages/qa-bridge/README.md).
The browser adapter is in [packages/qa-playwright](packages/qa-playwright/README.md).
The licence matrix for optional adapter frameworks is in [third_party](third_party/README.md).
