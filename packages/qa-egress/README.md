# qa-egress

The enforcement point for the harness egress policy. The harness QA module (`agent_harness.qa.egress`) is pure: it decides,
it never connects. This package is what connects: an egress **gateway** that every browser request goes through, and the
browser **launch configuration** that makes the gateway the only way out. Standard library only; the policy is consumed from the
pinned harness tree (`pins.toml`), never copied.

Licence: the family licence of this repository (source-available; see `LICENSE.md`).

## The gateway (`EgressGateway`, `GatewayServer`)

A forward proxy on `asyncio`. For each request or connection it asks the harness policy (default-deny operator allow-list, metadata
and link-local always refused, resolve-then-pin, userinfo refused, ports, `ws`/`wss`), refuses what is not allowed, and otherwise
connects **only to the address the decision pinned**. There is no second name resolution anywhere; the name is resolved once per
decision, through an injectable resolver (`SystemResolver` in production, a fake in tests), under a deadline. After connecting it
checks the peer really is the pinned address.

| Traffic | Handling |
|---|---|
| `http://` in absolute form | one request per connection, `Connection: close` both ways; hop-by-hop and `Proxy-*` headers removed; `Host` taken from the decided URL; the request body forwarded exactly up to its bound |
| `CONNECT host:port` | judged as an `https` target (so `wss` too), then an opaque byte tunnel under byte, idle and total bounds |
| WebSocket upgrade in absolute form | `ws://` or `http://` with `Upgrade: websocket`, judged as `ws`, relayed in both directions after a `101` |
| a redirect answer | its `Location` is decided again from scratch (relative forms resolved, an `https` to `http` downgrade refused, the redirect count enforced across the requests a browser makes) **before** the answer reaches the client; a refused hop is answered `403` |
| everything else | refused: other methods, origin-form requests, `https://` in a plain request (it needs `CONNECT`), transfer-coded request bodies, malformed or oversized heads, bare line feeds, extra bytes after a request, other `Upgrade` values |

What the gateway refuses **whatever a decider says** (it can make a decision stricter, never looser): a metadata or link-local address
among the decision's addresses or as the pinned address, the unspecified address, a multicast address, an IPv4-mapped or transition
address, no pinned address, a connection that did not reach the pinned address.

Bounds (`GatewayLimits`, each checked at construction): head bytes and lines, URI length, request body, response bytes, response head,
tunnel bytes, concurrent connections, decision records kept, distinct denied hosts counted, and a timeout for the head, the
connection, name resolution, the upstream answer, idleness and the whole request.

### Evidence and logs

Every request, redirect hop and tunnel is a record (`GatewayRecord`): the egress decision (plain data with a `canon-v1` hash:
scheme, host, port, addresses, reason codes) and what then happened (outcome, status, bytes, duration, the limit hit). A record
renders as the same `EgressDecision` evidence event the runner writes, plus the gateway's own fields; `Ledger.summary_event()`
is the `EgressSummary` (counters; denied hosts counted by host only). **No path, query, header, cookie or body is ever stored in a
record, an event, a counter or a log line.** A log line passes the harness redactor first; a line the redactor refuses is dropped and
counted. A host label is recorded because it is evidence (a name can carry exfiltrated data); the runner's evidence guard redacts
events before they are sealed.

### Run

```text
python -m qa_egress --config gateway.json
```

The configuration is one operator-owned JSON file (`listen`, `policy` in the harness `EgressPolicy.from_config` form, `limits`). It
binds loopback unless told otherwise. In a deployment the browser's network has no other route than to this gateway.

## The launch configuration (`build_launch_config`)

Produces the Chromium flags, the Playwright proxy setting and the context options for a browser that can reach the gateway and
nothing else:

* an explicit proxy for everything, with `--proxy-bypass-list=<-loopback>`: Chromium otherwise sends loopback destinations around
  the proxy (implicit bypass rules), and a proxy that never sees them cannot enforce anything there. No other bypass entry exists;
* no name resolution in the browser (`--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE <gateway>`);
* QUIC, non-proxied WebRTC traffic, DNS prefetch, pings, background networking, sync, component updates, extensions, new web contents
  and permission prompts off; downloads off; service workers blocked; no permissions.

Popups and downloads are off unless the test specification permits them (`allow_popups` drops `--block-new-web-contents`, `allow_downloads` turns on
`accept_downloads`); nothing else can be loosened. A session that needs either uses a second egress profile built with that option.

`tests/golden/launch_config.json` is the whole configuration for `127.0.0.1:18080`; a test compares it byte for byte and a second test
lists the exact flag set. `extra_args` can add a flag but never one that reopens a closed channel (`FORBIDDEN_PREFIXES`).

The flags and Playwright's `proxy` option carry the same value on purpose, so a Playwright-side default for per-context proxies
cannot replace them. Which flag or option removes the implicit loopback bypass in the pinned Chromium and Playwright is established by
the browser-lane test, which also runs the controls that show the bypass exists without it.

## Tests

* **Offline (default).** `python -m pytest` from the repository root. The gateway is exercised end to end over **loopback sockets only**:
  fake upstream servers on `127.0.0.1`, every name mapped by a scripted resolver, the policy listing the test network (`private_ok`)
  for exactly the names a test uses, and a raw HTTP client. More than 300 cases cover SSRF vectors: numeric, octal, hex and IPv6
  spellings, mapped, NAT64 and 6to4 forms, userinfo, ports, internal and metadata names, absolute-URI and request-line forms,
  `CONNECT`, DNS answers and rebinding, redirects to metadata and private targets and over-long chains, hop-by-hop headers, request
  smuggling shapes, oversized and malformed upstream answers, WebSocket, caps and timeouts; plus the same destinations against a
  policy with no `private_ok` entry (everything refused). Mutation tests remove one guard at a time (metadata refusal on the
  enforcement path, connect-to-pinned, redirect re-check, peer check, each cap, the policy itself, the request-line and
  transfer-coding refusals) and the suite fails each time. Clean shutdown, descriptor and task leaks, and secret leaks into
  records, events, counters and logs are tested as well.
* **Real browser.** `tests/browser`, marked `browser`, collected only when named and run only by the `browser` CI job. It launches
  Chromium through the adapter with the gateway as its proxy and requests `http://127.0.0.1:<port>/`, `http://localhost:<port>/` and a
  private-range literal, asserts the gateway's log saw each, asserts metadata addresses are refused even when listed, and runs two
  controls (no proxy; a proxy without `<-loopback>`) that must bypass the gateway, which proves the test can fail.
