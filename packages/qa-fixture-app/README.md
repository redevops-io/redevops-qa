# qa-fixture-app

A small local web app that is the target of the ReDevOps QA end-to-end tests: stable endpoints, seeded data, a login, a user settings
page, an order-discount business rule (as a page and as a JSON API) and **one switchable, documented defect**. Standard library
only (Python 3.11 or later), no third-party dependency, no network access, nothing written to disk except the request log you name.

Licence: the family licence of this repository (source-available; see `LICENSE.md`).

It is a test target, not an example of a secure application: there is no CSRF protection, the one password is printed below and
session identifiers are a counter.

## Run it

```text
python -m qa_fixture_app [--defect none|discount|settings] [--port N] [--request-log FILE] [--shutdown-on-stdin-eof]
redevops-qa-fixture-app  ...same options (console script, after `pip install --no-deps packages/qa-fixture-app`)
```

From a checkout, without installing: `PYTHONPATH=packages/qa-fixture-app/src python -m qa_fixture_app --port 0`.

| Option | Meaning |
|---|---|
| `--defect` | The one seeded defect to switch on: `none` (default), `discount`, `settings`. `--list-defects` prints them with their descriptions. |
| `--host` | Loopback only: `127.0.0.1` (default), another `127.x.x.x` address or `::1`. Any other value (a name, `0.0.0.0`, a LAN address) is refused with exit status 2 before anything is bound. There is no override. |
| `--port` | Default 8765. `0` asks the operating system for a free port; the port is in the ready line. |
| `--request-log FILE` | One JSON line per request, in the file you name (truncated at start). See "Request log". |
| `--shutdown-on-stdin-eof` | Exit cleanly when standard input is closed, so a parent that dies cannot leave the app behind. |
| `--version` | Print the package version and exit. |

**Standard output** is JSON lines only. When the socket is bound and the app answers:

```json
{"defect":"none","event":"ready","host":"127.0.0.1","port":49152,"url":"http://127.0.0.1:49152"}
```

and on a clean shutdown (SIGTERM, SIGINT, SIGHUP, or standard input closed with the option above):

```json
{"event":"stopped","requests":12}
```

Exit status: 0 clean shutdown, 1 the address could not be bound, 2 refused or unusable options. Errors go to standard error.
After the process exits no socket is open, no child process was ever started and no file exists except the request log.

Programmatic use (the same app, in your process):

```python
from qa_fixture_app import create_server
with create_server(defect="discount", port=0, request_log="requests.jsonl") as server:   # loopback only; a bad defect raises ValueError
    print(server.url)            # http://127.0.0.1:<port>
```

## Seeded data

One user, `alice@example.test`, password `correct horse`, initial settings `{"notifications": false, "theme": "light"}`.
State lives in memory and starts from this seed in every process; a restart forgets everything.

| Order | Lines (qty x unit, cents) | Subtotal | Discount | Total |
|---|---|---|---|---|
| 101 | 2 x 4000, 1 x 2500 | 10500 | 1050 | 9450 |
| 102 | 1 x 4999, 1 x 5000 | 9999 | 0 | 9999 |
| 103 | 1 x 10000 | 10000 | 1000 | 9000 |
| 104 | 1 x 10005 | 10005 | 1000 | 9005 |

**Business rule:** 10 percent of the subtotal, rounded down to the cent, when the subtotal is at least 10000 cents (100.00). Integer
cents only. Orders 102 and 103 sit on either side of the threshold; 104 exercises the rounding.

## Endpoints

| Method and path | Response |
|---|---|
| `GET /health` | `{"status": "ok"}`, byte-identical in every defect mode. |
| `GET /` | Index page with links. `GET /favicon.ico` is an empty 204. |
| `GET /login`, `POST /login` | Form with labelled `Email` and `Password`. Success: 303 to `/account` and cookie `sid=sess-NNNN`. Failure: 303 to `/login?bad=1`, which shows `role=alert` "Wrong email or password". |
| `GET /account` | "Welcome, alice" with a link to settings; 303 to `/login` when anonymous. |
| `GET /settings`, `POST /settings` | Checkbox "Email notifications" (`notifications=1`), select `theme` (`light` or `dark`), button "Save settings". A save is a 303 to `/settings?saved=1`, which shows `role=status data-testid=save-status` "Settings saved". An unknown theme is a 400. Anonymous: 303 to `/login`. |
| `GET /api/me/settings` | The stored settings as JSON; 401 `{"error": "unauthenticated"}` when anonymous. |
| `GET /orders`, `GET /orders/<id>` | Order list and order page with `data-testid` `order-subtotal`, `order-discount`, `order-total` (money as `105.00`); unknown id: 404 page. |
| `GET /api/orders`, `GET /api/orders/<id>` | JSON with `order_id`, `subtotal_cents`, `discount_cents`, `total_cents` (the single order also `lines`); unknown id: 404 `{"error": "not_found"}`. Sorted by id. |
| `GET /api/discount?subtotal_cents=N` | The rule on its own: `discount_cents`, `total_cents`, `subtotal_cents`, `rule`. `N` is 1 to 9 digits, otherwise 400 `{"error": "invalid_subtotal_cents"}`. |
| anything else | 404 (JSON for `/api/...`, a page otherwise); a known path with another method is 405 with `Allow`. |

Responses carry no `Date`, `ETag` or `Last-Modified` header, `Cache-Control: no-store` and `Connection: close`; JSON is
sorted-key, two-space indented, newline terminated.

## Seeded defects

Exactly one defect at most (`--defect`, or `create_server(defect=...)`); there is no combined mode.

| `--defect` | What is wrong | What changes (and nothing else) |
|---|---|---|
| `none` | Nothing. | |
| `discount` | The discount rule is not applied: `discount_cents` is 0 and the total equals the subtotal. | `/api/discount` for subtotals of at least 10000; `/api/orders`, `/api/orders/101`, `/103`, `/104`; `/orders`, `/orders/101`, `/103`, `/104`. Orders 102 (below the threshold), unknown ids, validation errors and all of settings are unchanged. |
| `settings` | Saving settings is acknowledged but nothing is stored. | After a save: `GET /settings` (with or without `?saved=1`) and `GET /api/me/settings` keep the previous values. The `POST /settings` response itself, login, orders and the rule are unchanged. |

The app never reveals which defect is seeded: `/health` is byte-identical in every mode and no response body or header names the
active defect. The defect is visible only to whoever starts the process (its arguments and the stdout `ready` line). The tests diff
the complete response set of each mode against `none` and fail unless the difference is exactly the one in this table.

## Request log

`--request-log FILE` writes one JSON object per line, with sorted keys and Unix line ends, flushed per request:

| Field | Content |
|---|---|
| `seq` | 1-based, in the order the app answered. |
| `method`, `target` | As received: `target` is the raw request target (path and query; an absolute URL or `host:port` for a proxy-style request or `CONNECT`). |
| `host` | The `Host` header, without `:<port>` when the port is the app's own (so a record does not depend on an ephemeral port). Another name or port is kept in full. |
| `status` | The response status. |
| `has_cookie` | Whether a `Cookie` header was sent (never its value). |
| `form_keys` | Sorted field names of a submitted form (never the values). |
| `body_bytes` | Length of the request body. |

There is no clock and no client address in a record, so the same requests give the same bytes. Requests that are not valid HTTP
(a request line the standard library cannot parse) are rejected by the transport and are not logged.

## Determinism

No clock, no randomness, sorted collections, session ids from a counter, no `Date` header. For the same sequence of requests the
responses and the log are byte-identical across processes and operating systems; the tests check two fresh servers on different
ports, thirty consecutive starts per mode, two separate processes per mode (responses and log), and the committed golden files.

## Extension point for hostile-target fixtures

Not built here. Pages that try to reach other hosts or ports, redirects to forbidden hosts, DNS-rebinding and WebRTC-like attempts
belong to the egress experiments that come later. The hook they will use exists and is tested:
`create_server(..., extra_routes={("GET", "/path"): handler})` where `handler(Request) -> Response` (both exported by
`qa_fixture_app`). Extra routes are consulted before the built-in ones, are answered under the same lock and are request-logged like
any other request. A `--hostile` option is deliberately absent until those fixtures exist; the app contains no code that opens an
outbound connection or resolves a name (a test reads the source to check).

## Reference check

`python -m qa_fixture_app.reference_check http://127.0.0.1:PORT` asks a running app the two questions the defects are about,
using its own restatement of the seed and its own arithmetic and talking HTTP only (no import from the app), and prints which
answers deviate. Exit status 0: none; 1: a deviation (`discount-rule` and/or `settings-persistence`); 2: unreachable, or not a loopback
URL. It saves one setting, so point it at an instance you can throw away. It exists so an engine's verdict can be compared with
a reference that does not share the engine's code or the app's.

## Tests

```text
python -m pytest -q packages/qa-fixture-app/tests     # run from the repository root; the package is not in the root testpaths, CI job `fixture-app` runs it
python packages/qa-fixture-app/tests/regen_golden.py     # rewrite tests/golden from the current code; review the diff
```

`tests/golden/none` holds the exact response (status, headers, body) of every step of one fixed scenario. `tests/golden/discount` and
`tests/golden/settings` hold only the steps that differ from `none`, so the file list of a directory is the list of what that defect
changes. The suite needs no browser.
