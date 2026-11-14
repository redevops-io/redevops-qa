# redevops-qa-service API (v1)

One API serves the browser interface (`/ui/`), scripts and other products. JSON, UTF-8. Implemented in `packages/qa-service/src/qa_service/server.py`; every claim below is pinned by `packages/qa-service/tests/test_qs_v1.py`, `test_qs_server.py` and the browser tests.

## Conventions

* **Errors:** `{"error": "<code>", "detail": "<text>", "message": "<same text>", "request_id": "<opaque>"}` plus fields named below. Codes: `unauthenticated` 401, `forbidden` 403, `csrf_required` 403, `not_found` 404, `method_not_allowed` 405, `conflict` 409, `busy` 409 (`active_run_id`), `stale_approval` 409, `no_bundle` 409, `bad_body`/`unknown_field` 400, `invalid` 422 (`field`), `plan_unavailable` 422 (`unavailable`), `estimate_required` 422, `estimate_refuses` 422 (`problems`), `too_many_attempts` 429, `evidence_unreadable`/`report_failed` 502. A refusal to run carries `unavailable: {code, reason, remedy}`.
* **Pagination:** `?limit=1..200&cursor=<opaque>` -> `{"items": [...], "next_cursor": "<opaque>"|null}` (`GET /v1/runs` also returns the same list as `runs`).
* **Timestamps** RFC 3339 UTC. **Ids:** run `rYYYYMMDDTHHMMSSZ-xxxxxx`, target `tgt-<12 hex>` (built-in `tgt-000000000000`), user `usr-<8 hex>`, estimate `est-<12 hex>`. No request names a path, a URL to open, a plan body or a command.
* **Credentials** (tried in this order): `Authorization: Bearer <service token>` (class `service`); `Authorization: Basic` with a local user (no cookie, no CSRF); the `qa_session` cookie (HttpOnly, SameSite=Strict) with `X-CSRF-Token` on every write and a matching `Origin` when sent. Probes `/healthz`, `/readyz`, the static `/ui/*` files and `POST /v1/session` need no credential; `GET /v1/session` answers `{"principal": null}` without one.
* **Roles:** `viewer` < `operator` < `admin`. The service token counts as operator for reads, estimates, starting runs that need no approval, cancelling and deleting; it is never human: it cannot approve a run, manage users or register targets.

## Routes

| Method and path | Role | Request body | Response |
|---|---|---|---|
| `GET /healthz`, `GET /readyz` | none | | `{"status": "ok"}`; `{"status": "ready"}` or 503 `{"status": "not_ready", "failing": [...]}` |
| `POST /v1/session` | none | `{username, password}` | 200 `{user, csrf}` + `Set-Cookie: qa_session=...`; 401; 429 after 8 failures a minute per client |
| `GET /v1/session` | any | | `{principal: {kind: "user"\|"service", name, role, via: "session"\|"basic"\|"service"}, user, csrf}` or `{principal: null, user: null, csrf: null}` |
| `DELETE /v1/session` | user | | 204, cookie cleared |
| `GET /v1/info` | viewer | | `{service, version, machine, defects[], capabilities{system, machine, missing_packages[], browser{status,message}, robot_layers{ok,reason?,message?}}, plans{<legacy plan>: {available, unavailable, command}}, profiles[...], levels{fixture_ceiling:"VERIFIED", external_ceiling:"CORROBORATED"}, run_timeout_seconds, target, auth{users:bool, roles[]}}` |
| `GET /v1/users` / `POST /v1/users` | admin (human) | `{name, role, password, display_name?}` | list / 201 user (`user_id, name, display_name, role, created_at, created_by, disabled, last_login_at`) |
| `PATCH /v1/users/{id}` | admin (human) | `{role?, disabled?, password?}` | user; the user's sessions end; the last enabled admin cannot be demoted or disabled (409) |
| `GET /v1/targets`, `GET /v1/targets/{id}` | viewer | | target: `{id, name, kind: "fixture-app"\|"external-origin", origin\|null, declared_by:"operator", declared_at, declared_user, egress_profile:"origin-only", credential_refs:[], mutating:false, run_approval:"required"\|"none", level_ceiling:"VERIFIED"\|"CORROBORATED", builtin, notes, last_probe{at, ok, detail}\|null}` |
| `POST /v1/targets` | admin (human) | `{name, origin?, run_approval?, notes?}` | 201 target. With `origin`: external-origin; validated by the same code as `redevops-qa freeze`/`estimate`; 422 `TARGET_OUT_OF_SCOPE` (only `http://127.0.0.1:<port>`), `NOT_FIXTURE_MODE` (its `/health` must report `demo.enabled=true`), `invalid`; external targets always require approval. Without `origin`: a fixture-app target (`run_approval` `none` or `required`). 409 on a duplicate name |
| `DELETE /v1/targets/{id}` | admin (human) | | 204; 409 for the built-in target or a target a run used |
| `GET /v1/profiles?target_id=` | viewer | | `{items: [{id, title, description, engines[], targets[], mutating:false, est_duration_s, available, unavailable: null\|{code, reason, remedy}}]}`; ids: `fixture-demo`, `fixture-browser`, `fixture-robot`, `fixture-robot-not-enforced`, `edge-sentinel-fixture-readonly`. With `target_id`, a profile for another target kind is `unavailable` with `TARGET_KIND_MISMATCH` |
| `POST /v1/estimates` | operator | `{target_id?, profile}` | 201 `{estimate_id, digest, created, expires (1 h), target_id, profile, plan_id, plan_digest, origin, egress_policy_digest, engines[], lanes[], lane_deadlines{}, limits, credential_refs[] (names), problems[{code,message}], will_refuse, verification_ceiling, contacts, platform}`; runs `redevops-qa estimate` over a plan the service builds: nothing is contacted, no bundle is written |
| `POST /v1/runs` | operator | `{target_id?, profile?, plan?, defect?, estimate_digest?}` (`plan` is the 0.6.2 name: `demo`, `browser`, `robot`, `robot-not-enforced`; default target: the built-in fixture) | 202 run + `Location`. A target that requires approval: the run is `awaiting_approval` and `estimate_digest` of an unexpired estimate for this target and profile is required (`estimate_required`). 409 `busy`; 422 `plan_unavailable` + `unavailable{code,reason,remedy}` (also `EXTERNAL_RUN_NOT_ENABLED` for every external-origin target in this release); nothing is started |
| `POST /v1/runs/{id}/approval` | operator, human | `{approved: bool, estimate_digest, rationale?}` | run -> `running` (approved) or `refused`; 409 `stale_approval` (digest differs), 409 `conflict` (not waiting, or already decided), 403 for the service token, a viewer, or the requester when `QA_REQUIRE_TWO_PERSON=1`; 409 `busy` if another run is going |
| `POST /v1/runs/{id}/cancel` | operator | | run; a waiting run is `cancelled` at once, a running one is killed (process group) and recorded `cancelled`; 409 if ended |
| `GET /v1/runs?state=&target_id=&profile=&outcome=&limit=&cursor=` | viewer | | newest first |
| `GET /v1/runs/{id}` | viewer | | run: `{id, plan, defect, target_id, profile, state: awaiting_approval\|running\|finished\|failed_to_start\|timed_out\|interrupted\|cancelled\|refused, created, started, finished, exit_code, outcome (VERIFIED\|FAILED\|REFUSED\|NOT_COMPLETED\|INCONCLUSIVE\|EVIDENCE_REJECTED\|RUNNER_ERROR\|null), level (VERIFIED\|CORROBORATED\|null), level_ceiling, bundle, estimate_digest, approval{required, state: pending\|approved\|rejected\|null, actor_user, actor_role, via, at, rationale}\|null, requested_by{user, via}, progress: null, note}` |
| `GET /v1/runs/{id}/events?after=<seq>&limit=` | viewer | | `{items: [{seq, at, type, lane, engine, step, total, label, detail}], head, terminal}`; types `run.queued`, `run.approval_requested`, `run.approved`, `run.rejected`, `run.started`, `run.finished`, `run.cancelled`, `run.interrupted`. The client polls and stops when `terminal` is true. The runner reports no per-lane or per-step event in this release (`lane`, `step`, `total` are null) |
| `GET /v1/runs/{id}/output` | viewer | | the command's output, text, at most 1 MiB |
| `GET /v1/runs/{id}/evidence` | viewer | | `{run_id, bundle_id, level, ceiling, outcome, independent_restatement, restatement_note, lanes[], accounting, assertions[], manifest_digest, plan_digest, verification{accepted, agreeing_assertions, findings[], assurance}, files[{index, path, role, size, sha256}]}`, from `redevops-qa report --format json` (it verifies the bundle first) |
| `GET /v1/runs/{id}/evidence/files/{index}` | viewer | | one listed file (`index` into `files`, never a path), `application/octet-stream`, `Content-Disposition: attachment`, at most 16 MiB |
| `GET /v1/runs/{id}/verify` | viewer | | `{exit_code, meaning, result (the `redevops-qa verify --json` document), independent}`: re-verification in a separate process |
| `GET /v1/runs/{id}/report?format=text\|json\|html` | viewer | | the report; HTML has its own CSP (`default-src 'none'`, no script) |
| `GET /v1/runs/{id}/bundle.tar` | viewer | | the evidence bundle for `redevops-qa verify` elsewhere |
| `DELETE /v1/runs/{id}` | admin (or the service token) | | 204; 409 while running |

## Records (on the data volume)

`runs/<id>/status.json` (the run above), `runs/<id>/events.jsonl` (append-only, one event per line), `runs/<id>/output.txt`, `runs/<id>/evidence/<id>/` (the bundle), `targets.json`, `users.json` (0600), `estimates/est-*.json`. Readers of `status.json` should ignore keys they do not know.

## What is not in this API yet

A run of an `external-origin` target (P2-1, AC-6 to AC-9), per-step progress, signed approvals from another product (Projects/Sidekick; the approval route accepts only a signed-in user), and any credential reference for a target.
