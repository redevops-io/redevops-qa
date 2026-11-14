// redevops-qa interface: framework-free, no third-party asset, no markup built from strings, no inline handler. Every string from the API is placed as a text node.
const state = { session: null, csrf: null, info: null, poll: null, first: true };
const main = document.getElementById("main");
const live = document.getElementById("live");

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

class ApiError extends Error { constructor(status, body) { super((body && (body.detail || body.message)) || ("HTTP " + status)); this.status = status; this.body = body || {}; } }

async function api(method, path, body) {
  const headers = { "Accept": "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (state.csrf && method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
  if (res.status === 401 && path !== "/v1/session") { state.session = null; state.csrf = null; navigate("/ui/signin", true); throw new ApiError(401, data); }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

const rank = { viewer: 0, operator: 1, admin: 2 };
const can = (role) => state.session && rank[state.session.role] >= rank[role];

function announce(text) { live.textContent = text; }
function stopPolling() { if (state.poll) { clearTimeout(state.poll); state.poll = null; } }
function errBox(e) { return h("div", { class: "banner bad", role: "alert" }, h("strong", {}, "Not done: "), e.message, e.body && e.body.unavailable ? h("div", { class: "small" }, "Remedy: " + e.body.unavailable.remedy) : null); }
function badge(text, kind) { return h("span", { class: "badge " + (kind || "muted") }, text); }
function levelBadge(level, ceiling) {
  if (level === "VERIFIED") return badge("VERIFIED", "ok");
  if (level === "CORROBORATED") return badge("CORROBORATED", "warn");
  return badge(ceiling ? "no level (ceiling " + ceiling + ")" : "no level", "muted");
}
function outcomeBadge(o) { return badge(o || "not finished", o === "VERIFIED" ? "ok" : (o === "FAILED" ? "bad" : "muted")); }
function table(headers, rows, label) {
  const t = h("table", {}, h("thead", {}, h("tr", {}, headers.map((x) => h("th", { scope: "col" }, x)))), h("tbody", {}, rows));
  return h("div", { class: "scroll", tabindex: "0", role: "region", "aria-label": label }, t);
}
function lab(id, text, ...controls) { return h("div", { class: "field" }, h("label", { for: id }, text), ...controls); }
function kv(pairs) { return h("dl", { class: "kv" }, pairs.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])); }
function link(path, text) { return h("a", { href: path, onclick: (e) => { if (e.metaKey || e.ctrlKey || e.shiftKey || e.button) return; e.preventDefault(); navigate(path); } }, text); }

function navigate(path, replace) {
  if (replace) history.replaceState({}, "", path); else history.pushState({}, "", path);
  render();
}
window.addEventListener("popstate", render);

function buildNav() {
  const nav = document.getElementById("nav");
  nav.replaceChildren();
  const who = document.getElementById("who");
  who.replaceChildren();
  if (!state.session) return;
  const items = [["/ui/", "Dashboard"], ["/ui/targets", "Targets"], ["/ui/new", "New run"], ["/ui/runs", "Runs"]];
  if (can("admin")) items.push(["/ui/users", "Users"]);
  items.push(["/ui/about", "About"]);
  const here = location.pathname.replace(/\/$/, "") || "/ui";
  for (const [p, t] of items) { const a = link(p, t); if ((p.replace(/\/$/, "") || "/ui") === here || (p !== "/ui/" && here.startsWith(p))) a.setAttribute("aria-current", "page"); nav.append(a); }
  who.append(h("span", {}, state.session.name + " (" + state.session.role + ")"), h("button", { type: "button", onclick: signOut }, "Sign out"));
}

async function signOut() {
  try { await api("DELETE", "/v1/session"); } catch (e) { /* the session may already be gone */ }
  state.session = null; state.csrf = null; navigate("/ui/signin");
}

async function loadSession() {
  try {
    const s = await api("GET", "/v1/session");
    if (s.principal.kind === "user") { state.session = { name: s.principal.name, role: s.principal.role }; state.csrf = s.csrf; }
  } catch (e) { state.session = null; }
}

function page(title, ...content) {
  main.replaceChildren(h("h1", { tabindex: "-1", id: "title" }, title), ...content);
  document.title = title + " - redevops-qa";
  buildNav();
  if (!state.first) document.getElementById("title").focus();     // the first view keeps the natural tab order (the skip link comes first)
  state.first = false;
}

// ---------------------------------------------------------------------------------------------- views
function viewSignIn() {
  stopPolling();
  buildNav();
  const err = h("div", { "aria-live": "polite" });
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault(); err.replaceChildren();
    try {
      const r = await api("POST", "/v1/session", { username: form.username.value, password: form.password.value });
      state.session = { name: r.user.name, role: r.user.role }; state.csrf = r.csrf; navigate("/ui/", true);
    } catch (x) { err.replaceChildren(errBox(x)); }
  } },
    lab("username", "User name", h("input", { id: "username", name: "username", autocomplete: "username", required: true })),
    lab("password", "Password", h("input", { id: "password", name: "password", type: "password", autocomplete: "current-password", required: true })),
    h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Sign in")), err);
  page("Sign in", h("p", { class: "muted" }, "Sign in with a local user of this service. An administrator creates users (see the documentation)."), form);
}

async function viewDashboard() {
  const [info, runs] = await Promise.all([api("GET", "/v1/info"), api("GET", "/v1/runs?limit=5")]);
  state.info = info;
  const cap = info.capabilities;
  const unsupported = Object.values(info.plans).every((p) => !p.available);
  const banner = h("div", { class: "banner " + (unsupported ? "bad" : (Object.values(info.plans).some((p) => !p.available) ? "warn" : "ok")), role: "status" },
    h("strong", {}, unsupported ? "No lane can run on this installation. " : "This installation can run lanes. "),
    "Platform: " + cap.system + " " + cap.machine + ". " + (unsupported ? "Evidence can still be verified, reported and inspected." : ""));
  const rows = info.profiles.map((p) => h("tr", {}, h("td", {}, h("strong", {}, p.title), h("div", { class: "small muted" }, p.id)), h("td", {}, p.available ? badge("available", "ok") : badge("unavailable", "bad")),
    h("td", {}, p.available ? "-" : [h("div", {}, h("code", {}, p.unavailable.code), ": " + p.unavailable.reason), h("div", { class: "small muted" }, "Remedy: " + p.unavailable.remedy)])));
  const latest = runs.items.map(runRow);
  page("Dashboard", banner, h("h2", {}, "Profiles"), table(["Profile", "State", "Why it is unavailable"], rows, "Profiles and their availability"),
    h("h2", {}, "Latest runs"), latest.length ? table(["Run", "Profile", "State", "Outcome", "Level"], latest, "Latest runs") : h("p", { class: "muted" }, "No run yet. Start one from New run."),
    h("p", {}, link("/ui/new", "Start a run")));
}

function runRow(r) {
  return h("tr", {}, h("td", {}, link("/ui/runs/" + r.id, r.id)), h("td", {}, r.profile || r.plan), h("td", {}, r.state.replace("_", " ")), h("td", {}, outcomeBadge(r.outcome)), h("td", {}, levelBadge(r.level, r.level_ceiling)));
}

async function viewTargets() {
  const t = await api("GET", "/v1/targets");
  const rows = t.items.map((x) => h("tr", {}, h("td", {}, h("strong", {}, x.name), h("div", { class: "small muted mono" }, x.id)), h("td", {}, x.kind), h("td", { class: "mono" }, x.origin || "started by the runner"),
    h("td", {}, levelBadge(null, x.level_ceiling), h("div", { class: "small muted" }, "ceiling " + x.level_ceiling)), h("td", {}, x.run_approval === "required" ? "required" : "none"),
    h("td", {}, x.last_probe ? (x.last_probe.ok ? badge("fixture mode confirmed", "ok") : badge("not confirmed", "bad")) : "-", x.last_probe ? h("div", { class: "small muted" }, x.last_probe.at) : null),
    h("td", {}, can("admin") && !x.builtin ? h("button", { type: "button", onclick: async () => { try { await api("DELETE", "/v1/targets/" + x.id); announce("Target removed"); viewTargets(); } catch (e) { main.prepend(errBox(e)); } } }, "Remove") : null)));
  const nodes = [table(["Target", "Kind", "Origin", "Level ceiling", "Run approval", "Last probe", ""], rows, "Registered targets")];
  if (can("admin")) {
    const err = h("div", { "aria-live": "polite" });
    const form = h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.replaceChildren();
      const body = { name: form.name.value };
      if (form.origin.value.trim()) body.origin = form.origin.value.trim();
      if (form.approval.checked && !body.origin) body.run_approval = "required";
      try { await api("POST", "/v1/targets", body); announce("Target registered"); viewTargets(); } catch (x) { err.replaceChildren(errBox(x)); }
    } },
      lab("tname", "Name", h("input", { id: "tname", name: "name", required: true, maxlength: "80" })),
      lab("torigin", "Origin (optional)", h("input", { id: "torigin", name: "origin", placeholder: "http://127.0.0.1:8203", autocomplete: "off", "aria-describedby": "originhint" }),
        h("span", { class: "hint", id: "originhint" }, "Leave empty for a fixture-app target. This release accepts one external target: an Edge Sentinel started with EDGE_SENTINEL_DEMO=1 on http://127.0.0.1:<port>. The service reads its /health once and refuses it unless it reports fixture mode. An external target always needs approval for a run.")),
      h("label", { class: "row" }, h("input", { type: "checkbox", name: "approval" }), "Require approval for runs against a fixture-app target"),
      h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Register target")), err);
    nodes.push(h("h2", {}, "Register a target"), form);
  } else nodes.push(h("p", { class: "muted" }, "Registering targets needs the admin role."));
  page("Targets", ...nodes);
}

async function viewNew() {
  const [targets, info] = await Promise.all([api("GET", "/v1/targets"), api("GET", "/v1/info")]);
  const out = h("div", { "aria-live": "polite" });
  const target = h("select", { id: "ntarget", name: "target" }, targets.items.map((t) => h("option", { value: t.id }, t.name + " (" + t.kind + ")")));
  const profile = h("select", { id: "nprofile", name: "profile" });
  const defect = h("select", { id: "ndefect", name: "defect" }, ["none", "discount", "settings"].map((d) => h("option", { value: d }, d)));
  const reasons = h("div", {});
  let profiles = [];
  let estimate = null;
  const start = h("button", { class: "primary", type: "button", disabled: true }, "Start run");
  const est = h("button", { type: "button" }, "Estimate");
  const current = () => targets.items.find((t) => t.id === target.value);
  async function refresh() {
    estimate = null; start.disabled = true; out.replaceChildren();
    profiles = (await api("GET", "/v1/profiles?target_id=" + target.value)).items;
    profile.replaceChildren(...profiles.map((p) => h("option", { value: p.id, disabled: !p.available }, p.title + (p.available ? "" : " (unavailable)"))));
    const first = profiles.find((p) => p.available); if (first) profile.value = first.id;
    const blocked = profiles.filter((p) => !p.available);
    reasons.replaceChildren(blocked.length ? h("ul", { class: "plain" }, blocked.map((p) => h("li", {}, h("strong", {}, p.title + ": "), "unavailable because " + p.unavailable.reason + " (" + p.unavailable.code + "). Remedy: " + p.unavailable.remedy)))
      : h("p", { class: "muted" }, "Every profile is available for the chosen target."));
    defect.disabled = current().kind !== "fixture-app";
    est.disabled = !first; start.disabled = true;
    if (!first) out.replaceChildren(h("div", { class: "banner warn", role: "status" }, "No profile can run against this target here. The reasons are listed below."));
  }
  target.addEventListener("change", () => refresh().catch((e) => out.replaceChildren(errBox(e))));
  est.addEventListener("click", async () => {
    out.replaceChildren();
    try {
      estimate = await api("POST", "/v1/estimates", { target_id: target.value, profile: profile.value });
      const p = estimate.problems.map((x) => h("li", {}, h("code", {}, x.code), ": " + x.message));
      out.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Estimate"), kv([["Digest", h("code", {}, estimate.digest)], ["Origin", estimate.origin || "the fixture app, started by the runner"], ["Engines", estimate.engines.join(", ")],
        ["Ceiling", estimate.verification_ceiling], ["Credential references", estimate.credential_refs.length ? estimate.credential_refs.join(", ") : "none"], ["Contacts", estimate.contacts]]),
        p.length ? h("div", { class: "banner bad" }, h("strong", {}, "A run would refuse:"), h("ul", {}, p)) : h("div", { class: "banner ok" }, "Nothing in the estimate stops a run.")));
      start.disabled = estimate.will_refuse;
    } catch (e) { out.replaceChildren(errBox(e)); }
  });
  start.addEventListener("click", async () => {
    out.replaceChildren();
    const needs = current().run_approval === "required";
    if (needs && !estimate) { out.replaceChildren(h("div", { class: "banner warn" }, "This target needs an estimate first.")); return; }
    const body = { target_id: target.value, profile: profile.value };
    if (needs) body.estimate_digest = estimate.digest;
    if (!defect.disabled && defect.value !== "none") body.defect = defect.value;
    try { const r = await api("POST", "/v1/runs", body); navigate("/ui/runs/" + r.id); } catch (e) { out.replaceChildren(errBox(e)); }
  });
  profile.addEventListener("change", () => { estimate = null; start.disabled = !!current().run_approval && current().run_approval === "required"; if (current().run_approval !== "required") start.disabled = false; out.replaceChildren(); });
  const form = h("form", { onsubmit: (e) => e.preventDefault() },
    lab("ntarget", "Target", target), lab("nprofile", "Test profile", profile),
    lab("ndefect", "Seeded defect (fixture app only)", defect, h("span", { class: "hint" }, "A defect seeds a known fault so you can see a failing verdict.")),
    h("div", { class: "row" }, est, start));
  page("New run", form, out, h("h2", {}, "Profiles that cannot run here"), reasons);
  await refresh();
  start.disabled = current().run_approval === "required" ? true : !profiles.some((p) => p.available);
  const primary = form.querySelector("#nprofile"); primary.addEventListener("change", () => { start.disabled = current().run_approval === "required" ? true : false; });
  void info;
}

async function viewRuns() {
  const q = new URLSearchParams(location.search);
  const params = new URLSearchParams(); for (const k of ["state", "outcome", "cursor"]) if (q.get(k)) params.set(k, q.get(k)); params.set("limit", "20");
  const data = await api("GET", "/v1/runs?" + params.toString());
  const stateSel = h("select", { id: "fstate", name: "state" }, [["", "any state"], ["awaiting_approval", "awaiting approval"], ["running", "running"], ["finished", "finished"], ["cancelled", "cancelled"], ["refused", "refused"]].map(([v, t]) => h("option", { value: v, selected: q.get("state") === v }, t)));
  const outSel = h("select", { id: "foutcome", name: "outcome" }, [["", "any outcome"], ["VERIFIED", "VERIFIED"], ["FAILED", "FAILED"], ["INCONCLUSIVE", "INCONCLUSIVE"]].map(([v, t]) => h("option", { value: v, selected: q.get("outcome") === v }, t)));
  const filter = h("form", { class: "row", style: null, onsubmit: (e) => { e.preventDefault(); const p = new URLSearchParams(); if (stateSel.value) p.set("state", stateSel.value); if (outSel.value) p.set("outcome", outSel.value); navigate("/ui/runs" + (p.toString() ? "?" + p : "")); } },
    lab("fstate", "State", stateSel), lab("foutcome", "Outcome", outSel), h("button", { type: "submit" }, "Filter"));
  const rows = data.items.map(runRow);
  const next = data.next_cursor ? h("p", {}, link("/ui/runs?" + new URLSearchParams({ ...(q.get("state") ? { state: q.get("state") } : {}), ...(q.get("outcome") ? { outcome: q.get("outcome") } : {}), cursor: data.next_cursor }), "Older runs")) : null;
  page("Runs", filter, rows.length ? table(["Run", "Profile", "State", "Outcome", "Level"], rows, "Run history") : h("p", { class: "muted" }, "No run matches."), next);
}

async function viewRun(id) {
  let after = 0;
  const eventsBody = h("tbody", {});
  const box = h("div", {});
  const actions = h("div", { class: "row" });
  const evid = h("div", {});
  page("Run " + id, box, h("h2", {}, "Progress"), h("p", { class: "small muted" }, "The runner reports the start and the end of a run; it does not report per-step progress in this release."),
    h("div", { class: "scroll", tabindex: "0", role: "region", "aria-label": "Run events" }, h("table", {}, h("thead", {}, h("tr", {}, ["#", "Time", "Event", "Detail"].map((x) => h("th", { scope: "col" }, x)))), eventsBody)), evid);
  async function once() {
    let r;
    try { r = await api("GET", "/v1/runs/" + id); } catch (e) { box.replaceChildren(errBox(e)); return; }
    const ev = await api("GET", "/v1/runs/" + id + "/events?after=" + after);
    for (const e of ev.items) { after = e.seq; eventsBody.append(h("tr", {}, h("td", {}, e.seq), h("td", { class: "mono" }, e.at), h("td", {}, e.type), h("td", {}, e.label))); }
    if (ev.items.length) announce("Run " + r.state.replace("_", " "));
    const approval = r.approval;
    const nodes = [h("div", { class: "card" }, kv([["State", r.state.replace("_", " ")], ["Outcome", outcomeBadge(r.outcome)], ["Level", [levelBadge(r.level, r.level_ceiling), h("span", { class: "small muted" }, " ceiling " + r.level_ceiling + (r.level_ceiling === "CORROBORATED" ? ": no independent restatement backs an external target" : ""))]],
      ["Profile", r.profile], ["Target", r.target_id], ["Requested by", r.requested_by.user + " via " + r.requested_by.via], ["Note", r.note || "-"]]))];
    if (r.state === "awaiting_approval") {
      const rationale = h("input", { id: "rationale", maxlength: "300" });
      const err = h("div", { "aria-live": "polite" });
      const decide = async (approved) => { try { await api("POST", "/v1/runs/" + id + "/approval", { approved, estimate_digest: r.estimate_digest, rationale: rationale.value }); after = after; once(); } catch (e) { err.replaceChildren(errBox(e)); } };
      nodes.push(h("div", { class: "banner warn", role: "region", "aria-label": "Approval" }, h("strong", {}, "Waiting for approval. "), "Approving starts the run for exactly the estimate with digest ", h("code", {}, r.estimate_digest), ". The run is not started until a user with the operator role approves it.",
        can("operator") ? h("div", {}, lab("rationale", "Reason (optional)", rationale), h("div", { class: "row" }, h("button", { class: "primary", type: "button", onclick: () => decide(true) }, "Approve"), h("button", { type: "button", onclick: () => decide(false) }, "Reject")), err)
          : h("p", {}, "Your role cannot approve.")));
    } else if (approval && approval.state) nodes.push(h("p", { class: "small" }, "Approval: " + approval.state + " by " + approval.actor_user + " (" + approval.actor_role + ", " + approval.via + ") at " + approval.at + (approval.rationale ? ". Reason: " + approval.rationale : "")));
    box.replaceChildren(...nodes);
    actions.replaceChildren();
    const terminal = ["finished", "failed_to_start", "timed_out", "interrupted", "cancelled", "refused"].includes(r.state);
    const links = [];
    if (!terminal && can("operator")) links.push(h("button", { type: "button", onclick: async () => { try { await api("POST", "/v1/runs/" + id + "/cancel"); once(); } catch (e) { box.prepend(errBox(e)); } } }, "Cancel run"));
    if (r.bundle) {
      links.push(h("a", { href: "/v1/runs/" + id + "/report?format=html", target: "_blank", rel: "noopener" }, "Open the report"), link("/ui/runs/" + id + "/evidence", "Evidence and verification"), h("a", { href: "/v1/runs/" + id + "/bundle.tar" }, "Download the evidence bundle"));
    }
    if (r.state !== "awaiting_approval" || true) links.push(h("a", { href: "/v1/runs/" + id + "/output", target: "_blank", rel: "noopener" }, "Command output"));
    evid.replaceChildren(h("h2", {}, "Links"), h("div", { class: "row" }, links));
    if (!terminal) state.poll = setTimeout(once, r.state === "running" ? 3000 : 5000);
  }
  stopPolling();
  await once();
}

async function viewEvidence(id) {
  const [ev, ver] = await Promise.all([api("GET", "/v1/runs/" + id + "/evidence"), api("GET", "/v1/runs/" + id + "/verify")]);
  const rows = ev.files.map((f) => h("tr", {}, h("td", { class: "mono" }, f.path), h("td", {}, f.role), h("td", {}, f.size), h("td", { class: "mono" }, f.sha256), h("td", {}, h("a", { href: "/v1/runs/" + id + "/evidence/files/" + f.index }, "Download"))));
  const res = ver.result || {};
  page("Evidence of " + id,
    h("p", {}, link("/ui/runs/" + id, "Back to the run")),
    h("div", { class: "banner " + (ev.verification.accepted ? "ok" : "bad"), role: "status" }, h("strong", {}, "Independent verification: "), ver.meaning + " (exit status " + ver.exit_code + "). " + (ev.verification.accepted ? "The bundle verified: " + ev.verification.agreeing_assertions + " verdict(s) recomputed from the bundle alone agree with the report." : "The bundle did not verify.")),
    h("div", { class: "card" }, kv([["Level", [levelBadge(ev.level, ev.ceiling), " ceiling " + ev.ceiling]], ["Independent restatement", ev.independent_restatement ? "yes" : "no"], ["Why", ev.restatement_note], ["Manifest digest", h("code", {}, ev.manifest_digest || "-")], ["Plan digest", h("code", {}, ev.plan_digest || "-")], ["Assurance", res.assurance || ev.verification.assurance || "-"]])),
    h("p", { class: "small muted" }, "Verification is an internal-consistency check: without an external anchor it does not show the bundle was not rewritten, and it never shows the application under test is correct. Anchor the manifest digest where the producer cannot rewrite it (see the documentation)."),
    ev.verification.findings && ev.verification.findings.length ? h("div", { class: "banner bad" }, h("ul", {}, ev.verification.findings.map((f) => h("li", {}, typeof f === "string" ? f : JSON.stringify(f))))) : null,
    h("h2", {}, "Files"), table(["Path", "Role", "Size", "sha256", ""], rows, "Evidence files"));
}

async function viewUsers() {
  const data = await api("GET", "/v1/users");
  const rows = data.items.map((u) => h("tr", {}, h("td", {}, u.name), h("td", {}, u.role), h("td", {}, u.disabled ? badge("disabled", "bad") : badge("enabled", "ok")), h("td", { class: "mono" }, u.last_login_at || "never"),
    h("td", {}, h("button", { type: "button", onclick: async () => { try { await api("PATCH", "/v1/users/" + u.user_id, { disabled: !u.disabled }); viewUsers(); } catch (e) { main.prepend(errBox(e)); } } }, u.disabled ? "Enable" : "Disable"))));
  const err = h("div", { "aria-live": "polite" });
  const form = h("form", { onsubmit: async (e) => { e.preventDefault(); err.replaceChildren(); try { await api("POST", "/v1/users", { name: form.uname.value, role: form.role.value, password: form.pw.value }); viewUsers(); } catch (x) { err.replaceChildren(errBox(x)); } } },
    lab("uname", "Name", h("input", { id: "uname", name: "uname", required: true, pattern: "[a-z0-9][a-z0-9._-]{2,39}", autocomplete: "off" })),
    lab("urole", "Role", h("select", { id: "urole", name: "role" }, ["viewer", "operator", "admin"].map((r) => h("option", { value: r }, r)))),
    lab("upw", "Password (12 characters or more)", h("input", { id: "upw", name: "pw", type: "password", minlength: "12", required: true, autocomplete: "new-password" })),
    h("div", { class: "row" }, h("button", { class: "primary", type: "submit" }, "Add user")), err);
  page("Users", table(["Name", "Role", "State", "Last sign-in", ""], rows, "Users"), h("h2", {}, "Add a user"), form);
}

async function viewAbout() {
  const info = await api("GET", "/v1/info");
  page("About", kv([["Service", info.service + " " + info.version], ["Platform", info.capabilities.system + " " + info.capabilities.machine], ["Levels", "fixture target: " + info.levels.fixture_ceiling + "; external target: " + info.levels.external_ceiling],
    ["Run timeout", info.run_timeout_seconds + " s"], ["Target", info.target], ["Roles", info.auth.roles.join(", ")]]),
    h("p", {}, "Licence: source-available under the family licence (AGPL-3.0-or-later with the Commons Clause). Documentation: docs/standalone in the repository."));
}

// ---------------------------------------------------------------------------------------------- router
async function render() {
  stopPolling();
  const path = location.pathname.replace(/\/+$/, "") || "/ui";
  try {
    if (!state.session) await loadSession();
    if (!state.session) { if (path !== "/ui/signin") history.replaceState({}, "", "/ui/signin"); return viewSignIn(); }
    if (path === "/ui/signin") { history.replaceState({}, "", "/ui/"); }
    const p = location.pathname.replace(/\/+$/, "") || "/ui";
    let m;
    if (p === "/ui") return await viewDashboard();
    if (p === "/ui/targets") return await viewTargets();
    if (p === "/ui/new") return await viewNew();
    if (p === "/ui/runs") return await viewRuns();
    if (p === "/ui/users" && can("admin")) return await viewUsers();
    if (p === "/ui/about") return await viewAbout();
    if ((m = p.match(/^\/ui\/runs\/(r[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6})$/))) return await viewRun(m[1]);
    if ((m = p.match(/^\/ui\/runs\/(r[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6})\/evidence$/))) return await viewEvidence(m[1]);
    page("Not found", h("p", {}, "There is no such page. ", link("/ui/", "Back to the dashboard")));
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return;
    page("Something went wrong", errBox(e instanceof ApiError ? e : new ApiError(0, { detail: "the interface failed: " + e.message })));
  }
}
render();
