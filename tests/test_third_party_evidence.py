# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The evidence behind the third-party licence facts of the matrix: what a ``verified`` item needs, what the open items must say, that a notice file or an evidence table cannot be edited unnoticed,
and that a licence-bearing file of a shipped wheel that nobody recorded is found. Offline: synthetic wheels and small trees; the real matrix, lock and tables are read from the repository."""
import copy
import hashlib
import importlib.util
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_adapter_licenses", ROOT / "tools" / "check_adapter_licenses.py")
chk = importlib.util.module_from_spec(SPEC)
sys.modules["check_adapter_licenses"] = chk
SPEC.loader.exec_module(chk)

MATRIX_PATH = ROOT / "third_party" / "adapter-license-matrix.yaml"
REAL = yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))
NOTICES_LOCK = json.loads((ROOT / "third_party" / "notices" / "notices.lock.json").read_text(encoding="utf-8"))


def fresh():
    return copy.deepcopy(REAL)


def comp(matrix, cid):
    return next(c for c in matrix["components"] if c["id"] == cid)


def item(matrix, cid, iid):
    return next(i for i in comp(matrix, cid)["third_party_evidence"] if i["id"] == iid)


def codes(findings):
    return sorted({f.code for f in findings})


def findings_of(matrix):
    return [f for f in chk.check_matrix(matrix)]


# -------------------------------------------------------------------------------------------------------------------------- the real records
def test_the_real_matrix_notices_lock_and_tables_pass_together():
    assert chk.run(MATRIX_PATH, ROOT) == []


def test_every_verified_item_has_its_evidence_and_every_open_item_is_a_named_blocker_and_nothing_is_cleared():
    for cid in ("playwright-python", "robotframework"):
        c = comp(REAL, cid)
        open_ids = sorted(i["id"] for i in c["third_party_evidence"] if i["status"] != "verified")
        assert c["redistribution"]["public_distribution_blockers"] == open_ids and open_ids
        assert c["redistribution"]["public_distribution"] == "owner_decision_required" and c["redistribution"]["status"] == "staged_unmodified"
        for i in c["third_party_evidence"]:
            if i["status"] == "verified":
                assert i["version"] and i["identified_by"] and i["residual"] and i["licence_texts"]
                for src in i["sources"]:
                    assert src["url"].startswith("https://") and re.fullmatch(r"\d{4}-\d{2}-\d{2}", src["retrieved_on"]) and re.fullmatch(r"[0-9a-f]{64}", src["sha256"])
    assert not re.search(r"\b(cleared|approved|clearance)\b", MATRIX_PATH.read_text(encoding="utf-8"), re.I)


def test_the_four_items_of_the_request_are_recorded_with_the_status_the_evidence_supports():
    pw, rf = comp(REAL, "playwright-python"), comp(REAL, "robotframework")
    by = {i["id"]: i["status"] for c in (pw, rf) for i in c["third_party_evidence"]}
    assert by["pw-node-runtime"] == "verified" and by["pw-npm-inlined"] == "verified" and by["pw-minimatch"] == "verified"
    assert by["pw-proxy-agent-negotiate"] == "declared_only"                                  # no licence text in any primary source: stays open
    assert by["rf-jquery-3.5.1"] == "verified" and by["rf-libdoc-handlebars"] == "verified" and by["rf-tablesorter-2.30.5"] == "declared_only"
    assert item(REAL, "playwright-python", "pw-node-runtime")["version"] == "24.22.1"


def test_the_node_table_lists_the_44_sections_and_the_npm_table_the_81_notice_sections_of_the_wheel_files():
    node = json.loads((ROOT / "third_party" / "evidence" / "node-24.22.1-licence-sections.json").read_text(encoding="utf-8"))
    npm = json.loads((ROOT / "third_party" / "evidence" / "playwright-1.64.1-inlined-npm-packages.json").read_text(encoding="utf-8"))
    assert node["count"] == len(node["sections"]) == 44 and all(s["spdx"] for s in node["sections"])
    assert npm["count"] == len(npm["packages"]) == 81 and len({p["package"] for p in npm["packages"]}) == 79
    assert [p["package"] for p in npm["packages"] if not p["notice_text_contains_tarball_licence_file"]] == ["proxy-agent-negotiate@1.1.0"]
    assert all(p["tarball_sha512_verified"] for p in npm["packages"])


# ------------------------------------------------------------------------------------------------------- a verified item needs its evidence fields
@pytest.mark.parametrize("field", ["version", "identified_by", "residual", "spdx", "component"])
def test_a_verified_item_without_a_required_text_field_is_found(field):
    m = fresh()
    del item(m, "playwright-python", "pw-minimatch")[field]
    assert "EVIDENCE_MISSING_FIELD" in codes(findings_of(m))


@pytest.mark.parametrize("key", ["url", "retrieved_on", "sha256"])
def test_a_source_without_its_url_date_or_digest_is_found(key):
    m = fresh()
    del item(m, "robotframework", "rf-jquery-3.5.1")["sources"][3][key]                     # the licence_text source
    assert "EVIDENCE_MISSING_FIELD" in codes(findings_of(m))


def test_a_source_with_a_malformed_digest_date_or_url_is_found():
    for key, bad in (("sha256", "abc"), ("retrieved_on", "yesterday"), ("url", "http://example.org/x")):
        m = fresh()
        item(m, "playwright-python", "pw-minimatch")["sources"][2][key] = bad
        assert "EVIDENCE_MISSING_FIELD" in codes(findings_of(m)), key


def test_a_verified_item_without_a_fetched_licence_text_or_without_shipped_notices_is_found():
    m = fresh()
    it = item(m, "playwright-python", "pw-minimatch")
    it["sources"] = [s for s in it["sources"] if s["role"] != "licence_text"]
    assert "EVIDENCE_UNSUPPORTED_VERIFIED" in codes(findings_of(m))
    m = fresh()
    item(m, "playwright-python", "pw-minimatch")["licence_texts"] = []
    assert "EVIDENCE_UNSUPPORTED_VERIFIED" in codes(findings_of(m))
    m = fresh()
    item(m, "playwright-python", "pw-minimatch")["sources"] = [s for s in item(m, "playwright-python", "pw-minimatch")["sources"] if s["role"] == "licence_text"]
    assert any(f.code == "EVIDENCE_MISSING_FIELD" and "identification" in f.message for f in findings_of(m))


def test_an_item_cannot_become_verified_by_changing_the_word():
    m = fresh()
    item(m, "playwright-python", "pw-proxy-agent-negotiate")["status"] = "verified"            # no fetched licence text exists: the other fields do not carry it
    found = codes(findings_of(m))
    assert "EVIDENCE_UNSUPPORTED_VERIFIED" in found and "EVIDENCE_BLOCKERS" in found


def test_a_declared_only_item_states_where_the_text_was_not_found_and_the_options():
    for field in ("licence_text_absent", "options"):
        m = fresh()
        del item(m, "robotframework", "rf-tablesorter-2.30.5")[field]
        assert "EVIDENCE_MISSING_FIELD" in codes(findings_of(m)), field


def test_an_unverified_item_states_its_reason():
    m = fresh()
    it = item(m, "robotframework", "rf-tablesorter-2.30.5")
    it["status"] = "unverified"
    assert "EVIDENCE_MISSING_FIELD" in codes(findings_of(m))
    it["reason"] = "could not be read"
    assert "EVIDENCE_MISSING_FIELD" not in codes([f for f in findings_of(m) if "reason" in f.message])


def test_the_blockers_list_must_name_exactly_the_items_that_are_not_verified():
    m = fresh()
    comp(m, "playwright-python")["redistribution"]["public_distribution_blockers"] = []
    assert "EVIDENCE_BLOCKERS" in codes(findings_of(m))
    m = fresh()
    comp(m, "robotframework")["redistribution"]["public_distribution_blockers"] = ["rf-tablesorter-2.30.5", "rf-jquery-3.5.1"]
    assert "EVIDENCE_BLOCKERS" in codes(findings_of(m))


def test_an_evidence_item_never_says_cleared_or_approved_and_public_distribution_cannot_be_changed():
    m = fresh()
    item(m, "robotframework", "rf-jquery-3.5.1")["residual"] = "approved for public distribution"
    assert "EVIDENCE_CLAIM" in codes(findings_of(m))
    m = fresh()
    comp(m, "robotframework")["redistribution"]["public_distribution"] = "cleared"
    assert "STAGED_PUBLIC_CLAIM" in codes(findings_of(m))


def test_an_unverified_licence_in_a_shipped_wheel_needs_an_evidence_item_that_says_why():
    m = fresh()
    for d in comp(m, "playwright-python")["bundled_deps"]:
        if d["name"].startswith("proxy-agent-negotiate"):
            del d["evidence"]
    assert any(f.code == "EVIDENCE_MISSING_FIELD" and "unverified licence in a shipped wheel" in f.message for f in findings_of(m))
    m = fresh()
    for d in comp(m, "robotframework")["bundled_deps"]:
        if d["name"].startswith("Handlebars"):
            d["spdx"] = "unverified"                                                            # verified evidence but the licence still marked unverified
    assert "EVIDENCE_SCHEMA" in codes(findings_of(m))


def test_dropping_a_component_from_the_evidence_leaves_its_dependency_entry_without_a_reason():
    m = fresh()
    c = comp(m, "playwright-python")
    c["third_party_evidence"] = [i for i in c["third_party_evidence"] if i["id"] != "pw-minimatch"]
    found = findings_of(m)
    assert "EVIDENCE_SCHEMA" in codes(found) and any("pw-minimatch" in f.message for f in found)


# ------------------------------------------------------------------------------------------------------------- the notices lock and the files behind it
def make_repo(tmp_path):
    """A copy of the parts of the repository the notices checks read: the notices tree, the evidence tables and the matrix."""
    shutil.copytree(ROOT / "third_party" / "notices", tmp_path / "third_party" / "notices")
    shutil.copytree(ROOT / "third_party" / "evidence", tmp_path / "third_party" / "evidence")
    return tmp_path


def lock_findings(matrix, lock, root):
    return chk.check_notices_lock(matrix, lock, root)


def test_the_real_lock_matches_the_repository_files_and_the_matrix(tmp_path):
    assert lock_findings(REAL, copy.deepcopy(NOTICES_LOCK), make_repo(tmp_path)) == []


def test_an_edited_upstream_notice_file_is_found_by_its_digest(tmp_path):
    root = make_repo(tmp_path)
    path = root / "third_party" / "notices" / "upstream" / "minimatch-10.2.5" / "LICENSE.md"
    path.write_bytes(path.read_bytes() + b"\nan edit\n")
    found = lock_findings(REAL, copy.deepcopy(NOTICES_LOCK), root)
    assert "NOTICE_DIGEST" in codes(found) and any("LICENSE.md" in f.message for f in found)


def test_a_file_added_under_the_notices_tree_without_a_lock_entry_is_found(tmp_path):
    root = make_repo(tmp_path)
    (root / "third_party" / "notices" / "upstream" / "stray.txt").write_text("x")
    assert "UNLISTED_NOTICE_FILE" in codes(lock_findings(REAL, copy.deepcopy(NOTICES_LOCK), root))


def test_a_licence_file_of_a_shipped_wheel_that_the_lock_does_not_ship_is_found(tmp_path):
    lock = copy.deepcopy(NOTICES_LOCK)
    lock["files"] = [f for f in lock["files"] if not f["dest"].endswith("playwright/driver/LICENSE")]
    found = lock_findings(REAL, lock, make_repo(tmp_path))
    assert "NOTICE_NOT_SHIPPED" in codes(found) and "EVIDENCE_NOTICE" in codes(found)


def test_a_lock_entry_for_a_file_the_matrix_does_not_record_is_found_and_so_is_a_different_digest(tmp_path):
    lock = copy.deepcopy(NOTICES_LOCK)
    lock["files"].append({"id": "extra", "dest": "wheels/pyee-14.0.0/pyee-14.0.0.dist-info/licenses/EXTRA", "sha256": "0" * 64,
                          "origin": {"kind": "wheel", "wheel": "pyee", "version": "14.0.0", "member": "pyee-14.0.0.dist-info/licenses/EXTRA"}, "covers": []})
    assert "NOTICES_LOCK" in codes(lock_findings(REAL, lock, make_repo(tmp_path)))
    lock = copy.deepcopy(NOTICES_LOCK)
    next(f for f in lock["files"] if f["dest"].endswith("pyee-14.0.0.dist-info/licenses/LICENSE"))["sha256"] = "1" * 64
    assert "NOTICE_DIGEST" in codes(lock_findings(REAL, lock, make_repo(tmp_path / "b")))


def test_an_evidence_item_that_names_a_notice_the_lock_does_not_have_or_does_not_cover_is_found(tmp_path):
    m = fresh()
    item(m, "robotframework", "rf-jquery-3.5.1")["licence_texts"].append("no-such-notice")
    assert "EVIDENCE_NOTICE" in codes(lock_findings(m, copy.deepcopy(NOTICES_LOCK), make_repo(tmp_path)))
    lock = copy.deepcopy(NOTICES_LOCK)
    next(f for f in lock["files"] if f["id"] == "jquery-3.5.1-license")["covers"] = []
    assert "EVIDENCE_NOTICE" in codes(lock_findings(REAL, lock, make_repo(tmp_path / "b")))
    m = fresh()
    next(s for s in item(m, "robotframework", "rf-jquery-3.5.1")["sources"] if s["role"] == "licence_text")["sha256"] = "2" * 64      # the fetched text is not the shipped one
    assert any("is not the shipped notice" in f.message for f in lock_findings(m, copy.deepcopy(NOTICES_LOCK), make_repo(tmp_path / "c")))


def test_a_malformed_lock_is_found(tmp_path):
    root = make_repo(tmp_path)
    for mutate in (lambda l: l.update(schema="x"), lambda l: l["files"][0].update(dest="../x"), lambda l: l["files"][0].update(sha256="short"),
                   lambda l: l["files"][1].update(id=l["files"][0]["id"]), lambda l: l["files"][2].update(origin={"kind": "elsewhere"})):
        lock = copy.deepcopy(NOTICES_LOCK)
        mutate(lock)
        assert "NOTICES_LOCK" in codes(lock_findings(REAL, lock, root))


def test_an_edited_evidence_table_is_found_by_its_digest(tmp_path):
    root = make_repo(tmp_path)
    assert chk.check_evidence_tables(REAL, root) == []
    path = root / "third_party" / "evidence" / "playwright-1.64.1-inlined-npm-packages.json"
    path.write_text(path.read_text(encoding="utf-8").replace("proxy-agent-negotiate@1.1.0", "proxy-agent-negotiate@1.1.1", 1), encoding="utf-8")
    assert "EVIDENCE_TABLE" in codes(chk.check_evidence_tables(REAL, root))


# ------------------------------------------------------------------------------------------- a built notices tree, and the wheels it came from
def make_tree(tmp_path, lock, files):
    tree = tmp_path / "THIRD_PARTY_NOTICES"
    for dest, data in files.items():
        (tree / dest).parent.mkdir(parents=True, exist_ok=True)
        (tree / dest).write_bytes(data)
    (tree / "INDEX.json").write_text(json.dumps({"files": [{"path": f["dest"], "sha256": f["sha256"]} for f in lock["files"]]}))
    return tree


def small_lock(wheel_bytes):
    return {"schema": chk.NOTICES_LOCK_SCHEMA, "version": 1, "files": [
        {"id": "a", "dest": "upstream/a/LICENSE", "sha256": hashlib.sha256(b"a text").hexdigest(), "origin": {"kind": "upstream", "path": "third_party/notices/upstream/a/LICENSE", "url": "https://x.org", "retrieved_on": "2026-11-03"}, "covers": []},
        {"id": "w", "dest": "wheels/w-1/w-1.dist-info/licenses/LICENSE", "sha256": hashlib.sha256(wheel_bytes).hexdigest(), "origin": {"kind": "wheel", "wheel": "w", "version": "1", "member": "w-1.dist-info/licenses/LICENSE"}, "covers": []}]}


def test_the_tree_check_finds_an_edited_added_or_missing_file_a_wrong_index_and_a_file_that_is_not_the_wheels_member(tmp_path):
    wheelhouse = tmp_path / "wh"
    wheelhouse.mkdir()
    with zipfile.ZipFile(wheelhouse / "w-1-py3-none-any.whl", "w") as zf:
        zf.writestr("w-1.dist-info/licenses/LICENSE", "w licence")
    lock = small_lock(b"w licence")
    files = {"upstream/a/LICENSE": b"a text", "wheels/w-1/w-1.dist-info/licenses/LICENSE": b"w licence"}
    tree = make_tree(tmp_path, lock, files)
    assert chk.check_notices_tree(lock, tree, wheelhouse) == []
    (tree / "upstream/a/LICENSE").write_bytes(b"edited")
    assert "NOTICE_DIGEST" in codes(chk.check_notices_tree(lock, tree, wheelhouse))
    (tree / "upstream/a/LICENSE").write_bytes(b"a text")
    (tree / "extra").write_bytes(b"x")
    assert "NOTICES_TREE" in codes(chk.check_notices_tree(lock, tree, wheelhouse))
    (tree / "extra").unlink()
    (tree / "upstream/a/LICENSE").unlink()
    assert "NOTICES_TREE" in codes(chk.check_notices_tree(lock, tree, wheelhouse))
    (tree / "upstream/a/LICENSE").write_bytes(b"a text")
    (tree / "INDEX.json").write_text(json.dumps({"files": []}))
    assert any("INDEX.json" in f.component for f in chk.check_notices_tree(lock, tree, wheelhouse))
    other = make_tree(tmp_path / "o", lock, {**files, "wheels/w-1/w-1.dist-info/licenses/LICENSE": b"w licence"})
    with zipfile.ZipFile(wheelhouse / "w-1-py3-none-any.whl", "w") as zf:                      # the shipped wheel's licence file changed after the notices were made
        zf.writestr("w-1.dist-info/licenses/LICENSE", "another licence")
    assert any("byte for byte" in f.message for f in chk.check_notices_tree(lock, other, wheelhouse))


# ----------------------------------------------------------------------------- licence-bearing files of a shipped wheel and the tables checked against the wheel
def one_wheel_matrix(tmp_path, members, extra=None):
    path = tmp_path / "w-1-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("w-1.dist-info/licenses/LICENSE", "licence")
        for name, data in members.items():
            zf.writestr(name, data)
    sha = lambda b: hashlib.sha256(b).hexdigest()
    rec = {"name": "w", "version": "1", "file": path.name, "sha256": sha(path.read_bytes()), "license_files": [{"path": "w-1.dist-info/licenses/LICENSE", "sha256": sha(b"licence")}], "recorded_members": []}
    comp_ = {"id": "x", "shipped_wheels": [rec]}
    comp_.update(extra or {})
    return {"components": [comp_]}


@pytest.mark.parametrize("member", ["w/THIRD-PARTY-NOTICES.txt", "w/vendor/licenses/mit.txt", "w/vendor/COPYING.lib", "w/lib/foo.LICENSE", "w/Copyright.md", "w/notices/foo.txt", "w/node_modules/x/license"])
def test_a_licence_bearing_file_that_is_not_recorded_is_found(tmp_path, member):
    matrix = one_wheel_matrix(tmp_path, {member: "text"})
    assert "UNRECORDED_LICENCE_FILE" in codes(chk.check_wheelhouse(matrix, tmp_path))


def test_a_recorded_licence_bearing_file_and_an_ordinary_file_pass(tmp_path):
    matrix = one_wheel_matrix(tmp_path, {"w/code.py": "x = 1", "w/data.json": "{}"})
    assert chk.check_wheelhouse(matrix, tmp_path) == []


def test_the_node_table_is_checked_against_the_licence_file_of_the_wheel(tmp_path):
    text = ("Node.js is licensed for use as follows:\n\n- Alpha, located at deps/alpha, is licensed as follows:\n  MIT text one\n\n- Beta, located at tools/beta/, is licensed as follows:\n  BSD text two\n")
    sections = chk.node_license_sections(text)
    assert [(s["name"], s["location_class"]) for s in sections] == [("Alpha", "source-dependency"), ("Beta", "tools-or-test-path")]
    evidence = tmp_path / "third_party" / "evidence"
    evidence.mkdir(parents=True)
    table = {"schema": chk.NODE_TABLE_SCHEMA, "license_file_sha256": hashlib.sha256(text.encode()).hexdigest(), "sections": [dict(s, spdx="MIT") for s in sections]}
    (evidence / "n.json").write_text(json.dumps(table))
    item_ = {"id": "n", "table": {"kind": "node-licence-sections", "path": "third_party/evidence/n.json", "source_member": "w/nodelist.txt"}}
    matrix = one_wheel_matrix(tmp_path, {"w/nodelist.txt": text}, {"third_party_evidence": [item_]})
    assert chk.check_wheelhouse(matrix, tmp_path, tmp_path) == []
    matrix2 = one_wheel_matrix(tmp_path / "b", {"w/nodelist.txt": text.replace("- Beta, located at tools/beta/, is licensed as follows:\n  BSD text two\n", "")}, {"third_party_evidence": [item_]}) if (tmp_path / "b").mkdir() is None else None
    found = chk.check_wheelhouse(matrix2, tmp_path / "b", tmp_path)                           # a component dropped from the wheel's licence file
    assert "NODE_TABLE_MISMATCH" in codes(found)
    matrix3 = one_wheel_matrix(tmp_path / "c", {"w/nodelist.txt": text.replace("MIT text one", "MIT text ONE")}, {"third_party_evidence": [item_]}) if (tmp_path / "c").mkdir() is None else None
    assert "NODE_TABLE_MISMATCH" in codes(chk.check_wheelhouse(matrix3, tmp_path / "c", tmp_path))     # a section's text changed


def npm_sidecar(sections):
    return "".join(f"%% {key} NOTICES AND INFORMATION BEGIN HERE\n=========================================\n{body}\n=========================================\nEND OF {key} NOTICES AND INFORMATION\n\n" for key, body in sections.items())


def test_the_npm_table_is_checked_against_the_sidecar_notice_files(tmp_path):
    mit = "The MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy"
    sidecar = npm_sidecar({"a@1.0.0": mit, "b@2.0.0": "(no license text found; declared licenses: MIT)"})
    parsed = chk.npm_notice_sections(sidecar)
    assert parsed["a@1.0.0"][0] == "MIT" and parsed["b@2.0.0"][0] == "none-declared"
    rows = [{"package": "a@1.0.0", "notice_file": "sidecar.txt", "notice_section_sha256": parsed["a@1.0.0"][1], "registry_license": "MIT", "tarball_sha512_verified": True,
             "licence_files_in_tarball": {"LICENSE": "x"}, "notice_text_contains_tarball_licence_file": ["LICENSE"]},
            {"package": "b@2.0.0", "notice_file": "sidecar.txt", "notice_section_sha256": parsed["b@2.0.0"][1], "registry_license": "MIT", "tarball_sha512_verified": True,
             "licence_files_in_tarball": {}, "notice_text_contains_tarball_licence_file": []}]
    evidence = tmp_path / "third_party" / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "n.json").write_text(json.dumps({"schema": chk.NPM_TABLE_SCHEMA, "packages": rows}))
    item_ = {"id": "n", "table": {"kind": "npm-inlined-packages", "path": "third_party/evidence/n.json", "source_members": ["w/sidecar.txt"]}}
    matrix = one_wheel_matrix(tmp_path, {"w/sidecar.txt": sidecar}, {"third_party_evidence": [item_]})
    assert chk.check_wheelhouse(matrix, tmp_path, tmp_path) == []
    for n, (edit, expected) in enumerate((
            (lambda: sidecar.replace("a@1.0.0 NOTICES AND INFORMATION BEGIN HERE", "a@1.0.1 NOTICES AND INFORMATION BEGIN HERE"), "NPM_TABLE_MISMATCH"),         # a package at another version
            (lambda: sidecar.split("%% b@2.0.0")[0], "NPM_TABLE_MISMATCH"),                                                                                     # a package dropped from the wheel
            (lambda: sidecar.replace("Permission is hereby granted, free of charge", "Permission is hereby granted, for a fee"), "NPM_TABLE_MISMATCH"),         # a text changed
            (lambda: sidecar.replace("(no license text found; declared licenses: MIT)", mit), "NPM_LICENCE_DISAGREES"))):
        sub = tmp_path / f"m{n}"
        sub.mkdir()
        (sub / "third_party").symlink_to(tmp_path / "third_party")
        text = edit()
        matrix_n = one_wheel_matrix(sub, {"w/sidecar.txt": text}, {"third_party_evidence": [item_]})
        assert expected in codes(chk.check_wheelhouse(matrix_n, sub, tmp_path)), n
    rows[0]["registry_license"] = "GPL-3.0-only"                                                              # the registry declares something the notice does not say
    (evidence / "n.json").write_text(json.dumps({"schema": chk.NPM_TABLE_SCHEMA, "packages": rows}))
    assert "NPM_LICENCE_DISAGREES" in codes(chk.check_wheelhouse(matrix, tmp_path, tmp_path))


def test_an_evidence_member_that_is_not_in_the_wheel_or_not_recorded_is_found(tmp_path):
    item_ = {"id": "m", "shipped_members": ["w/code.py", "w/other.py"], "inlined_in": "w/missing.js"}
    matrix = one_wheel_matrix(tmp_path, {"w/code.py": "x = 1"}, {"third_party_evidence": [item_]})
    found = codes(chk.check_wheelhouse(matrix, tmp_path, tmp_path))
    assert "EVIDENCE_MEMBER_MISSING" in found and "EVIDENCE_MEMBER_UNRECORDED" in found


# -------------------------------------------------------------------------------------------------------------- the collector tool and the workflow
def test_the_node_collector_refuses_a_licence_file_with_a_component_it_was_not_told_about_or_a_section_that_does_not_support_its_licence(tmp_path):
    spec = importlib.util.spec_from_file_location("collect_licence_evidence", ROOT / "tools" / "collect_licence_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["collect_licence_evidence"] = mod
    spec.loader.exec_module(mod)
    text = "".join(f"- {n}, located at deps/{n.lower()}, is licensed as follows:\n  \"\"\"\n  MIT text\n  \"\"\"\n\n" for n in mod.NODE_CLASSES)
    wheel = tmp_path / "pw.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(mod.NODE_LICENSE_MEMBER, text)
    with pytest.raises(SystemExit, match="does not contain the words"):                         # every section says 'MIT text', so the first non-MIT classification stops the tool
        mod.node_sections(wheel, "1")
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(mod.NODE_LICENSE_MEMBER, text + "- Newcomer, located at deps/new, is licensed as follows:\n  x\n")
    with pytest.raises(SystemExit, match="Newcomer"):
        mod.node_sections(wheel, "1")


def test_the_bundle_job_checks_the_notices_tree_against_the_lock_and_the_shipped_wheels_and_the_matrix_job_runs_these_tests():
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    bundle = "\n".join(str(s.get("run", "")) for s in wf["jobs"]["bundle"]["steps"])
    assert "--notices" in bundle and "THIRD_PARTY_NOTICES" in bundle and "--wheelhouse" in bundle
    licences = "\n".join(str(s.get("run", "")) for s in wf["jobs"]["adapter-licences"]["steps"])
    assert "tests/test_third_party_evidence.py" in licences
