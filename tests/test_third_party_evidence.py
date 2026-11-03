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
    assert "MATRIX_CLAIM" in codes(findings_of(m))
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
    (tmp_path / "bundle").mkdir()
    shutil.copyfile(ROOT / "bundle" / "README.md", tmp_path / "bundle" / "README.md")
    (tmp_path / "tools").mkdir()
    shutil.copyfile(ROOT / "tools" / "build_bundle.py", tmp_path / "tools" / "build_bundle.py")
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
    text = ("Node.js is licensed for use as follows:\n\n- Alpha, located at deps/alpha, is licensed as follows:\n  Permission is hereby granted, free of charge, MIT one\n\n- Beta, located at tools/beta/, is licensed as follows:\n  Permission is hereby granted, free of charge, two\n")
    sections = chk.node_license_sections(text)
    assert [(s["name"], s["location_class"]) for s in sections] == [("Alpha", "source-dependency"), ("Beta", "tools-or-test-path")]
    evidence = tmp_path / "third_party" / "evidence"
    evidence.mkdir(parents=True)
    table = {"schema": chk.NODE_TABLE_SCHEMA, "count": 2, "license_file_sha256": hashlib.sha256(text.encode()).hexdigest(), "sections": [dict(s, spdx="MIT") for s in sections]}
    (evidence / "n.json").write_text(json.dumps(table))
    item_ = {"id": "n", "table": {"kind": "node-licence-sections", "path": "third_party/evidence/n.json", "source_member": "w/nodelist.txt"}}
    matrix = one_wheel_matrix(tmp_path, {"w/nodelist.txt": text}, {"third_party_evidence": [item_]})
    assert chk.check_wheelhouse(matrix, tmp_path, tmp_path) == []
    matrix2 = one_wheel_matrix(tmp_path / "b", {"w/nodelist.txt": text.replace("- Beta, located at tools/beta/, is licensed as follows:\n  Permission is hereby granted, free of charge, two\n", "")}, {"third_party_evidence": [item_]}) if (tmp_path / "b").mkdir() is None else None
    found = chk.check_wheelhouse(matrix2, tmp_path / "b", tmp_path)                           # a component dropped from the wheel's licence file
    assert "NODE_TABLE_MISMATCH" in codes(found)
    matrix3 = one_wheel_matrix(tmp_path / "c", {"w/nodelist.txt": text.replace("Permission is hereby granted, free of charge, MIT one", "MIT text ONE")}, {"third_party_evidence": [item_]}) if (tmp_path / "c").mkdir() is None else None
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
    (evidence / "n.json").write_text(json.dumps({"schema": chk.NPM_TABLE_SCHEMA, "count": 2, "distinct": 2, "packages": rows}))
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
    (evidence / "n.json").write_text(json.dumps({"schema": chk.NPM_TABLE_SCHEMA, "count": 2, "distinct": 2, "packages": rows}))
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


# ------------------------------------------------------------------------------------------------------------------------------- owner decisions
def decision_findings(matrix, root, lock=None):
    return chk.check_owner_decisions(matrix, lock or copy.deepcopy(NOTICES_LOCK), root)


def test_the_owner_decisions_of_2026_11_03_are_recorded_with_date_and_conditions_and_every_other_shipped_item_says_none_yet(tmp_path):
    pw, rf = comp(REAL, "playwright-python"), comp(REAL, "robotframework")
    want = {"pw-node-runtime": "accepted provisionally", "pw-node-icu": "accepted", "pw-minimatch": "accepted", "pw-proxy-agent-negotiate": "conditional acceptance", "rf-tablesorter-2.30.5": "conditional acceptance"}
    decided = {}
    for c in (pw, rf):
        for i in c["third_party_evidence"]:
            block = i["owner_decision"]
            if block["decision"] != "none yet":
                decided[i["id"]] = block["decision"]
                assert block["date"] == "2026-11-03" and block["decided_by"] == "owner" and block["conditions"] and all(k["status"] == "satisfied" for k in block["conditions"])
            else:
                assert set(block) == {"decision"}
    assert decided == want
    assert item(REAL, "robotframework", "rf-tablesorter-2.30.5")["owner_decision"]["elected_licence"] == "MIT"
    for cid in ("playwright-python", "robotframework", "playwright-python-direct-deps", "typing-extensions-shipped", "pyyaml-shipped"):
        assert comp(REAL, cid)["owner_decision"] == {"decision": "none yet"}
    pending = REAL["bundle_public_distribution"]
    assert pending["status"] == "owner_decision_required" and pending["pending_decisions"] == chk.pending_decisions(REAL) and "pw-vite-codicon" in pending["pending_decisions"] and "pw-minimatch" not in pending["pending_decisions"]
    assert decision_findings(REAL, make_repo(tmp_path)) == []


def test_every_open_item_and_every_item_found_in_the_review_has_no_owner_decision_yet():
    for iid, cid in (("pw-webp-codec", "playwright-python"), ("pw-vite-react", "playwright-python"), ("pw-vite-codemirror", "playwright-python"), ("pw-vite-xterm", "playwright-python"), ("pw-vite-codicon", "playwright-python"),
                     ("pw-vite-browser-logos", "playwright-python"), ("pw-vendored-sources", "playwright-python"), ("rf-jquery-tmpl", "robotframework"), ("rf-jquery-highlight", "robotframework"), ("rf-jsxcompressor", "robotframework")):
        assert item(REAL, cid, iid)["owner_decision"] == {"decision": "none yet"}, iid


def test_a_shipped_item_or_component_with_neither_a_decision_nor_none_yet_is_found():
    m = fresh()
    del item(m, "playwright-python", "pw-vite-react")["owner_decision"]
    assert "OWNER_DECISION_MISSING" in codes(findings_of(m))
    m = fresh()
    del comp(m, "pyyaml-shipped")["owner_decision"]
    assert "OWNER_DECISION_MISSING" in codes(findings_of(m))
    m = fresh()
    item(m, "playwright-python", "pw-vite-react")["owner_decision"] = {"decision": "approved"}
    assert "OWNER_DECISION_MISSING" in codes(findings_of(m))


@pytest.mark.parametrize("edit", ["date", "decided_by", "conditions", "condition_text", "condition_kind", "condition_status"])
def test_a_recorded_decision_without_its_date_or_conditions_is_found(edit):
    m = fresh()
    block = item(m, "playwright-python", "pw-minimatch")["owner_decision"]
    if edit == "date": del block["date"]
    elif edit == "decided_by": block["decided_by"] = "someone"
    elif edit == "conditions": block["conditions"] = []
    elif edit == "condition_text": del block["conditions"][0]["text"]
    elif edit == "condition_kind": block["conditions"][0]["kind"] = "trust_me"
    else: block["conditions"][0]["status"] = "probably"
    assert "OWNER_DECISION_INCOMPLETE" in codes(findings_of(m))


def test_a_conditional_decision_whose_condition_is_not_evidenced_is_found(tmp_path):
    root = make_repo(tmp_path)
    m = fresh()                                                                                    # tablesorter: fewer than five sources quote the MIT alternative
    it = item(m, "robotframework", "rf-tablesorter-2.30.5")
    next(sr for sr in it["sources"] if sr["role"] == "declared_licence")["quote"] = "Dual licensed under the GPL"
    found = decision_findings(m, root)
    assert "OWNER_CONDITION_UNEVIDENCED" in codes(found) and "OWNER_CONDITION_STATUS" in codes(found)
    m = fresh()
    item(m, "robotframework", "rf-tablesorter-2.30.5")["owner_decision"]["elected_licence"] = "GPL-2.0"      # the elected alternative is not MIT
    assert "OWNER_CONDITION_UNEVIDENCED" in codes(decision_findings(m, root))
    m = fresh()
    item(m, "playwright-python", "pw-proxy-agent-negotiate")["licence_text_absent"] = ""                      # the missing text is no longer documented in the item
    assert "OWNER_CONDITION_UNEVIDENCED" in codes(decision_findings(m, root))
    (root / "bundle" / "README.md").write_text((root / "bundle" / "README.md").read_text().replace("proxy-agent-negotiate", "the package"))    # nor where a redistributor reads it
    assert any("bundle/README.md does not mention" in f.message for f in decision_findings(fresh(), root))


def test_the_provisional_decision_on_node_needs_its_notices_and_its_retained_residuals(tmp_path):
    root = make_repo(tmp_path)
    m = fresh()
    it = item(m, "playwright-python", "pw-node-runtime")
    it["residual"] = it["residual"].replace("signature", "checksum")                                           # the unresolved release-signature check is no longer retained in the record
    assert any("residual" in f.message for f in decision_findings(m, root))
    lock = copy.deepcopy(NOTICES_LOCK)
    lock["files"] = [f for f in lock["files"] if not f["id"].endswith("driver-package-notice")]               # a required notice is no longer shipped
    assert "OWNER_CONDITION_UNEVIDENCED" in codes(decision_findings(fresh(), root, lock))


def test_the_acceptance_of_minimatch_needs_its_licence_text_and_its_attribution_file(tmp_path):
    root = make_repo(tmp_path)
    lock = copy.deepcopy(NOTICES_LOCK)
    entry = next(f for f in lock["files"] if f["id"] == "minimatch-10.2.5-package-json")
    assert "attribution" in entry["label"] and entry["origin"]["member"] == "package/package.json"
    assert json.loads((root / entry["origin"]["path"]).read_text())["author"].startswith("Isaac Z. Schlueter")
    entry["label"] = "package.json"                                                                           # no longer labelled as the attribution
    assert "OWNER_CONDITION_UNEVIDENCED" in codes(decision_findings(fresh(), root, lock))
    lock["files"] = [f for f in lock["files"] if f["id"] != "minimatch-10.2.5-package-json"]
    assert "OWNER_CONDITION_UNEVIDENCED" in codes(decision_findings(fresh(), root, lock))


def test_the_icu_acceptance_needs_the_icu_section_of_the_table(tmp_path):
    root = make_repo(tmp_path)
    path = root / "third_party" / "evidence" / "node-24.22.1-licence-sections.json"
    table = json.loads(path.read_text())
    next(sec for sec in table["sections"] if sec["name"] == "ICU")["spdx"] = "MIT"
    path.write_text(json.dumps(table))
    assert any("no section ICU" in f.message for f in decision_findings(fresh(), root))


def test_a_condition_recorded_with_the_wrong_status_is_found():
    m = fresh()
    item(m, "playwright-python", "pw-minimatch")["owner_decision"]["conditions"][0]["status"] = "open"
    found = decision_findings(m, ROOT)
    assert "OWNER_CONDITION_STATUS" in codes(found)
    assert chk.pending_decisions(m) != REAL["bundle_public_distribution"]["pending_decisions"] and "BUNDLE_PUBLIC_DISTRIBUTION" in codes(findings_of(m))


def test_the_bundle_level_block_stays_owner_decision_required_and_lists_exactly_the_pending_items():
    m = fresh()
    m["bundle_public_distribution"]["status"] = "permitted"
    assert "BUNDLE_PUBLIC_DISTRIBUTION" in codes(findings_of(m))
    m = fresh()
    m["bundle_public_distribution"]["pending_decisions"].remove("pw-vite-react")
    assert "BUNDLE_PUBLIC_DISTRIBUTION" in codes(findings_of(m))
    m = fresh()
    del m["bundle_public_distribution"]
    assert "BUNDLE_PUBLIC_DISTRIBUTION" in codes(findings_of(m))


def test_the_run_function_evaluates_the_decisions_so_the_command_line_check_does_too(tmp_path):
    m = fresh()
    item(m, "playwright-python", "pw-minimatch")["owner_decision"]["conditions"][1]["notices"] = ["no-such-notice"]
    path = tmp_path / "third_party" / "adapter-license-matrix.yaml"
    shutil.copytree(ROOT / "third_party" / "notices", tmp_path / "third_party" / "notices")
    shutil.copytree(ROOT / "third_party" / "evidence", tmp_path / "third_party" / "evidence")
    path.write_text(yaml.safe_dump(m, sort_keys=False))
    assert "OWNER_CONDITION_UNEVIDENCED" in codes(chk.run(path, tmp_path))


# ---------------------------------------------------------------------------------------------------------------- the review's follow-up findings
def test_the_npm_item_does_not_rest_on_the_hash_of_the_authors_own_table(tmp_path):
    root = make_repo(tmp_path)
    it = item(REAL, "playwright-python", "pw-npm-inlined")
    table_sha = it["table"]["sha256"]
    assert all(src["sha256"] != table_sha for src in it["sources"]) and all(src.get("derived") for src in it["sources"])
    assert chk.check_evidence_tables(REAL, root) == []
    m = fresh()
    item(m, "playwright-python", "pw-npm-inlined")["sources"][0]["sha256"] = table_sha                         # the table's own digest presented as what was fetched
    assert "EVIDENCE_SELF_REFERENCE" in codes(chk.check_evidence_tables(m, root))
    m = fresh()
    item(m, "playwright-python", "pw-npm-inlined")["sources"][1]["sha256"] = "3" * 64                          # a derived digest that is not the one recomputed from the rows
    assert "EVIDENCE_DERIVED" in codes(chk.check_evidence_tables(m, root))
    m = fresh()
    del item(m, "playwright-python", "pw-npm-inlined")["table"]
    assert "EVIDENCE_DERIVED" in codes(chk.check_evidence_tables(m, root))


def test_the_npm_table_count_and_the_derived_digests_are_recomputed(tmp_path):
    root = make_repo(tmp_path)
    path = root / "third_party" / "evidence" / "playwright-1.64.1-inlined-npm-packages.json"
    data = json.loads(path.read_text())
    assert data["derived_digests"] == chk.npm_table_digests(data)
    data["count"] = 80
    path.write_text(json.dumps(data))
    m = fresh()
    item(m, "playwright-python", "pw-npm-inlined")["table"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert any("count 80" in f.message for f in chk.check_evidence_tables(m, root))


def test_a_licence_claim_on_a_bundled_dependency_must_agree_with_the_evidence_status():
    for cid, iid, name in (("robotframework", "rf-tablesorter-2.30.5", "jQuery tablesorter"), ("playwright-python", "pw-proxy-agent-negotiate", "proxy-agent-negotiate"), ("robotframework", "rf-jsxcompressor", "JSXCompressor")):
        m = fresh()
        dep = next(d for d in comp(m, cid)["bundled_deps"] if d.get("evidence") == iid)
        dep["spdx"] = "MIT"                                                                                   # a claimed licence for an item that is only declared
        assert any("only a verified item supports a licence" in f.message for f in findings_of(m)), name
    m = fresh()
    dep = next(d for d in comp(m, "playwright-python")["bundled_deps"] if d.get("evidence") == "pw-minimatch")
    dep["spdx"] = "unverified"
    assert "EVIDENCE_SCHEMA" in codes(findings_of(m))


def test_the_command_line_check_scans_the_whole_matrix_for_cleared_approved_compatible_permitted(tmp_path):
    for word in ("cleared", "approved", "compatible", "permitted", "clearance"):
        m = fresh()
        comp(m, "playwright-python")["trademark"]["note"] = f"this is {word} for use"
        path = tmp_path / f"m-{word}.yaml"
        path.write_text(yaml.safe_dump(m, sort_keys=False))
        found = chk.run(path, ROOT)
        assert "MATRIX_CLAIM" in codes(found), word
    assert not [f for f in chk.run(MATRIX_PATH, ROOT) if f.code == "MATRIX_CLAIM"]


def test_the_node_table_labels_are_recomputed_from_the_sections_own_text():
    text = "- Alpha, located at deps/alpha, is licensed as follows:\n  Permission is hereby granted, free of charge, to any person\n"
    assert chk.NODE_SPDX_SUPPORT["MIT"][0][0] in text.lower()
    assert not any(all(w in text.lower() for w in alt) for alt in chk.NODE_SPDX_SUPPORT["Apache-2.0"])


def test_the_node_table_with_a_wrong_licence_label_is_found_against_the_wheel(tmp_path):
    text = "- Alpha, located at deps/alpha, is licensed as follows:\n  Permission is hereby granted, free of charge, MIT one\n"
    sections = chk.node_license_sections(text)
    evidence = tmp_path / "third_party" / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "n.json").write_text(json.dumps({"schema": chk.NODE_TABLE_SCHEMA, "count": 1, "license_file_sha256": hashlib.sha256(text.encode()).hexdigest(), "sections": [dict(sections[0], spdx="Apache-2.0")]}))
    item_ = {"id": "n", "table": {"kind": "node-licence-sections", "path": "third_party/evidence/n.json", "source_member": "w/nodelist.txt"}}
    matrix = one_wheel_matrix(tmp_path, {"w/nodelist.txt": text}, {"third_party_evidence": [item_]})
    assert any("does not support the licence 'Apache-2.0'" in f.message for f in chk.check_wheelhouse(matrix, tmp_path, tmp_path))


def test_the_node_obligations_do_not_ask_a_binary_copy_for_a_zlib_notice():
    text = item(REAL, "playwright-python", "pw-node-runtime")["obligations_as_the_texts_state"]
    assert "MIT, BSD, ISC, Unicode-3.0 and BlueOak-1.0.0 texts" in text and "Zlib" in text and "asks nothing of a binary copy" in text and "MIT, BSD, ISC, Zlib" not in text


def test_the_playwright_trademark_is_recorded_as_not_checked_and_the_other_unscanned_files_are_listed():
    nc = " ".join(comp(REAL, "playwright-python")["not_checked"])
    assert "trademark" in nc and "not checked" in nc and "xdg-open" in nc and "nbytes" in nc


# -------------------------------------------------------------------------------------------------- the items the review found, and the original tablesorter text
def test_libwebp_and_emscripten_are_identified_from_the_pinned_sources_and_the_notice_is_the_regenerated_one():
    it = item(REAL, "playwright-python", "pw-webp-codec")
    assert it["status"] == "verified" and "3757b8afeb54e305eaef18502812a9a88b7ed662" in it["version"]
    urls = " ".join(s_["url"] for s_ in it["sources"])
    for needle in ("webmproject/libwebp/3757b8af", "/COPYING", "/PATENTS", "emscripten-core/emscripten/6.0.2/LICENSE", "utils/libwebp-wasm/build.sh", "packages/utils/webp/webp_codec.wasm"):
        assert needle in urls, needle
    assert "Additional IP Rights Grant" in it["obligations_as_the_texts_state"] or "patent licence" in it["obligations_as_the_texts_state"]


def test_the_vite_bundle_components_are_identified_with_their_versions_and_the_codicon_font_and_the_logos_stay_open():
    assert item(REAL, "playwright-python", "pw-vite-react")["version"].startswith("react 19.2.7")
    assert "5.65.18" in item(REAL, "playwright-python", "pw-vite-codemirror")["version"] and "5.5.0" in item(REAL, "playwright-python", "pw-vite-xterm")["version"]
    cod = item(REAL, "playwright-python", "pw-vite-codicon")
    assert cod["status"] == "declared_only" and "CC-BY-4.0" in cod["declared_spdx"] and "MIT" in cod["declared_spdx"] and cod["licence_texts"] == ["playwright-vscode-license", "vscode-codicons-license", "vscode-codicons-license-code"]
    assert "Attribution" not in cod["obligations_as_the_texts_state"] and "attribution" in cod["obligations_as_the_texts_state"] and "URI or hyperlink" in cod["obligations_as_the_texts_state"]
    logos = item(REAL, "playwright-python", "pw-vite-browser-logos")
    assert logos["status"] == "declared_only" and "trademarks" in logos["licence_text_absent"]
    assert sum(1 for s_ in logos["sources"] if "byte for byte the shipped" in s_.get("note", "")) == 4


def test_the_robot_assets_the_review_found_are_open_declared_only_items_with_their_exact_quotes():
    for iid, quote in (("rf-jquery-tmpl", "Dual licensed under the MIT or GPL Version 2 licenses."), ("rf-jquery-highlight", "Licensed under MIT license."), ("rf-jsxcompressor", "Dual licensed under the Apache License Version 2.0, or LGPL Version 3 licenses.")):
        it = item(REAL, "robotframework", iid)
        assert it["status"] == "declared_only" and it["spdx"] == "unverified" and any(quote in s_.get("quote", "") for s_ in it["sources"]) and it["options"] and it["licence_text_absent"]
    assert comp(REAL, "robotframework")["redistribution"]["public_distribution_blockers"] == ["rf-asserts-unittest", "rf-highlighting-burgaud", "rf-jquery-highlight", "rf-jquery-tmpl", "rf-jsxcompressor", "rf-tablesorter-2.30.5"]


def test_tablesorter_records_five_declarations_verbatim_the_wording_difference_and_the_original_repositorys_text():
    it = item(REAL, "robotframework", "rf-tablesorter-2.30.5")
    declared = [s_ for s_ in it["sources"] if s_["role"] == "declared_licence"]
    quotes = [s_["quote"] for s_ in declared]
    assert len(declared) == 5 and sum("(MIT OR GPL-2.0)" in q_ for q_ in quotes) == 3 and any("or [GPLv2]" in q_ for q_ in quotes) and any("MIT and GPL" in q_ for q_ in quotes)
    assert "MIT and GPL" in it["residual"] and "carries NO licence header" in it["identified_by"] and "the fork has no text of its own" in it["residual"] and "has no licence text" in it["licence_text_absent"]
    original = next(s_ for s_ in it["sources"] if s_["role"] == "related_licence_text")
    assert "christianbach/tablesorter" in original["url"] and original["notice"] == "tablesorter-original-license" and "ORIGINAL repository" in original["note"]
    assert any("christianbach/tablesorter" in s_.get("quote", "") for s_ in it["sources"] if s_["role"] == "identification")        # the fork's README names it as the original
    entry = next(f for f in NOTICES_LOCK["files"] if f["id"] == "tablesorter-original-license")
    assert "ORIGINAL" in entry["label"] and "not the Mottie fork" in entry["label"] and entry["dest"].startswith("upstream/tablesorter-original-christianbach")


def test_an_excerpt_or_a_related_text_without_its_label_is_found(tmp_path):
    root = make_repo(tmp_path)
    lock = copy.deepcopy(NOTICES_LOCK)
    next(f for f in lock["files"] if f["id"] == "tablesorter-2.30.5-source-header")["label"] = "a file"
    assert "NOTICES_LOCK" in codes(lock_findings(REAL, lock, root))
    lock = copy.deepcopy(NOTICES_LOCK)
    del next(f for f in lock["files"] if f["id"] == "tablesorter-original-license")["label"]
    assert "NOTICES_LOCK" in codes(lock_findings(REAL, lock, root))
    for f in NOTICES_LOCK["files"]:
        if f["origin"].get("excerpt"):
            assert f["label"].startswith("EXCERPT"), f["id"]


def test_the_notices_readme_says_which_files_are_excerpts_and_which_texts_belong_to_a_related_project():
    text = (ROOT / "third_party" / "notices" / "README.md").read_text(encoding="utf-8")
    assert "EXCERPT" in text and "are not whole files" in text and "ORIGINAL tablesorter repository" in text and "not of the Mottie fork" in text
    assert "every other file is byte for byte" not in text.lower()
    assert not re.search(r"\b(cleared|approved|clearance|compatible|permitted)\b", text, re.I)


def test_a_declared_licence_source_without_its_verbatim_quote_is_found():
    m = fresh()
    src = next(s_ for s_ in item(m, "robotframework", "rf-jquery-tmpl")["sources"] if s_["role"] == "declared_licence")
    del src["quote"]
    assert any("quotes the declaration verbatim" in f.message for f in findings_of(m))
    m = fresh()
    src = next(s_ for s_ in item(m, "playwright-python", "pw-minimatch")["sources"] if s_["role"] == "declared_licence")
    src["quote"] = ""
    assert "EVIDENCE_MISSING_FIELD" in codes(findings_of(m))


def test_the_npm_tables_section_count_must_be_the_one_the_wheels_notice_files_have(tmp_path):
    mit = "The MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy"
    sidecar = npm_sidecar({"a@1.0.0": mit})
    parsed = chk.npm_notice_sections(sidecar)
    rows = [{"package": "a@1.0.0", "notice_file": "sidecar.txt", "notice_section_sha256": parsed["a@1.0.0"][1], "registry_license": "MIT", "tarball_sha512_verified": True,
             "licence_files_in_tarball": {"LICENSE": "x"}, "notice_text_contains_tarball_licence_file": ["LICENSE"]}]
    evidence = tmp_path / "third_party" / "evidence"
    evidence.mkdir(parents=True)
    item_ = {"id": "n", "table": {"kind": "npm-inlined-packages", "path": "third_party/evidence/n.json", "source_members": ["w/sidecar.txt"]}}
    matrix = one_wheel_matrix(tmp_path, {"w/sidecar.txt": sidecar}, {"third_party_evidence": [item_]})
    (evidence / "n.json").write_text(json.dumps({"schema": chk.NPM_TABLE_SCHEMA, "count": 1, "distinct": 1, "packages": rows}))
    assert chk.check_wheelhouse(matrix, tmp_path, tmp_path) == []
    (evidence / "n.json").write_text(json.dumps({"schema": chk.NPM_TABLE_SCHEMA, "count": 2, "distinct": 1, "packages": rows}))          # rows unchanged, the stated count is not what the wheel has
    assert any("the table says 2 sections" in f.message for f in chk.check_wheelhouse(matrix, tmp_path, tmp_path))


# ============================================================================================ round 2: more items, the inventory, the owner's wording protected
def test_zip_js_is_a_verified_item_with_the_version_from_the_lock_and_both_texts_and_no_decision_yet():
    it = item(REAL, "playwright-python", "pw-vite-zipjs")
    assert it["status"] == "verified" and it["spdx"] == "BSD-3-Clause" and "2.7.73" in it["version"] and "do not state a version" in it["version"] and it["owner_decision"] == {"decision": "none yet"}
    assert it["licence_texts"] == ["zipjs-2.7.73-license", "zipjs-2.7.73-codec-header"] and it["packages"] == ["@zip.js/zip.js"]
    assert "Gildas Lormeau" in it["sources"][3]["note"] and "JCraft" in it["sources"][4]["note"] and "stripped" in it["identified_by"]
    entry = next(f for f in NOTICES_LOCK["files"] if f["id"] == "zipjs-2.7.73-codec-header")
    assert entry["label"].startswith("EXCERPT") and (ROOT / entry["origin"]["path"]).read_text().count("JCRAFT") == 1


def test_the_browser_logo_item_names_all_ten_packages_and_says_which_logos_are_data_uris():
    it = item(REAL, "playwright-python", "pw-vite-browser-logos")
    assert len(it["packages"]) == 10 and all(n.startswith("@browser-logos/") for n in it["packages"])
    for v in ("chrome 2.0.0", "chrome-beta 3.0.0", "chrome-canary 2.0.0", "chrome-dev 3.0.0", "chromium 2.0.1", "edge 2.0.7", "firefox 3.0.10", "safari 2.1.0"):
        assert v in it["version"], v
    assert "six data:image/svg+xml" in it["identified_by"] and "not byte for byte" in it["identified_by"] and sum(1 for s_ in it["sources"] if s_["role"] == "identification" and "@browser-logos/" in s_.get("note", "") and "NOT byte for byte" in s_.get("note", "")) == 6


def test_the_other_items_of_round_two_are_present_with_their_facts():
    assert item(REAL, "playwright-python", "pw-vite-yaml")["spdx"] == "ISC" and "2.9.0" in item(REAL, "playwright-python", "pw-vite-yaml")["version"]
    css = item(REAL, "playwright-python", "pw-vite-vscode-css")
    assert css["status"] == "verified" and "533 of 533" in css["identified_by"] and css["licence_texts"] == ["playwright-vscode-license", "pw-vscode-colors-header", "pw-vscode-codicon-header"]
    xdg = item(REAL, "playwright-python", "pw-xdg-open")
    assert xdg["status"] == "verified" and "byte for byte package/xdg-open of the published npm package open 11.0.0" in xdg["identified_by"] and "Fathi Boudra" in xdg["identified_by"]
    for iid in ("rf-asserts-unittest", "rf-highlighting-burgaud"):
        it = item(REAL, "robotframework", iid)
        assert it["status"] == "declared_only" and it["spdx"] == "unverified" and it["owner_decision"] == {"decision": "none yet"} and it["options"] and any(s_.get("wheel_member") for s_ in it["sources"])
    assert "Steve Purcell" in item(REAL, "robotframework", "rf-asserts-unittest")["identified_by"] and "Andre Burgaud" in item(REAL, "robotframework", "rf-highlighting-burgaud")["identified_by"]
    oi = item(REAL, "robotframework", "rf-open-iconic")
    assert oi["status"] == "verified" and oi["spdx"] == "MIT" and sum(1 for s_ in oi["sources"] if "svg/" in s_["url"]) == 6 and "223 files" in oi["identified_by"]


def test_the_codicon_item_does_not_state_the_font_is_licensed_cc_by_4_as_a_fact():
    cod = item(REAL, "playwright-python", "pw-vite-codicon")
    assert "the font is licensed" not in json.dumps(cod) and "(the font)" not in cod["licence_text_absent"]
    assert "inference" in cod["licence_text_absent"] and "documentation and other content" in cod["licence_text_absent"] and "README" in cod["declared_spdx"]
    assert cod["spdx"] == "unverified"


# ------------------------------------------------------------------------------------------------------------------------- the inventory (best effort)
def test_the_matrix_states_how_the_inventory_is_derived_and_that_it_cannot_prove_completeness():
    inv = REAL["inventory"]
    assert "cannot prove completeness" in inv["limits"].lower() or "cannot prove completeness" in inv["limits"] and "BEST EFFORT" in inv["limits"]
    assert "it never claims that nothing else is shipped" in inv["limits"] and "complete inventory" not in json.dumps(inv).lower()
    for needle in ("import-candidates", "header scan", "Node.js LICENSE", "lock file"):
        assert needle.lower() in inv["method"].lower(), needle
    text = (ROOT / "third_party" / "README.md").read_text(encoding="utf-8")
    assert "How the inventory is derived" in text and "best effort" in text.lower() and "cannot prove" in text and "does not claim completeness" in text


def inventory_wheel(tmp_path, members):
    path = tmp_path / "w-1-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("w-1.dist-info/licenses/LICENSE", "licence")
        for name, data in members.items():
            zf.writestr(name, data)
    sha = lambda b: hashlib.sha256(b).hexdigest()
    rec = {"name": "w", "version": "1", "file": path.name, "sha256": sha(path.read_bytes()), "license_files": [{"path": "w-1.dist-info/licenses/LICENSE", "sha256": sha(b"licence")}], "recorded_members": []}
    return path, rec


def inv_matrix(rec, items):
    return {"inventory": {"own_holders": ["acme corp"]}, "components": [{"id": "x", "third_party_evidence": items, "shipped_wheels": [rec]}]}


def test_the_header_scan_finds_a_foreign_holder_a_bare_licence_marker_and_ignores_own_code_and_headerless_files(tmp_path):
    path, rec = inventory_wheel(tmp_path, {"w/own.py": "# Copyright 2020 Acme Corp\\n", "w/lib.js": "/*! thing (c) Foreign Authors | MIT */\\nvar a=1", "w/css.css": "/* Icons are from X. Licensed under the MIT License. */", "w/min.js": "var a=1;function b(){return 2}", "w/gen.py": "# Copyright 2020 Acme Corp\\n# Licensed under the Apache License, Version 2.0\\n"})
    with zipfile.ZipFile(path) as zf:
        hits = chk.scan_wheel_inventory(zf, ["acme corp"])
    assert set(hits) == {"w/lib.js", "w/css.css"} and "Foreign Authors" in hits["w/lib.js"][0][0]


def test_a_licence_bearing_file_that_no_item_covers_fails_the_checker_and_covers_paths_or_members_silence_it(tmp_path):
    path, rec = inventory_wheel(tmp_path, {"w/lib.js": "/*! thing (c) Foreign Authors | MIT */\\nvar a=1", "w/other/x.js": "/* Copyright (c) 2015 Someone Else. All rights reserved. */"})
    matrix = inv_matrix(rec, [{"id": "i", "shipped_members": [], "covers_paths": []}])
    assert [f.message.split(" ")[0] for f in chk.check_wheelhouse(matrix, tmp_path, tmp_path) if f.code == "INVENTORY_UNCOVERED"] == ["w/lib.js", "w/other/x.js"]
    matrix["components"][0]["third_party_evidence"] = [{"id": "i", "shipped_members": ["w/lib.js"], "covers_paths": ["w/other/*"]}]
    found = chk.check_wheelhouse(matrix, tmp_path, tmp_path)
    assert not [f for f in found if f.code == "INVENTORY_UNCOVERED"]


def test_a_matrix_without_an_inventory_block_does_not_scan(tmp_path):
    path, rec = inventory_wheel(tmp_path, {"w/lib.js": "/* (c) Foreign Authors */"})
    matrix = inv_matrix(rec, [{"id": "i"}])
    del matrix["inventory"]
    assert not [f for f in chk.check_wheelhouse(matrix, tmp_path, tmp_path) if f.code == "INVENTORY_UNCOVERED"]


def test_every_package_playwrights_sources_import_for_the_wheel_is_covered_excluded_or_a_finding(tmp_path):
    root = make_repo(tmp_path)
    assert chk.check_import_candidates(REAL, root) == []
    table = json.loads((root / "third_party" / "evidence" / "playwright-1.64.1-import-candidates.json").read_text())
    names = {p["name"] for p in table["packages"]}
    assert {"@zip.js/zip.js", "yaml", "react", "codemirror", "chromium-bidi", "vite"} <= names
    m = fresh()
    del m["inventory"]["excluded_packages"]["chromium-bidi"]
    assert any(f.code == "INVENTORY_UNCOVERED_PACKAGE" and "chromium-bidi" in f.message for f in chk.check_import_candidates(m, root))
    m = fresh()
    item(m, "playwright-python", "pw-vite-zipjs")["packages"] = []
    assert any("@zip.js/zip.js" in f.message for f in chk.check_import_candidates(m, root))
    m = fresh()
    m["inventory"]["excluded_packages"]["vite"] = ""
    assert "INVENTORY_CANDIDATES" in codes(chk.check_import_candidates(m, root))
    (root / "third_party" / "evidence" / "playwright-1.64.1-import-candidates.json").write_text(json.dumps({"schema": "x"}))
    assert "INVENTORY_CANDIDATES" in codes(chk.check_import_candidates(REAL, root))


def test_the_candidate_collector_follows_import_statements_of_the_wheel_packages_and_resolves_them_against_the_lock(tmp_path):
    import io
    import tarfile
    spec = importlib.util.spec_from_file_location("collect_licence_evidence", ROOT / "tools" / "collect_licence_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["collect_licence_evidence"] = mod
    spec.loader.exec_module(mod)
    lock = {"packages": {"node_modules/left-pad": {"version": "1.0.0", "license": "MIT"}, "node_modules/@scope/lib": {"version": "2.0.0", "license": "ISC", "dev": True}, "node_modules/tester": {"version": "3.0.0"}}}
    files = {"r/package-lock.json": json.dumps(lock), "r/packages/web/src/a.ts": "import x from 'left-pad';\\nimport y from '@scope/lib/deep';\\nimport z from './rel';\\nimport b from 'node:fs';", "r/packages/web/tests/t.ts": "import q from 'tester';",
             "r/packages/other/src/a.ts": "import q from 'tester';", "r/packages/utils/src/b.ts": "const k = require('left-pad');"}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(text.encode())
            tf.addfile(info, io.BytesIO(text.encode()))
    tar = tmp_path / "r.tar.gz"
    tar.write_bytes(buf.getvalue())
    table = mod.import_candidates(tar, "v0", "2026-11-03")
    assert [(p["name"], p["imported_by"], p["dev"]) for p in table["packages"]] == [("@scope/lib", ["web"], True), ("left-pad", ["utils", "web"], False)]
    assert table["schema"] == chk.IMPORT_TABLE_SCHEMA and table["repository_tarball_sha256"] == hashlib.sha256(buf.getvalue()).hexdigest()


# ------------------------------------------------------------------------------------------------------------------ the owner's wording is protected by the checker
def decided_item(m, iid):
    cid = "playwright-python" if iid.startswith("pw-") else "robotframework"
    return item(m, cid, iid)


def test_the_required_decisions_are_constants_of_the_checker_and_the_real_record_meets_them():
    assert set(chk.REQUIRED_DECISIONS) == {"pw-node-runtime", "pw-node-icu", "pw-minimatch", "pw-proxy-agent-negotiate", "rf-tablesorter-2.30.5"}
    assert chk.check_required_decisions(REAL) == []
    assert chk.REQUIRED_DECISIONS["rf-tablesorter-2.30.5"]["conditions"][0]["min_sources"] == 5 and chk.REQUIRED_DECISIONS["pw-node-runtime"]["conditions"][1]["contains"] == ["signature", "linked"]


@pytest.mark.parametrize("iid, edit", [
    ("pw-node-runtime", lambda b: b["conditions"].pop(1)),                                             # the retained-residual condition deleted
    ("pw-node-runtime", lambda b: b["conditions"][1].update(contains=["signature"])),                  # linkage dropped from it
    ("pw-node-runtime", lambda b: b["conditions"][0].update(notices=b["conditions"][0]["notices"][:1])),   # a required notice dropped
    ("pw-node-runtime", lambda b: b.update(decision="accepted")),                                      # provisional made final
    ("pw-node-icu", lambda b: b["conditions"].pop(1)),
    ("pw-minimatch", lambda b: b["conditions"].pop(1)),                                                # the attribution condition deleted
    ("pw-minimatch", lambda b: b["conditions"][1].pop("label_contains")),
    ("pw-minimatch", lambda b: b["conditions"][1].update(notices=[])),
    ("pw-proxy-agent-negotiate", lambda b: b["conditions"][0]["files"].pop("tools/build_bundle.py")),
    ("pw-proxy-agent-negotiate", lambda b: b["conditions"][0]["files"].pop("bundle/README.md")),
    ("pw-proxy-agent-negotiate", lambda b: b.update(decision="accepted")),
    ("rf-tablesorter-2.30.5", lambda b: b["conditions"][0].update(min_sources=3)),                     # five sources weakened to three
    ("rf-tablesorter-2.30.5", lambda b: b.update(elected_licence="GPL-2.0")),
    ("rf-tablesorter-2.30.5", lambda b: b.update(date="2026-11-04")),
    ("rf-tablesorter-2.30.5", lambda b: b.update(conditions=[])),
])
def test_deleting_or_weakening_a_condition_the_owner_set_is_found_even_when_everything_else_is_consistent(iid, edit):
    m = fresh()
    edit(decided_item(m, iid)["owner_decision"])
    found = codes(chk.check_required_decisions(m))
    assert "OWNER_CONDITION_WEAKENED" in found or "OWNER_DECISION_WEAKENED" in found


def test_an_item_the_owner_decided_cannot_go_back_to_none_yet_or_disappear():
    m = fresh()
    decided_item(m, "pw-minimatch")["owner_decision"] = {"decision": "none yet"}
    assert "OWNER_DECISION_WEAKENED" in codes(chk.check_required_decisions(m))
    m = fresh()
    c = comp(m, "playwright-python")
    c["third_party_evidence"] = [i for i in c["third_party_evidence"] if i["id"] != "pw-node-icu"]
    assert "OWNER_DECISION_WEAKENED" in codes(chk.check_required_decisions(m))


def test_more_than_the_owner_required_is_allowed():
    m = fresh()
    block = decided_item(m, "rf-tablesorter-2.30.5")["owner_decision"]
    block["conditions"][0]["min_sources"] = 6
    block["conditions"].append({"id": "extra", "text": "also this", "kind": "residuals_retained", "contains": ["MIT and GPL"], "status": "satisfied"})
    assert chk.check_required_decisions(m) == []


def test_the_decision_words_are_exactly_the_four_the_record_uses():
    assert chk.DECISIONS == {"accepted", "accepted provisionally", "conditional acceptance", "none yet"}


@pytest.mark.parametrize("spdx", ["CC-BY-4.0", "MIT", "MIT OR GPL-2.0-only", "BlueOak-1.0.0"])
def test_a_declared_only_item_cannot_state_a_licence_as_established(spdx):
    for cid, iid in (("playwright-python", "pw-vite-codicon"), ("playwright-python", "pw-vite-browser-logos"), ("robotframework", "rf-jquery-tmpl")):
        m = fresh()
        item(m, cid, iid)["spdx"] = spdx
        assert "EVIDENCE_SPDX_ESTABLISHED" in codes(findings_of(m)), (iid, spdx)


def test_a_declared_only_item_may_carry_the_declared_form_and_a_verified_item_a_licence():
    m = fresh()
    item(m, "playwright-python", "pw-vite-codicon")["spdx"] = "declared:MIT or CC-BY-4.0"
    assert "EVIDENCE_SPDX_ESTABLISHED" not in codes(findings_of(m))
    assert item(REAL, "playwright-python", "pw-vite-react")["spdx"] == "MIT"


def test_the_derived_name_of_a_source_cannot_be_empty():
    m = fresh()
    item(m, "playwright-python", "pw-npm-inlined")["sources"][0]["derived"] = ""
    assert any("derived, when present" in f.message for f in findings_of(m))


def test_a_quote_is_checked_against_the_pinned_bytes_where_the_source_is_pinned(tmp_path):
    root = make_repo(tmp_path)
    m = fresh()
    src = next(s_ for s_ in item(m, "robotframework", "rf-tablesorter-2.30.5")["sources"] if s_["role"] == "declared_licence" and "README" in s_["url"])
    src["quote"] = "* Dual licensed under the Apache License"
    found = lock_findings(m, copy.deepcopy(NOTICES_LOCK), root)
    assert "QUOTE_NOT_IN_SOURCE" in codes(found)
    assert not [f for f in lock_findings(REAL, copy.deepcopy(NOTICES_LOCK), root) if f.code == "QUOTE_NOT_IN_SOURCE"]
    unpinned = next(s_ for s_ in item(m, "robotframework", "rf-tablesorter-2.30.5")["sources"] if s_["role"] == "declared_licence" and s_["url"].endswith("package.json"))
    unpinned["quote"] = "a quote that no pinned file can contradict"                                  # not pinned: presence only, stated in third_party/README.md
    assert "QUOTE_NOT_IN_SOURCE" in codes(found) and len([f for f in lock_findings(m, copy.deepcopy(NOTICES_LOCK), root) if f.code == "QUOTE_NOT_IN_SOURCE"]) == 1


def test_a_quote_of_a_source_that_is_a_wheel_member_is_checked_against_the_wheel(tmp_path):
    path, rec = inventory_wheel(tmp_path, {"w/hdr.js": "/* Licensed under MIT license. */"})
    src = {"role": "declared_licence", "wheel_member": "w/hdr.js", "quote": "Licensed under MIT license."}
    matrix = inv_matrix(rec, [{"id": "i", "shipped_members": ["w/hdr.js"], "sources": [src]}])
    del matrix["inventory"]
    matrix["components"][0]["shipped_wheels"][0]["recorded_members"] = [{"path": "w/hdr.js", "size": len(b"/* Licensed under MIT license. */"), "sha256": hashlib.sha256(b"/* Licensed under MIT license. */").hexdigest()}]
    assert chk.check_wheelhouse(matrix, tmp_path, tmp_path) == []
    src["quote"] = "Licensed under GPL"
    assert "QUOTE_NOT_IN_SOURCE" in codes(chk.check_wheelhouse(matrix, tmp_path, tmp_path))
    src["wheel_member"] = "w/gone.js"
    assert "QUOTE_NOT_IN_SOURCE" in codes(chk.check_wheelhouse(matrix, tmp_path, tmp_path))


def test_the_excerpt_labels_do_not_say_tag_for_a_commit():
    for f in NOTICES_LOCK["files"]:
        if f["origin"].get("excerpt"):
            assert "cited tag" not in f["label"] and f["origin"]["url"] in f["label"], f["id"]
    assert "07d08cb72c7556e950593d6c011d5725db54228e" in next(f for f in NOTICES_LOCK["files"] if f["id"] == "jquery-tmpl-source-header")["label"]


def test_the_matrix_check_and_the_run_function_apply_the_required_decisions_and_the_candidate_table(tmp_path):
    m = fresh()
    decided_item(m, "pw-minimatch")["owner_decision"]["conditions"].pop(1)                      # the attribution condition deleted: the pending list and the statuses stay consistent
    m["bundle_public_distribution"]["pending_decisions"] = chk.pending_decisions(m)
    assert "OWNER_CONDITION_WEAKENED" in codes(findings_of(m))
    m = fresh()
    del m["inventory"]["excluded_packages"]["chromium-bidi"]
    path = tmp_path / "third_party" / "adapter-license-matrix.yaml"
    shutil.copytree(ROOT / "third_party" / "notices", tmp_path / "third_party" / "notices")
    shutil.copytree(ROOT / "third_party" / "evidence", tmp_path / "third_party" / "evidence")
    path.write_text(yaml.safe_dump(m, sort_keys=False))
    assert "INVENTORY_UNCOVERED_PACKAGE" in codes(chk.run(path, tmp_path))
