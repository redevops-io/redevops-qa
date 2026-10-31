# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Image metadata checks over files only: OCI layouts, loose manifests and configurations, ``image inspect`` output."""
import ast
import itertools
import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

import qc_images as I
from redevops_qa_checks import image_store as store_mod
from redevops_qa_checks.adapter import CheckAdapter
from redevops_qa_checks.engine import CheckEngine
from redevops_qa_checks.errors import PathRefused, ResourceAmbiguous
from redevops_qa_checks.image_store import ImageStore
from redevops_qa_checks.manifests import tree_digest

USER, PORTS, LABELS, LAYERS, ATT = ("image.user-and-runtime", "image.ports-and-health", "image.labels-and-base", "image.layers", "image.attestations")


@pytest.fixture
def run_image(registry, tmp_path):
    counter = itertools.count()

    def _run(pid, digest, build, *, counts=False):
        root = tmp_path / f"case{next(counter)}"
        root.mkdir()
        built = build(root)
        d = digest(built) if callable(digest) else digest
        full = pid + (".counts" if counts else "")
        ref = registry.resolve({"id": full, "version": "1.0.0", "program_hash": registry.registered_program_hash(full, "1.0.0")}).ref
        out = CheckEngine(root, registry, image_store=ImageStore(root)).run_check(
            {"check_program_ref": ref, "inputs": [{"kind": "IMAGE_DIGEST", "digest": d}], "tier": "OFFLINE"})
        return out, built
    return _run


def layout_with(**kw):
    def build(root):
        lay = I.Layout(root / "img")
        info = I.add_image(lay, **kw)
        info["layout"] = lay
        return info
    return build


def md(info):
    return info["manifest_digest"]


# -- fields from an OCI layout ------------------------------------------------------------------------------------------------

def test_a_layout_gives_user_runtime_ports_health_labels_and_layers(run_image):
    hc = {"Test": ["CMD", "/bin/check"], "Interval": 30000000000, "Timeout": 3000000000, "Retries": 3, "StartPeriod": 5000000000}
    labels = {"org.opencontainers.image.source": "https://example.test/x", "org.opencontainers.image.base.digest": I.sha(b"base"),
              "org.opencontainers.image.base.name": "registry.example.test/base:1"}
    build = layout_with(user="10001:10001", entrypoint=["/app/run"], cmd=["--serve"], ports=("8080/tcp", "9090/udp"), healthcheck=hc,
                        labels=labels, layers=3, volumes=("/data",), ref_name="app:1")
    out, info = run_image(USER, md, build)
    r = out.value["images"][0]
    assert (r["kind"], r["user"], r["uid"], r["uid_is_zero"], r["entrypoint"], r["cmd"], r["working_dir"], r["volumes"]) == \
        ("image", "10001:10001", 10001, False, ["/app/run"], ["--serve"], "/app", ["/data"])
    assert r["env_names"] == ["MODE", "PATH"] and r["digest"] == md(info)
    p = run_image(PORTS, md, build)[0].value["images"][0]
    assert p["exposed_ports"] == [{"port": 8080, "protocol": "tcp", "raw": "8080/tcp"}, {"port": 9090, "protocol": "udp", "raw": "9090/udp"}]
    assert (p["healthcheck_present"], p["healthcheck_test"], p["healthcheck_retries"], p["healthcheck_interval_ns"]) == (True, ["CMD", "/bin/check"], 3, 30000000000)
    l = run_image(LABELS, md, build)[0].value["images"][0]
    assert l["base_digest"] == I.sha(b"base") and l["base_name"] == "registry.example.test/base:1" and l["ref_names"] == ["app:1"]
    assert l["has_source_label"] is True and l["has_revision_label"] is False
    y = run_image(LAYERS, md, build)[0].value["images"][0]
    assert (y["layer_count"], y["diff_id_count"], y["architecture"], y["os"], y["layer_descriptors_on_disk"], y["layer_descriptors_not_on_disk"]) == (3, 3, "amd64", "linux", 3, 0)
    assert y["layer_media_types"] == [I.OCI_LAYER] and y["layer_size_total"] > 0 and y["config_digest"] == info["config_digest"]


@pytest.mark.parametrize("user,uid,zero,named", [("", 0, True, False), ("root", 0, True, False), ("0", 0, True, False), ("0:0", 0, True, False),
                                                 ("1000", 1000, False, False), ("1000:1000", 1000, False, False), ("app", None, None, True),
                                                 ("app:grp", None, None, True), ("root:wheel", 0, True, False)])
def test_user_forms_are_classified_without_guessing_names(run_image, user, uid, zero, named):
    r = run_image(USER, md, layout_with(user=user))[0].value["images"][0]
    assert (r["uid"], r["uid_is_zero"], r["user_is_name"], r["user_unset"]) == (uid, zero, named, user == "")


def test_a_missing_user_field_is_an_unset_user(run_image):
    out, _ = run_image(USER, md, layout_with(user=None), counts=True)
    assert out.value["counts"]["user_unset"] == 1 and out.value["counts"]["uid_zero"] == 1


def test_counts_projection_for_users(run_image):
    c = run_image(USER, md, layout_with(user="1000"), counts=True)[0].value
    assert c == {"counts": {"images": 1, "config_missing": 0, "user_unset": 0, "uid_zero": 0, "uid_non_zero": 1, "user_by_name": 0,
                            "no_entrypoint_and_no_cmd": 1}, "input_error_count": 0}


@pytest.mark.parametrize("hc,present,disabled", [(None, False, False), ({"Test": ["NONE"]}, True, True), ({"Test": ["CMD-SHELL", "true"]}, True, False)])
def test_health_check_presence_and_disabled(run_image, hc, present, disabled):
    p = run_image(PORTS, md, layout_with(healthcheck=hc))[0].value["images"][0]
    assert (p["healthcheck_present"], p["healthcheck_disabled"]) == (present, disabled)


def test_no_exposed_port_is_an_empty_list(run_image):
    assert run_image(PORTS, md, layout_with(ports=()))[0].value["images"][0]["exposed_ports"] == []


def test_base_digest_is_read_from_a_manifest_annotation_too_and_absence_is_reported(run_image):
    ann = {"org.opencontainers.image.base.digest": I.sha(b"b2")}
    assert run_image(LABELS, md, layout_with(annotations=ann))[0].value["images"][0]["base_digest"] == I.sha(b"b2")
    c = run_image(LABELS, md, layout_with(), counts=True)[0].value["counts"]
    assert c["without_base_digest"] == 1 and c["with_base_digest"] == 0


def test_layer_descriptors_without_blobs_are_reported_not_hidden(run_image):
    y = run_image(LAYERS, md, layout_with(layers=2, write_layer_blobs=False))[0].value["images"][0]
    assert (y["layer_count"], y["layer_descriptors_on_disk"], y["layer_descriptors_not_on_disk"]) == (2, 0, 2)
    assert run_image(LAYERS, md, layout_with(layers=2, write_layer_blobs=False), counts=True)[0].value["counts"]["layer_descriptors_not_on_disk"] == 2


def test_environment_values_and_build_commands_are_never_kept(run_image):
    canary = "".join(["s3cr", "et-ba", "ck-", "77x1"])
    build = layout_with(env=[f"API_KEY={canary}", "PLAIN=ok"], history_cmds=[f"RUN curl -H 'x: {canary}' https://example.test", "RUN true"])
    out, _ = run_image(USER, md, build)
    assert canary not in json.dumps(out.value) and out.value["images"][0]["env_names"] == ["API_KEY", "PLAIN"]
    doc = ImageStore(Path(_[ "layout"].root.parent)).documents()[0]
    assert canary not in json.dumps(doc, default=lambda m: dict(m)) and doc["history_count"] == 2


# -- SBOM and attestations ------------------------------------------------------------------------------------------------------

def test_no_attestation_means_no_sbom(run_image):
    out, _ = run_image(ATT, md, layout_with())
    r = out.value["images"][0]
    assert (r["sbom_present"], r["provenance_present"], r["attestations"]) == (False, False, [])
    assert out.value["counts"] == {"images": 1, "with_sbom": 0, "without_sbom": 1, "with_provenance": 0}


def test_a_build_tool_attestation_manifest_in_the_layout_is_an_sbom(run_image):
    def build(root):
        info = layout_with()(root)
        I.add_buildx_attestation(info["layout"], md(info))
        return info
    out, info = run_image(ATT, md, build)
    r = out.value["images"][0]
    assert r["sbom_present"] is True and r["sbom_via"] == ["attestation-manifest"] and r["attestations"][0]["predicate_type"] == "https://spdx.dev/Document"
    assert len(out.value["images"]) == 1                      # the attestation manifest is not itself an image


def test_a_provenance_attestation_is_not_an_sbom(run_image):
    def build(root):
        info = layout_with()(root)
        I.add_buildx_attestation(info["layout"], md(info), "https://slsa.dev/provenance/v0.2")
        return info
    r = run_image(ATT, md, build)[0].value["images"][0]
    assert (r["sbom_present"], r["provenance_present"]) == (False, True)


def test_an_oci_referrer_with_an_sbom_artifact_type_is_an_sbom(run_image):
    def build(root):
        info = layout_with()(root)
        I.add_referrer(info["layout"], md(info), "application/vnd.cyclonedx+json")
        return info
    r = run_image(ATT, md, build)[0].value["images"][0]
    assert r["sbom_present"] is True and r["sbom_via"] == ["referrer"]


def test_an_attestation_for_another_subject_is_not_attributed(run_image):
    def build(root):
        info = layout_with()(root)
        I.add_buildx_attestation(info["layout"], I.sha(b"another-image"))
        return info
    assert run_image(ATT, md, build)[0].value["images"][0]["sbom_present"] is False


def test_an_sbom_document_beside_loose_image_files_is_reported_as_colocated(run_image):
    def build(root):
        cfg = I.config_doc()
        cbytes = I.dumps(cfg)
        man = {"schemaVersion": 2, "mediaType": I.OCI_MANIFEST, "config": {"mediaType": I.OCI_CONFIG, "digest": I.sha(cbytes), "size": len(cbytes)},
               "layers": [{"mediaType": I.OCI_LAYER, "digest": I.sha(b"x"), "size": 1}]}
        d = root / "loose"
        d.mkdir()
        (d / "config.json").write_bytes(cbytes)
        (d / "manifest.json").write_bytes(I.dumps(man))
        (d / "app.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
        return {"manifest_digest": I.sha(I.dumps(man))}
    r = run_image(ATT, md, build)[0].value["images"][0]
    assert r["sbom_present"] is True and r["sbom_via"] == ["colocated-file"]


# -- integrity ----------------------------------------------------------------------------------------------------------------------

def test_a_config_blob_that_does_not_match_its_name_is_not_trusted(tmp_path):
    lay = I.Layout(tmp_path / "img")
    info = I.add_image(lay)
    blob = lay.root / "blobs" / "sha256" / info["config_digest"].split(":", 1)[1]
    blob.write_bytes(blob.read_bytes().replace(b"10001", b"0"))
    s = ImageStore(tmp_path)
    doc = s.get(info["manifest_digest"])
    assert doc["config_present"] is False and doc["user"] == "" and "config_missing_or_unverified" in doc["problems"]
    assert ("img", "BLOB_DIGEST_MISMATCH") in s.errors()


def test_a_manifest_blob_that_does_not_match_its_name_gives_no_document(tmp_path):
    lay = I.Layout(tmp_path / "img")
    info = I.add_image(lay)
    blob = lay.root / "blobs" / "sha256" / info["manifest_digest"].split(":", 1)[1]
    blob.write_bytes(blob.read_bytes() + b" ")
    s = ImageStore(tmp_path)
    assert s.get(info["manifest_digest"]) is None and s.documents() == () and ("img", "BLOB_DIGEST_MISMATCH") in s.errors()


def test_a_missing_config_blob_is_a_problem_not_an_empty_config(tmp_path):
    lay = I.Layout(tmp_path / "img")
    info = I.add_image(lay)
    (lay.root / "blobs" / "sha256" / info["config_digest"].split(":", 1)[1]).unlink()
    doc = ImageStore(tmp_path).get(info["manifest_digest"])
    assert doc["config_present"] is False and list(doc["problems"]) == ["config_missing_or_unverified"]


def test_the_unresolvable_digest_is_unresolved_not_a_value(run_image):
    out, _ = run_image(USER, "sha256:" + "9" * 64, layout_with())
    assert out.resolution == "UNRESOLVED" and out.value is None


def test_an_incomplete_or_malformed_layout_is_an_error_entry(tmp_path):
    lay = tmp_path / "img"
    lay.mkdir()
    (lay / "oci-layout").write_text("{}", encoding="utf-8")
    (lay / "index.json").write_text("{}", encoding="utf-8")
    s = ImageStore(tmp_path)
    assert s.documents() == () and ("img", "LAYOUT_MALFORMED") in s.errors()
    (lay / "index.json").unlink()
    assert ("img", "LAYOUT_INCOMPLETE") in ImageStore(tmp_path).errors()


def test_a_symbolic_link_inside_a_layout_is_refused(tmp_path):
    lay = I.Layout(tmp_path / "img")
    info = I.add_image(lay)
    blob = lay.root / "blobs" / "sha256" / info["config_digest"].split(":", 1)[1]
    real = tmp_path / "elsewhere"
    real.write_bytes(blob.read_bytes())
    blob.unlink()
    os.symlink(real, blob)
    with pytest.raises(PathRefused):
        ImageStore(tmp_path).get(info["manifest_digest"])


def test_an_oversized_blob_is_refused(tmp_path, monkeypatch):
    lay = I.Layout(tmp_path / "img")
    I.add_image(lay)
    monkeypatch.setattr(store_mod, "MAX_FILE_BYTES", 10)
    with pytest.raises(PathRefused):
        ImageStore(tmp_path).documents()


def test_a_non_sha256_digest_is_not_read(tmp_path):
    lay = I.Layout(tmp_path / "img")
    lay.descriptors.append({"mediaType": I.OCI_MANIFEST, "digest": "sha512:" + "0" * 128, "size": 1})
    lay.write_index()
    s = ImageStore(tmp_path)
    assert s.documents() == () and ("img", "BAD_DIGEST") in s.errors()


# -- indexes, loose files, inspect output --------------------------------------------------------------------------------------------

def test_an_index_digest_resolves_to_an_index_document_with_its_children(run_image):
    def build(root):
        lay = I.Layout(root / "img")
        a = I.add_image(lay, arch="amd64")
        b = I.add_image(lay, arch="arm64", user="2000")
        idx = I.dumps({"schemaVersion": 2, "mediaType": I.OCI_INDEX, "manifests": [
            {"mediaType": I.OCI_MANIFEST, "digest": a["manifest_digest"], "size": 1, "platform": {"os": "linux", "architecture": "amd64"}},
            {"mediaType": I.OCI_MANIFEST, "digest": b["manifest_digest"], "size": 1, "platform": {"os": "linux", "architecture": "arm64"}}]})
        d = lay.put(idx)
        lay.descriptors.append({"mediaType": I.OCI_INDEX, "digest": d, "size": len(idx)})
        lay.write_index()
        return {"index": d, "a": a, "b": b}
    out, built = run_image(LAYERS, lambda b: b["index"], build)
    r = out.value["images"][0]
    assert r["kind"] == "index" and [c["platform"] for c in r["children"]] == sorted(c["platform"] for c in r["children"]) and len(r["children"]) == 2
    assert out.value["counts"]["indexes"] == 1


def test_loose_manifest_and_config_are_joined_by_digest(tmp_path):
    cfg = I.dumps(I.config_doc(user="77"))
    man = I.dumps({"schemaVersion": 2, "mediaType": I.OCI_MANIFEST, "config": {"mediaType": I.OCI_CONFIG, "digest": I.sha(cfg), "size": len(cfg)},
                   "layers": [{"mediaType": I.OCI_LAYER, "digest": I.sha(b"l"), "size": 1}]})
    (tmp_path / "m.json").write_bytes(man)
    (tmp_path / "c.json").write_bytes(cfg)
    doc = ImageStore(tmp_path).get(I.sha(man))
    assert doc["kind"] == "image" and doc["user"] == "77" and doc["config_present"] is True and doc["layer_count"] == 1


def test_a_loose_manifest_without_its_configuration_says_so(tmp_path):
    man = I.dumps({"schemaVersion": 2, "mediaType": I.OCI_MANIFEST, "config": {"mediaType": I.OCI_CONFIG, "digest": I.sha(b"no"), "size": 1}, "layers": []})
    (tmp_path / "m.json").write_bytes(man)
    assert ImageStore(tmp_path).get(I.sha(man))["config_present"] is False


def test_a_bare_config_file_is_keyed_by_its_own_digest(tmp_path):
    cfg = I.dumps(I.config_doc(user="5"))
    (tmp_path / "c.json").write_bytes(cfg)
    doc = ImageStore(tmp_path).get(I.sha(cfg))
    assert doc["kind"] == "config" and doc["user"] == "5"


def test_image_inspect_output_is_read_as_a_list_or_one_object(tmp_path):
    d1 = I.inspect_doc(user="1000", repo_digest=I.sha(b"r1"))
    d2 = I.inspect_doc(user="", repo_digest=I.sha(b"r2"), labels={"org.opencontainers.image.base.digest": I.sha(b"bb")})
    (tmp_path / "inspect.json").write_text(json.dumps([d1, d2]), encoding="utf-8")
    (tmp_path / "one.json").write_text(json.dumps(I.inspect_doc(user="x", ident=I.sha(b"only-id"))), encoding="utf-8")
    s = ImageStore(tmp_path)
    assert s.get(I.sha(b"r1"))["user"] == "1000" and s.get(I.sha(b"r2"))["base_digest"] == I.sha(b"bb")
    assert s.get(I.sha(b"only-id"))["user"] == "x" and s.get(I.sha(b"r1"))["kind"] == "inspect" and s.get(I.sha(b"r1"))["layer_count"] == 3


def test_two_documents_with_one_digest_are_ambiguous_not_first_wins(tmp_path, registry):
    dg = I.sha(b"same")
    (tmp_path / "a.json").write_text(json.dumps([I.inspect_doc(user="1", repo_digest=dg)]), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps([I.inspect_doc(user="2", repo_digest=dg)]), encoding="utf-8")
    with pytest.raises(ResourceAmbiguous):
        ImageStore(tmp_path).get(dg)
    ref = registry.resolve({"id": USER, "version": "1.0.0", "program_hash": registry.registered_program_hash(USER, "1.0.0")}).ref
    out = CheckEngine(tmp_path, registry, image_store=ImageStore(tmp_path)).run_check(
        {"check_program_ref": ref, "inputs": [{"kind": "IMAGE_DIGEST", "digest": dg}], "tier": "OFFLINE"})
    assert out.resolution == "AMBIGUOUS" and out.value is None


def test_kubernetes_manifests_in_the_same_tree_are_not_mistaken_for_images(case_root):
    assert ImageStore(case_root).documents() == ()


# -- offline guarantees ----------------------------------------------------------------------------------------------------------------

def test_the_store_never_touches_the_network_or_a_process(tmp_path, monkeypatch):
    lay = I.Layout(tmp_path / "img")
    info = I.add_image(lay)

    def boom(*a, **k):
        raise AssertionError("network or process use during image inspection")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    assert ImageStore(tmp_path).get(info["manifest_digest"]) is not None


def test_the_image_store_module_imports_only_the_standard_library_and_the_package():
    tree = ast.parse(Path(store_mod.__file__).read_text(encoding="utf-8"))
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.level == 0:
            mods.add((n.module or "").split(".")[0])
    assert mods <= {"__future__", "hashlib", "json", "os", "re", "stat", "collections", "pathlib", "typing"}


def test_a_run_over_a_read_only_layout_changes_nothing(tmp_path, registry):
    lay = I.Layout(tmp_path / "img")
    info = I.add_image(lay)
    before = tree_digest(tmp_path)
    for p in sorted(tmp_path.rglob("*"), reverse=True):
        os.chmod(p, 0o555 if p.is_dir() else 0o444)
    os.chmod(tmp_path, 0o555)
    try:
        for pid in (USER, PORTS, LABELS, LAYERS, ATT):
            ref = registry.resolve({"id": pid, "version": "1.0.0", "program_hash": registry.registered_program_hash(pid, "1.0.0")}).ref
            CheckEngine(tmp_path, registry, image_store=ImageStore(tmp_path)).run_check(
                {"check_program_ref": ref, "inputs": [{"kind": "IMAGE_DIGEST", "digest": info["manifest_digest"]}], "tier": "OFFLINE"})
        assert tree_digest(tmp_path) == before
    finally:
        for p in sorted(tmp_path.rglob("*")):
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.chmod(tmp_path, 0o755)


# -- the adapter and the verifier ------------------------------------------------------------------------------------------------------------

def test_image_digest_inputs_run_through_the_adapter_and_the_verifier(tmp_path, registry, neutral):
    from agent_harness.qa import records as R, specstore, verifier
    lay = I.Layout(tmp_path / "img")
    info = I.add_image(lay, user="10001")
    a = CheckAdapter(tmp_path, registry=registry)
    w = a.open_workspace(R.CheckProfile(case_root_digest=tree_digest(tmp_path), tier=R.CheckTier.OFFLINE))
    res = a.resolve(w, R.ResourceRef(kind=R.ResourceKind.IMAGE_DIGEST, digest=info["manifest_digest"]))
    assert res.content_digest.startswith("sha256:")
    pid = USER + ".counts"
    expected = {"counts": {"images": 1, "config_missing": 0, "user_unset": 0, "uid_zero": 0, "uid_non_zero": 1, "user_by_name": 0,
                           "no_entrypoint_and_no_cmd": 1}, "input_error_count": 0}
    doc = {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": "a-user", "executor": "SCRIPT",
           "check_program_ref": {"id": pid, "version": "1.0.0", "program_hash": registry.registered_program_hash(pid, "1.0.0")},
           "determinism": "DETERMINISTIC", "on_unresolvable": "INDETERMINATE", "predicate": {"op": "EQUALS", "expected": expected},
           "subject": {"kind": "RESOURCE_INPUTS", "inputs": [{"kind": "IMAGE_DIGEST", "digest": info["manifest_digest"]}], "subject_alternates": []},
           "verifier_id": verifier.VERIFIER_ID, "verifier_version_range": ">=0.0,<99"}
    pin = verifier.assertion_set_pin((R.AssertionSpec.from_json(doc),))
    v = verifier.DeterministicVerifier(programs=registry, check_adapter=a)
    out = v.verify_run(specstore.InMemorySpecStore({pin: [doc]}), pin, lineage=verifier.ApprovedLineage([pin]), workspace=w)
    assert out[0].check.verdict.value == "PASS"


def test_an_unknown_image_digest_through_the_verifier_is_indeterminate_never_a_pass(tmp_path, registry, neutral):
    from agent_harness.qa import records as R, specstore, verifier
    I.add_image(I.Layout(tmp_path / "img"))
    a = CheckAdapter(tmp_path, registry=registry)
    w = a.open_workspace(R.CheckProfile(case_root_digest=tree_digest(tmp_path), tier=R.CheckTier.OFFLINE))
    pid = USER + ".counts"
    doc = {"schema_id": "runtime-contracts/qa/assertion-spec", "schema_version": "0.1", "assertion_id": "a-user", "executor": "SCRIPT",
           "check_program_ref": {"id": pid, "version": "1.0.0", "program_hash": registry.registered_program_hash(pid, "1.0.0")},
           "determinism": "DETERMINISTIC", "on_unresolvable": "INDETERMINATE", "predicate": {"op": "NOT_EQUALS", "expected": 1},
           "subject": {"kind": "RESOURCE_INPUTS", "inputs": [{"kind": "IMAGE_DIGEST", "digest": "sha256:" + "7" * 64}], "subject_alternates": []},
           "verifier_id": verifier.VERIFIER_ID, "verifier_version_range": ">=0.0,<99"}
    pin = verifier.assertion_set_pin((R.AssertionSpec.from_json(doc),))
    out = verifier.DeterministicVerifier(programs=registry, check_adapter=a).verify_run(
        specstore.InMemorySpecStore({pin: [doc]}), pin, lineage=verifier.ApprovedLineage([pin]), workspace=w)
    assert out[0].check.verdict.value == "INDETERMINATE"
