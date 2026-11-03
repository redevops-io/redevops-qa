# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The browser pin: the lock file's shape, the tree check (a tampered file, a changed mode, an extra file, a missing file, a link), the download check (a truncated archive, wrong bytes,
more bytes than pinned, a fallback URL) and the unpacking (nothing outside the install directory, nothing the lock does not list). A stand-in for the archives; no browser, no network."""
import copy
import hashlib
import io
import json
import os
import stat
from pathlib import Path

import pytest

from qa_runner import browser_pin as bp
from qr_browser_fake import SPECS, make_fake_browser, make_lock_doc, write_zip

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture()
def fake(tmp_path):
    return make_fake_browser(tmp_path)


@pytest.fixture()
def installed(tmp_path, fake):
    browsers = tmp_path / "browsers"
    fake.install(browsers)
    return browsers


def codes(problems):
    return sorted({p.code for p in problems})


def relock(doc):
    return bp.parse_lock(bp.render_lock(doc).encode("utf-8"))


# ------------------------------------------------------------------------------------------------------------------------------ the committed lock
def test_the_committed_lock_is_well_formed_canonical_and_names_the_archives_the_playwright_installer_downloads():
    path = ROOT / "bundle" / bp.LOCK_NAME
    lock = bp.load_lock(path)
    assert path.read_text(encoding="utf-8") == bp.render_lock(json.loads(path.read_text(encoding="utf-8"))), "the lock file is not in the canonical rendering of tools/make_browser_lock.py"
    assert lock.playwright_version == "1.64.1" and lock.revision == "1248" and lock.browser_version == "156.0.8078.4"
    assert sorted(a.dir for a in lock.archives) == ["chromium-1248", "chromium_headless_shell-1248", "ffmpeg-1013"]
    for a in lock.archives:
        assert all(u.startswith("https://") for u in a.urls) and a.size > 0 and len(a.sha256) == 64
    assert lock.files[f"chromium-1248/{bp.MARKER}"][1] == 0 and len(lock.files) > 500
    third_party = json.loads((ROOT / "bundle" / "third-party.lock.json").read_text(encoding="utf-8"))
    assert f"playwright=={lock.playwright_version}" in third_party["direct"]


def test_the_lock_modes_are_what_a_zip_unpacks_to_not_secret_files_with_a_wide_mode():
    lock = bp.load_lock(ROOT / "bundle" / bp.LOCK_NAME)
    assert {m for m, _s, _h in lock.files.values()} <= {0o644, 0o755, 0o600}
    assert lock.files["chromium-1248/chrome-linux64/chrome"][0] == 0o755


# ------------------------------------------------------------------------------------------------------------------------------ the lock file is strict
def test_a_lock_round_trips_through_its_canonical_rendering(fake):
    assert bp.render_lock(json.loads(fake.lock_bytes)).encode() == fake.lock_bytes
    assert fake.lock.digest == hashlib.sha256(fake.lock_bytes).hexdigest()


def mut_schema(d): d["schema"] = "something-else"
def mut_platform(d): d["target"]["platform"] = "linux-arm64"
def mut_tree_digest(d): d["tree_sha256"] = "0" * 64
def mut_file_hash(d): d["tree"]["files"]["ffmpeg-1000/ffmpeg-linux"][2] = "0" * 64        # tree_sha256 no longer matches
def mut_unsafe_path(d): d["tree"]["files"]["chromium-1000/../../etc/x"] = ["0644", 1, "0" * 64]
def mut_absolute(d): d["tree"]["files"]["/etc/x"] = ["0644", 1, "0" * 64]
def mut_outside_roots(d): d["tree"]["files"]["other-1/x"] = ["0644", 1, "0" * 64]
def mut_http(d): d["archives"][0]["urls"] = ["http://example.invalid/chrome-linux64.zip"]
def mut_url_file(d): d["archives"][0]["urls"] = ["https://example.invalid/other.zip"]
def mut_no_marker(d): del d["tree"]["files"]["ffmpeg-1000/" + bp.MARKER]
def mut_nonempty_marker(d): d["tree"]["files"]["ffmpeg-1000/" + bp.MARKER] = ["0644", 3, "0" * 64]
def mut_extra_key(d): d["archives"][0]["extra"] = 1
def mut_dup_dir(d): d["archives"][1]["dir"] = d["archives"][0]["dir"]
def mut_no_archives(d): d["archives"] = []
def mut_bad_size(d): d["archives"][0]["size"] = 0
def mut_bad_mode(d): d["tree"]["files"]["ffmpeg-1000/ffmpeg-linux"][0] = "755"
def mut_unlisted_parent(d): d["tree"]["files"]["chromium-1000/newdir/file"] = ["0644", 1, "0" * 64]
def mut_no_registry_hash(d): d["playwright"]["browsers_json_sha256"] = "short"
def mut_browser_name(d): d["browser"]["name"] = "firefox"


@pytest.mark.parametrize("edit", [mut_schema, mut_platform, mut_tree_digest, mut_file_hash, mut_unsafe_path, mut_absolute, mut_outside_roots, mut_http, mut_url_file, mut_no_marker,
                                  mut_nonempty_marker, mut_extra_key, mut_dup_dir, mut_no_archives, mut_bad_size, mut_bad_mode, mut_unlisted_parent, mut_no_registry_hash, mut_browser_name],
                         ids=lambda f: f.__name__)
def test_a_lock_that_is_not_exactly_the_documented_shape_is_refused(fake, edit):
    doc = copy.deepcopy(fake.doc)
    edit(doc)
    with pytest.raises(bp.LockError):
        bp.parse_lock(json.dumps(doc).encode())


@pytest.mark.parametrize("edit", [lambda d: d["tree"]["files"].pop("ffmpeg-1000/" + bp.MARKER), lambda d: d["tree"]["files"].__setitem__("ffmpeg-1000/" + bp.MARKER, ["0644", 3, "0" * 64])],
                         ids=["no marker", "marker with content"])
def test_a_lock_whose_install_directory_has_no_empty_marker_is_refused_even_when_its_digest_is_right(fake, edit):
    doc = copy.deepcopy(fake.doc)
    edit(doc)
    files = {k: (int(v[0], 8), v[1], v[2]) for k, v in doc["tree"]["files"].items()}
    doc["tree_sha256"] = bp.tree_digest({k: int(v, 8) for k, v in doc["tree"]["directories"].items()}, files)
    with pytest.raises(bp.LockError, match="must list an empty"):
        bp.parse_lock(bp.render_lock(doc).encode())


def test_a_lock_with_a_duplicate_key_or_that_is_not_json_is_refused(fake):
    text = fake.lock_bytes.decode().replace('"schema_version": "1.0"', '"schema_version": "1.0", "schema_version": "1.0"', 1)
    with pytest.raises(bp.LockError, match="duplicate"):
        bp.parse_lock(text.encode())
    with pytest.raises(bp.LockError):
        bp.parse_lock(b"\xff\xfe not json")
    with pytest.raises(bp.LockError):
        bp.parse_lock(b"[]")


def test_a_lock_that_cannot_be_read_is_a_lock_error(tmp_path):
    with pytest.raises(bp.LockError, match="cannot read"):
        bp.load_lock(tmp_path / "missing.json")


# ------------------------------------------------------------------------------------------------------------------------------ installing and the tree check
def test_a_fresh_install_is_exactly_the_pinned_tree_with_the_modes_the_zip_gives(fake, installed):
    assert bp.verify_tree(installed, fake.lock) == []
    assert stat.S_IMODE(os.lstat(installed / "chromium-1000/chrome-linux64/chrome").st_mode) == 0o755
    assert stat.S_IMODE(os.lstat(installed / "chromium-1000/chrome-linux64/private.key").st_mode) == 0o600
    assert (installed / "ffmpeg-1000" / bp.MARKER).is_file() and (installed / "ffmpeg-1000" / bp.MARKER).stat().st_size == 0
    assert sorted(os.listdir(installed)) == ["chromium-1000", "chromium_headless_shell-1000", "ffmpeg-1000"]       # no staging directory is left


def test_the_install_does_not_depend_on_the_umask(tmp_path, fake):
    old = os.umask(0o077)
    try:
        browsers = tmp_path / "b077"
        fake.install(browsers)
    finally:
        os.umask(old)
    assert bp.verify_tree(browsers, fake.lock) == []


def test_a_file_changed_without_changing_its_size_is_found(fake, installed):
    target = installed / "chromium-1000/chrome-linux64/chrome"
    data = target.read_bytes()
    target.write_bytes(data[:-2] + b"X\n")
    problems = bp.verify_tree(installed, fake.lock)
    assert [(p.code, p.path) for p in problems] == [("CHANGED", "chromium-1000/chrome-linux64/chrome")]
    assert fake.lock.files["chromium-1000/chrome-linux64/chrome"][2] in problems[0].detail


def test_a_file_with_another_size_is_found_as_a_size_difference(fake, installed):
    (installed / "ffmpeg-1000/ffmpeg-linux").write_bytes(b"short")
    assert [(p.code, p.path) for p in bp.verify_tree(installed, fake.lock)] == [("SIZE", "ffmpeg-1000/ffmpeg-linux")]


@pytest.mark.parametrize("rel,mode", [("chromium-1000/chrome-linux64/chrome", 0o644), ("chromium-1000/chrome-linux64/resources.pak", 0o755), ("chromium-1000/chrome-linux64/private.key", 0o644),
                                      ("chromium-1000/chrome-linux64/chrome", 0o4755), ("chromium-1000/chrome-linux64/resources.pak", 0o664)])
def test_a_changed_file_mode_is_found_whatever_the_content(fake, installed, rel, mode):
    os.chmod(installed / rel, mode)
    assert [(p.code, p.path) for p in bp.verify_tree(installed, fake.lock)] == [("MODE", rel)]


def test_a_changed_directory_mode_is_found(fake, installed):
    os.chmod(installed / "chromium-1000/chrome-linux64/locales", 0o775)
    assert [(p.code, p.path) for p in bp.verify_tree(installed, fake.lock)] == [("MODE", "chromium-1000/chrome-linux64/locales")]


def test_an_extra_file_or_directory_is_found_wherever_it_is(fake, installed):
    (installed / "chromium-1000/chrome-linux64/locales/extra.pak").write_bytes(b"x")
    (installed / "ffmpeg-1000/newdir").mkdir()
    (installed / "chromium_headless_shell-1000/loose.txt").write_text("x")
    assert sorted((p.code, p.path) for p in bp.verify_tree(installed, fake.lock)) == [
        ("EXTRA", "chromium-1000/chrome-linux64/locales/extra.pak"), ("EXTRA", "chromium_headless_shell-1000/loose.txt"), ("EXTRA", "ffmpeg-1000/newdir")]


def test_a_missing_file_or_directory_is_found(fake, installed):
    (installed / "chromium-1000/chrome-linux64/resources.pak").unlink()
    os.unlink(installed / "chromium-1000/chrome-linux64/locales/en.pak")
    os.rmdir(installed / "chromium-1000/chrome-linux64/locales")
    got = sorted((p.code, p.path) for p in bp.verify_tree(installed, fake.lock))
    assert got == [("MISSING", "chromium-1000/chrome-linux64/locales"), ("MISSING", "chromium-1000/chrome-linux64/locales/en.pak"), ("MISSING", "chromium-1000/chrome-linux64/resources.pak")]


def test_a_missing_install_directory_is_not_installed_and_the_others_are_still_checked(fake, installed):
    import shutil
    shutil.rmtree(installed / "ffmpeg-1000")
    (installed / "chromium-1000/chrome-linux64/chrome").write_bytes(b"#!/bin/sh\necho changed....!!\n")
    got = {(p.code, p.path) for p in bp.verify_tree(installed, fake.lock)}
    assert got == {("NOT_INSTALLED", "ffmpeg-1000"), ("SIZE", "chromium-1000/chrome-linux64/chrome")}


def test_an_empty_browsers_directory_is_not_installed(tmp_path, fake):
    (tmp_path / "empty").mkdir()
    problems = bp.verify_tree(tmp_path / "empty", fake.lock)
    assert codes(problems) == ["NOT_INSTALLED"] and len(problems) == 3


def test_a_link_inside_the_tree_or_in_place_of_an_install_directory_is_found_and_not_followed(fake, installed, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_text("x")
    os.symlink(outside, installed / "chromium-1000/chrome-linux64/linked-dir")
    os.symlink(outside / "payload", installed / "ffmpeg-1000/linked-file")
    got = {(p.code, p.path) for p in bp.verify_tree(installed, fake.lock)}
    assert got == {("TYPE", "chromium-1000/chrome-linux64/linked-dir"), ("TYPE", "ffmpeg-1000/linked-file")}
    os.unlink(installed / "chromium-1000/chrome-linux64/linked-dir")
    os.unlink(installed / "ffmpeg-1000/linked-file")
    import shutil
    shutil.move(str(installed / "ffmpeg-1000"), str(tmp_path / "elsewhere"))
    os.symlink(tmp_path / "elsewhere", installed / "ffmpeg-1000")
    assert [(p.code, p.path) for p in bp.verify_tree(installed, fake.lock)] == [("TYPE", "ffmpeg-1000")]


def test_a_file_replaced_by_a_link_to_a_file_with_the_same_content_is_still_a_difference(fake, installed, tmp_path):
    target = installed / "ffmpeg-1000/COPYING.LGPLv2.1"
    copy_ = tmp_path / "copy.txt"
    copy_.write_bytes(target.read_bytes())
    target.unlink()
    os.symlink(copy_, target)
    assert [(p.code, p.path) for p in bp.verify_tree(installed, fake.lock)] == [("TYPE", "ffmpeg-1000/COPYING.LGPLv2.1")]


def test_the_marker_playwright_writes_on_first_launch_is_allowed_when_empty_and_nowhere_else(fake, installed):
    (installed / "chromium-1000/DEPENDENCIES_VALIDATED").write_bytes(b"")
    assert bp.verify_tree(installed, fake.lock) == []
    (installed / "chromium-1000/DEPENDENCIES_VALIDATED").write_bytes(b"code")
    assert [(p.code, p.path) for p in bp.verify_tree(installed, fake.lock)] == [("EXTRA", "chromium-1000/DEPENDENCIES_VALIDATED")]
    (installed / "chromium-1000/DEPENDENCIES_VALIDATED").unlink()
    (installed / "chromium-1000/chrome-linux64/DEPENDENCIES_VALIDATED").write_bytes(b"")
    assert [(p.code, p.path) for p in bp.verify_tree(installed, fake.lock)] == [("EXTRA", "chromium-1000/chrome-linux64/DEPENDENCIES_VALIDATED")]


def test_other_entries_in_the_browsers_directory_are_not_part_of_the_pin(fake, installed):
    (installed / "firefox-9999").mkdir()
    (installed / "firefox-9999/firefox").write_text("x")
    (installed / ".links").mkdir()
    assert bp.verify_tree(installed, fake.lock) == []


def test_the_summary_names_the_counts_and_the_first_differences(fake, installed):
    for rel in ("chrome-linux64/chrome", "chrome-linux64/resources.pak", "chrome-linux64/private.key"):
        os.chmod(installed / "chromium-1000" / rel, 0o666)
    text = bp.summarise(bp.verify_tree(installed, fake.lock), limit=2)
    assert text.startswith("3 difference(s) from the pin (3 MODE)") and text.count("MODE chromium-1000") == 2 and text.endswith("; ...")


# ------------------------------------------------------------------------------------------------------------------------------ the download check
def staged(fake, tmp_path, mirror=None, **kw):
    return bp.stage(fake.lock, tmp_path / "browsers", tmp_path / "stage", mirror=str(mirror if mirror is not None else fake.archives_dir), **kw)


def serve_copy(fake, tmp_path, edit):
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    for f in fake.archives_dir.iterdir():
        (mirror / f.name).write_bytes(f.read_bytes())
    edit(mirror)
    (tmp_path / "browsers").mkdir(exist_ok=True)
    return mirror


def nothing_left(tmp_path):
    assert not (tmp_path / "stage").exists() and sorted(os.listdir(tmp_path / "browsers")) == []


def test_a_truncated_archive_is_refused_with_the_expected_and_the_actual_hash_and_nothing_is_left(fake, tmp_path):
    path = lambda m: (m / "chrome-linux64.zip")
    mirror = serve_copy(fake, tmp_path, lambda m: path(m).write_bytes(path(m).read_bytes()[:-50]))
    with pytest.raises(bp.InstallError) as exc:
        staged(fake, tmp_path, mirror)
    text = str(exc.value)
    wanted = next(a for a in fake.lock.archives if a.file == "chrome-linux64.zip")
    assert "chrome-linux64.zip does not match its pin" in text and f"expected sha256 {wanted.sha256}" in text and f"({wanted.size} bytes)" in text
    assert f"got sha256 {hashlib.sha256(path(mirror).read_bytes()).hexdigest()}" in text and f"({wanted.size - 50} bytes)" in text
    nothing_left(tmp_path)


def test_an_archive_with_one_changed_byte_is_refused_before_anything_is_unpacked(fake, tmp_path):
    def flip(m):
        data = bytearray((m / "ffmpeg-linux.zip").read_bytes())
        data[len(data) // 2] ^= 1
        (m / "ffmpeg-linux.zip").write_bytes(bytes(data))
    mirror = serve_copy(fake, tmp_path, flip)
    with pytest.raises(bp.InstallError, match="ffmpeg-linux.zip does not match its pin"):
        staged(fake, tmp_path, mirror)
    nothing_left(tmp_path)


def test_a_valid_zip_that_is_not_the_pinned_archive_is_refused_even_if_it_unpacks_cleanly(fake, tmp_path):
    def swap(m):
        write_zip(m / "ffmpeg-linux.zip", [("ffmpeg-linux", 0o755, b"#!/bin/sh\necho evil\n"), ("COPYING.LGPLv2.1", 0o644, b"licence")], [])
    mirror = serve_copy(fake, tmp_path, swap)
    with pytest.raises(bp.InstallError, match="expected sha256"):
        staged(fake, tmp_path, mirror)
    nothing_left(tmp_path)


def test_a_bad_archive_among_good_ones_leaves_none_of_them_in_the_browsers_directory(fake, tmp_path):
    mirror = serve_copy(fake, tmp_path, lambda m: (m / "chrome-headless-shell-linux64.zip").write_bytes(b"not a zip"))
    with pytest.raises(bp.InstallError):
        staged(fake, tmp_path, mirror)
    nothing_left(tmp_path)


def test_a_host_that_sends_more_than_the_pinned_size_is_cut_off_and_refused(fake, tmp_path):
    wanted = next(a for a in fake.lock.archives if a.file == "ffmpeg-linux.zip")
    served = []

    class Endless:
        """A response that never ends: every read returns exactly what was asked for."""
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            served.append(n)
            return b"\0" * n

    (tmp_path / "browsers").mkdir()
    dest = tmp_path / "x.zip"
    with pytest.raises(bp.InstallError, match="more than the pinned size"):
        bp.fetch_archive(wanted, dest, "https://mirror.invalid/", opener=lambda req, timeout=0: Endless())
    assert sum(served) == wanted.size + 1 and not dest.exists()                  # one byte past the pinned size is read, then the transfer is cut off


def test_the_first_url_may_be_wrong_when_a_later_one_serves_the_pinned_bytes_and_a_total_failure_names_every_url(fake, tmp_path):
    wanted = next(a for a in fake.lock.archives if a.file == "ffmpeg-linux.zip")
    good = (fake.archives_dir / "ffmpeg-linux.zip").read_bytes()
    seen = []

    def opener(req, timeout=0):
        seen.append(req.full_url)
        return io.BytesIO(b"junk" if "/first/" in req.full_url else good) if "/third/" not in req.full_url else (_ for _ in ()).throw(OSError("down"))

    class Ctx(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    served = bp.fetch_archive(wanted, tmp_path / "a.zip", opener=lambda req, timeout=0: Ctx(opener(req).getvalue()))
    assert served.endswith("/second/ffmpeg-linux.zip") and seen == [wanted.urls[0], wanted.urls[1]] and (tmp_path / "a.zip").read_bytes() == good
    with pytest.raises(bp.InstallError) as exc:
        bp.fetch_archive(wanted, tmp_path / "b.zip", opener=lambda req, timeout=0: Ctx(b"junk"))
    assert wanted.urls[0] in str(exc.value) and wanted.urls[1] in str(exc.value) and "expected sha256" in str(exc.value) and not (tmp_path / "b.zip").exists()


def test_an_unreachable_host_is_an_install_error_that_names_the_url(fake, tmp_path):
    wanted = next(a for a in fake.lock.archives if a.file == "ffmpeg-linux.zip")

    def down(req, timeout=0):
        raise OSError("connection refused")
    with pytest.raises(bp.InstallError, match="the download failed"):
        bp.fetch_archive(wanted, tmp_path / "a.zip", opener=down)


def test_a_mirror_must_be_an_http_file_url_or_an_absolute_directory(fake):
    a = fake.lock.archives[0]
    assert bp.archive_urls(a, "https://m.example/base/") == [f"https://m.example/base/{a.file}"]
    assert bp.archive_urls(a, "/abs/dir")[0].startswith("file:///abs/dir/")
    for bad in ("relative/dir", "ftp://x/y", ""):
        with pytest.raises(bp.InstallError):
            bp.archive_urls(a, bad)
    assert bp.archive_urls(a, None) == list(a.urls)


# ------------------------------------------------------------------------------------------------------------------------------ the unpacking
def lock_for_archive(tmp_path, fake, file, entries, dirs=()):
    """A lock that pins a hostile archive exactly (its hash is the pin), to show that the unpacking refuses it on its own account."""
    mirror = tmp_path / "hostile"
    mirror.mkdir()
    for f in fake.archives_dir.iterdir():
        (mirror / f.name).write_bytes(f.read_bytes())
    write_zip(mirror / file, entries, list(dirs))
    doc = make_lock_doc(mirror)
    # the tree entries stay those of the honest archives: whatever the hostile archive adds is not listed
    return mirror, relock(doc)


@pytest.mark.parametrize("name,mode", [("../escape", 0o644), ("/abs/path", 0o644), ("chrome-linux64/../../escape", 0o644), ("a\\b", 0o644)])
def test_an_archive_entry_that_names_a_path_outside_the_install_directory_is_refused(tmp_path, fake, name, mode):
    mirror, lock = lock_for_archive(tmp_path, fake, "ffmpeg-linux.zip", [(name, mode, b"x")])
    (tmp_path / "browsers").mkdir()
    with pytest.raises(bp.InstallError, match="unsafe name"):
        bp.stage(lock, tmp_path / "browsers", tmp_path / "stage", mirror=str(mirror))
    assert not (tmp_path / "escape").exists() and not (tmp_path / "stage").exists()


@pytest.mark.parametrize("entries,match", [
    ([("ffmpeg-linux", 0o4755, b"x"), ("COPYING.LGPLv2.1", 0o644, b"x")], "setuid"),
    ([("ffmpeg-linux", 0o755, b"x"), ("COPYING.LGPLv2.1", 0o644, b"x"), ("extra", 0o644, b"x")], "does not list"),
    ([("ffmpeg-linux", 0o755, b"x"), ("COPYING.LGPLv2.1", 0o644, b"x"), ("COPYING.LGPLv2.1", 0o644, b"y")], "(or lists twice)"),
], ids=["setuid", "unlisted", "twice"])
def test_an_archive_with_a_setuid_file_an_unlisted_file_or_a_repeated_name_is_refused(tmp_path, fake, entries, match):
    mirror, _ = lock_for_archive(tmp_path, fake, "ffmpeg-linux.zip", entries)
    lock = relock(make_lock_doc(mirror))
    (tmp_path / "browsers").mkdir()
    with pytest.raises(bp.InstallError, match=match.replace("(", r"\(").replace(")", r"\)")):
        bp.stage(lock, tmp_path / "browsers", tmp_path / "stage", mirror=str(mirror))
    assert os.listdir(tmp_path / "browsers") == [] and not (tmp_path / "stage").exists()


def test_an_archive_entry_that_is_a_symbolic_link_is_refused(tmp_path, fake):
    import zipfile
    mirror, _ = lock_for_archive(tmp_path, fake, "ffmpeg-linux.zip", [("ffmpeg-linux", 0o755, b"x"), ("COPYING.LGPLv2.1", 0o644, b"x")])
    with zipfile.ZipFile(mirror / "ffmpeg-linux.zip", "w") as zf:
        info = zipfile.ZipInfo("ffmpeg-linux")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")
    lock = relock(make_lock_doc(mirror))
    (tmp_path / "browsers").mkdir()
    with pytest.raises(bp.InstallError, match="not a regular file"):
        bp.stage(lock, tmp_path / "browsers", tmp_path / "stage", mirror=str(mirror))
    assert os.listdir(tmp_path / "browsers") == []


def test_the_tree_check_of_the_staged_files_catches_an_archive_whose_content_is_not_what_the_tree_pins(tmp_path, fake):
    """The archive is pinned by hash AND the tree by file: an archive that was re-pinned (a lock edited by one hand) but not its tree is refused after unpacking."""
    mirror = tmp_path / "m"
    mirror.mkdir()
    for f in fake.archives_dir.iterdir():
        (mirror / f.name).write_bytes(f.read_bytes())
    write_zip(mirror / "ffmpeg-linux.zip", [("ffmpeg-linux", 0o755, b"#!/bin/sh\necho changed\n"), ("COPYING.LGPLv2.1", 0o644, b"licence")], [])
    lock = relock(make_lock_doc(mirror))
    (tmp_path / "browsers").mkdir()
    with pytest.raises(bp.InstallError, match="not the pinned tree"):
        bp.stage(lock, tmp_path / "browsers", tmp_path / "stage", mirror=str(mirror))
    assert sorted(os.listdir(tmp_path / "browsers")) == [] and not (tmp_path / "stage").exists()


# ------------------------------------------------------------------------------------------------------------------------------ placing and re-running
def test_stage_refuses_a_staging_directory_that_exists(tmp_path, fake):
    (tmp_path / "stage").mkdir()
    (tmp_path / "browsers").mkdir()
    with pytest.raises(bp.InstallError, match="already exists"):
        bp.stage(fake.lock, tmp_path / "browsers", tmp_path / "stage", mirror=str(fake.archives_dir))
    assert (tmp_path / "stage").is_dir()


def test_staging_alone_places_nothing_in_the_browsers_directory(tmp_path, fake):
    (tmp_path / "browsers").mkdir()
    names = bp.stage(fake.lock, tmp_path / "browsers", tmp_path / "stage", mirror=str(fake.archives_dir))
    assert sorted(names) == sorted(fake.lock.dirs()) and os.listdir(tmp_path / "browsers") == []
    assert bp.verify_tree(tmp_path / "stage", fake.lock) == []
    bp.commit(fake.lock, tmp_path / "browsers", tmp_path / "stage")
    assert bp.verify_tree(tmp_path / "browsers", fake.lock) == [] and not (tmp_path / "stage").exists()


def test_an_identical_install_is_left_alone_and_nothing_is_downloaded(tmp_path, fake, installed):
    def no_network(req, timeout=0):
        raise AssertionError("downloaded although everything is installed")
    names = bp.stage(fake.lock, installed, tmp_path / "stage", mirror=str(fake.archives_dir), opener=no_network)
    assert names == []


def test_an_install_directory_that_differs_is_never_replaced_and_the_error_says_so(tmp_path, fake, installed):
    (installed / "ffmpeg-1000/ffmpeg-linux").write_bytes(b"#!/bin/sh\necho tampered....\n")
    before = (installed / "ffmpeg-1000/ffmpeg-linux").read_bytes()
    with pytest.raises(bp.InstallError, match="was not touched"):
        bp.stage(fake.lock, installed, tmp_path / "stage", mirror=str(fake.archives_dir))
    assert (installed / "ffmpeg-1000/ffmpeg-linux").read_bytes() == before and not (tmp_path / "stage").exists()


def test_a_partial_install_is_completed_without_touching_what_is_there(tmp_path, fake, installed):
    import shutil
    shutil.rmtree(installed / "chromium_headless_shell-1000")
    inode = (installed / "chromium-1000/chrome-linux64/chrome").stat().st_ino
    names = bp.stage(fake.lock, installed, tmp_path / "stage", mirror=str(fake.archives_dir))
    assert names == ["chromium_headless_shell-1000"]
    bp.commit(fake.lock, installed, tmp_path / "stage")
    assert bp.verify_tree(installed, fake.lock) == [] and (installed / "chromium-1000/chrome-linux64/chrome").stat().st_ino == inode


def test_a_failed_move_removes_what_was_already_moved(tmp_path, fake, monkeypatch):
    (tmp_path / "browsers").mkdir()
    bp.stage(fake.lock, tmp_path / "browsers", tmp_path / "stage", mirror=str(fake.archives_dir))
    real = os.rename
    calls = []

    def flaky(src, dst):
        calls.append(dst)
        if len(calls) == 2:
            raise OSError("disk full")
        return real(src, dst)
    monkeypatch.setattr(bp.os, "rename", flaky)
    with pytest.raises(OSError):
        bp.commit(fake.lock, tmp_path / "browsers", tmp_path / "stage")
    assert os.listdir(tmp_path / "browsers") == [] and not (tmp_path / "stage").exists()


# ------------------------------------------------------------------------------------------------------------------------------ the command line
def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    return bp.main(list(argv), out, err), out.getvalue(), err.getvalue()


def test_the_command_line_verifies_stages_and_commits_and_reports_in_json(tmp_path, fake):
    lock = tmp_path / "lock.json"
    lock.write_bytes(fake.lock_bytes)
    browsers = tmp_path / "browsers"
    browsers.mkdir()
    code, out, err = run_main("verify", "--lock", str(lock), "--browsers", str(browsers))
    assert code == 1 and "NOT_INSTALLED" in err
    code, out, err = run_main("stage", "--lock", str(lock), "--browsers", str(browsers), "--staging", str(tmp_path / "s"), "--mirror", str(fake.archives_dir))
    assert code == 0 and "staged ffmpeg-1000" in out and "matches the pin" in out
    code, out, err = run_main("commit", "--lock", str(lock), "--browsers", str(browsers), "--staging", str(tmp_path / "s"))
    assert code == 0 and "installed ffmpeg-1000" in out
    code, out, err = run_main("verify", "--lock", str(lock), "--browsers", str(browsers))
    assert code == 0 and "exactly the pinned Chromium 9.9.9.9" in out and fake.lock.digest in out
    (browsers / "ffmpeg-1000/COPYING.LGPLv2.1").write_bytes(b"licensX")
    code, out, err = run_main("verify", "--lock", str(lock), "--browsers", str(browsers), "--json")
    doc = json.loads(out)
    assert code == 1 and doc["ok"] is False and doc["problems"][0]["path"] == "ffmpeg-1000/COPYING.LGPLv2.1" and doc["problems"][0]["code"] == "CHANGED"


def test_the_command_line_reports_an_unusable_lock_and_a_usage_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    code, _out, err = run_main("verify", "--lock", str(bad), "--browsers", str(tmp_path))
    assert code == 1 and "the lock file is not usable" in err
    assert run_main("verify")[0] == 2 and run_main("frobnicate")[0] == 2


def test_the_module_runs_isolated_with_the_standard_library_only(tmp_path, fake):
    """install-browser.sh runs it as ``python -I -m qa_runner.browser_pin`` with the installation's interpreter: no import outside the standard library."""
    import subprocess
    import sys
    lock = tmp_path / "lock.json"
    lock.write_bytes(fake.lock_bytes)
    (tmp_path / "browsers").mkdir()
    src = Path(bp.__file__).resolve().parents[1]
    done = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r); import runpy; sys.argv=['x','verify','--lock',%r,'--browsers',%r]; runpy.run_module('qa_runner.browser_pin', run_name='__main__')"
                           % (str(src), str(lock), str(tmp_path / "browsers")), "-X", "importtime"], capture_output=True, text=True)
    assert done.returncode == 1 and "NOT_INSTALLED" in done.stderr
    imported = {line.split("|")[-1].strip().split(".")[0] for line in done.stderr.splitlines() if line.startswith("import time:")}
    assert not ({"playwright", "yaml", "robot", "pytest", "qa_evidence", "redevops_qa_bridge", "agent_harness"} & imported)


# ------------------------------------------------------------------------------------------------------------------------------ do the listed URLs serve the pinned bytes
class _Body(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_check_urls_reports_every_url_that_does_not_serve_the_pinned_bytes(fake):
    good = {a.file: (fake.archives_dir / a.file).read_bytes() for a in fake.lock.archives}
    log = []

    def opener(req, timeout=0):
        url = req.full_url
        file = url.rsplit("/", 1)[-1]
        if "/second/" in url and file == "ffmpeg-linux.zip":
            return _Body(good[file][:-1] + b"X")                    # another mirror, other bytes
        if "/second/" in url and file == "chrome-linux64.zip":
            raise OSError("not reachable")
        return _Body(good[file])
    bad = bp.check_urls(fake.lock, log.append, opener=opener)
    assert sorted(bad) == ["https://example.invalid/second/chrome-linux64.zip", "https://example.invalid/second/ffmpeg-linux.zip"]
    assert sum(1 for x in log if x.startswith("same bytes")) == 4 and sum(1 for x in log if x.startswith("MISMATCH")) == 2
    assert bp.check_urls(fake.lock, opener=lambda req, timeout=0: _Body(good[req.full_url.rsplit("/", 1)[-1]])) == []


def test_check_urls_can_skip_the_first_url_of_each_archive(fake):
    seen = []
    good = {a.file: (fake.archives_dir / a.file).read_bytes() for a in fake.lock.archives}

    def opener(req, timeout=0):
        seen.append(req.full_url)
        return _Body(good[req.full_url.rsplit("/", 1)[-1]])
    assert bp.check_urls(fake.lock, fallbacks_only=True, opener=opener) == []
    assert seen and all("/second/" in u for u in seen) and len(seen) == len(fake.lock.archives)
