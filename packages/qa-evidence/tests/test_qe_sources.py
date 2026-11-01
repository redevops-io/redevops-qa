# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Directory and archive sources: caps, depth, and reading that never follows a link or opens a special file."""
import os

import pytest

from qa_evidence.build import write_directory
from qa_evidence.constants import Limits
from qa_evidence.sources import DirSource, MemorySource, SourceError, TarSource, open_source
from qa_evidence.tarfmt import write_tar
from qa_evidence.verify import verify_bundle

from qe_helpers import build_base, codes


def test_a_directory_with_more_files_than_the_cap_is_refused(tmp_path):
    write_directory(build_base().files, str(tmp_path / "d"))
    r = verify_bundle(str(tmp_path / "d"), limits=Limits(max_files=3))
    assert "" in {f.path for f in r.findings if f.code == "TOO_MANY_FILES"}      # found while listing, before any manifest is read


def test_directories_nested_deeper_than_the_cap_are_refused(tmp_path):
    deep = tmp_path / "d"
    cursor = deep
    for i in range(20):
        cursor = cursor / f"n{i}"
    cursor.mkdir(parents=True)
    (cursor / "f.txt").write_bytes(b"x")
    assert [p[0] for p in DirSource(str(deep)).problems] == ["PATH_TOO_DEEP"]


def test_an_archive_larger_than_the_ceiling_is_refused_without_being_read(tmp_path):
    path = tmp_path / "big.tar"
    path.write_bytes(write_tar({"a": b"x" * 20000}))
    src = TarSource(str(path), Limits(max_total_bytes=10, max_files=1))
    assert [p[0] for p in src.problems] == ["ARCHIVE_TOO_LARGE"] and src.entries == []
    src.close()


def test_reading_never_follows_a_symbolic_link_even_if_one_appears_after_listing(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "real.txt").write_bytes(b"real")
    (tmp_path / "secret.txt").write_bytes(b"secret")
    src = DirSource(str(tmp_path / "d"))
    os.remove(tmp_path / "d" / "real.txt")
    os.symlink(tmp_path / "secret.txt", tmp_path / "d" / "real.txt")
    with pytest.raises(OSError):
        src.read_all("real.txt", 100)


def test_reading_refuses_a_pipe_that_replaced_a_file(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f.txt").write_bytes(b"x")
    src = DirSource(str(tmp_path / "d"))
    os.remove(tmp_path / "d" / "f.txt")
    os.mkfifo(tmp_path / "d" / "f.txt")
    with pytest.raises(OSError):
        src.read_all("f.txt", 100)


def test_reads_are_bounded_by_the_limit_plus_one_in_every_form(tmp_path):
    data = b"x" * 3000
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f.bin").write_bytes(data)
    (tmp_path / "t.tar").write_bytes(write_tar({"f.bin": data}))
    for src in (DirSource(str(tmp_path / "d")), TarSource(str(tmp_path / "t.tar")), MemorySource({"f.bin": data})):
        assert len(src.read_all("f.bin", 10)) == 11 and src.read_all("f.bin", 5000) == data
        src.close()


def test_open_source_refuses_what_is_not_a_directory_or_regular_file(tmp_path):
    with pytest.raises(SourceError):
        open_source(str(tmp_path / "missing"))
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(SourceError):
        open_source(str(tmp_path / "pipe"))
    os.symlink(tmp_path, tmp_path / "alias")
    with pytest.raises(SourceError):
        open_source(str(tmp_path / "alias"))


def test_a_file_that_cannot_be_listed_or_read_is_a_finding_not_a_crash(tmp_path):
    write_directory(build_base().files, str(tmp_path / "d"))
    locked = tmp_path / "d" / "logs"
    os.chmod(locked, 0)
    try:
        if os.access(locked, os.R_OK):
            pytest.fail("the test host ignores directory permissions; run as an ordinary user")
        r = verify_bundle(str(tmp_path / "d"))
        assert "UNREADABLE" in codes(r) and not r.ok
    finally:
        os.chmod(locked, 0o755)
