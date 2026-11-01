# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The archive form: generated headers, standard-tool compatibility, and refusal of everything that is not the canonical form."""
import io
import shutil
import subprocess
import tarfile

import pytest

from qa_evidence.constants import Limits
from qa_evidence.tarfmt import BLOCK, RECORD, encode_header, scan_tar, write_tar


def scan(data, limits=Limits()):
    return scan_tar(io.BytesIO(data), len(data), limits)


FILES = {"b/two.txt": b"two", "a.txt": b"one" * 200, "empty": b"", "café.txt": b"x"}


def test_a_round_trip_lists_every_entry_in_sorted_order():
    data = write_tar(FILES)
    entries, problems = scan(data)
    assert problems == [] and [e.path for e in entries] == sorted(FILES)
    for e in entries:
        assert data[e.offset:e.offset + e.size] == FILES[e.path]
    assert len(data) % RECORD == 0


def test_the_archive_is_a_valid_tar_that_standard_readers_open():
    data = write_tar(FILES)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
        members = tf.getmembers()
        assert [m.name for m in members] == sorted(FILES)
        for m in members:
            assert m.isreg() and m.uid == 0 and m.gid == 0 and m.uname == "" and m.gname == "" and m.mtime == 0 and m.mode == 0o644
            assert tf.extractfile(m).read() == FILES[m.name]


def test_the_system_tar_lists_the_archive(tmp_path):
    tar = shutil.which("tar")
    assert tar, "tar is expected on the test hosts"
    path = tmp_path / "a.tar"
    path.write_bytes(write_tar(FILES))
    out = subprocess.run([tar, "-tf", str(path)], capture_output=True, text=True, check=True).stdout.split("\n")
    assert sorted(x for x in out if x) == sorted(FILES)


def test_writing_is_independent_of_input_order_and_repeatable():
    assert write_tar(FILES) == write_tar(dict(reversed(list(FILES.items())))) == write_tar(dict(FILES))


def test_header_bytes_contain_no_owner_time_or_host_information():
    head = encode_header("a.txt", 5)
    assert head[100:108] == b"0000644\x00" and head[108:124] == b"0000000\x00" * 2 and head[136:148] == b"00000000000\x00"
    assert head[265:329] == b"\x00" * 64 and head[345:500] == b"\x00" * 155 and head[156:157] == b"0" and head[157:257] == b"\x00" * 100


@pytest.mark.parametrize("name", ["", "x" * 101, "a\x00b"])
def test_names_the_format_cannot_hold_are_refused_at_write_time(name):
    with pytest.raises(ValueError):
        encode_header(name, 1)


def _std_tar(build):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        build(tf)
    return buf.getvalue()


def _member(name, data=b"x", **attrs):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    for k, v in attrs.items():
        setattr(info, k, v)
    return info, data


def _add(tf, info, data=b""):
    tf.addfile(info, io.BytesIO(data) if info.isreg() else None)


def test_a_standard_tar_with_ordinary_metadata_is_not_the_canonical_form():
    data = _std_tar(lambda tf: _add(tf, *_member("a.txt", mtime=1700000000, uid=1000, gid=1000, uname="me", gname="grp", mode=0o600)))
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(data)[1]}


@pytest.mark.parametrize("attrs", [{"type": tarfile.SYMTYPE, "linkname": "/etc/passwd"}, {"type": tarfile.LNKTYPE, "linkname": "a.txt"},
                                   {"type": tarfile.DIRTYPE}, {"type": tarfile.CHRTYPE}, {"type": tarfile.FIFOTYPE}])
def test_links_directories_and_devices_are_not_canonical(attrs):
    info = tarfile.TarInfo("thing")
    for k, v in attrs.items():
        setattr(info, k, v)
    info.mode, info.mtime = 0o644, 0
    data = _std_tar(lambda tf: _add(tf, info))
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(data)[1]}


def test_pax_and_gnu_extended_headers_are_not_canonical():
    for fmt in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
            info = tarfile.TarInfo("x" * 150)
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
        assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(buf.getvalue())[1]}


def test_entries_out_of_order_or_duplicated_are_reported():
    def raw(names):
        out = bytearray()
        for n in names:
            out += encode_header(n, 1) + b"x" + b"\x00" * (BLOCK - 1)
        out += b"\x00" * (2 * BLOCK)
        out += b"\x00" * (-len(out) % RECORD)
        return bytes(out)
    assert "ARCHIVE_ORDER" in {c for c, _, _ in scan(raw(["b", "a"]))[1]}
    assert "DUPLICATE_PATH" in {c for c, _, _ in scan(raw(["a", "a"]))[1]}


def test_trailing_data_a_missing_marker_and_truncation_are_reported():
    good = write_tar({"a": b"x"})
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(good + b"junk" + b"\x00" * (RECORD - 4))[1]}
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(b"\x00" * BLOCK + b"\x01" * BLOCK + b"\x00" * (RECORD - 2 * BLOCK))[1]}   # one zero block only
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(good + b"\x00" * RECORD)[1]}
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(good[:BLOCK * 2])[1]}          # no end-of-archive marker
    hidden = good[:-1] + b"\x01"                                                       # same length: data hidden in the padding
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(hidden)[1]}
    assert "ARCHIVE_TRUNCATED" in {c for c, _, _ in scan(good[:100])[1]}
    big = encode_header("a", 5000) + b"x" * 100
    assert "ARCHIVE_TRUNCATED" in {c for c, _, _ in scan(big)[1]}


def test_a_header_with_a_forged_checksum_or_size_field_is_refused():
    good = bytearray(write_tar({"a": b"x"}))
    bad = bytearray(good)
    bad[148:156] = b"0000000\x00"
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(bytes(bad))[1]}
    bad = bytearray(good)
    bad[124:136] = b"7777777777\x00\x00"
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(bytes(bad))[1]}
    bad = bytearray(good)
    bad[0:2] = b"\xff\xfe"
    assert "ARCHIVE_NONCANONICAL" in {c for c, _, _ in scan(bytes(bad))[1]}


def test_the_entry_cap_is_enforced_while_scanning():
    data = write_tar({f"f{i}": b"x" for i in range(10)})
    assert "TOO_MANY_FILES" in {c for c, _, _ in scan(data, Limits(max_files=5))[1]}
