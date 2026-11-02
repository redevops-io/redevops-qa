# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The kit's bounded read: one descriptor, regular files only, byte and time caps, and (with a root) no symbolic link at any component. Probes use a FIFO with no writer, /dev/null, a lying size,
a symlinked directory and `..`; nothing here opens /dev/zero or any unbounded source. The FIFO probes run in a child with a hard timeout, so a regression cannot hang the suite."""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from qa_adapter_kit.boundedread import UnsafeRead, read_regular

SRC = str(Path(__file__).resolve().parents[1] / "src")


def test_a_regular_file_is_read_and_the_cap_is_inclusive(tmp_path):
    (tmp_path / "f").write_bytes(b"abc")
    assert read_regular(str(tmp_path / "f"), max_bytes=3) == b"abc"
    with pytest.raises(UnsafeRead) as exc:
        read_regular(str(tmp_path / "f"), max_bytes=2)
    assert exc.value.code == "TOO_LARGE"


def test_a_fifo_with_no_writer_is_refused_at_once_in_a_child_with_a_hard_timeout(tmp_path):
    fifo = tmp_path / "output.xml"
    os.mkfifo(fifo)
    code = f"import sys; sys.path.insert(0, {SRC!r})\nfrom qa_adapter_kit.boundedread import read_regular, UnsafeRead\ntry:\n    read_regular({str(fifo)!r}, max_bytes=100)\nexcept UnsafeRead as e:\n    print(e.code)"
    t0 = time.monotonic()
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=20)
    assert done.stdout.strip() == "NOT_A_REGULAR_FILE" and time.monotonic() - t0 < 10


def test_a_device_and_a_directory_are_refused(tmp_path):
    for p in ("/dev/null", str(tmp_path)):
        with pytest.raises(UnsafeRead) as exc:
            read_regular(p, max_bytes=100)
        assert exc.value.code == "NOT_A_REGULAR_FILE"


def test_a_deadline_stops_a_read(tmp_path):
    (tmp_path / "f").write_bytes(b"x" * 10)
    with pytest.raises(UnsafeRead) as exc:
        read_regular(str(tmp_path / "f"), max_bytes=100, deadline_s=-1)
    assert exc.value.code == "TIMEOUT"


def test_under_a_root_a_symlink_at_any_component_is_refused(tmp_path):
    """Retest L-R4: O_NOFOLLOW on the last component alone follows a `blobs` directory that was replaced by a link."""
    root = tmp_path / "root"
    (root / "real").mkdir(parents=True)
    (root / "real" / "f.bin").write_bytes(b"data")
    (root / "link").symlink_to(root / "real")
    (root / "real" / "file-link").symlink_to(root / "real" / "f.bin")
    assert read_regular(str(root / "real" / "f.bin"), max_bytes=10, follow_symlinks=False, root=str(root)) == b"data"
    for bad in (root / "link" / "f.bin", root / "real" / "file-link"):
        with pytest.raises(UnsafeRead) as exc:
            read_regular(str(bad), max_bytes=10, follow_symlinks=False, root=str(root))
        assert exc.value.code == "NOT_A_REGULAR_FILE", bad
    # without the root the directory link is followed (that is the gap the root closes)
    assert read_regular(str(root / "link" / "f.bin"), max_bytes=10, follow_symlinks=False) == b"data"


def test_a_path_outside_the_root_or_with_dotdot_is_refused(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.bin").write_bytes(b"x")
    (root / "a").mkdir()
    for bad in (tmp_path / "outside.bin", root / "a" / ".." / ".." / "outside.bin", root):
        with pytest.raises(UnsafeRead):
            read_regular(str(bad), max_bytes=10, follow_symlinks=False, root=str(root))


def test_a_root_that_is_itself_reached_through_a_link_is_fine_only_below_it_is_checked(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "f").write_bytes(b"ok")
    (tmp_path / "alias").symlink_to(real)
    assert read_regular(str(tmp_path / "alias" / "f"), max_bytes=10, follow_symlinks=False, root=str(tmp_path / "alias")) == b"ok"
