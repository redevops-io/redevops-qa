# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The mutation harness leaves nothing behind when a mutant's test times out (retest R2-8): the whole tree is killed, children that started their own session included."""
import subprocess
import sys
import time

import pytest

import qr_mutation
from qr_support import alive, wait_gone


def test_a_timed_out_run_is_killed_with_every_descendant_including_a_child_in_its_own_session(tmp_path):
    pidfile = tmp_path / "grandchild"
    code = (f"import subprocess, sys, time\n"
            f"g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'], start_new_session=True)\n"
            f"open({str(pidfile)!r}, 'w').write(str(g.pid))\ntime.sleep(300)\n")
    with pytest.raises(subprocess.TimeoutExpired):
        qr_mutation._run_tree([sys.executable, "-c", code], tmp_path, None, timeout=3)
    pid = int(pidfile.read_text())
    assert wait_gone(pid, 10), "a descendant of the timed-out run was left behind"


def test_the_descendants_of_a_process_are_found_by_parent_links(tmp_path):
    proc = subprocess.Popen([sys.executable, "-c", "import subprocess, sys, time\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)\ntime.sleep(60)"])
    try:
        end = time.monotonic() + 10
        found = []
        while not found and time.monotonic() < end:
            time.sleep(0.2)
            found = qr_mutation.descendants(proc.pid)
        assert found and all(alive(p) for p in found)
    finally:
        qr_mutation.kill_tree(proc.pid)
        proc.wait()
