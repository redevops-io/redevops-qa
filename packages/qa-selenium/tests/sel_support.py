# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import shutil
import sys
from pathlib import Path

from qa_adapter_kit import InteractiveActionRequest, InteractiveSession, Limits, SuiteRunRequest, SuiteRunner
from qa_selenium import AdapterConfig, SeleniumInteractiveAdapter, SeleniumSuiteAdapter, interactive_manifest, suite_manifest
from qa_selenium.testing.fake import FakeBrowser, site

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
HOSTS = frozenset({"app.test:8080"})


def make_session(tmp_path, *, browser=None, config=None, limits=None, factory=None):
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    holder = {}

    def default_factory():
        holder["browser"] = browser or FakeBrowser(site())
        return holder["browser"]

    adapter = SeleniumInteractiveAdapter(factory or default_factory, config=config or AdapterConfig(allowed_hosts=HOSTS),
                                         manifest=interactive_manifest(limits=limits))
    return InteractiveSession(adapter, output_dir=out), adapter, holder


def act(step, kind, target="", **kw):
    return InteractiveActionRequest(session_id="s1", adapter_id="selenium-interactive", step_index=step, kind=kind, target=target, **kw)


def mini_workspace(tmp_path, name="mini_suite.txt"):
    ws, out = tmp_path / "workspace", tmp_path / "output"
    (ws / "suite").mkdir(parents=True)
    out.mkdir()
    shutil.copy(FIXTURES / "suites" / name, ws / "suite" / "test_mini.py")
    return ws, out


def run_suite(tmp_path, *, selectors=(), mapping=None, required=(), limits=None, text=None, **kw):
    ws, out = mini_workspace(tmp_path)
    if text is not None:
        (ws / "suite" / "test_mini.py").write_text(text)
    adapter = SeleniumSuiteAdapter(sys.executable, suite_manifest(sys.executable, limits=limits or Limits(deadline_s=120, output_limit_bytes=200_000, kill_grace_s=2)))
    req = SuiteRunRequest(run_id="run-1", adapter_id="selenium-suite", workspace=str(ws), suite_path="suite/test_mini.py", output_dir=str(out),
                          selectors=tuple(selectors), assertion_mapping=mapping or {}, required_assertions=tuple(required), **kw)
    return SuiteRunner(adapter).run(req), ws, out
