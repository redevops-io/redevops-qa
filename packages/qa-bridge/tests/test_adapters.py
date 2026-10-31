# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import pytest

from redevops_qa_bridge import adapters, convert
from redevops_qa_bridge.errors import AdapterRefused

from fakes import FakeCheckAdapter, FakeQAAdapter


@pytest.fixture()
def c_fake(golden, contracts):
    return FakeQAAdapter("contracts", golden)


@pytest.fixture()
def n_fake(golden, neutral):
    return FakeQAAdapter("neutral", golden)


def _caller_args(side, golden):
    """The arguments a caller on ``side`` passes, built from golden data."""
    helper = FakeQAAdapter(side, golden)
    ar = helper.value
    return dict(profile=ar("session_profile"), handle=ar("session_handle"), req=ar("observe_request"),
                target=ar("locator_descriptor"), action=ar("action_request"), resolved=ar("resolved_target"),
                subject=ar("assertion_subject_ui"))


def test_contracts_adapter_is_usable_through_the_neutral_protocol(c_fake, golden, neutral, contracts):
    shim = adapters.NeutralQAAdapterFromContracts(c_fake)
    assert isinstance(shim, neutral.ports.NeutralQAAdapter)
    a = _caller_args("neutral", golden)
    n = neutral.records
    handle = shim.open_session(a["profile"])
    assert type(handle) is n.SessionHandle
    assert type(shim.observe(handle, a["req"])) is n.Observation
    assert type(shim.locate(handle, a["target"], mode=n.LocateMode.EXACT)) is n.LocateResult
    assert type(shim.act(handle, a["action"], a["resolved"])) is n.ActionOutcome
    assert type(shim.assert_(handle, a["subject"])) is n.ObservedValue
    refs = shim.capture(handle, [n.CaptureKind.SCREENSHOT])
    assert refs and all(type(r) is n.EvidenceRef for r in refs)
    assert type(shim.reset(handle, n.ResetScope.CONTEXT)) is n.ResetResult
    assert type(shim.close_session(handle)) is n.CleanupReport
    assert (shim.adapter_id, shim.adapter_version, shim.api_version) == ("fake-qa", "0.0.1", "qa-adapter/1")


def test_the_contracts_side_only_ever_receives_contracts_objects(c_fake, golden, neutral):
    shim = adapters.NeutralQAAdapterFromContracts(c_fake)
    a = _caller_args("neutral", golden)
    n = neutral.records
    handle = shim.open_session(a["profile"])
    shim.observe(handle, a["req"])
    shim.locate(handle, a["target"], mode=n.LocateMode.SEMANTIC)
    shim.act(handle, a["action"], a["resolved"])
    shim.assert_(handle, a["subject"])
    shim.capture(handle, [n.CaptureKind.TRACE])
    shim.reset(handle, n.ResetScope.FIXTURE)
    shim.close_session(handle)
    assert len(c_fake.calls) == 8
    for method, modules in c_fake.calls:
        assert set(modules) == {"runtime_contracts"}, (method, modules)


def test_neutral_adapter_is_usable_through_the_contracts_protocol(n_fake, golden, contracts):
    shim = adapters.ContractsQAAdapterFromNeutral(n_fake)
    assert isinstance(shim, contracts.QAAdapter)
    a = _caller_args("contracts", golden)
    handle = shim.open_session(a["profile"])
    assert type(handle) is contracts.SessionHandle
    assert type(shim.observe(handle, a["req"])) is contracts.Observation
    assert type(shim.locate(handle, a["target"], mode=contracts.LocateMode.EXACT)) is contracts.LocateResult
    assert type(shim.act(handle, a["action"], a["resolved"])) is contracts.ActionOutcome
    assert type(shim.assert_(handle, a["subject"])) is contracts.ObservedValue
    refs = shim.capture(handle, [contracts.CaptureKind.SCREENSHOT])
    assert refs and all(type(r).__module__.startswith("runtime_contracts") for r in refs)
    assert type(shim.reset(handle, contracts.ResetScope.CONTEXT)) is contracts.ResetResult
    assert type(shim.close_session(handle)) is contracts.CleanupReport
    for method, modules in n_fake.calls:
        assert set(modules) == {"agent_harness"}, (method, modules)


def test_typed_errors_cross_by_code_in_both_directions(c_fake, n_fake, golden, contracts, neutral):
    a = _caller_args("neutral", golden)
    c_fake.raise_on["observe"] = contracts.LocatorNotFound("gone")
    shim = adapters.NeutralQAAdapterFromContracts(c_fake)
    with pytest.raises(neutral.errors.LocatorNotFound) as info:
        shim.observe(shim.open_session(a["profile"]), a["req"])
    assert info.value.code == "LOCATOR_NOT_FOUND" and info.value.recoverable is True

    b = _caller_args("contracts", golden)
    n_fake.raise_on["act"] = neutral.errors.ActionBlockedByPolicy("no decision")
    shim2 = adapters.ContractsQAAdapterFromNeutral(n_fake)
    with pytest.raises(contracts.ActionBlockedByPolicy) as info2:
        shim2.act(shim2.open_session(b["profile"]), b["action"], b["resolved"])
    assert info2.value.code.value == "ACTION_BLOCKED_BY_POLICY"


def test_a_non_qa_exception_is_not_swallowed(c_fake, golden, neutral):
    a = _caller_args("neutral", golden)
    c_fake.raise_on["observe"] = RuntimeError("crash")
    shim = adapters.NeutralQAAdapterFromContracts(c_fake)
    with pytest.raises(RuntimeError):
        shim.observe(shim.open_session(a["profile"]), a["req"])


def test_a_shim_refuses_a_component_that_does_not_satisfy_the_protocol(c_fake):
    class Missing:
        adapter_id = "x"; adapter_version = "1"; api_version = "qa-adapter/1"
    with pytest.raises(AdapterRefused) as info:
        adapters.NeutralQAAdapterFromContracts(Missing())
    assert info.value.code == "ADAPTER_REFUSED" and "open_session" in info.value.details["missing"]
    c_fake.api_version = "qa-adapter/2"
    with pytest.raises(AdapterRefused):
        adapters.NeutralQAAdapterFromContracts(c_fake)


def test_a_shim_does_not_accept_a_foreign_class_instance_as_an_argument(c_fake, golden, contracts):
    shim = adapters.NeutralQAAdapterFromContracts(c_fake)
    with pytest.raises(Exception) as info:
        shim.open_session(contracts.SessionProfile.from_json(golden["values"]["session_profile"]["input"]))
    assert getattr(info.value, "code", "") == "UNKNOWN_TYPE"


# -- CheckAdapter ---------------------------------------------------------------------------------------------------

def test_check_adapter_shims_both_ways(golden, contracts, neutral):
    c_fake = FakeCheckAdapter("contracts", golden)
    shim = adapters.NeutralCheckAdapterFromContracts(c_fake)
    assert isinstance(shim, neutral.ports.NeutralCheckAdapter)
    h = FakeCheckAdapter("neutral", golden).value
    n = neutral.records
    w = shim.open_workspace(h("check_profile_offline"))
    assert type(w) is n.WorkspaceHandle
    assert type(shim.resolve(w, h("resource_ref_manifest_path"))) is n.ResolvedResource
    assert type(shim.run_check(w, h("check_subject"))) is n.ObservedValue
    assert shim.capture(w, [n.CaptureKind.DOM_META])
    assert type(shim.reset(w, n.ResetScope.ENVIRONMENT)) is n.ResetResult
    assert type(shim.close_workspace(w)) is n.CleanupReport
    assert all(set(m) == {"runtime_contracts"} for _, m in c_fake.calls)

    n_fake = FakeCheckAdapter("neutral", golden)
    shim2 = adapters.ContractsCheckAdapterFromNeutral(n_fake)
    assert isinstance(shim2, contracts.CheckAdapter)
    hc = FakeCheckAdapter("contracts", golden).value
    w2 = shim2.open_workspace(hc("check_profile_k"))
    assert type(w2) is contracts.WorkspaceHandle
    assert type(shim2.run_check(w2, hc("check_subject"))) is contracts.ObservedValue
    assert all(set(m) == {"agent_harness"} for _, m in n_fake.calls)


def test_check_adapter_errors_cross(golden, contracts, neutral):
    c_fake = FakeCheckAdapter("contracts", golden)
    c_fake.raise_on["run_check"] = contracts.UnsupportedOperation("closed world")
    shim = adapters.NeutralCheckAdapterFromContracts(c_fake)
    h = FakeCheckAdapter("neutral", golden).value
    with pytest.raises(neutral.errors.UnsupportedOperation):
        shim.run_check(shim.open_workspace(h("check_profile_offline")), h("check_subject"))


# -- blob store and redactor ----------------------------------------------------------------------------------------------

class _Blob:
    def __init__(self):
        self.items = {}

    def put(self, data, *, media_type):
        self.items[len(self.items)] = (data, media_type)
        return "sha256:" + "ab" * 32

    def get(self, digest):
        return b"x"

    def exists(self, digest):
        return True

    def size(self, digest):
        return 1


class _NeutralBlob(_Blob):
    def put(self, data, media_type):
        return super().put(data, media_type=media_type)


def test_blob_shims_bridge_the_keyword_only_difference(contracts, neutral):
    c = _Blob()
    sink = adapters.NeutralBlobSinkFromContracts(c)
    assert sink.put(b"d", "image/png") == "sha256:" + "ab" * 32 and c.items[0] == (b"d", "image/png")
    assert isinstance(sink, neutral.ports.BlobSink)
    n = _NeutralBlob()
    store = adapters.ContractsBlobStoreFromNeutral(n)
    assert store.put(b"d", media_type="text/plain") == "sha256:" + "ab" * 32
    assert isinstance(store, contracts.BlobStore)
    with pytest.raises(TypeError):
        store.put(b"d", "text/plain")        # contracts protocol: media_type is keyword-only


def test_redactor_shims_and_redaction_failure_crosses(contracts, neutral):
    class CRedactor:
        policy_id = "rcv1:" + "1" * 64

        def redact(self, data, *, media_type):
            raise contracts.RedactionFailed("no")
    shim = adapters.NeutralRedactorFromContracts(CRedactor())
    assert isinstance(shim, neutral.ports.Redactor) and shim.policy_id.startswith("rcv1:")
    with pytest.raises(neutral.errors.RedactionFailed):
        shim.redact(b"x", "text/plain")

    class NRedactor:
        policy_id = "rcv1:" + "2" * 64

        def redact(self, data, media_type):
            return data.upper()
    shim2 = adapters.ContractsRedactorFromNeutral(NRedactor())
    assert isinstance(shim2, contracts.Redactor) and shim2.redact(b"ab", media_type="text/plain") == b"AB"
