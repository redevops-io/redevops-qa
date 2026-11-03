# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The negative experiments of the Robot lane's egress layers.

A hostile Robot library (``hostile_suite/HostileLib.py``) runs inside the real lane child, under the real Robot Framework and the kit supervisor, and tries to reach hostile LOOPBACK listeners
that the lane's allow-list does not name, by every route below. The listeners count what reaches them: that count decides, not what the library says. The same attempts run in
four configurations:

* ``control``: the plan says ``not-enforced``, no layer is installed (the attempts must REACH: otherwise an attempt that does nothing would count as blocked);
* ``both``: the layers as the lane installs them;
* ``seccomp-only`` and ``landlock-only``: one layer alone, to show which layer does what, and what each does not stop.

Nothing here connects to anything but this machine's loopback interface. Nothing skips: a kernel without the layers makes the ``both`` tests fail.
"""
import pytest

from qa_runner import egresslog

from hostile_world import World
from lane_run import run_hostile

ATTACKS = ["allowed_origin", "bad_address", "direct", "ip_literal_http", "same_port_other_ip", "zero_address", "dns_udp_query", "dns_rebind", "dns_tcp_query", "getaddrinfo", "redirect", "raw_socket", "udp",
           "ipv6", "subprocess_curl", "subprocess_python", "subprocess_bash", "ctypes_connect", "raw_syscall", "thread", "import_time", "proxy_env", "unix_stream", "unix_dgram", "unix_dgram_pair", "udp6", "fast_open",
           "fast_open_sendmsg", "io_uring", "race"]
#: what the listener of an experiment counts as proof of reach; an attempt that is not here is judged by the library's own report (it created the socket, it resolved the name)
HITS = {"direct": "direct", "ip_literal_http": "ip_literal_http", "same_port_other_ip": "shadow", "dns_udp_query": "resolver_udp", "dns_rebind": "dns_rebind_target", "dns_tcp_query": "resolver_tcp",
        "redirect": "redirect", "udp": "udp", "ipv6": "ipv6", "subprocess_curl": "subprocess_curl", "subprocess_python": "subprocess_python", "subprocess_bash": "subprocess_bash",
        "ctypes_connect": "ctypes_connect", "raw_syscall": "raw_syscall", "thread": "thread", "import_time": "import_time", "proxy_env": "proxy_env", "unix_stream": "unix_stream",
        "unix_dgram": "unix_dgram", "unix_dgram_pair": "unix_dgram_pair", "udp6": "udp6", "fast_open": "fast_open", "fast_open_sendmsg": "fast_open_sendmsg", "race": "race"}
CONFIGS = {"control": ("not-enforced", "-"), "both": ("origin-only", "-"), "seccomp-only": ("origin-only", egresslog.LAYER_SECCOMP), "landlock-only": ("origin-only", egresslog.LAYER_LANDLOCK)}
#: not asserted in a configuration, with the reason: the outcome depends on the machine, not on the layers
NOT_ASSERTED = {"raw_socket": "needs root to succeed even without any layer", "getaddrinfo": "no name resolves without a resolver this machine would use", "io_uring": "a container's own filter may refuse it first"}

#: reached (True) or blocked (False) in each configuration; the entries are what was MEASURED, and a change of the layers that changes one is a change of what the report may say
CONTROL = {a: True for a in ATTACKS if a not in NOT_ASSERTED}
CONTROL["bad_address"] = False                  # the kernel refuses an address that is not memory (EFAULT) with no layer at all: not a reach, here only to show the supervisor survives it
BOTH = {a: False for a in ATTACKS if a not in NOT_ASSERTED}
BOTH["allowed_origin"] = True
SECCOMP_ONLY = dict(BOTH)
del SECCOMP_ONLY["race"]                       # a second thread can change the address between the supervisor's look and the kernel's: may reach another address on the allowed PORT or any port; not asserted
LANDLOCK_ONLY = {a: False for a in ATTACKS if a not in NOT_ASSERTED}
LANDLOCK_ONLY.update({a: True for a in ("allowed_origin", "same_port_other_ip", "zero_address", "dns_udp_query", "udp", "udp6", "unix_stream", "unix_dgram", "unix_dgram_pair", "fast_open", "fast_open_sendmsg")})   # what Landlock (TCP connect to a port) does not see
EXPECTED = {"control": CONTROL, "both": BOTH, "seccomp-only": SECCOMP_ONLY, "landlock-only": LANDLOCK_ONLY}
#: attempts whose refusal the supervisor must have recorded, in the configurations that have it
AUDITED = [a for a in ATTACKS if a not in ("allowed_origin", "io_uring")]


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    cache = {}
    worlds = []

    def get(name):
        if name not in cache:
            tmp = tmp_path_factory.mktemp(name.replace("-", "_"))
            world = World(str(tmp))
            worlds.append(world)
            profile, layers = CONFIGS[name]
            cache[name] = run_hostile(tmp, world, profile=profile, layers=layers, race_attempts=150 if name == "control" else 1500)
        return cache[name]
    yield get
    for w in worlds:
        w.close()


def reached(run, attack):
    if attack in HITS:
        return run.world.hits(HITS[attack]) > 0
    return bool(run.results[attack]["reached"])


def cases(config):
    return [pytest.param(config, a, id=f"{config}-{a}") for a in ATTACKS if a in EXPECTED[config]]


@pytest.mark.parametrize("config,attack", [c for cfg in CONFIGS for c in cases(cfg)])
def test_what_each_configuration_reaches_and_blocks(runs, config, attack):
    run = runs(config)
    assert run.exit_code == 0 and set(ATTACKS) <= set(run.results), run.stderr
    got = reached(run, attack)
    assert got is EXPECTED[config][attack], f"{attack} under {config}: reached={got}, results={run.results.get(attack)}"


def test_the_hostile_listeners_were_up_and_every_attempt_ran(runs):
    run = runs("control")
    assert run.world.shadow is not None, "no listener could be bound on 127.0.0.2: the same-port experiment would prove nothing"
    assert set(run.results) == set(ATTACKS)


# ---- the audit record ----------------------------------------------------------------------------------------------------------------
def segments(events):
    """The supervisor's decisions grouped by the attempt that caused them: the library makes one refused socket call carrying the attempt's number before each attempt."""
    out, current = {}, None
    for e in events:
        if e["syscall"] == "socket" and str(e.get("detail", "")).startswith("SOCK_DGRAM/2") and e["verdict"] == "deny" and e.get("family") == "AF_INET":
            current = ATTACKS_ORDER[int(e["detail"].split("/")[1]) - 200]
            out[current] = []
        elif current is not None:
            out[current].append(e)
    return out


ATTACKS_ORDER = ATTACKS                    # the library runs them in this order and numbers its markers by it


@pytest.mark.parametrize("config", ["both", "seccomp-only"])
@pytest.mark.parametrize("attack", AUDITED)
def test_every_refused_attempt_is_in_the_audit_record(runs, config, attack):
    run = runs(config)
    assert not run.log_problems and run.log_header is not None
    refusals = [e for e in segments(run.log_events).get(attack, []) if e["verdict"] == "deny"]
    assert refusals, f"{attack} under {config}: the supervisor recorded no refusal between its marker and the next"


@pytest.mark.parametrize("config", ["both", "seccomp-only"])
def test_a_connect_with_an_address_that_is_not_memory_is_refused_and_the_supervisor_goes_on(runs, config):
    run = runs(config)
    mine = [e for e in segments(run.log_events)["bad_address"] if e["verdict"] == "deny"]
    assert [(e["syscall"], e["reason"]) for e in mine] == [("connect", "address-unreadable")] and not run.outcome.raw_status == "egress-fence-lost"
    assert segments(run.log_events)["direct"], "the attempts after it were still decided and recorded"


@pytest.mark.parametrize("config", ["both", "seccomp-only"])
def test_the_allowed_origin_is_allowed_and_recorded_as_such(runs, config):
    run = runs(config)
    mine = segments(run.log_events)["allowed_origin"]
    assert [(e["verdict"], e["port"]) for e in mine] == [("allow", run.world.allowed_port)], mine


@pytest.mark.parametrize("config", ["both", "seccomp-only"])
def test_nothing_is_allowed_outside_the_allow_list_and_the_log_is_well_formed(runs, config):
    run = runs(config)
    assert not run.log_problems
    for e in run.log_events:
        if e["verdict"] == "allow":
            assert (e["syscall"], e["family"], e["address"], e["port"]) == ("connect", "AF_INET", "127.0.0.1", run.world.allowed_port), e


@pytest.mark.parametrize("config,layers", [("both", list(egresslog.ALL_LAYERS)), ("seccomp-only", [egresslog.LAYER_SECCOMP]), ("landlock-only", [egresslog.LAYER_LANDLOCK])])
def test_the_log_says_which_layers_were_installed_and_the_self_test_that_passed(runs, config, layers):
    run = runs(config)
    h = run.log_header
    assert h["event"] == "mechanism" and h["layers"] == layers and h["allowed"] == [f"127.0.0.1/32:{run.world.allowed_port}"]
    assert h["selftest"]["forbidden_tcp_refused"] is True and (h["selftest"].get("udp_refused") is True) == (egresslog.LAYER_SECCOMP in layers)


def test_a_refused_attempt_ends_the_lane_as_an_engine_error_not_a_pass(runs):
    """The hostile library finishes normally (it swallows every error), so Robot itself says PASS: the lane's status must come from the refusals."""
    for config in ("both", "seccomp-only"):
        o = runs(config).outcome
        assert (o.native_status, o.raw_status) == ("NATIVE_ERROR", "egress-denied") and o.egress["fence_denied"] > 100, (config, o.native_status, o.raw_status)
    c = runs("control").outcome
    assert (c.native_status, c.raw_status) == ("NATIVE_PASS", "PASS") and "lanes/robot/egress-log.jsonl" not in c.files and c.egress == {}


def test_the_control_lane_has_no_layers_and_says_so(runs):
    c = runs("control").outcome
    import json
    assert json.loads(c.files["lanes/robot/egress-profile.json"][0])["profile"] == "not-enforced"
