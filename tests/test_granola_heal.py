"""Tests for dotfiles/bin/granola-heal: pure logic, plus the guard loop with every side effect faked.

The incident fixtures follow the process table and breadcrumb shapes observed on
2026-09-29. The PIDs and start times are the real ones; user, meeting, and document
identifiers are replaced with synthetic values.
"""
import importlib.machinery
import importlib.util
import json
import pathlib
import random
import signal

import pytest
from hypothesis import given, settings, strategies as st

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "bin" / "granola-heal"
APP = "/Applications/Granola.app"
MAIN = APP + "/Contents/MacOS/Granola"
HELPER = APP + "/Contents/Frameworks/Granola Helper.app/Contents/MacOS/Granola Helper"
RENDERER = (APP + "/Contents/Frameworks/Granola Helper (Renderer).app/Contents/MacOS/"
            "Granola Helper (Renderer)")
CRASHPAD = APP + "/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler"
NATIVE_HOST = APP + "/Contents/Resources/native-host/meet-consent-host"


@pytest.fixture(scope="module")
def gh():
    loader = importlib.machinery.SourceFileLoader("granola_heal", str(SCRIPT))
    spec = importlib.util.spec_from_loader("granola_heal", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


# `ps -axo pid=,ppid=,lstart=,comm=` as it looked just before the 2026-09-29 fix.
INCIDENT_PS = "\n".join([
    f"  7620     1 Mon Sep 28 17:09:02 2026     {MAIN}",
    f"  7956     1 Mon Sep 28 17:09:06 2026     {CRASHPAD}",
    f"  7957  7620 Mon Sep 28 17:09:06 2026     {HELPER}",
    f"  7960  7620 Mon Sep 28 17:09:06 2026     {RENDERER}",
    f"  7961  7620 Mon Sep 28 17:09:06 2026     Granola Helper (MacOSMicAppsWithDevices)",
    f"  7964  7620 Mon Sep 28 17:09:06 2026     {RENDERER}",
    f"  7970  7620 Mon Sep 28 17:09:06 2026     Granola Helper (MissionControl)",
    f"  8095  7620 Mon Sep 28 17:09:07 2026     Granola Helper (Storage)",
    f" 27111 26599 Mon Sep 28 19:08:57 2026     {NATIVE_HOST}",
    f" 35816  7620 Mon Sep 28 17:13:02 2026     Granola Helper (Audio)",
    f" 44814     1 Thu Sep 24 16:35:05 2026     Granola Helper (Audio)",
    f" 91183     1 Thu Sep 24 15:50:48 2026     Granola Helper (MacOSMicAppsWithDevices)",
    f" 91190     1 Thu Sep 24 15:50:48 2026     Granola Helper (MissionControl)",
    f" 91380     1 Thu Sep 24 15:50:49 2026     Granola Helper (Storage)",
    f"  4242     1 Thu Sep 24 09:00:00 2026     /usr/sbin/cfprefsd",
])
INCIDENT_ORPHANS = {44814, 91183, 91190, 91380}

# The relaunched, healthy instance a few seconds after `open -g -a Granola`.
HEALTHY_PS = "\n".join([
    f" 94286     1 Tue Sep 29 12:18:56 2026     {MAIN}",
    f" 95219     1 Tue Sep 29 12:19:01 2026     {CRASHPAD}",
    f" 95277 94286 Tue Sep 29 12:19:01 2026     {RENDERER}",
    f" 95281 94286 Tue Sep 29 12:19:01 2026     Granola Helper (MacOSMicAppsWithDevices)",
    f" 95612 94286 Tue Sep 29 12:19:02 2026     Granola Helper (Storage)",
    f" 97524 94286 Tue Sep 29 12:19:11 2026     Granola Helper (ThirdPartyMeetingAutomation)",
    f" 93271 26599 Tue Sep 29 12:18:52 2026     {NATIVE_HOST}",
])


def crumb(ts, message, *args):
    return {"timestamp": ts, "category": "console", "level": "info", "message": message,
            "data": {"arguments": list(args), "logger": "console"}}


def stuck_skip(ts, trigger="polling"):
    """The structured skip and its plain-text twin, logged in the same second."""
    return [
        crumb(ts, "Full sync already in progress, skipping", "Full sync already in progress, skipping"),
        crumb(ts + 0.001, "full-sync-skipped [object Object]", "full-sync-skipped",
              {"user_id": "user-synthetic", "trigger": trigger, "reason": "sync-already-in-progress"}),
    ]


def scope(*crumbs):
    flat = []
    for c in crumbs:
        flat.extend(c if isinstance(c, list) else [c])
    return {"scope": {"breadcrumbs": flat}, "event": {}}


def by_pid(procs):
    return {p["pid"]: p for p in procs}


# ---------------------------------------------------------------- parse_ps

def test_parse_ps_reads_the_incident_table(gh):
    procs = gh.parse_ps(INCIDENT_PS)
    assert len(procs) == 15
    p = by_pid(procs)
    assert p[91380]["comm"] == "Granola Helper (Storage)"
    assert p[7964]["comm"] == RENDERER            # spaces inside the path survive
    assert p[7620]["ppid"] == 1
    assert p[91380]["start"] < p[7620]["start"]   # the orphan predates the instance


def test_parse_ps_skips_malformed_rows_and_handles_padded_days(gh):
    text = "\n".join([
        "garbage",
        "  12 abc Tue Sep 29 12:00:00 2026 x",
        "  13 1 Tue Sep 99 12:00:00 2026 bad-date",
        f"  14 1 Thu Oct  1 09:05:00 2026 {MAIN}",
        "",
    ])
    procs = gh.parse_ps(text)
    assert [p["pid"] for p in procs] == [14]
    assert procs[0]["comm"] == MAIN


# ---------------------------------------------------------------- classification

def test_incident_orphans_are_exactly_the_four_stale_helpers(gh):
    procs = gh.parse_ps(INCIDENT_PS)
    orphans = gh.select_orphans(procs, now=1e12)
    assert {p["pid"] for p in orphans} == INCIDENT_ORPHANS


def test_healthy_instance_has_no_orphans(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    assert gh.select_orphans(procs, now=1e12) == []
    assert gh.count_storage(procs) == 1


def test_crashpad_and_native_host_are_never_helpers(gh):
    procs = by_pid(gh.parse_ps(INCIDENT_PS))
    assert not gh.is_helper(procs[7956])     # crashpad: PPID 1 by design
    assert not gh.is_helper(procs[27111])    # Chrome's native host
    assert not gh.is_helper(procs[4242])     # not Granola at all
    assert gh.is_helper(procs[91380])


def test_without_main_orphans_wait_out_the_grace_period(gh):
    procs = [p for p in gh.parse_ps(INCIDENT_PS) if p["comm"] != MAIN]
    storage = by_pid(procs)[91380]
    assert storage["pid"] in {p["pid"] for p in gh.select_orphans(procs, storage["start"] + 10_000)}
    young = dict(storage, start=5_000.0)
    assert gh.select_orphans([young], now=5_000.0 + gh.ORPHAN_GRACE_S - 1) == []
    assert gh.select_orphans([young], now=5_000.0 + gh.ORPHAN_GRACE_S) == [young]


def test_ppid1_helper_newer_than_main_is_left_alone(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    main = gh.current_main(procs)
    odd = {"pid": 99999, "ppid": 1, "start": main["start"] + 60, "comm": "Granola Helper (Storage)"}
    assert gh.select_orphans(procs + [odd], now=main["start"] + 10_000) == []


def test_restart_targets_spare_only_the_native_host(gh):
    procs = gh.parse_ps(INCIDENT_PS)
    targets = {p["pid"] for p in gh.restart_targets(procs)}
    assert 27111 not in targets
    assert 4242 not in targets
    assert {7620, 7956, 8095} | INCIDENT_ORPHANS <= targets


def test_current_main_picks_the_newest(gh):
    procs = [{"pid": 10, "ppid": 1, "start": 100.0, "comm": MAIN},
             {"pid": 11, "ppid": 1, "start": 200.0, "comm": MAIN}]
    assert gh.current_main(procs)["pid"] == 11
    assert gh.current_main([]) is None


# ---------------------------------------------------------------- breadcrumbs

def test_breadcrumbs_classify_the_observed_messages(gh):
    t = 1_790_000_000.0
    s = scope(
        stuck_skip(t),
        crumb(t + 1, "full-sync-skipped [object Object]", "full-sync-skipped",
              {"reason": "window-visible-sync-skipped"}),
        crumb(t + 2, "sqlite-init-start [object Object]", "sqlite-init-start", {}),
        crumb(t + 3, "sqlite-init-success [object Object]", "sqlite-init-success", {}),
        crumb(t + 4, "full-sync-complete [object Object]", "full-sync-complete", {"durationMs": 1505.7}),
        crumb(t + 5, "2026-09-29T16:19:20.617Z \x1b[32mtranscription-latency-assembly-partial\x1b[0m {}"),
        crumb(t + 6, "calendar-event-disabled-transcription-check-skipped [object Object]"),
        {"timestamp": "bad", "message": "full-sync-complete"},
        {"message": "full-sync-complete"},
        "not-a-dict",
        {"timestamp": t + 7, "message": 42},
    )
    assert gh.breadcrumb_events(s, since=0) == [
        (int(t), "sync_stuck"),
        (int(t) + 3, "sqlite_ok"),
        (int(t) + 4, "sync_complete"),
        (int(t) + 5, "transcribing"),
    ]
    assert gh.breadcrumb_events(s, since=t + 3.5) == [(int(t) + 4, "sync_complete"),
                                                       (int(t) + 5, "transcribing")]


@pytest.mark.parametrize("bad", [None, {}, {"scope": None}, {"scope": {"breadcrumbs": None}}, []])
def test_unreadable_breadcrumbs_yield_nothing(gh, bad):
    assert gh.breadcrumb_events(bad, since=0) == []


# ---------------------------------------------------------------- wedge evidence

def incident_main(gh):
    return gh.current_main(gh.parse_ps(INCIDENT_PS))


def test_incident_breadcrumbs_read_as_a_wedge(gh):
    main = incident_main(gh)
    t = main["start"] + 18 * 3600
    state = {}
    # 11:09:54 polling skip and 11:57:17 window-visibility skip, seen on separate ticks
    # (the buffer had evicted the first by the second).
    gh.merge_evidence(state, main, gh.breadcrumb_events(scope(stuck_skip(t)), main["start"]))
    assert not gh.wedged(state)
    gh.merge_evidence(state, main, gh.breadcrumb_events(scope(stuck_skip(t + 2843, "window-visibility")),
                                                        main["start"]))
    assert gh.wedged(state)


def test_a_completed_sync_clears_wedge_evidence(gh):
    main = incident_main(gh)
    t = main["start"] + 3600
    state = {}
    gh.merge_evidence(state, main, gh.breadcrumb_events(scope(stuck_skip(t), stuck_skip(t + 2000)), 0))
    assert gh.wedged(state)
    gh.merge_evidence(state, main, [(int(t) + 2001, "sync_complete")])
    assert not gh.wedged(state) and state["skips"] == []


def test_short_span_is_not_a_wedge(gh):
    main = incident_main(gh)
    state = gh.merge_evidence({}, main, [(100, "sync_stuck"), (100 + gh.WEDGE_SPAN_S - 1, "sync_stuck")])
    assert not gh.wedged(state)


def test_new_instance_resets_evidence(gh):
    main = incident_main(gh)
    state = gh.merge_evidence({}, main, [(100, "sync_stuck"), (5000, "sync_stuck")])
    state["tainted"] = True
    other = dict(main, pid=main["pid"] + 1, start=main["start"] + 10)
    gh.merge_evidence(state, other, [])
    assert state["skips"] == [] and state["tainted"] is False and state["main"] == [other["pid"], other["start"]]


# ---------------------------------------------------------------- recording

PMSET_RECORDING = """Assertion status system-wide:
   PreventUserIdleDisplaySleep    1
Listed by owning process:
   pid 94286(Granola): [0x000689c40005842a] 00:02:25 NoDisplaySleepAssertion named: "Electron"
   pid 512(Google Chrome): [0x0001] 00:30:00 NoDisplaySleepAssertion named: "WebRTC has active PeerConnections"
"""
PMSET_IDLE = """Listed by owning process:
   pid 512(Google Chrome): [0x0001] 00:30:00 NoDisplaySleepAssertion named: "WebRTC has active PeerConnections"
   pid 88(powerd): [0x0002] 01:00:00 PreventUserIdleSystemSleep named: "Powerd - Prevent sleep while display is on"
"""


def test_recording_from_the_observed_assertion(gh):
    assert gh.recording_signals(PMSET_RECORDING, [], now=0) == ["pid 94286 holds NoDisplaySleepAssertion"]
    assert gh.recording_signals(PMSET_IDLE, [], now=0) == []


def test_recording_from_recent_transcription_breadcrumbs(gh):
    now = 10_000
    assert gh.recording_signals("", [(now - 21, "transcribing")], now)
    assert gh.recording_signals("", [(now - gh.RECORDING_RECENT_S, "transcribing")], now) == []
    assert gh.recording_signals(None, [(now - 5, "sync_complete")], now) == []


# ---------------------------------------------------------------- plan

def test_plan_incident_kills_orphans_and_restarts_when_idle(gh):
    procs = gh.parse_ps(INCIDENT_PS)
    d = gh.plan(procs, {}, recording=[], now=2e9, last_restart=0)
    assert set(d["kill"]) == INCIDENT_ORPHANS
    assert d["restart"] and d["reason"] == "instance ran alongside orphaned helpers" and d["blocked"] is None


def test_plan_defers_restart_while_recording_but_still_kills_orphans(gh):
    procs = gh.parse_ps(INCIDENT_PS)
    d = gh.plan(procs, {}, recording=["pid 7620 holds NoDisplaySleepAssertion"], now=2e9, last_restart=0)
    assert set(d["kill"]) == INCIDENT_ORPHANS
    assert not d["restart"] and d["blocked"].startswith("recording")


def test_plan_respects_cooldown_but_manual_does_not(gh):
    procs = gh.parse_ps(INCIDENT_PS)
    now = 2e9
    d = gh.plan(procs, {}, [], now, last_restart=now - 60)
    assert not d["restart"] and d["blocked"].startswith("cooldown")
    d = gh.plan(procs, {}, [], now, last_restart=now - 60, manual=True)
    assert d["restart"] and d["reason"] == "manual fix"


def test_plan_manual_refuses_recording_unless_forced(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    rec = ["pid 94286 holds NoDisplaySleepAssertion"]
    assert not gh.plan(procs, {}, rec, 2e9, 0, manual=True)["restart"]
    assert gh.plan(procs, {}, rec, 2e9, 0, manual=True, force=True)["restart"]


def test_plan_healthy_instance_does_nothing(gh):
    d = gh.plan(gh.parse_ps(HEALTHY_PS), {}, [], 2e9, 0)
    assert d == {"kill": [], "restart": False, "reason": None, "blocked": None}


def test_plan_tainted_state_restarts_after_orphans_are_gone(gh):
    d = gh.plan(gh.parse_ps(HEALTHY_PS), {"tainted": True}, [], 2e9, 0)
    assert d["restart"] and d["reason"] == "instance ran alongside orphaned helpers"


def test_plan_wedge_restarts(gh):
    state = {"skips": [100, 100 + gh.WEDGE_SPAN_S], "last_complete": 0}
    d = gh.plan(gh.parse_ps(HEALTHY_PS), state, [], 2e9, 0)
    assert d["restart"] and d["reason"] == "full sync stuck in progress"


def test_plan_without_main_never_restarts(gh):
    procs = [p for p in gh.parse_ps(INCIDENT_PS) if p["comm"] != MAIN]
    d = gh.plan(procs, {"tainted": True, "skips": [0, 99999]}, [], 2e9, 0, manual=True, force=True)
    assert not d["restart"] and set(d["kill"]) == INCIDENT_ORPHANS


# ---------------------------------------------------------------- verify_restart

def test_verify_restart_accepts_the_observed_healthy_relaunch(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    main = gh.current_main(procs)
    ok, detail = gh.verify_restart(procs, [(int(main["start"]) + 16, "sqlite_ok")], main["start"] - 5)
    assert ok, detail


@pytest.mark.parametrize("mutate,events,expect", [
    (lambda ps: [p for p in ps if p["comm"] != MAIN], [(0, "sqlite_ok")], "no new Granola main"),
    (lambda ps: ps + [dict(ps[4], pid=1)], [(0, "sqlite_ok")], "more than one Storage"),
    (lambda ps: ps, [], "no sqlite-init-success"),
])
def test_verify_restart_failures(gh, mutate, events, expect):
    procs = mutate(gh.parse_ps(HEALTHY_PS))
    ok, detail = gh.verify_restart(procs, events, restarted_at=gh.parse_ps(HEALTHY_PS)[0]["start"] - 5)
    assert not ok and expect in detail


def test_verify_restart_rejects_the_old_instance(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    main = gh.current_main(procs)
    ok, detail = gh.verify_restart(procs, [(0, "sqlite_ok")], restarted_at=main["start"] + 60)
    assert not ok and "no new Granola main" in detail


# ---------------------------------------------------------------- properties

COMMS = [MAIN, HELPER, RENDERER, CRASHPAD, NATIVE_HOST, "Granola Helper (Storage)", "Granola Helper (Audio)",
         "Granola Helper (MacOSMicAppsWithDevices)", "Granola Helper (MissionControl)",
         "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/sbin/cfprefsd",
         "/Applications/Granola Notes.app/Contents/MacOS/Granola"]


@st.composite
def process_tables(draw):
    n = draw(st.integers(min_value=0, max_value=14))
    pids = draw(st.lists(st.integers(min_value=2, max_value=5000), min_size=n, max_size=n, unique=True))
    procs = []
    for pid in pids:
        ppid = draw(st.sampled_from([1, 1, 26599] + pids))
        procs.append({"pid": pid, "ppid": ppid, "start": float(draw(st.integers(0, 10_000))),
                      "comm": draw(st.sampled_from(COMMS))})
    return procs


evidence = st.fixed_dictionaries({
    "tainted": st.booleans(),
    "skips": st.lists(st.integers(0, 20_000), max_size=5),
    "last_complete": st.integers(0, 20_000),
})


@settings(max_examples=400, deadline=None)
@given(procs=process_tables(), state=evidence, recording=st.lists(st.just("rec"), max_size=1),
       now=st.integers(0, 20_000), last_restart=st.integers(0, 20_000),
       manual=st.booleans(), force=st.booleans())
def test_plan_invariants(gh, procs, state, recording, now, last_restart, manual, force):
    d = gh.plan(procs, dict(state), recording, now, last_restart, manual=manual, force=force)
    procs_by = by_pid(procs)
    main = gh.current_main(procs)
    for pid in d["kill"]:
        p = procs_by[pid]
        # Only PPID-1 Granola helpers: never main, crashpad, the native host, or another app.
        assert p["ppid"] == 1 and gh.is_helper(p)
        assert p["comm"] != MAIN and "chrome_crashpad_handler" not in p["comm"]
        assert not p["comm"].startswith(APP + "/Contents/Resources/native-host/")
        assert p["comm"].startswith("Granola Helper") or p["comm"].startswith(APP + "/")
        if main is not None:
            assert p["start"] < main["start"] and p["ppid"] != main["pid"]
    assert len(d["kill"]) == len(set(d["kill"]))
    if d["restart"]:
        assert main is not None
        assert force or not recording
        assert manual or now - last_restart >= gh.RESTART_COOLDOWN_S
        assert d["blocked"] is None and d["reason"]
    if d["blocked"]:
        assert d["reason"] and not d["restart"]
    assert gh.plan(procs, dict(state), recording, now, last_restart, manual=manual, force=force) == d


@settings(max_examples=200, deadline=None)
@given(procs=process_tables())
def test_restart_targets_never_include_foreign_or_chrome_owned_processes(gh, procs):
    for p in gh.restart_targets(procs):
        assert p["comm"].startswith(APP + "/") or p["comm"].startswith("Granola Helper")
        assert not p["comm"].startswith(APP + "/Contents/Resources/native-host/")


crumb_strategy = st.one_of(
    st.builds(lambda ts, trig: stuck_skip(ts, trig)[1], st.integers(0, 10_000).map(float),
              st.sampled_from(["polling", "window-visibility"])),
    st.builds(lambda ts: crumb(ts, "full-sync-complete [object Object]"), st.integers(0, 10_000).map(float)),
    st.builds(lambda ts: crumb(ts, "sqlite-init-success [object Object]"), st.integers(0, 10_000).map(float)),
    st.builds(lambda ts: crumb(ts, "noise"), st.integers(0, 10_000).map(float)),
)


@settings(max_examples=300, deadline=None)
@given(crumbs=st.lists(crumb_strategy, max_size=30), since=st.integers(0, 10_000), seed=st.integers())
def test_breadcrumb_events_are_sorted_unique_bounded_and_order_free(gh, crumbs, since, seed):
    events = gh.breadcrumb_events(scope(crumbs), since)
    assert events == sorted(set(events))
    assert all(ts >= since for ts, _ in events)
    shuffled = list(crumbs)
    random.Random(seed).shuffle(shuffled)
    assert gh.breadcrumb_events(scope(shuffled), since) == events


events_strategy = st.lists(st.tuples(st.integers(0, 10_000), st.sampled_from(["sync_stuck", "sync_complete"])),
                           max_size=20)


@settings(max_examples=300, deadline=None)
@given(a=events_strategy, b=events_strategy)
def test_merge_evidence_is_idempotent_and_tick_order_free(gh, a, b):
    main = {"pid": 7, "ppid": 1, "start": 0.0, "comm": MAIN}
    once = gh.merge_evidence({}, main, a)
    twice = gh.merge_evidence(gh.merge_evidence({}, main, a), main, a)
    assert once == twice
    ab = gh.merge_evidence(gh.merge_evidence({}, main, a), main, b)
    ba = gh.merge_evidence(gh.merge_evidence({}, main, b), main, a)
    assert ab == ba


@settings(max_examples=300, deadline=None)
@given(a=events_strategy, later=st.integers(0, 20_000))
def test_a_sync_complete_never_creates_a_wedge(gh, a, later):
    main = {"pid": 7, "ppid": 1, "start": 0.0, "comm": MAIN}
    state = gh.merge_evidence({}, main, a)
    before = gh.wedged(state)
    gh.merge_evidence(state, main, [(later, "sync_complete")])
    assert gh.wedged(state) <= before


# ---------------------------------------------------------------- guard loop (all side effects faked)

class FakeWorld:
    """A process table that responds to signals and `open -g -a`, like the 2026-09-29 fix."""

    def __init__(self, gh, table, respawn_during_shutdown=True):
        self.gh = gh
        self.procs = gh.parse_ps(table)
        self.signals = []
        self.opened = 0
        self.respawn = respawn_during_shutdown
        self.clock = 2_000_000_000.0
        self.scope_data = scope()

    def kill(self, pid, sig):
        self.signals.append((pid, sig))
        target = next((p for p in self.procs if p["pid"] == pid), None)
        if target is None:
            raise ProcessLookupError(pid)
        self.procs = [p for p in self.procs if p["pid"] != pid]
        if self.respawn and target["comm"] == MAIN:
            # Observed: TERM on the wedged main briefly spawned new helpers.
            self.respawn = False
            self.procs.append({"pid": 89512, "ppid": 1, "start": self.clock, "comm": HELPER})

    def open_app(self):
        self.opened += 1
        start = self.clock
        self.procs = [p for p in self.procs if p["comm"] == NATIVE_HOST]
        self.procs += [
            {"pid": 94286, "ppid": 1, "start": start, "comm": MAIN},
            {"pid": 95612, "ppid": 94286, "start": start + 6, "comm": "Granola Helper (Storage)"},
        ]
        self.scope_data = scope(crumb(start + 16, "sqlite-init-success [object Object]"),
                                crumb(start + 16.2, "full-sync-complete [object Object]"))


class _Proxy:
    """Delegates to a real module except for the attributes set on the instance."""

    def __init__(self, real, **overrides):
        self._real = real
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture
def world(gh, tmp_path, monkeypatch):
    import os as real_os
    import subprocess as real_subprocess
    import time as real_time

    def make(table=INCIDENT_PS, assertions="", scope_data=None):
        w = FakeWorld(gh, table)
        if scope_data is not None:
            w.scope_data = scope_data
        monkeypatch.setattr(gh, "LOG", str(tmp_path / "granola-heal.log"))
        monkeypatch.setattr(gh, "STATE_DIR", str(tmp_path / "state"))
        monkeypatch.setattr(gh, "STATE", str(tmp_path / "state" / "state.json"))
        monkeypatch.setattr(gh, "LOCK", str(tmp_path / "state" / "lock"))
        # Module-local fakes: the real os/time/subprocess stay untouched for pytest itself.
        monkeypatch.setattr(gh, "os", _Proxy(real_os, kill=lambda pid, sig: w.kill(pid, sig),
                                             path=_Proxy(real_os.path, isdir=lambda path: True)))
        monkeypatch.setattr(gh, "time", _Proxy(real_time, time=lambda: w.clock,
                                               sleep=lambda s: setattr(w, "clock", w.clock + s)))

        def run(cmd, *a, **k):
            if cmd[:2] != ["/usr/bin/open", "-g"]:
                pytest.fail("unexpected subprocess %s" % cmd)
            w.open_app()
        monkeypatch.setattr(gh, "subprocess", _Proxy(real_subprocess, run=run))
        monkeypatch.setattr(gh.Guard, "procs", lambda self: [dict(p) for p in w.procs])
        monkeypatch.setattr(gh.Guard, "assertions", lambda self: assertions)
        monkeypatch.setattr(gh.Guard, "scope", lambda self: w.scope_data)
        w.notes = []
        monkeypatch.setattr(gh.Guard, "notify",
                            lambda self, state, key, msg, now: w.notes.append((key, msg)))
        w.log = tmp_path / "granola-heal.log"
        w.state = tmp_path / "state" / "state.json"
        return w
    return make


def test_tick_replays_the_incident_fix(gh, world):
    w = world()
    assert gh.Guard().run() == 0
    signalled = {pid for pid, _ in w.signals}
    assert INCIDENT_ORPHANS <= signalled
    assert 27111 not in signalled                       # Chrome's native host is never touched
    assert 89512 in signalled                           # the helper spawned during shutdown
    assert w.opened == 1
    log = w.log.read_text()
    assert "killing 4 orphaned helper(s)" in log and "VERIFIED" in log
    state = json.loads(w.state.read_text())
    assert state["main"][0] == 94286 and state["tainted"] is False and state["last_restart"] > 0
    # The next tick sees a healthy instance and does nothing.
    before = list(w.signals)
    assert gh.Guard().run() == 0
    assert w.signals == before and w.opened == 1


def test_tick_defers_restart_while_recording(gh, world, monkeypatch):
    w = world(assertions=PMSET_RECORDING.replace("94286", "7620"))
    assert gh.Guard().run() == 0
    assert {pid for pid, _ in w.signals} == INCIDENT_ORPHANS   # orphans die, the live instance stays
    assert w.opened == 0
    assert [k for k, _ in w.notes] == ["deferred"]
    state = json.loads(w.state.read_text())
    assert state["tainted"] is True
    # Recording over: the next tick restarts the tainted instance.
    monkeypatch.setattr(gh.Guard, "assertions", lambda self: "")
    assert gh.Guard().run() == 0
    assert w.opened == 1


def test_tick_restarts_a_wedged_instance_without_orphans(gh, world):
    w = world(table=HEALTHY_PS)
    main_start = gh.current_main(w.procs)["start"]
    w.scope_data = scope(stuck_skip(main_start + 3600))
    gh.Guard().run()
    assert w.opened == 0                                  # one skip is not a wedge
    w.scope_data = scope(stuck_skip(main_start + 3600 + gh.WEDGE_SPAN_S))
    w.clock = main_start + 3600 + gh.WEDGE_SPAN_S + 30
    gh.Guard().run()
    assert w.opened == 1 and "full sync stuck in progress" in w.log.read_text()


def test_fix_refuses_while_recording_without_force(gh, world, capsys):
    w = world(table=HEALTHY_PS, assertions=PMSET_RECORDING)
    assert gh.Guard(echo=True).run(manual=True) == 3
    assert w.opened == 0 and "deferred: recording" in capsys.readouterr().out
    assert gh.Guard(echo=True).run(manual=True, force=True) == 0
    assert w.opened == 1


def test_failed_verification_notifies_and_returns_1(gh, world, monkeypatch):
    w = world()
    real_open = w.open_app

    def open_without_breadcrumbs():
        real_open()
        w.scope_data = scope()
    monkeypatch.setattr(w, "open_app", open_without_breadcrumbs)
    assert gh.Guard().run() == 1
    assert "FAILED: no sqlite-init-success" in w.log.read_text()
    assert [k for k, _ in w.notes] == ["failed"]


def test_dry_run_changes_nothing(gh, world):
    w = world()
    assert gh.Guard(dry=True).run() == 0
    assert w.signals == [] and w.opened == 0
    assert not w.log.exists() and not w.state.exists()


def test_signals_are_term_then_kill(gh, world, monkeypatch):
    w = world()
    stubborn = {91380}
    real_kill = w.kill

    def kill(pid, sig):
        if pid in stubborn and sig == signal.SIGTERM:
            w.signals.append((pid, sig))
            return
        real_kill(pid, sig)
    monkeypatch.setattr(w, "kill", kill)
    assert gh.Guard().terminate([91380]) == []
    assert w.signals == [(91380, signal.SIGTERM), (91380, signal.SIGKILL)]
