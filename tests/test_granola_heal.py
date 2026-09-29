"""Tests for dotfiles/bin/granola-heal: pure logic, plus the guard loop with every side effect faked.

Fixtures copy the process tables, updater log timeline and breadcrumb shapes observed
on 2026-09-29. PIDs and start times are real; user, meeting and document IDs are
synthetic. `ps` runs with TZ=UTC0, so the lstart strings below are UTC.
"""
import calendar
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import random
import signal
import time as real_time

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
SHIPIT = APP + "/Contents/Frameworks/Squirrel.framework/Resources/ShipIt"
CLI = APP + "/Contents/Resources/bin/granola"
UID = 501


@pytest.fixture(scope="module")
def gh():
    loader = importlib.machinery.SourceFileLoader("granola_heal", str(SCRIPT))
    spec = importlib.util.spec_from_loader("granola_heal", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def row(pid, ppid, lstart, comm, uid=UID):
    return f"{uid:5d} {pid:5d} {ppid:5d} {lstart}     {comm}"


def utc(lstart):
    return float(calendar.timegm(real_time.strptime(lstart, "%a %b %d %H:%M:%S %Y")))


# `ps -axo uid=,pid=,ppid=,lstart=,comm=` just before the 2026-09-29 fix (UTC).
INCIDENT_PS = "\n".join([
    row(7620, 1, "Mon Sep 28 21:09:02 2026", MAIN),
    row(7956, 1, "Mon Sep 28 21:09:06 2026", CRASHPAD),
    row(7957, 7620, "Mon Sep 28 21:09:06 2026", HELPER),
    row(7960, 7620, "Mon Sep 28 21:09:06 2026", RENDERER),
    row(7961, 7620, "Mon Sep 28 21:09:06 2026", "Granola Helper (MacOSMicAppsWithDevices)"),
    row(7964, 7620, "Mon Sep 28 21:09:06 2026", RENDERER),
    row(7970, 7620, "Mon Sep 28 21:09:06 2026", "Granola Helper (MissionControl)"),
    row(8095, 7620, "Mon Sep 28 21:09:07 2026", "Granola Helper (Storage)"),
    row(27111, 26599, "Mon Sep 28 23:08:57 2026", NATIVE_HOST),
    row(35816, 7620, "Mon Sep 28 21:13:02 2026", "Granola Helper (Audio)"),
    row(44814, 1, "Thu Sep 24 20:35:05 2026", "Granola Helper (Audio)"),
    row(91183, 1, "Thu Sep 24 19:50:48 2026", "Granola Helper (MacOSMicAppsWithDevices)"),
    row(91190, 1, "Thu Sep 24 19:50:48 2026", "Granola Helper (MissionControl)"),
    row(91380, 1, "Thu Sep 24 19:50:49 2026", "Granola Helper (Storage)"),
    row(4242, 1, "Thu Sep 24 13:00:00 2026", "/usr/sbin/cfprefsd"),
    row(5151, 1, "Thu Sep 24 19:00:00 2026", "Granola Helper (Storage)", uid=502),  # another user
])
INCIDENT_ORPHANS = {44814, 91183, 91190, 91380}
INCIDENT_NOW = utc("Tue Sep 29 16:17:00 2026")

# The relaunched, healthy instance a few seconds after `open -g -a Granola`.
HEALTHY_PS = "\n".join([
    row(94286, 1, "Tue Sep 29 16:18:56 2026", MAIN),
    row(95219, 1, "Tue Sep 29 16:19:01 2026", CRASHPAD),
    row(95277, 94286, "Tue Sep 29 16:19:01 2026", RENDERER),
    row(95281, 94286, "Tue Sep 29 16:19:01 2026", "Granola Helper (MacOSMicAppsWithDevices)"),
    row(95612, 94286, "Tue Sep 29 16:19:02 2026", "Granola Helper (Storage)"),
    row(97524, 94286, "Tue Sep 29 16:19:11 2026", "Granola Helper (ThirdPartyMeetingAutomation)"),
    row(93271, 26599, "Tue Sep 29 16:18:52 2026", NATIVE_HOST),
])
HEALTHY_MAIN_START = utc("Tue Sep 29 16:18:56 2026")


def crumb(ts, message, *args):
    return {"timestamp": ts, "category": "console", "level": "info", "message": message,
            "data": {"arguments": list(args), "logger": "console"}}


def stuck_pair(ts, trigger="polling"):
    """The plain-text skip and its structured twin, logged in the same second."""
    return [
        crumb(ts, "Full sync already in progress, skipping", "Full sync already in progress, skipping"),
        crumb(ts + 0.001, "full-sync-skipped [object Object]", "full-sync-skipped",
              {"user_id": "user-synthetic", "trigger": trigger, "reason": "sync-already-in-progress"}),
    ]


def tx(ts, text="transcription-latency-assembly-partial"):
    return crumb(ts, "2026-09-29T16:19:20.617Z \x1b[32m%s\x1b[0m {}" % text)


def scope(*crumbs):
    flat = []
    for c in crumbs:
        flat.extend(c if isinstance(c, list) else [c])
    return {"scope": {"breadcrumbs": flat}, "event": {}}


def by_pid(procs):
    return {p["pid"]: p for p in procs}


def P(pid, ppid, start, comm):
    return {"pid": pid, "ppid": ppid, "start": float(start), "comm": comm}


# ---------------------------------------------------------------- parse_ps

def test_parse_ps_reads_the_incident_table_as_utc(gh):
    procs = gh.parse_ps(INCIDENT_PS)
    assert len(procs) == 16
    p = by_pid(procs)
    assert p[91380]["comm"] == "Granola Helper (Storage)"
    assert p[7964]["comm"] == RENDERER
    assert p[7620]["start"] == 1790629742.0            # 2026-09-28 21:09:02 UTC, independent of $TZ


def test_parse_ps_filters_other_users(gh):
    assert 5151 in by_pid(gh.parse_ps(INCIDENT_PS))
    assert 5151 not in by_pid(gh.parse_ps(INCIDENT_PS, uid=UID))


def test_parse_ps_skips_malformed_rows_and_handles_padded_days(gh):
    text = "\n".join([
        "garbage",
        "  501 12 abc Tue Sep 29 12:00:00 2026 x",
        "  501 13 1 Tue Sep 99 12:00:00 2026 bad-date",
        f"  501 14 1 Thu Oct  1 09:05:00 2026 {MAIN}",
        "",
    ])
    procs = gh.parse_ps(text)
    assert [p["pid"] for p in procs] == [14]
    assert procs[0]["start"] == utc("Thu Oct 1 09:05:00 2026")


# ---------------------------------------------------------------- classification

def test_incident_orphans_are_exactly_the_four_stale_helpers(gh):
    procs = gh.parse_ps(INCIDENT_PS, uid=UID)
    assert {p["pid"] for p in gh.select_orphans(procs, INCIDENT_NOW)} == INCIDENT_ORPHANS


def test_orphans_wait_until_the_new_main_has_run_for_the_grace_period(gh):
    procs = gh.parse_ps(INCIDENT_PS, uid=UID)
    main = gh.current_main(procs)
    assert gh.select_orphans(procs, main["start"] + gh.ORPHAN_GRACE_S - 1) == []
    assert {p["pid"] for p in gh.select_orphans(procs, main["start"] + gh.ORPHAN_GRACE_S)} == INCIDENT_ORPHANS


def test_healthy_instance_has_no_orphans(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    assert gh.select_orphans(procs, now=HEALTHY_MAIN_START + 10_000) == []
    assert gh.count_storage(procs) == 1


def test_non_helpers_are_never_helpers(gh):
    for comm in (CRASHPAD, NATIVE_HOST, SHIPIT, CLI, MAIN, "/usr/sbin/cfprefsd",
                 "/Applications/Granola Notes.app/Contents/MacOS/Granola Helper"):
        assert not gh.is_helper(P(9, 1, 0, comm)), comm
    for comm in (HELPER, RENDERER, "Granola Helper (Storage)"):
        assert gh.is_helper(P(9, 1, 0, comm)), comm


def test_without_main_orphans_wait_out_the_grace_period(gh):
    young = P(91380, 1, 5_000, "Granola Helper (Storage)")
    assert gh.select_orphans([young], now=5_000 + gh.ORPHAN_GRACE_S - 1) == []
    assert gh.select_orphans([young], now=5_000 + gh.ORPHAN_GRACE_S) == [young]


def test_ppid1_helper_newer_than_main_is_left_alone(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    odd = P(99999, 1, HEALTHY_MAIN_START + 60, "Granola Helper (Storage)")
    assert gh.select_orphans(procs + [odd], now=HEALTHY_MAIN_START + 10_000) == []


def test_restart_targets_are_the_instance_only(gh):
    procs = gh.parse_ps(INCIDENT_PS, uid=UID) + [P(50895, 1, 0, SHIPIT), P(61000, 7620, 0, CLI)]
    targets = {p["pid"] for p in gh.restart_targets(procs)}
    assert {7620, 7956, 8095, 35816} | INCIDENT_ORPHANS <= targets
    assert not targets & {27111, 4242, 50895, 61000}


def test_current_main_picks_the_newest_not_the_highest_pid(gh):
    procs = [P(90000, 1, 100, MAIN), P(11, 1, 200, MAIN)]
    assert gh.current_main(procs)["pid"] == 11
    assert gh.current_main([]) is None


# ---------------------------------------------------------------- ShipIt (Squirrel updater)

# ShipIt_stderr.log, 2026-09-25: install request 15:10:33 local, install ran 16:21:10-16:31:28 with no main.
SHIPIT_925 = P(48415, 1, utc("Fri Sep 25 19:10:33 2026"), SHIPIT)


def test_shipit_mid_install_is_never_an_orphan(gh):
    now = utc("Fri Sep 25 20:25:00 2026")
    d = gh.plan([SHIPIT_925], wedge=False, recording=[], now=now, last_restart=0)
    assert d["kill"] == [] and not d["restart"]


def test_shipit_next_to_a_fresh_main_is_left_alone_and_blocks_restarts(gh):
    # 2026-09-28 21:07 UTC: ShipIt 50895 (submitted 20:31:43) waits while a main launches.
    procs = [P(50895, 1, utc("Mon Sep 28 20:31:43 2026"), SHIPIT), P(92507, 1, utc("Mon Sep 28 21:07:00 2026"), MAIN)]
    now = utc("Mon Sep 28 21:30:00 2026")
    d = gh.plan(procs, wedge=True, recording=[], now=now, last_restart=0)
    assert d["kill"] == [] and not d["restart"] and "ShipIt" in d["blocked"]
    assert gh.plan(procs, wedge=True, recording=[], now=now, last_restart=0, manual=True, force=True)["restart"]


def test_verify_restart_ignores_a_respawned_shipit(gh):
    procs = gh.parse_ps(HEALTHY_PS) + [P(94132, 1, HEALTHY_MAIN_START - 1, SHIPIT)]
    ok, detail = gh.verify_restart(procs, [(0, "sqlite_ok")], HEALTHY_MAIN_START - 5, HEALTHY_MAIN_START + 20)
    assert ok, detail


# ---------------------------------------------------------------- breadcrumbs

def test_breadcrumbs_classify_the_observed_messages(gh):
    t = 1_790_000_000.0
    s = scope(
        stuck_pair(t),
        crumb(t + 1, "full-sync-skipped [object Object]", "full-sync-skipped", {"reason": "window-visible-sync-skipped"}),
        crumb(t + 2, "sqlite-init-start [object Object]", "sqlite-init-start", {}),
        crumb(t + 3, "sqlite-init-success [object Object]", "sqlite-init-success", {}),
        crumb(t + 4, "full-sync-complete [object Object]", "full-sync-complete", {"durationMs": 1505.7}),
        tx(t + 5),
        crumb(t + 6, "calendar-event-disabled-transcription-check-skipped [object Object]"),
        crumb(t + 7, 'x \x1b[32maudio-capture-state\x1b[0m {"active":false,"microphoneCapture":"starting"}'),
        crumb(t + 8, "x \x1b[32mtranscription-session-stop\x1b[0m {}"),
        {"timestamp": "bad", "message": "full-sync-complete"},
        {"message": "full-sync-complete"},
        {"timestamp": float("nan"), "message": "full-sync-complete"},
        {"timestamp": float("inf"), "message": "full-sync-complete"},
        {"timestamp": True, "message": "full-sync-complete"},
        {"timestamp": t + 9, "message": "full-sync-skipped", "data": ["not", "a", "dict"]},
        "not-a-dict",
        {"timestamp": t + 7, "message": 42},
    )
    assert gh.breadcrumb_events(s, since=0) == [
        (int(t), "sync_stuck"),
        (int(t) + 3, "sqlite_ok"),
        (int(t) + 4, "sync_complete"),
        (int(t) + 5, "transcribing"),
        (int(t) + 8, "transcription_stopped"),
    ]
    assert gh.breadcrumb_events(s, since=t + 3.5)[0] == (int(t) + 4, "sync_complete")


@pytest.mark.parametrize("which", [0, 1])
def test_each_skip_form_alone_is_detected(gh, which):
    assert gh.breadcrumb_events(scope(stuck_pair(100.0)[which]), 0) == [(100, "sync_stuck")]


@pytest.mark.parametrize("text", [
    "transcription-latency-assembly-final", "transcription-first-buffer-sent-timestamp",
    'audio-capture-state\x1b[0m {"active":true,"caller":"x"}',
    'transcription-handler-state-change\x1b[0m {"state":"active","source":"microphone"}',
])
def test_each_transcribing_marker(gh, text):
    assert gh.breadcrumb_events(scope(tx(100.0, text)), 0) == [(100, "transcribing")]


def test_inactive_handler_state_is_not_transcribing(gh):
    s = scope(tx(100.0, 'transcription-handler-state-change\x1b[0m {"state":"inactive"}'))
    assert gh.breadcrumb_events(s, 0) == []


@pytest.mark.parametrize("bad", [None, {}, {"scope": None}, {"scope": {"breadcrumbs": None}}, [], "x",
                                 {"scope": {"breadcrumbs": {"a": 1}}}])
def test_malformed_scopes_yield_nothing(gh, bad):
    assert gh.breadcrumb_events(bad, since=0) == []


# ---------------------------------------------------------------- wedge evidence

MAIN_X = P(7620, 1, 1_000_000, MAIN)


def test_the_incident_breadcrumbs_read_as_a_wedge_after_awake_time(gh):
    t = MAIN_X["start"] + 18 * 3600          # 11:09:54 skip, seen by a tick
    state = gh.merge_evidence({}, MAIN_X, gh.breadcrumb_events(scope(stuck_pair(t)), 0), now_mono=500.0)
    assert not gh.wedged(state, now=t + 60, now_mono=560.0)
    # The 11:09 skip is evicted from the buffer by 11:57; its evidence persists.
    gh.merge_evidence(state, MAIN_X, gh.breadcrumb_events(scope(stuck_pair(t + 2843, "window-visibility")), 0),
                      now_mono=500.0 + 2843)
    assert gh.wedged(state, now=t + 2843, now_mono=500.0 + 2843)


def test_sleep_does_not_count_toward_a_wedge(gh):
    t = MAIN_X["start"] + 3600
    state = gh.merge_evidence({}, MAIN_X, [(int(t), "sync_stuck")], now_mono=100.0)
    # Lid closed for 8 hours: wall clock jumps, monotonic time barely moves.
    assert not gh.wedged(state, now=t + 8 * 3600, now_mono=160.0)
    assert gh.wedged(state, now=t + 8 * 3600 + gh.WEDGE_AWAKE_S, now_mono=100.0 + gh.WEDGE_AWAKE_S)


def test_a_completed_sync_clears_wedge_evidence(gh):
    t = MAIN_X["start"] + 3600
    state = gh.merge_evidence({}, MAIN_X, [(int(t), "sync_stuck")], now_mono=0.0)
    assert gh.wedged(state, t + 5000, 5000.0)
    gh.merge_evidence(state, MAIN_X, [(int(t) + 1, "sync_complete")], now_mono=5000.0)
    assert not gh.wedged(state, t + 5000, 5000.0) and state["skips"] == []


def test_sqlite_ok_does_not_clear_skips(gh):
    state = gh.merge_evidence({}, MAIN_X, [(10, "sync_stuck"), (20, "sqlite_ok")], now_mono=0.0)
    assert [s[0] for s in state["skips"]] == [10]


def test_many_frequent_skips_keep_the_earliest(gh):
    events = [(10 * i, "sync_stuck") for i in range(1, 200)]           # every 10 s for 33 min
    state = gh.merge_evidence({}, MAIN_X, [], now_mono=0.0)
    for i, ev in enumerate(events):
        gh.merge_evidence(state, MAIN_X, [ev], now_mono=float(10 * i))
    assert len(state["skips"]) == gh.MAX_SKIPS_KEPT and state["skips"][0][0] == 10
    assert gh.wedged(state, now=2000.0, now_mono=1990.0)


def test_new_instance_resets_evidence(gh):
    state = gh.merge_evidence({}, MAIN_X, [(100, "sync_stuck")], now_mono=0.0)
    other = dict(MAIN_X, pid=7621, start=MAIN_X["start"] + 10)
    gh.merge_evidence(state, other, [], now_mono=0.0)
    assert state["skips"] == [] and state["main"] == [7621, other["start"]]


def test_corrupt_state_skips_are_ignored(gh):
    state = {"main": [MAIN_X["pid"], MAIN_X["start"]], "skips": [[1, "x"], "junk", [2], [3, 4]]}
    gh.merge_evidence(state, MAIN_X, [], now_mono=0.0)
    assert state["skips"] == [[3, 4]]


# ---------------------------------------------------------------- recording

PMSET_RECORDING = """Assertion status system-wide:
   PreventUserIdleDisplaySleep    1
Listed by owning process:
   pid 94286(Granola): [0x000689c40005842a] 00:02:25 NoDisplaySleepAssertion named: "Electron"
   pid 512(Google Chrome): [0x0001] 00:30:00 NoDisplaySleepAssertion named: "WebRTC has active PeerConnections"
"""
PMSET_IDLE = """Listed by owning process:
   pid 512(Google Chrome): [0x0001] 00:30:00 NoDisplaySleepAssertion named: "WebRTC"
   pid 88(powerd): [0x0002] 01:00:00 PreventUserIdleSystemSleep named: "Powerd"
"""


def test_recording_from_the_observed_assertion(gh):
    assert gh.recording_signals(PMSET_RECORDING, [], now=0) == ["pid 94286 holds NoDisplaySleepAssertion"]
    assert gh.recording_signals(PMSET_IDLE, [], now=0) == []


@pytest.mark.parametrize("kind", ["NoDisplaySleepAssertion", "PreventUserIdleDisplaySleep",
                                  "PreventUserIdleSystemSleep", "NoIdleSleepAssertion"])
@pytest.mark.parametrize("name", ["Granola", "Granola Helper (Audio)"])
def test_every_assertion_kind_and_process_name(gh, kind, name):
    line = '   pid 42(%s): [0x1] 00:00:10 %s named: "x"' % (name, kind)
    assert gh.recording_signals(line, [], 0) == ["pid 42 holds %s" % kind]


def test_recording_state_unknown_fails_closed(gh):
    assert gh.recording_signals(None, [], 0) == ["recording state unknown (pmset failed)"]
    assert gh.recording_signals("", [], 0, "unreadable") == ["recording state unknown (breadcrumbs unreadable)"]
    assert gh.recording_signals("", [], 0, "missing") == []


def test_recording_from_breadcrumbs_uses_the_newest_and_respects_stops(gh):
    now = 10_000
    stale_and_fresh = [(now - 3000, "transcribing"), (now - 21, "transcribing")]
    assert gh.recording_signals("", stale_and_fresh, now) == ["transcription breadcrumb 21s ago"]
    assert gh.recording_signals("", [(now - 3000, "transcribing")], now) == []
    stopped = [(now - 30, "transcribing"), (now - 27, "transcription_stopped")]
    assert gh.recording_signals("", stopped, now) == []
    restarted = stopped + [(now - 5, "transcribing")]
    assert gh.recording_signals("", restarted, now)
    assert gh.recording_signals("", [(now - gh.RECORDING_RECENT_S, "transcribing")], now) == []


# ---------------------------------------------------------------- plan

def test_plan_kills_orphans_but_does_not_restart_for_them(gh):
    d = gh.plan(gh.parse_ps(INCIDENT_PS, uid=UID), False, [], INCIDENT_NOW, 0)
    assert set(d["kill"]) == INCIDENT_ORPHANS and not d["restart"] and d["reason"] is None


def test_plan_restarts_a_wedge(gh):
    d = gh.plan(gh.parse_ps(INCIDENT_PS, uid=UID), True, [], INCIDENT_NOW, 0)
    assert d["restart"] and d["reason"] == "full sync stuck in progress"


def test_plan_defers_while_recording_but_still_kills_orphans(gh):
    d = gh.plan(gh.parse_ps(INCIDENT_PS, uid=UID), True, ["pid 7620 holds NoDisplaySleepAssertion"], INCIDENT_NOW, 0)
    assert set(d["kill"]) == INCIDENT_ORPHANS and not d["restart"] and d["blocked"].startswith("recording")


def test_plan_cooldown_applies_to_automatic_only(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    now = HEALTHY_MAIN_START + 10_000
    d = gh.plan(procs, True, [], now, last_restart=now - 60)
    assert not d["restart"] and d["blocked"].startswith("cooldown")
    assert gh.plan(procs, False, [], now, last_restart=now - 60, manual=True)["restart"]


def test_plan_recording_blocker_wins_over_cooldown(gh):
    now = HEALTHY_MAIN_START + 10_000
    d = gh.plan(gh.parse_ps(HEALTHY_PS), True, ["rec"], now, last_restart=now - 60)
    assert d["blocked"].startswith("recording")


def test_plan_manual_refuses_recording_unless_forced(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    rec = ["pid 94286 holds NoDisplaySleepAssertion"]
    assert not gh.plan(procs, False, rec, 2e9, 0, manual=True)["restart"]
    assert gh.plan(procs, False, rec, 2e9, 0, manual=True, force=True)["restart"]


def test_plan_healthy_instance_does_nothing(gh):
    assert gh.plan(gh.parse_ps(HEALTHY_PS), False, [], 2e9, 0) == {
        "kill": [], "restart": False, "reason": None, "blocked": None}


def test_plan_without_main_never_restarts(gh):
    procs = [p for p in gh.parse_ps(INCIDENT_PS, uid=UID) if p["comm"] != MAIN]
    d = gh.plan(procs, True, [], INCIDENT_NOW, 0, manual=True, force=True)
    assert not d["restart"] and set(d["kill"]) == INCIDENT_ORPHANS


# ---------------------------------------------------------------- verify_restart / relaunch_due

def test_verify_restart_accepts_the_observed_healthy_relaunch(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    ok, detail = gh.verify_restart(procs, [(int(HEALTHY_MAIN_START) + 16, "sqlite_ok")],
                                   HEALTHY_MAIN_START - 5, HEALTHY_MAIN_START + 20)
    assert ok, detail


@pytest.mark.parametrize("mutate,events,status,expect", [
    (lambda ps: [p for p in ps if p["comm"] != MAIN], [(0, "sqlite_ok")], "ok", "no new Granola main"),
    (lambda ps: ps + [dict(ps[4], pid=1)], [(0, "sqlite_ok")], "ok", "more than one Storage"),
    (lambda ps: ps + [P(5, 1, 0, "Granola Helper (Audio)")], [(0, "sqlite_ok")], "ok", "orphaned helpers"),
    (lambda ps: ps, [], "ok", "no sqlite-init-success"),
    (lambda ps: ps, [], "unreadable", "no sqlite-init-success"),
])
def test_verify_restart_failures(gh, mutate, events, status, expect):
    procs = mutate(gh.parse_ps(HEALTHY_PS))
    ok, detail = gh.verify_restart(procs, events, HEALTHY_MAIN_START - 5, HEALTHY_MAIN_START + 60, status)
    assert not ok and expect in detail


def test_verify_restart_without_breadcrumb_file_uses_processes(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    assert not gh.verify_restart(procs, [], HEALTHY_MAIN_START - 5, HEALTHY_MAIN_START + 10, "missing")[0]
    ok, detail = gh.verify_restart(procs, [], HEALTHY_MAIN_START - 5, HEALTHY_MAIN_START + 30, "missing")
    assert ok and "process checks only" in detail


def test_verify_restart_rejects_the_old_instance(gh):
    procs = gh.parse_ps(HEALTHY_PS)
    ok, detail = gh.verify_restart(procs, [(0, "sqlite_ok")], HEALTHY_MAIN_START + 60, HEALTHY_MAIN_START + 90)
    assert not ok and "no new Granola main" in detail


def test_relaunch_due(gh):
    assert gh.relaunch_due({"attempts": 0, "last_attempt": 0}, now=100)
    assert not gh.relaunch_due({"attempts": 1, "last_attempt": 90}, now=100)
    assert gh.relaunch_due({"attempts": 1, "last_attempt": 40}, now=100)
    assert not gh.relaunch_due({"attempts": gh.RELAUNCH_ATTEMPTS, "last_attempt": 0}, now=10_000)
    assert not gh.relaunch_due(None, now=100)


# ---------------------------------------------------------------- properties

COMMS = [MAIN, HELPER, RENDERER, CRASHPAD, NATIVE_HOST, SHIPIT, CLI, "Granola Helper (Storage)",
         "Granola Helper (Audio)", "Granola Helper (MacOSMicAppsWithDevices)",
         "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/sbin/cfprefsd",
         "/Applications/Granola Notes.app/Contents/MacOS/Granola"]


@st.composite
def process_tables(draw):
    n = draw(st.integers(min_value=0, max_value=14))
    pids = draw(st.lists(st.integers(min_value=2, max_value=5000), min_size=n, max_size=n, unique=True))
    procs = []
    for pid in pids:
        ppid = draw(st.sampled_from([1, 1, 26599] + pids))
        procs.append(P(pid, ppid, draw(st.integers(0, 10_000)), draw(st.sampled_from(COMMS))))
    return procs


def expected_main(procs):
    mains = [p for p in procs if p["comm"] == MAIN]
    if not mains:
        return None
    best = mains[0]
    for p in mains[1:]:
        if p["start"] > best["start"] or (p["start"] == best["start"] and p["pid"] > best["pid"]):
            best = p
    return best


@settings(max_examples=500, deadline=None)
@given(procs=process_tables(), wedge=st.booleans(), recording=st.lists(st.just("rec"), max_size=1),
       now=st.integers(0, 20_000), last_restart=st.integers(0, 20_000),
       manual=st.booleans(), force=st.booleans())
def test_plan_invariants(gh, procs, wedge, recording, now, last_restart, manual, force):
    d = gh.plan(procs, wedge, recording, now, last_restart, manual=manual, force=force)
    procs_by = by_pid(procs)
    main = expected_main(procs)
    assert gh.current_main(procs) == main
    for pid in d["kill"]:
        p = procs_by[pid]
        assert p["ppid"] == 1
        assert p["comm"].startswith("Granola Helper") or p["comm"].startswith(APP + "/Contents/Frameworks/Granola Helper")
        if main is not None:
            assert p["start"] < main["start"] and now - main["start"] >= gh.ORPHAN_GRACE_S
        else:
            assert now - p["start"] >= gh.ORPHAN_GRACE_S
    assert len(d["kill"]) == len(set(d["kill"]))
    if d["restart"]:
        assert main is not None and d["blocked"] is None and d["reason"]
        assert force or not recording
        assert force or not any(p["comm"] == SHIPIT for p in procs)
        assert manual or now - last_restart >= gh.RESTART_COOLDOWN_S
        assert manual or wedge
    if d["blocked"]:
        assert d["reason"] and not d["restart"]
    assert gh.plan(procs, wedge, recording, now, last_restart, manual=manual, force=force) == d


@settings(max_examples=300, deadline=None)
@given(procs=process_tables())
def test_restart_targets_are_only_the_instance(gh, procs):
    for p in gh.restart_targets(procs):
        assert p["comm"] in (MAIN, CRASHPAD) or gh.is_helper(p)
        assert p["comm"] not in (SHIPIT, CLI, NATIVE_HOST)


crumb_strategy = st.one_of(
    st.builds(lambda ts, trig, which: stuck_pair(ts, trig)[which], st.integers(0, 10_000).map(float),
              st.sampled_from(["polling", "window-visibility"]), st.integers(0, 1)),
    st.builds(lambda ts: crumb(ts, "full-sync-complete [object Object]"), st.integers(0, 10_000).map(float)),
    st.builds(lambda ts: crumb(ts, "sqlite-init-success [object Object]"), st.integers(0, 10_000).map(float)),
    st.builds(lambda ts: tx(ts), st.integers(0, 10_000).map(float)),
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
                           max_size=80)


@settings(max_examples=300, deadline=None)
@given(a=events_strategy, b=events_strategy, m1=st.floats(0, 1e6), m2=st.floats(0, 1e6))
def test_merge_evidence_is_idempotent_and_its_skip_set_is_order_free(gh, a, b, m1, m2):
    once = gh.merge_evidence({}, MAIN_X, a, m1)
    assert gh.merge_evidence(json.loads(json.dumps(once)), MAIN_X, a, m1) == once
    ab = gh.merge_evidence(gh.merge_evidence({}, MAIN_X, a, m1), MAIN_X, b, m2)
    ba = gh.merge_evidence(gh.merge_evidence({}, MAIN_X, b, m2), MAIN_X, a, m1)
    assert ab["last_complete"] == ba["last_complete"]
    if len(ab["skips"]) < gh.MAX_SKIPS_KEPT:
        assert [s[0] for s in ab["skips"]] == [s[0] for s in ba["skips"]]
    assert all(s[0] > ab["last_complete"] for s in ab["skips"])
    assert len(ab["skips"]) <= gh.MAX_SKIPS_KEPT


@settings(max_examples=300, deadline=None)
@given(a=events_strategy, later=st.integers(0, 20_000), now=st.integers(0, 40_000), mono=st.floats(0, 1e5))
def test_a_sync_complete_never_creates_a_wedge(gh, a, later, now, mono):
    state = gh.merge_evidence({}, MAIN_X, a, 0.0)
    before = gh.wedged(state, now, mono)
    gh.merge_evidence(state, MAIN_X, [(later, "sync_complete")], mono)
    assert gh.wedged(state, now, mono) <= before


@settings(max_examples=300, deadline=None)
@given(a=events_strategy, now=st.integers(0, 40_000), mono=st.floats(0, 1e5),
       dt=st.integers(0, 10_000), dm=st.floats(0, 1e4))
def test_wedge_is_monotone_in_time_without_new_events(gh, a, now, mono, dt, dm):
    state = gh.merge_evidence({}, MAIN_X, a, 0.0)
    if gh.wedged(state, now, mono):
        assert gh.wedged(state, now + dt, mono + dm)


# ---------------------------------------------------------------- guard loop (all side effects faked)

class _Proxy:
    """Delegates to a real module except for the attributes set on the instance."""

    def __init__(self, real, **overrides):
        self._real = real
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(self._real, name)


class FakeWorld:
    """A process table that responds to signals and `open -g -a`, like the 2026-09-29 fix."""

    def __init__(self, gh, procs, clock):
        self.gh = gh
        self.procs = [dict(p) for p in procs]
        self.signals = []
        self.opened = 0
        self.open_rc = 0
        self.respawn = True
        self.immune = set()               # pids that ignore every signal
        self.reuse = {}                   # pid -> replacement process after SIGTERM
        self.clock = clock
        self.mono = 1000.0
        self.scope_data = scope()
        self.scope_status = "ok"
        self.assertions = ""
        self.osascript = []
        self.new_main_pid = 94286

    def kill(self, pid, sig):
        self.signals.append((pid, sig))
        target = next((p for p in self.procs if p["pid"] == pid), None)
        if target is None:
            raise ProcessLookupError(pid)
        if pid in self.immune:
            return
        self.procs = [p for p in self.procs if p["pid"] != pid]
        if pid in self.reuse:
            self.procs.append(self.reuse.pop(pid))
        if self.respawn and target["comm"] == MAIN:
            # Observed: TERM on the wedged main briefly spawned new helpers.
            self.respawn = False
            self.procs.append(P(89512, target["pid"], self.clock, HELPER))

    def advance(self, s):
        self.clock += s
        self.mono += s

    def open_app(self):
        self.opened += 1
        if self.open_rc != 0:
            return self.open_rc
        start = float(int(self.clock))
        self.procs = [p for p in self.procs if p["comm"] in (NATIVE_HOST, SHIPIT) or p["pid"] in self.immune]
        self.procs += [P(self.new_main_pid, 1, start, MAIN),
                       P(95612, self.new_main_pid, start + 6, "Granola Helper (Storage)")]
        old = (self.scope_data or {}).get("scope", {}).get("breadcrumbs", []) if self.scope_data else []
        self.scope_data = scope(old, crumb(start + 16, "sqlite-init-success [object Object]"),
                                crumb(start + 16.2, "full-sync-complete [object Object]"))
        return 0


@pytest.fixture
def world(gh, tmp_path, monkeypatch):
    import os as real_os
    import subprocess as real_subprocess

    def make(procs=None, clock=INCIDENT_NOW):
        w = FakeWorld(gh, gh.parse_ps(INCIDENT_PS, uid=UID) if procs is None else procs, clock)
        monkeypatch.setattr(gh, "LOG", str(tmp_path / "granola-heal.log"))
        monkeypatch.setattr(gh, "STATE_DIR", str(tmp_path / "state"))
        monkeypatch.setattr(gh, "STATE", str(tmp_path / "state" / "state.json"))
        monkeypatch.setattr(gh, "LOCK", str(tmp_path / "state" / "lock"))
        # Module-local fakes: the real os/time/subprocess stay untouched for pytest itself.
        monkeypatch.setattr(gh, "os", _Proxy(real_os, kill=lambda pid, sig: w.kill(pid, sig),
                                             path=_Proxy(real_os.path, isdir=lambda path: True)))
        monkeypatch.setattr(gh, "time", _Proxy(real_time, time=lambda: w.clock, monotonic=lambda: w.mono,
                                               sleep=w.advance))

        class Done:
            def __init__(self, rc):
                self.returncode = rc

        def run(cmd, *a, **k):
            if cmd[:3] == ["/usr/bin/open", "-g", "-a"]:
                return Done(w.open_app())
            if cmd[0] == "/usr/bin/osascript":
                w.osascript.append(cmd)
                return Done(0)
            pytest.fail("unexpected subprocess %s" % cmd)
        monkeypatch.setattr(gh, "subprocess", _Proxy(real_subprocess, run=run))
        monkeypatch.setattr(gh.Guard, "procs", lambda self: [dict(p) for p in w.procs])
        monkeypatch.setattr(gh.Guard, "assertions", lambda self: w.assertions)
        monkeypatch.setattr(gh.Guard, "scope", lambda self: (w.scope_data, w.scope_status))
        w.log = tmp_path / "granola-heal.log"
        w.state = tmp_path / "state" / "state.json"
        w.notes = lambda: [c[2] for c in w.osascript]
        return w
    return make


def wedge_world(world, gh, **kw):
    """The incident table with the 11:09 and 11:57 stuck skips already observed."""
    w = world(**kw)
    main = gh.current_main(w.procs)
    w.scope_data = scope(stuck_pair(w.clock - 3000), stuck_pair(w.clock - 1200, "window-visibility"))
    gh.Guard().run()                         # first tick observes the skips: kills orphans, no wedge yet
    w.advance(gh.WEDGE_AWAKE_S)
    return w, main


def test_first_tick_kills_orphans_only(gh, world):
    w = world()
    assert gh.Guard().run() == 0
    assert {pid for pid, _ in w.signals} == INCIDENT_ORPHANS
    assert w.opened == 0
    assert "killing 4 orphaned helper(s)" in w.log.read_text()


def test_wedge_restart_replays_the_incident_fix(gh, world):
    w, _ = wedge_world(world, gh)
    assert gh.Guard().run() == 0
    signalled = {pid for pid, _ in w.signals}
    assert 27111 not in signalled and 4242 not in signalled     # Chrome's host and other apps untouched
    assert {7620, 7956, 8095, 89512} <= signalled                # incl. the helper spawned during shutdown
    assert w.opened == 1
    log = w.log.read_text()
    assert "restarting Granola: full sync stuck in progress" in log and "VERIFIED" in log
    state = json.loads(w.state.read_text())
    assert state["main"][0] == 94286 and state["skips"] == [] and "relaunch_pending" not in state
    assert state["last_restart"] > 0
    before = list(w.signals)
    w.advance(60)
    assert gh.Guard().run() == 0                                 # healthy now: nothing happens
    assert w.signals == before and w.opened == 1


def test_wedge_restart_defers_while_recording(gh, world):
    w, _ = wedge_world(world, gh)
    w.assertions = PMSET_RECORDING.replace("94286", "7620")
    assert gh.Guard().run() == 0
    assert w.opened == 0 and len(w.notes()) == 1 and "recording" in w.notes()[0]
    w.advance(60)
    gh.Guard().run()
    assert len(w.notes()) == 1                                   # rate-limited to one an hour
    w.assertions = ""
    w.advance(60)
    gh.Guard().run()
    assert w.opened == 1


def test_pmset_failure_blocks_a_restart(gh, world):
    w, _ = wedge_world(world, gh)
    w.assertions = None
    gh.Guard().run()
    assert w.opened == 0 and "recording state unknown (pmset failed)" in w.log.read_text()


def test_unreadable_breadcrumbs_block_a_restart(gh, world, monkeypatch):
    w, _ = wedge_world(world, gh)
    w.scope_status = "unreadable"
    w.scope_data = None
    gh.Guard().run()
    assert w.opened == 0


def test_recording_that_starts_after_the_plan_aborts_the_restart(gh, world, monkeypatch):
    w, _ = wedge_world(world, gh)
    calls = {"n": 0}

    def assertions(self):
        calls["n"] += 1
        return "" if calls["n"] == 1 else PMSET_RECORDING.replace("94286", "7620")
    monkeypatch.setattr(gh.Guard, "assertions", assertions)
    assert gh.Guard().run() == 1
    assert w.opened == 0 and not any(pid == 7620 for pid, _ in w.signals)
    assert "aborted: recording started" in w.log.read_text()


def test_updater_running_blocks_the_restart(gh, world):
    w, _ = wedge_world(world, gh)
    w.procs.append(P(94132, 1, w.clock - 600, SHIPIT))
    gh.Guard().run()
    assert w.opened == 0 and not any(pid == 94132 for pid, _ in w.signals)
    assert "ShipIt" in w.log.read_text()


def test_pid_reuse_is_never_signalled(gh, world):
    w = world()
    w.immune = set()
    target = by_pid(w.procs)[91380]
    stubborn = dict(target)
    # 91380 ignores SIGTERM ... then exits, and its pid is reused by an unrelated process.
    real_kill = w.kill

    def kill(pid, sig):
        if pid == 91380 and sig == signal.SIGTERM:
            w.signals.append((pid, sig))
            w.procs = [p for p in w.procs if p["pid"] != 91380] + [P(91380, 1, w.clock, "/usr/bin/some-daemon")]
            return
        real_kill(pid, sig)
    w.kill = kill
    left = gh.Guard().terminate([stubborn])
    assert left == []
    assert (91380, signal.SIGKILL) not in w.signals


def test_signals_are_term_then_kill(gh, world):
    w = world()
    w.immune = {91380}
    target = by_pid(w.procs)[91380]
    left = gh.Guard().terminate([target])
    assert w.signals == [(91380, signal.SIGTERM), (91380, signal.SIGKILL)]
    assert left == [target]


def test_main_surviving_sigkill_fails_without_relaunch(gh, world):
    w, _ = wedge_world(world, gh)
    w.immune = {7620}
    assert gh.Guard().run() == 1
    assert w.opened == 0
    state = json.loads(w.state.read_text())
    assert "relaunch_pending" not in state
    assert "main process survived" in w.log.read_text() and w.notes()


def test_helper_surviving_sigkill_still_relaunches(gh, world):
    w, _ = wedge_world(world, gh)
    w.immune = {7957}
    gh.Guard().run()
    assert w.opened == 1
    assert "helpers survived SIGKILL (relaunching anyway)" in w.log.read_text()


def test_failed_open_is_retried_by_later_ticks_then_notifies(gh, world):
    w, _ = wedge_world(world, gh)
    w.open_rc = 1
    assert gh.Guard().run() == 1
    assert w.opened == 2                                         # launch() retries once
    state = json.loads(w.state.read_text())
    assert state["relaunch_pending"]["attempts"] == 1
    for _ in range(4):
        w.advance(gh.RELAUNCH_SPACING_S)
        gh.Guard().run()
    assert w.opened == 2 + 2 * 2                                 # attempts 2 and 3, each open retried once
    assert any("3 relaunches failed" in n for n in w.notes())
    assert "relaunch_pending" not in json.loads(w.state.read_text())


def test_pending_relaunch_recovers_on_a_later_tick(gh, world):
    w, _ = wedge_world(world, gh)
    w.open_rc = 1
    gh.Guard().run()
    w.open_rc = 0
    w.advance(gh.RELAUNCH_SPACING_S)
    gh.Guard().run()
    assert gh.current_main(w.procs)["pid"] == 94286
    w.advance(60)
    gh.Guard().run()
    assert "relaunch_pending" not in json.loads(w.state.read_text())


def test_pending_relaunch_waits_for_the_updater(gh, world):
    w, _ = wedge_world(world, gh)
    w.open_rc = 1
    gh.Guard().run()
    opened = w.opened
    w.procs.append(P(94132, 1, w.clock, SHIPIT))
    w.advance(gh.RELAUNCH_SPACING_S)
    gh.Guard().run()
    assert w.opened == opened


def test_failed_verification_notifies_and_returns_1(gh, world, monkeypatch):
    w, _ = wedge_world(world, gh)
    real_open = w.open_app

    def open_without_success():
        rc = real_open()
        w.scope_data = scope()
        return rc
    w.open_app = open_without_success
    assert gh.Guard().run() == 1
    assert "FAILED: no sqlite-init-success" in w.log.read_text() and w.notes()


def test_old_instance_breadcrumbs_do_not_verify_the_new_one(gh, world):
    w, _ = wedge_world(world, gh)
    old_success = crumb(w.clock - 50, "sqlite-init-success [object Object]")

    def open_keeping_only_old():
        w.opened += 1
        start = float(int(w.clock))
        w.procs = [p for p in w.procs if p["comm"] == NATIVE_HOST]
        w.procs += [P(94286, 1, start, MAIN)]
        w.scope_data = scope(old_success)
        return 0
    w.open_app = open_keeping_only_old
    assert gh.Guard().run() == 1


def test_cooldown_after_an_automatic_restart(gh, world):
    w, _ = wedge_world(world, gh)
    w.open_rc = 1
    gh.Guard().run()                                              # automatic restart, fails
    w.open_rc = 0
    w.advance(gh.RELAUNCH_SPACING_S)
    gh.Guard().run()                                              # pending relaunch brings it back
    new_start = gh.current_main(w.procs)["start"]
    w.scope_data = scope(stuck_pair(new_start + 30))
    w.advance(30)
    gh.Guard().run()
    w.advance(gh.WEDGE_AWAKE_S)
    opened = w.opened
    gh.Guard().run()
    assert w.opened == opened and "cooldown" in w.log.read_text()


def test_manual_fix_does_not_start_the_cooldown(gh, world):
    w = world(procs=gh.parse_ps(HEALTHY_PS), clock=HEALTHY_MAIN_START + 3600)
    assert gh.main(["fix"]) == 0
    assert w.opened == 1 and "last_restart" not in json.loads(w.state.read_text())


# ---------------------------------------------------------------- CLI

def test_cli_tick_dry_run_touches_nothing(gh, world, capsys):
    w, _ = wedge_world(world, gh)
    state_before = w.state.read_text()
    signals_before = list(w.signals)
    assert gh.main(["tick", "--dry-run"]) == 0
    assert w.signals == signals_before and w.opened == 0
    assert w.state.read_text() == state_before
    assert "[dry-run] restarting Granola" in capsys.readouterr().out


def test_cli_dry_run_takes_no_lock_and_writes_no_state(gh, world, tmp_path):
    w = world()
    assert gh.main(["tick", "--dry-run"]) == 0
    assert not (tmp_path / "state").exists() and not w.log.exists()


def test_cli_fix_refuses_while_recording_then_force(gh, world, capsys):
    w = world(procs=gh.parse_ps(HEALTHY_PS), clock=HEALTHY_MAIN_START + 3600)
    w.assertions = PMSET_RECORDING
    assert gh.main(["fix"]) == 3
    assert w.opened == 0 and "blocked: recording" in capsys.readouterr().out
    assert gh.main(["fix", "--force"]) == 0
    assert w.opened == 1


def test_cli_fix_launches_granola_when_it_is_not_running(gh, world):
    w = world(procs=[P(93271, 26599, 0, NATIVE_HOST)], clock=HEALTHY_MAIN_START)
    assert gh.main(["tick"]) == 0 and w.opened == 0            # the tick never launches on its own
    assert gh.main(["fix", "--dry-run"]) == 0 and w.opened == 0
    assert gh.main(["fix"]) == 0 and w.opened == 1


@pytest.mark.parametrize("argv", [["bogus"], ["tick", "--force"], ["fix", "--json"], ["status", "--dry-run"],
                                  ["tick", "--dry-run", "--dry-run"]])
def test_cli_rejects_unknown_arguments(gh, argv, capsys):
    assert gh.main(argv) == 2


def test_cli_lock_contention(gh, world, tmp_path):
    import fcntl
    world(procs=gh.parse_ps(HEALTHY_PS), clock=HEALTHY_MAIN_START + 3600)
    (tmp_path / "state").mkdir(exist_ok=True)
    with open(tmp_path / "state" / "lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert gh.main(["fix"]) == 4
        assert gh.main(["tick"]) == 0


@pytest.mark.parametrize("table", ["incident", "healthy"])
def test_cli_status_runs(gh, world, capsys, table):
    procs = gh.parse_ps(INCIDENT_PS, uid=UID) if table == "incident" else gh.parse_ps(HEALTHY_PS)
    world(procs=procs, clock=INCIDENT_NOW)
    assert gh.main(["status"]) == 0
    out = capsys.readouterr().out
    assert ("ORPHAN:" in out) == (table == "incident")
    assert gh.main(["status", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["orphans"]) == (4 if table == "incident" else 0)


def test_real_notify_is_rate_limited_and_silent_in_dry_run(gh, world):
    w = world()
    state = {}
    g = gh.Guard()
    g.notify(state, "k", "one", now=10_000)
    g.notify(state, "k", "two", now=10_000 + 60)
    g.notify(state, "other", "three", now=10_000 + 60)
    g.notify(state, "k", "four", now=10_000 + gh.NOTIFY_EVERY_S)
    assert [c[2].count("one") + c[2].count("three") + c[2].count("four") for c in w.osascript] == [1, 1, 1]
    gh.Guard(dry=True).notify({}, "k", "dry", now=0)
    assert len(w.osascript) == 3


# ---------------------------------------------------------------- real I/O methods (subprocess/files stubbed)

def test_real_procs_pins_utc_and_filters_to_this_user(gh, monkeypatch):
    import subprocess as real_subprocess
    seen = {}

    class Out:
        stdout = INCIDENT_PS
        returncode = 0

    def run(cmd, *a, **k):
        seen["cmd"], seen["env"], seen["timeout"] = cmd, k.get("env"), k.get("timeout")
        return Out()
    monkeypatch.setattr(gh, "subprocess", _Proxy(real_subprocess, run=run))
    monkeypatch.setattr(gh, "os", _Proxy(os, getuid=lambda: UID))
    procs = gh.Guard().procs()
    assert seen["cmd"] == ["/bin/ps", "-axo", "uid=,pid=,ppid=,lstart=,comm="]
    assert seen["env"]["TZ"] == "UTC0" and seen["env"]["LC_ALL"] == "C" and seen["timeout"]
    assert 5151 not in by_pid(procs) and 91380 in by_pid(procs)
    assert by_pid(procs)[7620]["start"] == 1790629742.0


@pytest.mark.parametrize("outcome,expected", [
    ("ok", PMSET_IDLE), ("rc", None), ("timeout", None), ("oserror", None)])
def test_real_assertions_fail_closed(gh, monkeypatch, outcome, expected):
    import subprocess as real_subprocess

    class Out:
        stdout = PMSET_IDLE
        returncode = 0 if outcome == "ok" else 1

    def run(cmd, *a, **k):
        if outcome == "timeout":
            raise real_subprocess.TimeoutExpired(cmd, 1)
        if outcome == "oserror":
            raise OSError("no pmset")
        return Out()
    monkeypatch.setattr(gh, "subprocess", _Proxy(real_subprocess, run=run))
    assert gh.Guard().assertions() == expected


def test_real_scope_statuses(gh, monkeypatch, tmp_path):
    monkeypatch.setattr(gh, "time", _Proxy(real_time, sleep=lambda s: None))
    path = tmp_path / "scope_v3.json"
    monkeypatch.setattr(gh, "BREADCRUMBS", str(path))
    assert gh.Guard().scope() == (None, "missing")
    path.write_text('{"scope": {"breadcrumbs": [')                  # torn write
    assert gh.Guard().scope() == (None, "unreadable")
    path.write_text(json.dumps(scope(stuck_pair(1.0))))
    data, status = gh.Guard().scope()
    assert status == "ok" and gh.breadcrumb_events(data, 0) == [(1, "sync_stuck")]


def test_real_launch_checks_the_return_code_and_retries_once(gh, monkeypatch):
    import subprocess as real_subprocess
    calls = []

    class Out:
        def __init__(self, rc):
            self.returncode = rc

    rcs = [1, 0]
    monkeypatch.setattr(gh, "subprocess", _Proxy(real_subprocess, run=lambda cmd, *a, **k: (calls.append(cmd), Out(rcs.pop(0)))[1]))
    monkeypatch.setattr(gh, "time", _Proxy(real_time, sleep=lambda s: None))
    assert gh.Guard().launch() is True
    assert calls == [["/usr/bin/open", "-g", "-a", APP]] * 2
    rcs[:] = [1, 1]
    calls.clear()
    assert gh.Guard().launch() is False and len(calls) == 2
    assert gh.Guard(dry=True).launch() is True and len(calls) == 2
