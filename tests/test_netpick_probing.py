"""bin/netpick measuring, watching and the CLI, driven through a fake Mac.

FakeMac (tests/netpick_fakes.py) answers every command netpick runs from a
script and passes each one through netpick's own read-only allowlist first,
so these tests also show that a whole run stays inside it.
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netpick_fakes import FIXTURES, NP, SCRIPT, T0, FakeMac, make_prober, tether, wifi

PROBES = ("ping", "curl", "networkQuality")
BIND = {"ping": "-b", "curl": "--interface", "networkQuality": "-I"}


def bound(argv):
    return argv[argv.index(BIND[argv[0]]) + 1]


def by_iface(recs):
    return {r["interface"]: r for r in recs}


def kinds(mac):
    """Each call as (kind, iface): ping, conn, stream, nq, or None for reads."""
    out = []
    for _t, _gw, a in mac.calls:
        if a[0] == "ping":
            out.append(("ping", bound(a)))
        elif a[0] == "networkQuality":
            out.append(("nq", bound(a)))
        elif a[0] == "curl" and "-I" in a:
            out.append(("conn", bound(a)))
        elif a[0] == "curl" and "speed.cloudflare.com" in a[-1]:
            out.append(("stream", bound(a)))
    return out


# ---------------------------------------------------------------- coexisting links


def tether_like_1104(**kw):
    """The 11/04 USB tether: clean pings, every other new connection failed."""
    return tether(loss_pct=0.0, rtt_ms=37.0, conn_fail=lambda n: n % 2 == 1, nq="fail", **kw)


def test_coexisting_links_are_measured_together_with_every_probe_bound():
    mac = FakeMac([wifi(loss_pct=15.0, rtt_ms=330.0, rtt_sd=80.0), tether_like_1104()], primary="en13")
    recs = make_prober(mac).measure(make_prober(mac).candidates())
    assert [r["interface"] for r in recs] == ["en13", "en0"]  # primary first
    for argv in mac.argvs():
        if argv[0] in PROBES:
            assert bound(argv) in ("en0", "en13")
    for iface in ("en0", "en13"):
        assert {k for k, i in kinds(mac) if i == iface} == {"ping", "conn", "stream", "nq"}
    r = by_iface(recs)
    assert (r["en13"]["conns"]["ok"], r["en13"]["conns"]["attempted"]) == (4, 8)
    assert r["en13"]["ping"]["loss_pct"] == 0.0 and r["en13"]["nq"]["error"]
    assert r["en0"]["conns"]["ok"] == 8 and r["en0"]["ping"]["loss_pct"] == 15.0
    assert r["en0"]["security_class"] == "wpa2" and r["en0"]["wifi"]["channel"] == 36
    assert r["en13"]["label"] == "Pixel 11 Pro Fold · AS6167 Cellco Partnership DBA…"
    assert r["en0"]["label"] == "Wi-Fi WPA2 gw 172.21.112.1 · AS64500 Example Networks"
    assert r["en0"]["dns"]["ok"] == 4 and r["en0"]["dns"]["server"] == "172.21.112.1"


def test_the_1104_tether_loses_to_lossy_wifi_and_the_hint_says_unplug_it():
    mac = FakeMac([wifi(loss_pct=15.0, rtt_ms=330.0, rtt_sd=80.0), tether_like_1104()], primary="en13")
    recs = make_prober(mac).measure(make_prober(mac).candidates())
    ranked = NP.rank(recs)
    current = by_iface(recs)["en13"]
    assert [r["interface"] for r in ranked] == ["en0", "en13"]
    got = NP.recommend(ranked, current)
    assert got["action"] == "switch" and got["pick"]["interface"] == "en0"
    assert "8/8 connections vs 4/8" in got["text"]
    assert "Turn off or unplug Pixel 11 Pro Fold; traffic then falls back to Wi-Fi." in got["text"]


def test_a_better_tether_behind_wifi_gets_the_service_order_hint():
    mac = FakeMac([wifi(conn_fail=lambda n: n % 3 == 0), tether()], primary="en0")
    recs = make_prober(mac).measure(make_prober(mac).candidates())
    got = NP.recommend(NP.rank(recs), by_iface(recs)["en0"])
    assert got["action"] == "switch" and got["pick"]["interface"] == "en13"
    assert "Pixel 11 Pro Fold is up, but macOS routes over Wi-Fi now" in got["text"]
    assert "netpick changes neither" in got["text"]


def test_phases_line_up_across_links():
    """All links ping, then all connect, then all transfer, then all run
    networkQuality: no link's transfer overlaps another link's pings."""
    mac = FakeMac([wifi(), tether()], primary="en0")
    make_prober(mac).measure(make_prober(mac).candidates())
    seq = [k for k, _i in kinds(mac)]
    order = ["ping", "conn", "stream", "nq"]
    for a, b in zip(order, order[1:]):
        last_a = max(i for i, k in enumerate(seq) if k == a)
        first_b = min(i for i, k in enumerate(seq) if k == b)
        assert last_a < first_b, (a, b)


# ---------------------------------------------------------------- data budget


def test_default_run_stays_inside_the_budget():
    mac = FakeMac([wifi()])
    rec = make_prober(mac).measure(make_prober(mac).candidates())[0]
    # one-connection estimate 20 + 10 Mbps -> plan 12 s; networkQuality moves 25 + 15 Mbps
    assert rec["nq"]["planned_s"] == 12 and "stopped" not in rec["nq"]
    assert rec["stream"]["bytes"] == 7_500_000
    assert rec["data_bytes"] == 7_500_000 + 60_000_000 <= 100e6
    assert rec["metrics"]["via"] == "nq" and rec["metrics"]["rpm"] == 300.0


def test_fast_link_skips_networkquality_and_ranks_on_the_transfer():
    mac = FakeMac([wifi(down_mbps=100.0, up_mbps=100.0)])
    rec = make_prober(mac).measure(make_prober(mac).candidates())[0]
    assert rec["nq"]["skipped"].startswith("skipped: at ~200 Mbps a 5 s run could pass the 100 MB budget")
    assert not mac.argvs("networkQuality")
    assert (rec["metrics"]["down_mbps"], rec["metrics"]["via"]) == (100.0, "stream")
    assert any("networkQuality skipped" in n for n in NP.notes_for([rec]))


def test_watchdog_stops_networkquality_at_the_budget_within_one_poll():
    """networkQuality moving far more than the plan assumed (800 Mbps against
    a 3 Mbps estimate) is stopped by the byte-counter watchdog."""
    mac = FakeMac([wifi(down_mbps=2.0, up_mbps=1.0, nq_down=400.0, nq_up=400.0)])
    rec = make_prober(mac).measure(make_prober(mac).candidates())[0]
    nq = rec["nq"]
    assert nq["stopped"] == "budget" and nq["planned_s"] == 20
    remaining = 100e6 - rec["stream"]["bytes"]
    one_poll = 800e6 / 8 * 0.5
    assert remaining <= nq["bytes"] < remaining + one_poll
    assert rec["metrics"]["via"] == "stream"
    assert "networkQuality stopped (budget)" in "\n".join(NP.notes_for([rec]))


def test_failed_and_hung_networkquality_fall_back_to_the_transfer():
    mac = FakeMac([wifi(nq="fail"), tether(nq="hang")], primary="en0")
    recs = by_iface(make_prober(mac).measure(make_prober(mac).candidates()))
    assert recs["en0"]["nq"]["error"] == "Error: the test could not complete"
    assert recs["en13"]["nq"]["stopped"] == "timeout"
    assert recs["en13"]["nq"]["seconds"] >= recs["en13"]["nq"]["planned_s"] + 15
    for r in recs.values():
        assert r["metrics"]["via"] == "stream" and r["metrics"]["down_mbps"] == 20.0


def test_quick_mode_moves_no_bulk_data():
    mac = FakeMac([wifi(), tether()])
    recs = make_prober(mac, stream=False, nq=False).measure(make_prober(mac).candidates())
    assert not mac.argvs("networkQuality") and not [k for k, _ in kinds(mac) if k == "stream"]
    assert all(r["data_bytes"] == 0 and r["metrics"]["up_mbps"] is None for r in recs)


def moved_on(mac, iface):
    """Bytes the fake link carried for netpick (FakeMac counters start at 9 GB)."""
    return sum(mac.octets.get(iface, (8_000_000_000, 1_000_000_000))) - 9_000_000_000


def test_a_small_budget_skips_the_transfer_and_networkquality():
    """Review finding 1: a 1 MB budget used to run the 7.5 MB transfer anyway."""
    mac = FakeMac([wifi()])
    rec = make_prober(mac, budget_mb=1).measure(make_prober(mac).candidates())[0]
    assert rec["stream"]["skipped"] == "skipped: its 7.5 MB would pass the 1 MB budget"
    assert rec["nq"]["skipped"] == "skipped: no transfer estimate, and under 20 MB of the budget left"
    assert rec["data_bytes"] == 0 == moved_on(mac, "en0")
    assert not [k for k, _ in kinds(mac) if k in ("stream", "nq")]
    assert "en0: bounded transfer skipped: its 7.5 MB would pass the 1 MB budget" in NP.notes_for([rec])


def test_rounds_share_one_budget():
    """Review finding 1: 20 rounds on the 100 MB budget used to move 150 MB of
    transfers. Round 1 runs the transfer and a 12 s networkQuality run (60 MB);
    later rounds run the transfer while its 7.5 MB still fits."""
    mac = FakeMac([wifi()])
    rec = make_prober(mac).measure(make_prober(mac).candidates(), rounds=20)[0]
    assert len(mac.argvs("networkQuality")) == 1 and len([k for k, _ in kinds(mac) if k == "stream"]) == 2 * 5
    assert (rec["stream"]["bytes"], rec["nq"]["bytes"]) == (5 * 7_500_000, 60_000_000)
    assert rec["data_bytes"] == 97_500_000 == moved_on(mac, "en0")


@given(budget=st.floats(0, 300), rounds=st.integers(1, 5), down=st.floats(0.5, 500), up=st.floats(0.5, 500),
       nq_down=st.floats(0, 2000), nq_up=st.floats(0, 2000), sizes=st.tuples(st.floats(0, 20), st.floats(0, 20)),
       longest=st.integers(NP.NQ_MIN_SECONDS, 60))
def test_no_run_moves_more_than_its_budget(budget, rounds, down, up, nq_down, nq_up, sizes, longest):
    """Invariant: a link's data in one run, over every round's transfer and
    networkQuality, stays within the budget plus at most one half-second
    watchdog check of networkQuality's own rate, which can be far above the
    plan's estimate. netpick's count matches what the link carried."""
    mac = FakeMac([wifi(down_mbps=down, up_mbps=up, nq_down=nq_down, nq_up=nq_up)])
    opts = dict(budget_mb=budget, stream_down_mb=sizes[0], stream_up_mb=sizes[1], nq_seconds=longest)
    rec = make_prober(mac, **opts).measure(make_prober(mac).candidates(), rounds=rounds)[0]
    one_check = (nq_down + nq_up) * 1e6 / 8 * 0.5
    moved = moved_on(mac, "en0")
    assert moved <= budget * 1e6 + one_check + 1000
    assert abs(rec["data_bytes"] - moved) <= 1000  # the fake rounds each half second's bytes down


def test_networkquality_needs_byte_counters_to_run():
    """Review finding 2: with no counters the watchdog used to be off, and an
    800 Mbps run moved 2 GB under a 100 MB budget."""
    mac = FakeMac([wifi(down_mbps=2.0, up_mbps=1.0, nq_down=400.0, nq_up=400.0)])
    p = NP.Prober(runner=mac, dns=mac.dns, resolve=mac.resolve, counters=lambda iface: None, clock=mac.clock,
                  sleep=mac.sleep)
    rec = p.measure(p.candidates())[0]
    assert rec["nq"] == {"skipped": "skipped: no byte counters for en0 to hold it to the budget", "bytes": 0}
    assert not mac.argvs("networkQuality") and rec["data_bytes"] == 7_500_000 == moved_on(mac, "en0")


def test_a_failed_counter_read_stops_networkquality():
    """The third read during the run fails: netpick stops networkQuality and
    counts the 10 MB that the last good read saw (two checks at 80 Mbps)."""
    mac = FakeMac([wifi(nq_down=40.0, nq_up=40.0)])
    reads = []

    def failing(iface):
        reads.append(iface)
        return mac.if_counters(iface) if len(reads) <= 3 else None

    p = NP.Prober(runner=mac, dns=mac.dns, resolve=mac.resolve, counters=failing, clock=mac.clock, sleep=mac.sleep)
    nq = p.measure(p.candidates())[0]["nq"]
    assert (nq["stopped"], nq["bytes"]) == ("counters", 10_000_000)


def test_counters_that_go_backward_stop_networkquality():
    mac = FakeMac([wifi()])
    reads = []

    def resetting(iface):  # the interface came back with fresh counters
        reads.append(iface)
        ib, ob = mac.if_counters(iface)
        return (ib, ob) if len(reads) < 3 else (ib - 8_000_000_000, ob - 1_000_000_000)

    p = NP.Prober(runner=mac, dns=mac.dns, resolve=mac.resolve, counters=resetting, clock=mac.clock, sleep=mac.sleep)
    nq = p.measure(p.candidates())[0]["nq"]
    assert (nq["stopped"], nq["bytes"]) == ("counters", 2_500_000)  # one check at 40 Mbps


class FaultyMac(FakeMac):
    """A fake Mac whose byte counts go missing: the transfers numbered in lost
    (from 0) end before curl prints its counts, though the link carries their
    bytes, and networkQuality reports json_share of the bytes it moved."""

    def __init__(self, links, lost=(), json_share=1.0):
        super().__init__(links)
        self.lost, self.json_share, self.transfers = set(lost), json_share, 0

    def answer(self, a, stdin):
        got = super().answer(a, stdin)
        if a[0] == "curl" and "speed.cloudflare.com" in a[-1]:
            self.transfers += 1
            if self.transfers - 1 in self.lost:  # killed at its outer timeout, before curl's summary
                return NP.Proc(-9, "", "", 13.0, "timeout")
        return got

    def run_watched(self, argv, timeout, should_stop, poll=0.5):
        p = super().run_watched(argv, timeout, should_stop, poll)
        if p.rc == 0:
            payload = json.loads(p.out)
            for k in ("dl_bytes_transferred", "ul_bytes_transferred"):
                payload[k] = int(payload[k] * self.json_share)
            p.out = json.dumps(payload)
        return p


def flaky_counters(mac, fail=(), reset=()):
    """mac's byte counters, except that read n (from 0) fails when n is in
    fail, and the counters start again from zero at each read in reset (as
    an interface that came back with fresh counters would)."""
    state = {"n": 0, "base": (0, 0)}

    def read(iface):
        n = state["n"]
        state["n"] += 1
        raw = mac.if_counters(iface)
        if raw is not None and n in reset:
            state["base"] = raw
        if raw is None or n in fail:
            return None
        return raw[0] - state["base"][0], raw[1] - state["base"][1]
    return read


def test_counter_reads_that_keep_failing_charge_the_rest_of_the_budget():
    """Round-2 review blocker: counters that answered at each run's start but
    failed at the first check and at the end charged nothing, so ten rounds at
    800 Mbps moved 500 MB under a 100 MB budget."""
    mac = FakeMac([wifi(nq_down=400.0, nq_up=400.0)])
    p = make_prober(mac, stream=False)
    p.counters = flaky_counters(mac, fail={n for n in range(100) if n % 3})
    rec = p.measure(p.candidates(), rounds=10)[0]
    assert len(mac.argvs("networkQuality")) == 1
    assert moved_on(mac, "en0") == 50_000_000  # one half-second check at 800 Mbps
    assert rec["notes"] == ["a byte-counter read during or right after networkQuality failed or ran backward, so "
                            "netpick charged the rest of the 100 MB budget"]


def test_a_transfer_without_byte_counts_charges_its_planned_size():
    """Round-2 review blocker: a transfer killed before curl printed its byte
    counts charged nothing, so each round ran it again: ten rounds moved 75 MB
    under a 7.5 MB budget. Now each transfer charges its 7.5 MB, so a 15 MB
    budget runs two."""
    mac = FaultyMac([wifi()], lost=range(100))
    rec = make_prober(mac, budget_mb=15, nq=False).measure(make_prober(mac).candidates(), rounds=10)[0]
    assert len([k for k, _ in kinds(mac) if k == "stream"]) == 2 * 2 and moved_on(mac, "en0") == 15_000_000
    assert rec["notes"] == ["curl printed no byte count for the transfer's download and upload, so netpick charged "
                            "the budget the planned 7.5 MB"] * 2
    assert rec["stream"]["bytes"] == 0  # the record keeps what netpick counted


@pytest.mark.parametrize("lost, counted, direction, mb", [({0}, 2_500_000, "download", "5"),
                                                          ({1}, 5_000_000, "upload", "2.5")])
def test_a_direction_without_a_byte_count_charges_that_directions_planned_size(lost, counted, direction, mb):
    """When only one direction loses its count, netpick charges that
    direction's planned size on top of what curl counted for the other: 7.5 MB
    in all, which leaves a 12.5 MB budget no room for a second transfer."""
    mac = FaultyMac([wifi()], lost=lost)
    rec = make_prober(mac, budget_mb=12.5, nq=False).measure(make_prober(mac).candidates(), rounds=2)[0]
    assert len([k for k, _ in kinds(mac) if k == "stream"]) == 2 and moved_on(mac, "en0") == 7_500_000
    assert rec["notes"] == [f"curl printed no byte count for the transfer's {direction}, so netpick charged the "
                            f"budget the planned {mb} MB"]
    assert rec["stream"]["bytes"] == counted


def test_networkquality_reporting_too_few_bytes_is_charged_what_the_counters_saw():
    """Round-2 review blocker: networkQuality reporting no bytes charged
    nothing, so ten 5-second runs moved 500 MB under a 100 MB budget. Now the
    first run costs the 50 MB the counters saw and the budget stops the second."""
    mac = FaultyMac([wifi(nq_down=40.0, nq_up=40.0)], json_share=0.0)
    rec = make_prober(mac, stream=False, nq_seconds=5).measure(make_prober(mac).candidates(), rounds=10)[0]
    assert len(mac.argvs("networkQuality")) == 2 and moved_on(mac, "en0") == 100_000_000
    assert rec["nq"]["runs"] == 1  # the second run stopped at the budget and gave no rates


@given(budget=st.floats(0, 300), rounds=st.integers(1, 5), down=st.floats(0.5, 500), up=st.floats(0.5, 500),
       nq_down=st.floats(0, 2000), nq_up=st.floats(0, 2000), sizes=st.tuples(st.floats(0, 20), st.floats(0, 20)),
       nq=st.sampled_from(["ok", "fail", "hang"]), lost=st.sets(st.integers(0, 9)), json_share=st.floats(0, 1),
       fail=st.sets(st.integers(0, 80)),
       reset=st.sets(st.integers(0, 80)).map(lambda r: {n for n in r if n - 1 not in r}))
def test_no_run_moves_more_than_its_budget_when_byte_counts_go_missing(budget, rounds, down, up, nq_down, nq_up, sizes,
                                                                      nq, lost, json_share, fail, reset):
    """Invariant 7 when counts go missing: counter reads that fail or start
    again from zero, transfers that end before curl prints its byte counts and
    networkQuality reports that count too few bytes still leave every run
    within its budget plus one half-second check, and the record never counts
    more than the link carried. A reset here reads exactly zero, so a second
    reset at the next read would look like a link that carried nothing in
    between, which no reading can tell apart; the model keeps resets out of
    successive reads."""
    mac = FaultyMac([wifi(down_mbps=down, up_mbps=up, nq_down=nq_down, nq_up=nq_up, nq=nq)], lost, json_share)
    p = make_prober(mac, budget_mb=budget, stream_down_mb=sizes[0], stream_up_mb=sizes[1])
    p.counters = flaky_counters(mac, fail, reset)
    rec = p.measure(p.candidates(), rounds=rounds)[0]
    moved = moved_on(mac, "en0")
    assert moved <= budget * 1e6 + (nq_down + nq_up) * 1e6 / 8 * 0.5 + 1000
    assert rec["data_bytes"] <= moved + 1000


def test_watchdog_on_the_real_runner_stops_within_a_check(tmp_path, monkeypatch):
    """Review finding 3, on the production path: Runner.run_watched with a
    stand-in networkQuality that never ends and counters that grow 200 MB a
    second. The budget runs out at 0.5 s; the stop comes at the next check,
    not after a slow read (netstat once took 2 s here)."""
    stand_in = tmp_path / "networkQuality"
    stand_in.write_text("#!/bin/sh\nexec sleep 30\n")
    stand_in.chmod(0o755)
    monkeypatch.setitem(NP.TOOL_PATHS, "networkQuality", str(stand_in))
    t0 = time.monotonic()

    def counters(iface):
        return int((time.monotonic() - t0) * 200e6), 0

    got = NP.Prober(runner=NP.Runner(), counters=counters).nq("en0", 0, {"down_mbps": 2.0, "up_mbps": 1.0})
    assert (got["stopped"], got["planned_s"]) == ("budget", 20)
    assert got["seconds"] < 2.5 and 100e6 <= got["bytes"] < 500e6


# ---------------------------------------------------------------- offline links and failures


def test_offline_link_is_identified_but_never_probed_and_ranks_last():
    mac = FakeMac([wifi(), tether(online_after=1e9)], primary="en13")
    recs = make_prober(mac).measure(make_prober(mac).candidates())
    probed = {(k, i) for k, i in kinds(mac)}
    assert not {i for _k, i in probed} - {"en0"}
    assert [a for a in mac.argvs("curl", "en13")] == [a for a in mac.argvs("curl", "en13") if NP.CAPTIVE_URL in a]
    off = by_iface(recs)["en13"]
    assert not off["online"] and off["egress"] is None
    assert "no internet (no captive portal sign-in yet?)" in off["notes"]
    ranked = NP.rank(recs)
    assert ranked[-1] is off
    got = NP.recommend(ranked, off)
    assert got["action"] == "switch" and "has no internet" in got["text"]
    assert "offline" in NP.table(ranked)


def test_one_links_failure_becomes_a_note_not_a_crash():
    class Flaky(FakeMac):
        def answer(self, a, stdin):
            if a[0] == "curl" and "speed.cloudflare.com" in a[-1] and "en13" in a:
                raise ConnectionResetError("tether dropped")
            return super().answer(a, stdin)

    mac = Flaky([wifi(), tether()])
    recs = by_iface(make_prober(mac).measure(make_prober(mac).candidates()))
    assert "bounded transfer failed: ConnectionResetError: tether dropped" in recs["en13"]["notes"]
    assert recs["en0"]["stream"]["down_mbps"] == 20.0 and not recs["en0"]["notes"]


def test_an_unsafe_command_is_never_swallowed():
    class Rogue(FakeMac):
        def answer(self, a, stdin):
            if a[0] == "ping":
                self.run(["networksetup", "-setairportpower", "en0", "off"], 5)
            return super().answer(a, stdin)

    mac = Rogue([wifi()])
    with pytest.raises(NP.UnsafeCommand):
        make_prober(mac).measure(make_prober(mac).candidates())


def test_ping_on_a_missing_interface_reports_the_error():
    got = make_prober(FakeMac([wifi()])).ping("en7")
    assert got == {"sent": 0, "received": 0, "loss_pct": None, "error": "ping: bad interface name"}


def test_two_rounds_pool_pings_and_connections():
    mac = FakeMac([wifi(loss_pct=5.0)])
    rec = make_prober(mac, stream=False, nq=False).measure(make_prober(mac).candidates(), rounds=2)[0]
    assert rec["rounds"] == 2
    assert (rec["ping"]["sent"], rec["ping"]["received"]) == (80, 76)
    assert (rec["conns"]["attempted"], rec["conns"]["ok"]) == (16, 16)
    assert rec["dns"]["attempts"] == 8


def test_system_resolve_keeps_public_answers_only(monkeypatch):
    def fake(answer):
        return lambda *a, **k: [(2, 1, 6, "", (answer, 443))]

    monkeypatch.setattr(NP.socket, "getaddrinfo", fake("10.0.0.5"))  # a captive portal's DNS
    assert NP.system_resolve("api.anthropic.com") is None
    monkeypatch.setattr(NP.socket, "getaddrinfo", fake("160.79.104.10"))
    assert NP.system_resolve("api.anthropic.com") == "160.79.104.10"


def test_a_hung_resolver_costs_its_timeout_not_the_run():
    """Review finding 4: getaddrinfo has no timeout, and a resolver that never
    answered held the measurement until the test released it."""
    release = threading.Event()

    def hung(host):
        release.wait(30)
        return "93.184.216.34"

    mac = FakeMac([wifi()])
    p = NP.Prober(runner=mac, opts=NP.Options(stream=False, nq=False), dns=mac.dns, resolve=hung,
                  counters=mac.if_counters, clock=mac.clock, sleep=mac.sleep, resolve_timeout=0.2)
    try:
        t = time.monotonic()
        rec = p.measure(p.candidates())[0]
        assert time.monotonic() - t < 5 and rec["conns"]["ok"] == 8
        pinned = {a[a.index("--resolve") + 1] for a in mac.argvs("curl") if "--resolve" in a}
        assert pinned == {f"{h}:443:{ip}" for h, ip in NP.FALLBACK_IPS.items()}
        t = time.monotonic()
        assert p.api_check("en0")["ok"] == 8 and time.monotonic() - t < 5
    finally:
        release.set()


def test_resolver_errors_and_junk_use_the_fixed_addresses():
    def broken(host):
        raise OSError("no route to host")

    for resolve in (broken, lambda h: None, lambda h: "not an address", lambda h: "300.1.1.1"):
        assert NP.Prober(runner=FakeMac([wifi()]), resolve=resolve).pinned_ips() == NP.FALLBACK_IPS
    assert NP.Prober(runner=FakeMac([wifi()]), resolve=lambda h: "160.79.104.99").pinned_ips() == {
        h: "160.79.104.99" for h in NP.HOSTS}


def test_dns_uses_the_first_of_several_dhcp_servers():
    """Review finding 10: '1.1.1.1 8.8.8.8' used to read as no server at all."""
    mac = FakeMac([wifi(dns_reply="1.1.1.1 8.8.8.8\n")])
    rec = make_prober(mac, stream=False, nq=False).measure(make_prober(mac).candidates())[0]
    assert rec["dns_server"] == "1.1.1.1"
    assert (rec["dns"]["server"], rec["dns"]["ok"], rec["dns"]["attempts"]) == ("1.1.1.1", 4, 4)


# ---------------------------------------------------------------- watch mode

A = dict(gateway="172.21.112.1", ip="172.21.121.112", security="WPA2_PSK")
B = dict(gateway="10.243.10.226", ip="10.243.10.147", security="WPA3_SAE")
C = dict(gateway="172.16.224.1", ip="172.16.225.243", security="NONE")


def watch(mac, tmp_path, **kw):
    lines = []
    store = NP.Store(tmp_path / "history.jsonl")
    kw.setdefault("minutes", 10)
    rc = NP.watch_loop(make_prober(mac), store, out=lines.append, **kw)
    return rc, "\n".join(lines), store


def test_watch_measures_a_new_network_after_its_portal_and_dns_settle(tmp_path):
    a = wifi(loss_pct=10.0, **A)
    b = wifi(online_after=20.0, **B)
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, a), (T0 + 100, None), (T0 + 110, b), (T0 + 400, a)]
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=2)
    assert rc == 0
    assert "baseline: measuring the current network (gateway 172.21.112.1)" in text
    assert "new network: gateway 10.243.10.226, ip 10.243.10.147, security WPA3_SAE" in text
    assert "online after 21s" in text and "letting DNS settle for 30s" in text
    assert "back on gateway 172.21.112.1" in text
    assert "API check: 4/4 Claude API, 4/4 GitHub connections" in text
    assert "done: measured 2 network(s)" in text
    # B came online at T0+130; nothing measured it before DNS had 30 s
    b_pings = [t for t, gw, argv in mac.calls if argv[0] == "ping" and gw == B["gateway"]]
    assert b_pings and min(b_pings) >= T0 + 130 + 30
    recs, bad = store.load()
    assert bad == 0 and [r["gateway"] for r in recs] == [A["gateway"], B["gateway"]]
    assert {r["mode"] for r in recs} == {"watch"} and recs[1]["security_class"] == "wpa3"
    # back on A at the end: B measured better (no loss), so the last word is to pick B
    tail = text.rsplit("done:", 1)[1]
    assert "Switch to Wi-Fi WPA3 gw 10.243.10.226" in tail and "Pick it in the Wi-Fi menu" in tail
    assert "netpick measured these one at a time" in tail
    for _t, _gw, argv in mac.calls:  # nothing but reads and en0-bound probes
        assert argv[0] in NP.READ_ONLY
        if argv[0] in PROBES:
            assert bound(argv) == "en0"


def test_watch_skips_gateways_already_tested(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 60, wifi(**B))]
    rc, text, store = watch(mac, tmp_path, seen=[B["gateway"]], max_new=1, minutes=5)
    assert "back on gateway 10.243.10.226 (netpick tested it already)" in text
    assert "API check: 4/4 Claude API, 4/4 GitHub connections" in text
    assert store.load() == ([], 0) and not mac.argvs("ping")


def test_watch_gives_up_on_a_portal_nobody_signs_in_to(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 60, wifi(online_after=1e9, **C))]
    rc, text, store = watch(mac, tmp_path, portal_wait=120, max_new=1, minutes=5)
    assert "still no internet after 2 min (no portal sign-in yet?), so netpick skipped it" in text
    assert "done: measured 0 network(s)" in text and not mac.argvs("ping")


def test_watch_follows_a_second_switch_during_the_portal_wait(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 60, wifi(online_after=1e9, **C)), (T0 + 90, wifi(**B))]
    rc, text, store = watch(mac, tmp_path, max_new=1, minutes=5, settle=10)
    assert "the network changed while waiting for internet" in text
    assert "new network: gateway 10.243.10.226" in text
    assert [r["gateway"] for r in store.load()[0]] == [B["gateway"]]


def test_watch_waits_for_a_baseline_network_without_internet(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(online_after=60.0, **C))]
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=1, minutes=5)
    assert "baseline: the current Wi-Fi network has no internet yet, so netpick waits for it" in text and rc == 0
    assert "baseline: gateway 172.16.224.1, ip 172.16.225.243, security NONE" in text and "online after 60s" in text
    assert "new network:" not in text
    assert [r["gateway"] for r in store.load()[0]] == [C["gateway"]]
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(online_after=1e9, **C))]  # a portal nobody signs in to
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=1, minutes=1)
    assert "no internet before the 1-minute limit" in text and mac.now <= T0 + 60 and rc == 0


@pytest.mark.parametrize("portal", [0.0, 10.0], ids=["already online", "portal opens after 10 s"])
@pytest.mark.parametrize("options, measured", [(dict(seen=[A["gateway"]], minutes=1), [A]), (dict(max_new=0), [A]),
                                               (dict(max_new=1), [A, B])],
                         ids=["--seen the current gateway", "--max 0", "--max 1 and a later switch"])
def test_a_baseline_keeps_its_meaning_while_it_waits_for_internet(tmp_path, portal, options, measured):
    """Round-4 review: with a portal, the baseline went down the new-network
    path, so --seen gave it an API check, --max 0 skipped it, and --max 1 ended
    the watch with the baseline before B appeared."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(online_after=portal, **A)), (T0 + 100, wifi(**B))]
    rc, text, store = watch(mac, tmp_path, **dict(dict(baseline=True, settle=5, max_new=1, minutes=3), **options))
    assert rc == 0 and [r["gateway"] for r in store.load()[0]] == [n["gateway"] for n in measured]
    assert "API check" not in text and "new network: gateway 172.21.112.1" not in text and "skipped" not in text


def test_a_baseline_measurement_ends_a_watch_with_nothing_else_to_do(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(online_after=10.0, **A))]
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=0, settle=5, minutes=3)
    assert rc == 0 and len(store.load()[0]) == 1 and mac.now - T0 < 60


@pytest.mark.parametrize("gap, online_after", [(T0 + 8.8, 20.0), (T0 + 10.8, 5.0)],
                         ids=["during the wait for internet", "while DNS settles"])
def test_a_drop_keeps_the_baseline_waiting(tmp_path, gap, online_after):
    """A read takes 1 s, so the next one finds the network back. It's still
    the baseline: --seen and --max 0 don't apply."""
    mac = FakeMac([], primary="en0")
    mac.cost = one_second_gateway_reads
    mac.wifi_schedule = [(T0, wifi(online_after=online_after, **C)), (gap, None),
                         (gap + 0.5, wifi(online_after=online_after, **C))]
    rc, text, store = watch(mac, tmp_path, baseline=True, seen=[C["gateway"]], max_new=0, minutes=5)
    assert text.count("baseline: gateway 172.16.224.1") == 2 and "back on gateway" not in text
    assert [r["gateway"] for r in store.load()[0]] == [C["gateway"]]


def test_a_drop_as_a_baseline_measurement_starts_keeps_it_waiting(tmp_path):
    """The captive check passes at T0 + 1. The measurement reads the address at
    T0 + 2, inside the drop, so it finds no network."""
    mac = FakeMac([], primary="en0")
    mac.cost = one_second_gateway_reads
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 1.8, None), (T0 + 2.3, wifi(**A))]
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=0, settle=5, minutes=5)
    assert "baseline: measuring the current network" in text and "baseline: gateway 172.21.112.1" in text
    assert [r["gateway"] for r in store.load()[0]] == [A["gateway"]]


@pytest.mark.parametrize("max_new, measured", [(0, []), (1, [B])], ids=["--max 0", "--max 1"])
def test_a_baseline_ends_when_the_wifi_moves_to_another_network(tmp_path, max_new, measured):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(online_after=1e9, **A)), (T0 + 20, wifi(**B))]
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=max_new, settle=5, minutes=5)
    assert "the network changed while waiting for internet" in text
    assert "baseline: the Wi-Fi moved to another network first, so netpick skipped the baseline" in text
    assert rc == 0 and [r["gateway"] for r in store.load()[0]] == [n["gateway"] for n in measured]
    assert mac.now - T0 < 60  # netpick has nothing left to wait for


def test_a_baseline_that_lapsed_counts_as_a_new_network_on_return(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(online_after=1e9, **A)), (T0 + 20, wifi(**B)), (T0 + 100, wifi(**A))]
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=2, settle=5, minutes=5)
    assert [r["gateway"] for r in store.load()[0]] == [B["gateway"], A["gateway"]]
    assert "new network: gateway 172.21.112.1" in text


def test_a_baseline_whose_portal_wait_runs_out_ends_a_watch_with_nothing_else_to_do(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(online_after=1e9, **A))]
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=0, portal_wait=60, minutes=5)
    assert "still no internet after 1 min (no portal sign-in yet?), so netpick skipped it" in text
    assert rc == 0 and store.load() == ([], 0) and mac.now - T0 == pytest.approx(60)


def test_a_baseline_with_no_network_at_the_start_is_skipped(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, None), (T0 + 20, wifi(**B))]
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=0, settle=5, minutes=5)
    assert "baseline: en0 has no network right now, so netpick skipped it" in text
    assert rc == 0 and store.load() == ([], 0) and mac.now == T0
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=1, settle=5, minutes=5)  # B then counts as new
    assert "new network: gateway 10.243.10.226" in text and [r["gateway"] for r in store.load()[0]] == [B["gateway"]]


@given(max_new=st.integers(0, 3), in_seen=st.booleans(), portal=st.sampled_from([0.0, 20.0]),
       drop=st.none() | st.floats(0.01, 60))
def test_a_baseline_on_a_network_i_stay_on_gets_one_measurement(max_new, in_seen, portal, drop):
    """Invariant: whatever --seen and --max say, however long the portal takes
    and wherever one short drop lands, a watch that starts on a network and
    stays there measures it once, and that measurement uses none of --max."""
    mac = FakeMac([], primary="en0")
    mac.cost = one_second_gateway_reads
    mac.wifi_schedule = [(T0, wifi(online_after=portal, **A))]
    if drop is not None:
        mac.wifi_schedule += [(T0 + drop, None), (T0 + drop + 0.5, wifi(online_after=portal, **A))]
    seen = [A["gateway"]] if in_seen else []
    with tempfile.TemporaryDirectory() as d:
        rc, text, store = watch(mac, pathlib.Path(d), baseline=True, seen=seen, max_new=max_new, settle=30,
                                portal_wait=60, minutes=4)
        assert rc == 0 and [r["gateway"] for r in store.load()[0]] == [A["gateway"]], text


def test_watch_starts_no_settle_the_time_limit_would_cut_short(tmp_path):
    """Review finding 8: a network that appeared 58 s into a 1-minute watch got
    the full 30 s settle and a measurement, so the watch ended at 90 s."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 58, wifi(**B))]
    rc, text, store = watch(mac, tmp_path, minutes=1, max_new=1)
    assert "new network: gateway 10.243.10.226" in text
    assert "the 1-minute limit ends before DNS could settle for 30s, so netpick didn't measure it" in text
    assert store.load() == ([], 0) and not mac.argvs("ping") and mac.now <= T0 + 60


def test_watch_waits_for_a_portal_and_a_return_only_until_the_time_limit(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 50, wifi(online_after=1e9, **C))]
    rc, text, _ = watch(mac, tmp_path, minutes=1, max_new=1)
    assert "no internet before the 1-minute limit, so netpick didn't measure it" in text and mac.now <= T0 + 60
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 50, wifi(**B))]  # back on a tested network 10 s before the end
    rc, text, _ = watch(mac, tmp_path, seen=[B["gateway"]], minutes=1, max_new=1)
    assert "back on gateway 10.243.10.226 (netpick tested it already)" in text and "API check" not in text
    assert mac.now <= T0 + 60 and all(NP.CAPTIVE_URL in a for a in mac.argvs("curl"))  # captive checks only


@pytest.mark.parametrize("first_visit", ["left during the portal wait", "portal wait ran out"])
def test_a_network_left_before_its_measurement_gets_one_on_return(tmp_path, first_visit):
    """Review finding 9: watch marked a gateway tested when it first saw it,
    so a return after the portal opened got only the API check."""
    mac = FakeMac([], primary="en0")
    back = T0 + (90 if first_visit == "left during the portal wait" else 300)
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 60, wifi(online_after=1e9, **C)), (back, wifi(**A)),
                         (back + 110, wifi(online_after=10.0, **C))]
    rc, text, store = watch(mac, tmp_path, seen=[A["gateway"]], portal_wait=120, max_new=1, minutes=15)
    assert ("the network changed while waiting for internet" if back == T0 + 90
            else "still no internet after 2 min (no portal sign-in yet?), so netpick skipped it") in text
    assert text.count("new network: gateway 172.16.224.1") == 2
    assert "172.16.224.1 (netpick tested it already)" not in text
    assert [r["gateway"] for r in store.load()[0]] == [C["gateway"]]


def timed_watch(mac, **kw):
    """Run watch_loop on mac and keep its timing: the time limit (from when
    watch has found the Wi-Fi interface), each measurement's two steps and
    each API check as a (kind, start, end) span, and each sleep as (start,
    end). -> (rc, records, limit, spans, sleeps)."""
    p = make_prober(mac)
    marks, spans, sleeps = {}, [], []
    find = p.wifi_interface

    def wifi_interface():
        got = find()
        marks["limit"] = mac.now + kw["minutes"] * 60
        return got

    def timed(kind, fn):
        def run(*a, **k):
            start = mac.now
            try:
                return fn(*a, **k)
            finally:
                spans.append((kind, start, mac.now))
        return run

    def sleep(seconds):
        start = mac.now
        mac.sleep(seconds)
        sleeps.append((start, mac.now))

    p.wifi_interface, p.sleep = wifi_interface, sleep
    p.candidates, p.measure = timed("candidates", p.candidates), timed("measure", p.measure)
    p.api_check = timed("api", p.api_check)
    with tempfile.TemporaryDirectory() as d:
        store = NP.Store(pathlib.Path(d) / "history.jsonl")
        rc = NP.watch_loop(p, store, out=lambda s: None, **kw)
        recs, bad = store.load()
    assert bad == 0 and p.deadline is None  # watch leaves no limit behind on the prober
    return rc, recs, marks["limit"], spans, sleeps


SLOW = ("netstat", "route", "ipconfig", "curl", "osascript", "ping")  # networksetup runs before the limit starts


@given(switches=st.lists(st.tuples(st.floats(1, 900), st.sampled_from([A, B, C]),
                                   st.sampled_from([0.0, 20.0, 1e9])), max_size=6),
       minutes=st.floats(0, 12), settle=st.sampled_from([0.0, 10.0, 30.0]),
       portal_wait=st.sampled_from([0.0, 60.0, 480.0]), baseline=st.booleans(), max_new=st.integers(0, 3),
       costs=st.dictionaries(st.sampled_from(SLOW), st.floats(0, 30)))
def test_watch_never_waits_past_its_time_limit(switches, minutes, settle, portal_wait, baseline, max_new, costs):
    """Invariant, for any sequence of switches and any command durations: no
    command outside a measurement or API check, and no wait, settle or poll,
    runs past --minutes. Every measurement and API check starts before it. A
    network that measured online is never measured again, and at most --max
    new ones are."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A))] + sorted(
        ((T0 + t, wifi(online_after=after, **net)) for t, net, after in switches), key=lambda s: s[0])
    mac.cost = lambda a: costs.get(a[0], 0.0)
    rc, recs, limit, spans, sleeps = timed_watch(mac, baseline=baseline, max_new=max_new, minutes=minutes,
                                                 portal_wait=portal_wait, settle=settle)
    assert rc == 0
    eps = 1e-6  # the fake clock counts from T0 = 1.8e9 s, so sums round by about 2e-7 s

    def inside(start, end):
        return any(a <= start and end <= b for _kind, a, b in spans)

    # a measurement starts with its candidates step, which may run past the limit
    assert all(start < limit for kind, start, _ in spans if kind in ("candidates", "api"))
    for start, end, argv in mac.timeline:
        assert inside(start, end) or end <= limit + eps, (argv, start - T0, end - T0, limit - T0)
    assert all(end <= limit + eps for start, end in sleeps if not inside(start, end))
    assert mac.now <= max([limit] + [b for _kind, _a, b in spans]) + eps
    online = [r["gateway"] for r in recs if r["online"]]
    assert len(online) == len(set(online))
    assert len(recs) <= max_new + baseline


def test_watch_without_wifi_hardware(tmp_path):
    class NoWifi(FakeMac):
        def answer(self, a, stdin):
            if a[0] == "networksetup":
                return NP.Proc(0, "\nHardware Port: USB 10/100/1000 LAN\nDevice: en5\n")
            return super().answer(a, stdin)

    rc, text, _ = watch(NoWifi([tether()]), tmp_path)
    assert rc == 3 and "No Wi-Fi interface found." in text


def test_a_slow_captive_check_stops_at_the_time_limit(tmp_path):
    """Round-2 review: a captive check that started 2 s before the end of a
    1-minute watch ran its 8 s, so the watch ended at 66 s."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 58, wifi(online_after=1e9, **B))]
    mac.cost = lambda a: 8.0 if a[0] == "curl" and a[-1] == NP.CAPTIVE_URL else 0.0
    rc, text, store = watch(mac, tmp_path, minutes=1, max_new=1)
    assert rc == 0 and mac.now == T0 + 60 and store.load() == ([], 0)
    assert "new network: gateway 10.243.10.226" in text and "no internet before the 1-minute limit, so netpick didn't measure it" in text


def test_a_slow_gateway_read_while_settling_starts_no_measurement_after_the_limit(tmp_path):
    """Round-2 review: a gateway read that started 1 s before the end of the
    settle and of a 1-minute watch ran 8 s, and the measurement started at 67 s."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 58, wifi(**B))]
    mac.cost = lambda a: 8.0 if a[0] == "netstat" and mac.now >= T0 + 59 else 0.0
    rc, text, store = watch(mac, tmp_path, minutes=1, max_new=1, settle=1)
    assert rc == 0 and mac.now == T0 + 60 and store.load() == ([], 0) and not mac.argvs("ping")
    assert "letting DNS settle for 1s" in text and "the 1-minute limit came before the measurement, so netpick didn't measure it" in text


def test_a_measurement_that_starts_before_the_limit_runs_to_its_end(tmp_path):
    """The limit cuts waits and reads, not a measurement under way: pings
    that take 10 s still finish when the watch has 3 s."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A))]
    mac.cost = lambda a: 10.0 if a[0] == "ping" else 0.0
    rc, text, store = watch(mac, tmp_path, baseline=True, minutes=0.05, max_new=1)
    recs, _ = store.load()
    assert rc == 0 and len(recs) == 1 and recs[0]["ping"]["received"] == 40 and mac.now == T0 + 10
    assert "done: measured 1 network(s)" in text


def test_a_watch_with_no_time_skips_the_baseline(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A))]
    rc, text, store = watch(mac, tmp_path, baseline=True, minutes=0)
    assert rc == 0 and "baseline: the 0-minute limit has passed, so netpick skipped it" in text and store.load() == ([], 0)
    assert [a[0] for _t, _gw, a in mac.calls] == ["networksetup"]  # finding the Wi-Fi interface, before the limit
    mac = FakeMac([], primary="en0")  # a captive check that passes just as the 3 s run out
    mac.wifi_schedule = [(T0, wifi(**A))]
    mac.cost = lambda a: 3.0 if a[0] == "curl" else 0.0
    rc, text, store = watch(mac, tmp_path, baseline=True, minutes=0.05)
    assert "baseline: the 0.05-minute limit has passed, so netpick skipped it" in text and not mac.argvs("ping")


def test_no_api_check_starts_at_the_limit(tmp_path):
    """Back on a tested network, with a captive check that passes just as the
    minute runs out and no settle: the limit has come, so no API check."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 58, wifi(**B))]
    mac.cost = lambda a: 2.0 if a[0] == "curl" and a[-1] == NP.CAPTIVE_URL else 0.0
    rc, text, _ = watch(mac, tmp_path, seen=[B["gateway"]], minutes=1, max_new=1, settle=0)
    assert "back on gateway 10.243.10.226 (netpick tested it already)" in text and "API check" not in text
    assert mac.now == T0 + 60 and all(NP.CAPTIVE_URL in a for a in mac.argvs("curl"))


def switch_between_the_settle_and_the_measurement():
    """The settle's last read comes at T0 + 40, and the measurement's at T0 + 41."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(**B)), (T0 + 40.5, wifi(**C))]
    mac.cost = one_second_gateway_reads
    return mac


def test_a_switch_as_a_measurement_starts_gives_the_new_network_its_settle(tmp_path):
    """A measurement at once would catch the new network's DNS before it settles."""
    mac = switch_between_the_settle_and_the_measurement()
    rc, text, store = watch(mac, tmp_path, minutes=5, max_new=2, settle=30)
    assert "the network changed as the measurement started, so netpick skipped it" in text
    assert "new network: gateway 172.16.224.1" in text
    assert [r["gateway"] for r in store.load()[0]] == [C["gateway"]]
    assert min(t for t, gw, argv in mac.calls if argv[0] == "ping") >= T0 + 40.5 + 30


def test_a_switch_as_a_measurement_starts_measures_no_seen_gateway(tmp_path):
    mac = switch_between_the_settle_and_the_measurement()
    rc, text, store = watch(mac, tmp_path, seen=[C["gateway"]], minutes=5, max_new=2, settle=30)
    assert store.load() == ([], 0) and not mac.argvs("ping")
    assert "back on gateway 172.16.224.1" in text and "API check: 4/4" in text


# ---------------------------------------------------------------- CLI


# ---------------------------------------------------------------- a network that drops and comes back


def one_second_gateway_reads(argv):
    return 1.0 if argv[0] == "netstat" else 0.0


@pytest.mark.parametrize("gap, online_after", [(T0 + 16, 0.0), (T0 + 14, 20.0)],
                         ids=["while DNS settles", "during the portal wait"])
def test_a_network_that_drops_for_one_read_still_gets_measured(tmp_path, gap, online_after):
    """Round-3 review: the one read without a gateway ended the visit, and the
    same gateway coming back didn't start another, so watch never measured it.
    A read takes 1 s, so the next one finds the network back."""
    mac = FakeMac([], primary="en0")
    mac.cost = one_second_gateway_reads
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(online_after=online_after, **C)), (gap, None),
                         (gap + 0.5, wifi(online_after=online_after, **C))]
    rc, text, store = watch(mac, tmp_path, settle=30, max_new=1, minutes=5)
    assert text.count("new network: gateway 172.16.224.1") == 2
    assert [r["gateway"] for r in store.load()[0]] == [C["gateway"]]


def test_a_network_i_come_back_to_after_a_drop_gets_its_measurement(tmp_path):
    """The portal wait ran out, the Wi-Fi dropped, and the same gateway came back signed in."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(online_after=1e9, **C)), (T0 + 130, None),
                         (T0 + 140, wifi(**C))]
    rc, text, store = watch(mac, tmp_path, portal_wait=60, max_new=1, minutes=15)
    assert "still no internet after 1 min" in text
    assert [r["gateway"] for r in store.load()[0]] == [C["gateway"]]


def test_a_drop_from_a_tested_network_gets_a_check_and_no_second_measurement(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(**C)), (T0 + 100, None), (T0 + 110, wifi(**C))]
    rc, text, store = watch(mac, tmp_path, max_new=2, minutes=5)
    assert [r["gateway"] for r in store.load()[0]] == [C["gateway"]]
    assert "back on gateway 172.16.224.1 (netpick tested it already)" in text and "API check: 4/4" in text


@pytest.mark.parametrize("gap, online_after", [(T0 + 16, 0.0), (T0 + 14, 20.0)],
                         ids=["while DNS settles", "during the wait for internet"])
def test_a_tested_network_that_drops_for_one_read_still_gets_its_check(tmp_path, gap, online_after):
    """Round-4 review: the same drop on a --seen gateway left the visit open,
    so the network came back and stayed, and netpick never checked it."""
    mac = FakeMac([], primary="en0")
    mac.cost = one_second_gateway_reads
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(online_after=online_after, **C)), (gap, None),
                         (gap + 0.5, wifi(online_after=online_after, **C))]
    rc, text, store = watch(mac, tmp_path, seen=[C["gateway"]], settle=30, max_new=1, minutes=5)
    assert text.count("back on gateway 172.16.224.1") == 2 and text.count("API check: 4/4") == 1
    assert store.load() == ([], 0)


def test_a_tested_network_without_internet_says_why_it_got_no_check(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(online_after=1e9, **C))]
    rc, text, store = watch(mac, tmp_path, seen=[C["gateway"]], max_new=1, minutes=5)
    assert "still no internet after 1 min, so netpick didn't check it" in text and "API check" not in text
    mac = FakeMac([], primary="en0")  # the wait runs into the limit: its last gateway read comes back empty
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 30, wifi(online_after=1e9, **C))]
    rc, text, store = watch(mac, tmp_path, seen=[C["gateway"]], max_new=1, minutes=1)
    assert "back on gateway 172.16.224.1" in text and "still no internet" not in text
    mac = FakeMac([], primary="en0")  # the limit cuts a slow captive check: no minute has passed
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 58, wifi(**C))]
    mac.cost = lambda a: 8.0 if a[0] == "curl" and a[-1] == NP.CAPTIVE_URL else 0.0
    rc, text, store = watch(mac, tmp_path, seen=[C["gateway"]], max_new=1, minutes=1)
    assert "back on gateway 172.16.224.1" in text and "still no internet" not in text


def test_a_drop_while_settling_at_the_limit_keeps_the_current_network_in_the_last_table(tmp_path):
    """The limit cuts off the settle's last gateway read on a tested network.
    That read says nothing about the network, so the last table keeps its marker."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 5, wifi(**B)), (T0 + 20, wifi(**C)), (T0 + 54, wifi(**B))]
    mac.cost = lambda argv: 1000.0 if argv[0] == "netstat" and mac.now >= T0 + 59 else 0.0  # only the last read
    rc, text, store = watch(mac, tmp_path, settle=5, max_new=5, minutes=1, poll=1)
    assert [r["gateway"] for r in store.load()[0]] == [B["gateway"], C["gateway"]]
    assert "back on gateway 10.243.10.226" in text
    tail = text.split(" done: measured 2 network(s)")[1]
    assert " *" in tail


@pytest.mark.parametrize("gap", [T0 + 16.8, T0 + 17.8], ids=["the route read", "the address read"])
def test_a_drop_as_a_measurement_starts_ends_the_visit(tmp_path, gap):
    """A settle of 5 s ends with a read at T0 + 14 and one at T0 + 16, so the
    measurement reads the routes at T0 + 17 and the address at T0 + 18. A drop
    across the first left a row with no gateway; a drop across the second left
    the network unmeasured."""
    mac = FakeMac([], primary="en0")
    mac.cost = one_second_gateway_reads
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(**C)), (gap, None), (gap + 0.5, wifi(**C))]
    rc, text, store = watch(mac, tmp_path, settle=5, max_new=1, minutes=5)
    assert text.count("new network: gateway 172.16.224.1") == 2
    assert [r["gateway"] for r in store.load()[0]] == [C["gateway"]]


def test_a_gateway_read_cut_off_at_the_limit_keeps_the_current_network_in_the_last_table(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(**B)), (T0 + 50, wifi(**C))]
    mac.cost = lambda argv: 1000.0 if argv[0] == "netstat" and mac.now >= T0 + 119 else 0.0  # only the last read
    rc, text, store = watch(mac, tmp_path, settle=5, max_new=5, minutes=2, poll=1)
    assert [r["gateway"] for r in store.load()[0]] == [B["gateway"], C["gateway"]]
    tail = text.split(" done: measured 2 network(s)")[1]
    assert " *" in tail and "Best link" not in tail


NETWORKS = {"A": A, "B": B, "C": C}


@given(visits=st.lists(st.tuples(st.sampled_from([None, "A", "B", "C"]), st.floats(0.5, 90)), max_size=8),
       stay=st.sampled_from(["A", "B", "C"]), portal=st.sampled_from([0.0, 20.0]))
def test_watch_measures_any_network_i_stay_on_long_enough(visits, stay, portal):
    """Whatever came before, a stay that outlasts the portal and the settle
    ends with a measurement of that network."""
    mac = FakeMac([], primary="en0")
    mac.cost = one_second_gateway_reads
    schedule, t = [(T0, wifi(gateway="192.0.2.1", ip="192.0.2.5", security="WPA2_PSK"))], T0 + 3
    for name, seconds in visits:
        schedule.append((t, wifi(**NETWORKS[name]) if name else None))
        t += seconds
    schedule.append((t, wifi(online_after=portal, **NETWORKS[stay])))
    mac.wifi_schedule = schedule
    with tempfile.TemporaryDirectory() as d:
        rc, text, store = watch(mac, pathlib.Path(d), settle=30, portal_wait=60, max_new=50,
                                minutes=(t - T0 + 200) / 60)
        assert NETWORKS[stay]["gateway"] in [r["gateway"] for r in store.load()[0]], text


@given(visits=st.lists(st.tuples(st.sampled_from([None, "A", "B", "C"]), st.floats(0.5, 90)), max_size=8),
       stay=st.sampled_from(["A", "B", "C"]), portal=st.sampled_from([0.0, 20.0]))
def test_watch_checks_any_tested_network_i_stay_on_long_enough(visits, stay, portal):
    """Whatever came before, the last visit to a tested network that I stay on
    long enough ends with a connection check, and no measurement of it. A drop
    that falls between two reads ends no visit, so the check can come before it."""
    mac = FakeMac([], primary="en0")
    mac.cost = one_second_gateway_reads
    schedule, t = [(T0, wifi(gateway="192.0.2.1", ip="192.0.2.5", security="WPA2_PSK"))], T0 + 3
    for name, seconds in visits:
        schedule.append((t, wifi(**NETWORKS[name]) if name else None))
        t += seconds
    schedule.append((t, wifi(online_after=portal, **NETWORKS[stay])))
    mac.wifi_schedule = schedule
    gateway, lines = NETWORKS[stay]["gateway"], []
    with tempfile.TemporaryDirectory() as d:
        store = NP.Store(pathlib.Path(d) / "history.jsonl")
        rc = NP.watch_loop(make_prober(mac), store, seen=[gateway], settle=30, portal_wait=60, max_new=50,
                           minutes=(t - T0 + 200) / 60, out=lines.append)
        assert rc == 0 and gateway not in [r["gateway"] for r in store.load()[0]]
    visits_to_it = [i for i, s in enumerate(lines) if f"back on gateway {gateway}" in s]
    assert visits_to_it and any("API check" in s for s in lines[visits_to_it[-1]:]), lines


def corrected_prober(mac, correction, at):
    """A Prober on a Mac whose wall clock steps by `correction` seconds at time `at`."""
    return NP.Prober(runner=mac, dns=mac.dns, resolve=mac.resolve, counters=mac.if_counters, sleep=mac.sleep,
                     clock=lambda: mac.now + (correction if mac.now >= at else 0.0), monotonic=mac.clock)


CORRECTIONS = pytest.mark.parametrize("correction", [-120.0, 3600.0], ids=["back two minutes", "ahead an hour"])


def timed_lines(mac):
    lines = []

    def seconds_between(first, second):
        return next(t for t, s in lines if second in s) - next(t for t, s in lines if first in s)

    return lambda s="": lines.append((mac.now, s)), seconds_between


@CORRECTIONS
def test_a_wall_clock_correction_leaves_the_watch_limit_alone(tmp_path, correction):
    """Round-3 review: watch timed its limit on the wall clock, so a step back
    of 120 s made a 60 s limit last 180 s."""
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 20, wifi(online_after=1e9, **C))]
    lines = []
    rc = NP.watch_loop(corrected_prober(mac, correction, T0 + 10), NP.Store(tmp_path / "history.jsonl"), minutes=1,
                       out=lines.append)
    assert rc == 0 and mac.now - T0 == pytest.approx(60) and "no internet before the 1-minute limit" in "\n".join(lines)


def test_a_wall_clock_correction_leaves_a_commands_limit_alone(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 58, wifi(online_after=1e9, **B))]
    mac.cost = lambda a: 8.0 if a[0] == "curl" and a[-1] == NP.CAPTIVE_URL else 0.0
    rc = NP.watch_loop(corrected_prober(mac, -120.0, T0 + 10), NP.Store(tmp_path / "history.jsonl"), minutes=1,
                       max_new=1, out=lambda s="": None)
    assert rc == 0 and mac.now == T0 + 60


@CORRECTIONS
def test_a_wall_clock_correction_moves_no_wait(tmp_path, correction):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(online_after=1e9, **C))]
    out, seconds_between = timed_lines(mac)
    NP.watch_loop(corrected_prober(mac, correction, T0 + 15), NP.Store(tmp_path / "history.jsonl"), minutes=5,
                  portal_wait=20, out=out)
    assert seconds_between("new network:", "still no internet") == pytest.approx(20)


@CORRECTIONS
def test_a_wall_clock_correction_moves_no_settle(tmp_path, correction):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 10, wifi(**C))]
    out, seconds_between = timed_lines(mac)
    NP.watch_loop(corrected_prober(mac, correction, T0 + 15), NP.Store(tmp_path / "history.jsonl"), minutes=5,
                  settle=10, max_new=1, out=out)
    assert seconds_between("letting DNS settle", " measuring") == pytest.approx(10)


def test_a_measurement_times_its_duration_on_the_monotonic_clock():
    mac = FakeMac([wifi()])
    mac.cost = lambda argv: 1.0
    prober = NP.Prober(runner=mac, opts=NP.Options(stream=False, nq=False), dns=mac.dns, resolve=mac.resolve,
                       counters=mac.if_counters, sleep=mac.sleep, clock=lambda: T0 - (mac.now - T0), monotonic=mac.clock)
    assert prober.measure(prober.candidates())[0]["duration_s"] > 0


# ---------------------------------------------------------------- the command line


def run_cli(argv, mac=None, tmp_path=None, store=None):
    lines = []
    store = store or NP.Store(tmp_path / "history.jsonl")
    prober = make_prober(mac) if mac else None
    rc = NP.main(argv, prober=prober, store=store, out=lines.append)
    return rc, "\n".join(lines), store


CAPTURES = [str(FIXTURES / n) for n in ("nettest_appam.txt", "nettest_net1_wpa3.txt", "nettest_net1_open.txt")]


def test_import_then_history_views(tmp_path):
    rc, text, store = run_cli(["import", *CAPTURES], tmp_path=tmp_path)
    assert rc == 0 and "imported 3 measurement(s)" in text
    rc, text, _ = run_cli(["import", *CAPTURES, str(FIXTURES / "ipinfo.json")], store=store)
    assert text.count("already in the history") == 3 and "not a nettest.sh capture" in text
    assert "imported 0 measurement(s)" in text
    rc, text, _ = run_cli(["history", "--rank"], store=store)
    rows = text.splitlines()
    assert rows[1].split()[1:6] == ["Wi-Fi", "WPA2", "gw", "172.21.112.1", NP.network_id(
        {"kind": "wifi", "gateway": "172.21.112.1", "security_class": "wpa2"})]
    assert "gw 10.243.10.226" in rows[2] and "gw 172.16.224.1" in rows[3]
    rc, text, _ = run_cli(["history", "--by-network"], store=store)
    assert len(text.splitlines()) == 1 + 3 + 1 and "Each row gives one network's medians." in text
    rc, text, _ = run_cli(["history", "--network", "wpa3", "--json"], store=store)
    assert [r["source_label"] for r in json.loads(text)] == ["net1_wpa3"]
    rc, text, _ = run_cli(["history", "--since", "1s"], store=store)
    assert "No measurements" in text and "within 1s" in text


def test_names(tmp_path):
    _, _, store = run_cli(["import", *CAPTURES], tmp_path=tmp_path)
    nid = NP.network_id({"kind": "wifi", "gateway": "172.21.112.1", "security_class": "wpa2"})
    rc, text, _ = run_cli(["name", nid[:5], "APPAM", "venue"], store=store)
    assert rc == 0 and text == f"{nid}: named 'APPAM venue'"
    assert "APPAM venue" in run_cli(["history", "--rank"], store=store)[1]
    assert run_cli(["name", "--list"], store=store)[1] == f"{nid}  APPAM venue"
    rc, text, _ = run_cli(["name", "zzzz", "x"], store=store)
    assert rc == 2 and "no such network id" in text
    store.set_name("aaaa1111", "one")
    store.set_name("aaaa2222", "two")
    rc, text, _ = run_cli(["name", "aaaa", "x"], store=store)
    assert rc == 2 and "ambiguous: aaaa1111, aaaa2222" in text
    rc, text, _ = run_cli(["name", nid, "--clear"], store=store)
    assert text == f"{nid}: name cleared" and nid not in store.names()


def test_history_skips_unreadable_lines(tmp_path):
    _, _, store = run_cli(["import", CAPTURES[0]], tmp_path=tmp_path)
    with open(store.path, "a") as f:
        f.write('{"truncated": \n["not a record"]\n{"time": "2026-11-05T20:00:00Z"}\n\n')
    recs, bad = store.load()
    assert len(recs) == 1 and bad == 3
    assert "(netpick skipped 3 unreadable line(s))" in run_cli(["history"], store=store)[1]


@pytest.mark.parametrize("flags, scope", [([], ""), (["--since", "2h"], " within 2h"),
                                          (["--network", "wpa3"], " for wpa3"), (["--rank"], ""), (["--by-network"], ""),
                                          (["--network", "wpa3", "--since", "2h"], " for wpa3 within 2h")],
                         ids=lambda v: " ".join(v) if isinstance(v, list) else None)
def test_a_history_with_nothing_readable_still_gives_the_count(tmp_path, flags, scope):
    """Round-4 review: with no line readable, netpick said only "No
    measurements", so a damaged history looked empty."""
    store = NP.Store(tmp_path / "history.jsonl")
    store.path.write_text('{"truncated": \n["not a record"]\n')
    rc, text, _ = run_cli(["history", *flags], store=store)
    assert rc == 0 and text == f"No measurements in {store.path}{scope}.\n(netpick skipped 2 unreadable line(s))"


def test_history_json_gives_the_count_on_stderr(tmp_path, capsys):
    store = NP.Store(tmp_path / "history.jsonl")
    store.path.write_text('{"truncated": \n["not a record"]\n')
    rc, text, _ = run_cli(["history", "--json"], store=store)
    assert rc == 0 and json.loads(text) == []
    assert capsys.readouterr().err == "(netpick skipped 2 unreadable line(s))\n"


def test_a_clean_history_mentions_no_skipped_lines(tmp_path, capsys):
    _, _, store = run_cli(["import", CAPTURES[0]], tmp_path=tmp_path)
    for flags in ([], ["--since", "1s"], ["--network", "no such network"], ["--json"]):
        assert "skipped" not in run_cli(["history", *flags], store=store)[1]
    assert capsys.readouterr().err == ""


def test_a_record_with_malformed_fields_is_skipped_not_shown(tmp_path):
    """Review finding 7: a line with a valid time and id but `"conns": [1]`
    loaded, then crashed `netpick history` with AttributeError."""
    _, _, store = run_cli(["import", CAPTURES[0]], tmp_path=tmp_path)
    good = json.loads(store.path.read_text())
    broken = [dict(good, online=True, conns=[1]), dict(good, ping={"sent": "40"}), dict(good, online="yes"),
              dict(good, metrics=dict(good["metrics"], via=3)), dict(good, notes="not a list"),
              dict(good, data_bytes=float("nan")), dict(good, egress={"org": 7}), dict(good, time="yesterday"),
              dict(good, network_id=""), dict(good, label=["x"]), dict(good, nq={"bytes": 10**400})]
    with open(store.path, "a") as f:
        f.writelines(json.dumps(r) + "\n" for r in broken)
    assert store.load() == ([good], len(broken))
    for view in VIEWS:
        assert run_cli(view, store=store)[0] == 0
    assert f"(netpick skipped {len(broken)} unreadable line(s))" in run_cli(["history"], store=store)[1]


VIEWS = (["history"], ["history", "--rank"], ["history", "--by-network"], ["history", "--json"],
         ["history", "--network", "wpa"], ["history", "--since", "30d"], ["name", "--list"])


def base_records():
    """Valid history lines as they read back from the file: the three captures,
    a watch run over a Wi-Fi network and a tether, and an offline network."""
    recs = [NP.parse_capture(pathlib.Path(p).read_text(), source=pathlib.Path(p).name) for p in CAPTURES]
    mac = FakeMac([wifi(**B), tether()], now=T0 - 600)
    recs += make_prober(mac).measure(make_prober(mac).candidates(), mode="watch")
    off = FakeMac([wifi(online_after=1e9, **C)], now=T0 - 300)
    recs += make_prober(off).measure(make_prober(off).candidates(), mode="watch")
    return [json.loads(json.dumps(r)) for r in recs]


BASE = base_records()
KEYS = sorted({k for r in BASE for v in (r, *(x for x in r.values() if isinstance(x, dict))) for k in v})
JSON_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=6),
    lambda kids: st.lists(kids, max_size=3) | st.dictionaries(st.text(max_size=6), kids, max_size=3),
    max_leaves=5,
)


def paths(x, here=()):
    yield here
    if isinstance(x, dict):
        for k, v in x.items():
            yield from paths(v, (*here, k))
    elif isinstance(x, list):
        for i, v in enumerate(x):
            yield from paths(v, (*here, i))


def at(x, path):
    for p in path:
        x = x[p]
    return x


@st.composite
def damaged_record(draw):
    """A valid record with one to three changes: a value anywhere replaced by
    arbitrary JSON (NaN, huge integers and lone surrogates included), a known
    field set to one, or a field removed."""
    rec = copy.deepcopy(draw(st.sampled_from(BASE)))
    for _ in range(draw(st.integers(1, 3))):
        where = draw(st.sampled_from(list(paths(rec))), label="path")
        how = draw(st.sampled_from(("replace", "set", "drop")), label="how")
        target = at(rec, where)
        if how == "replace" or not isinstance(target, dict):
            value = draw(JSON_VALUES, label="value")
            if where:
                at(rec, where[:-1])[where[-1]] = value
            else:
                rec = value
        elif how == "set":
            target[draw(st.sampled_from(KEYS), label="key")] = draw(JSON_VALUES, label="value")
        elif target:
            del target[draw(st.sampled_from(sorted(target)), label="field")]
    return rec


@given(st.lists(damaged_record(), min_size=1, max_size=4), st.lists(st.sampled_from(BASE), max_size=3))
def test_no_history_line_crashes_a_view(damaged, intact):
    """Invariant: every line is shown or counted as skipped, every intact line
    is shown, and no line makes a view fail: the history views, `name`, the
    list of networks measured earlier in a plain run, and `import`."""
    with tempfile.TemporaryDirectory() as d:
        store = NP.Store(pathlib.Path(d) / "history.jsonl")
        lines = [json.dumps(r) for r in [*damaged, *intact]]
        store.path.write_text("".join(line + "\n" for line in lines))
        recs, bad = store.load()
        assert len(recs) + bad == len(lines) and len(recs) >= len(intact)
        for view in VIEWS:
            assert NP.main(view, store=store, out=lambda s="": None) == 0
        assert NP.main(["name", "0", "x"], store=store, out=lambda s="": None) in (0, 2)
        prober = make_prober(FakeMac([wifi(**A)]))
        assert NP.main(["--quick", "--no-history"], prober=prober, store=store, out=lambda s="": None) == 0
        assert NP.main(["import", CAPTURES[0]], store=store, out=lambda s="": None) == 0


@pytest.mark.parametrize("history", ["names.json", "link-to-names.jsonl", "."])
@pytest.mark.parametrize("cmd", [["import", CAPTURES[0]], ["name", "34849952", "x"], ["name", "--list"], ["history"],
                                 ["now", "--quick"], ["watch", "--minutes", "1"]], ids=lambda c: c[0])
def test_a_history_path_that_could_lose_data_is_refused(tmp_path, history, cmd):
    """Review finding 6: with `--history names.json`, import then name replaced
    the history with the names dictionary. Every command now refuses such a
    path before it reads or writes anything."""
    other = tmp_path / "other"
    other.mkdir()
    (other / "names.json").write_text('{"34849952": "APPAM"}\n')
    (tmp_path / "link-to-names.jsonl").symlink_to(other / "names.json")
    (tmp_path / "names.json").write_text('{"34849952": "APPAM"}\n')
    before = {p: p.read_bytes() for p in (tmp_path / "names.json", other / "names.json")}
    mac = FakeMac([wifi()])
    lines = []
    rc = NP.main([*cmd, "--history", str(tmp_path / history)], prober=make_prober(mac), out=lines.append)
    assert rc == 2 and lines[0].startswith("netpick: ") and len(lines) == 1
    assert ("is a directory" if history == "." else "netpick keeps network names in names.json files") in lines[0]
    assert {p: p.read_bytes() for p in before} == before and not mac.calls
    assert sorted(p.name for p in tmp_path.iterdir()) == ["link-to-names.jsonl", "names.json", "other"]



def appam_record():
    return NP.finalize(NP.parse_capture((FIXTURES / "nettest_appam.txt").read_text()))


@pytest.mark.parametrize("case", ["a link named names.json", "two links to one file", "hard links to one file",
                                  "two links to one file not made yet", "NAMES.JSON"])
@pytest.mark.parametrize("cmd", [["import", CAPTURES[1]], ["name", "34849952", "x"], ["history"], ["now", "--quick"]],
                         ids=lambda c: c[0])
def test_a_history_that_shares_a_file_with_names_is_refused(tmp_path, case, cmd):
    """Round-2 review: `--history names.json` as a link to the real history
    passed the check, so naming replaced the link with the names object, and
    with the history and names.json linked to one file, import wrote records
    into the names. On a Mac's case-insensitive disk NAMES.JSON is names.json."""
    actual = tmp_path / "actual.jsonl"
    NP.Store(actual).append([appam_record()])
    history = tmp_path / "history.jsonl"
    if case == "a link named names.json":
        history = tmp_path / "names.json"
        history.symlink_to(actual)
    elif case == "two links to one file":
        history.symlink_to(actual)
        (tmp_path / "names.json").symlink_to(actual)
    elif case == "hard links to one file":
        os.link(actual, history)
        os.link(actual, tmp_path / "names.json")
    elif case == "two links to one file not made yet":
        history.symlink_to(tmp_path / "later.jsonl")
        (tmp_path / "names.json").symlink_to(tmp_path / "later.jsonl")
    else:
        history = tmp_path / "NAMES.JSON"
        history.write_bytes(actual.read_bytes())

    def layout():
        return {q.name: os.readlink(q) if q.is_symlink() else q.read_bytes() for q in tmp_path.iterdir()}

    before = layout()
    mac = FakeMac([wifi()])
    lines = []
    rc = NP.main([*cmd, "--history", str(history)], prober=make_prober(mac), out=lines.append)
    assert rc == 2 and len(lines) == 1 and lines[0].startswith("netpick: ") and not mac.calls
    assert ("are one file" if "one file" in case else "netpick keeps network names in names.json files") in lines[0]
    assert layout() == before


@pytest.mark.parametrize("history", ["/", ".", "a" * 300, "fifo", "file/history.jsonl", "unreadable.jsonl"])
def test_an_unusable_history_path_gets_one_line(tmp_path, monkeypatch, history):
    """Round-2 review: `--history /` crashed with ValueError before the
    directory check. A name too long for the disk crashed Python 3.11's
    Path.is_dir, a history netpick can't read crashed the views, and reading
    a named pipe would wait for a writer."""
    monkeypatch.chdir(tmp_path)
    os.mkfifo(tmp_path / "fifo")
    (tmp_path / "file").write_text("")
    (tmp_path / "unreadable.jsonl").write_text("")
    (tmp_path / "unreadable.jsonl").chmod(0)
    for cmd in (["history"], ["name", "--list"], ["import", CAPTURES[0]]):
        lines = []
        assert NP.main([*cmd, "--history", history], out=lines.append) == 2
        assert len(lines) == 1 and lines[0].startswith("netpick: ")
    assert sorted(q.name for q in tmp_path.iterdir()) == ["fifo", "file", "unreadable.jsonl"]


@pytest.mark.parametrize("tail", ["a whole record", "a record cut short"])
def test_a_record_appended_after_a_last_line_without_a_newline_gets_its_own_line(tmp_path, tail):
    """Round-2 review: after a last record with no newline (a hand edit), the
    next record went onto the same line, and both dropped out of the views.
    A record cut short stays one skipped line."""
    store = NP.Store(tmp_path / "history.jsonl")
    store.append([appam_record()])
    text = store.path.read_text().rstrip("\n")
    store.path.write_text(text if tail == "a whole record" else text[: len(text) // 2])
    assert run_cli(["import", CAPTURES[1]], store=store)[0] == 0
    recs, bad = store.load()
    want = (["appam", "net1_wpa3"], 0) if tail == "a whole record" else (["net1_wpa3"], 1)
    assert ([r["source_label"] for r in recs], bad) == want
    assert store.path.read_text().endswith("\n")


def test_saving_a_name_leaves_the_history_alone(tmp_path):
    _, _, store = run_cli(["import", *CAPTURES], tmp_path=tmp_path)
    before = store.path.read_bytes()
    nid = NP.network_id({"kind": "wifi", "gateway": "172.21.112.1", "security_class": "wpa2"})
    assert run_cli(["name", nid, "APPAM"], store=store)[0] == 0
    assert run_cli(["name", nid, "APPAM venue"], store=store)[0] == 0
    assert store.path.read_bytes() == before and store.names() == {nid: "APPAM venue"}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["history.jsonl", "names.json"]  # no temporary file left


def test_a_names_file_that_cant_be_written_is_reported(tmp_path, monkeypatch):
    _, _, store = run_cli(["import", CAPTURES[0]], tmp_path=tmp_path)
    def refuse(*a, **k):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(NP.tempfile, "mkstemp", refuse)
    rc, text, _ = run_cli(["name", "34849952", "APPAM"], store=store)
    assert rc == 1 and text == f"netpick: couldn't write the names file {store.names_path}: Permission denied"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["history.jsonl"]


def test_a_names_file_that_cant_be_read_is_reported(tmp_path):
    _, _, store = run_cli(["import", CAPTURES[0]], tmp_path=tmp_path)
    store.names_path.mkdir()  # something else holds the name
    for cmd in (["name", "34849952", "APPAM"], ["name", "--list"]):
        rc, text, _ = run_cli(cmd, store=store)
        assert rc == 1 and text == f"netpick: couldn't read the names file {store.names_path}: Is a directory"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["history.jsonl", "names.json"]


@pytest.mark.parametrize("damaged", ['{"34849952": "APPAM", "aaaa1111": "one"', '["APPAM"]', "\udcff",
                                     "[" * 100_000 + "]" * 100_000])
def test_a_names_file_that_doesnt_parse_keeps_its_names(tmp_path, damaged):
    """A hand edit that leaves names.json unparseable: before, the next
    `netpick name` replaced the file with that one name and lost the rest."""
    _, _, store = run_cli(["import", CAPTURES[0]], tmp_path=tmp_path)
    store.names_path.write_bytes(damaged.encode("utf-8", "surrogateescape"))
    before = store.names_path.read_bytes()
    for cmd in (["name", "34849952", "APPAM venue"], ["name", "--list"]):
        rc, text, _ = run_cli(cmd, store=store)
        assert rc == 1 and text == (f"netpick: the names file {store.names_path} doesn't parse as a JSON object, "
                                    "so netpick leaves it as it is; fix or remove it")
    with pytest.raises((ValueError, RecursionError)):
        store.set_name("34849952", "APPAM venue")
    assert store.names_path.read_bytes() == before and store.names() == {}
    for view in VIEWS[:-1]:
        assert run_cli(view, store=store)[0] == 0  # the views show the networks without names
    assert sorted(p.name for p in tmp_path.iterdir()) == ["history.jsonl", "names.json"]


def test_odd_characters_survive_the_history_and_names_files(tmp_path):
    """A lone surrogate, which only a damaged or hostile input can produce
    (here an egress owner's name), goes to the files as its JSON escape."""
    rec = NP.parse_capture((FIXTURES / "nettest_appam.txt").read_text())
    rec["egress"] = {"org": "AS64500 Café \ud83d"}
    NP.finalize(rec)
    store = NP.Store(tmp_path / "history.jsonl")
    store.append([rec])
    assert store.load() == ([json.loads(json.dumps(rec))], 0) and "\ud83d" in store.load()[0][0]["label"]
    store.set_name(rec["network_id"], "n\udcff")
    assert store.names() == {rec["network_id"]: "n\udcff"}
    assert "Café" in store.path.read_text(encoding="utf-8")  # other text stays readable


def test_bad_windows_exit_2_before_measuring(tmp_path):
    mac = FakeMac([wifi()])
    rc, text, _ = run_cli(["--recent", "soon"], mac, tmp_path)
    assert rc == 2 and "--recent" in text and not mac.calls
    rc, text, _ = run_cli(["history", "--since", "2 hours"], tmp_path=tmp_path)
    assert rc == 2 and "bad window '2 hours'" in text


def test_now_prints_table_recommendation_and_notes(tmp_path):
    mac = FakeMac([wifi(loss_pct=15.0, rtt_ms=330.0, rtt_sd=80.0), tether_like_1104()], primary="en13")
    rc, text, store = run_cli([], mac, tmp_path)
    assert rc == 0
    lines = text.splitlines()
    assert lines[0].split()[:3] == ["#", "network", "id"]
    assert lines[1].startswith("1  Wi-Fi WPA2 gw 172.21.112.1") and lines[2].startswith("2  Pixel 11 Pro Fold")
    assert " *" in lines[2] and "4/8" in lines[2] and "1-conn" in lines[2]
    assert "Switch to Wi-Fi WPA2 gw 172.21.112.1" in text and "Turn off or unplug Pixel 11 Pro Fold" in text
    assert "en13: networkQuality failed" in text and "en0: DNS 172.21.112.1 answered 4/4" in text
    assert text.rstrip().endswith(f"history: {store.path}")
    assert len(store.load()[0]) == 2


def test_now_json(tmp_path):
    mac = FakeMac([wifi(), tether_like_1104()], primary="en13")
    rc, text, store = run_cli(["--json", "--quick", "--no-history"], mac, tmp_path)
    got = json.loads(text)
    assert got["version"] == NP.VERSION
    assert got["recommendation"]["action"] == "switch" and got["recommendation"]["interface"] == "en0"
    assert got["ranking"][0] == by_iface(got["records"])["en0"]["network_id"]
    assert all(r["data_bytes"] == 0 for r in got["records"]) and store.load() == ([], 0)


def test_now_lists_better_networks_measured_earlier(tmp_path):
    store = NP.Store(tmp_path / "history.jsonl")
    hotspot = {"v": 1, "time": NP.utc_stamp(T0 - 600), "run": "r", "mode": "watch", "interface": "en0",
               "kind": "wifi", "port": "Wi-Fi", "online": True, "gateway": B["gateway"], "security": "WPA3_SAE",
               "conns": {"attempted": 8, "ok": 8}, "ping": {"sent": 40, "received": 40, "loss_pct": 0.0,
                                                            "avg_ms": 40.0, "stddev_ms": 5.0},
               "nq": {"down_mbps": 25.0, "up_mbps": 16.5}, "notes": []}
    old = dict(hotspot, time=NP.utc_stamp(T0 - 3 * 3600), gateway="10.9.9.1")
    imported = dict(hotspot, time=NP.utc_stamp(T0 - 60), gateway="10.8.8.1", mode="import")
    store.append([NP.finalize(r) for r in (hotspot, old, imported)])
    mac = FakeMac([wifi(loss_pct=10.0)])
    rc, text, _ = run_cli(["--quick", "--no-history"], mac, store=store)
    assert "netpick measured these earlier (within 2h), not now:" in text
    assert "gw 10.243.10.226" in text and "10m ago" in text
    assert "10.9.9.1" not in text and "10.8.8.1" not in text
    assert "Wi-Fi WPA3 gw 10.243.10.226 beat Wi-Fi WPA2 gw 172.21.112.1" in text and "on packet loss" in text
    assert "netpick watch --baseline" in text
    rc, text, _ = run_cli(["--quick", "--no-history", "--recent", "0"], mac, store=store)
    assert "measured these earlier" not in text
    rc, text, _ = run_cli(["--quick", "--no-history", "--recent", "all"], mac, store=store)
    assert "netpick measured these earlier, not now:" in text and "10.9.9.1" in text and "10.8.8.1" not in text


def test_interfaces(tmp_path):
    mac = FakeMac([wifi(), tether()], primary="en13")
    rc, text, _ = run_cli(["interfaces"], mac, tmp_path)
    rows = [line.split() for line in text.splitlines()]
    assert rows[0] == ["iface", "port", "ip", "gateway", "security", "route"]
    assert rows[1][0] == "en13" and rows[1][-1] == "primary" and "WPA2_PSK" in rows[2]
    rc, text, _ = run_cli(["interfaces", "--json"], mac, tmp_path)
    assert [c["interface"] for c in json.loads(text)] == ["en13", "en0"]
    assert not [a for a in mac.argvs() if a[0] in PROBES]  # listing sends no traffic


def test_no_links(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, None)]
    rc, text, _ = run_cli(["--no-history"], mac, tmp_path)
    assert rc == 3 and "No candidate links" in text


def test_measuring_needs_macos(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    rc, text, _ = run_cli(["now", "--no-history"], tmp_path=tmp_path)
    assert rc == 2 and "run it on the Mac" in text


def test_the_script_runs_as_a_program(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "NETPICK_HOME": str(tmp_path / "state")}
    got = subprocess.run([sys.executable, str(SCRIPT), "--version"], capture_output=True, text=True, env=env, timeout=30)
    assert got.returncode == 0 and got.stdout.strip() == f"netpick {NP.VERSION}"
    got = subprocess.run([sys.executable, str(SCRIPT), "history"], capture_output=True, text=True, env=env, timeout=30)
    assert got.returncode == 0 and str(tmp_path / "state" / "history.jsonl") in got.stdout
    got = subprocess.run([sys.executable, str(SCRIPT), "import", CAPTURES[0]], capture_output=True, text=True,
                         env=env, timeout=30)
    assert "imported 1 measurement(s)" in got.stdout
    assert json.loads((tmp_path / "state" / "history.jsonl").read_text())["source_label"] == "appam"
    # a label the terminal can't encode prints as its escape, with stdout held to strict UTF-8
    rec = NP.parse_capture((FIXTURES / "nettest_appam.txt").read_text())
    rec["egress"] = {"org": "AS64500 \ud83d"}
    NP.Store(tmp_path / "state" / "history.jsonl").append([NP.finalize(rec)])
    got = subprocess.run([sys.executable, str(SCRIPT), "history"], capture_output=True, text=True,
                         env=dict(env, PYTHONIOENCODING="utf-8:strict"), timeout=30)
    assert got.returncode == 0 and "AS64500 \\ud83d" in got.stdout, got.stderr


# ---------------------------------------------------------------- faults outside the measurements


CAPTURE_HEAD = "### venue on en0  2026-11-05T17:00:00Z\nip: 10.0.0.2  default via: 10.0.0.1\n"


@pytest.mark.parametrize("body", [
    CAPTURE_HEAD + "5 packets transmitted, 5 packets received, 1.2.3% packet loss\n",
    CAPTURE_HEAD + "5 packets transmitted, 5 packets received, 0.0% packet loss\n"
                   "round-trip min/avg/max/stddev = 1.2.3/1/1/1 ms\n",
    CAPTURE_HEAD + "5 packets transmitted, 5 packets received, 0.0% packet loss\n"
                   f"round-trip min/avg/max/stddev = {'9' * 400}/1/1/1 ms\n",
    CAPTURE_HEAD + "Uplink capacity: 1.2.3 Mbps\n",
    CAPTURE_HEAD + "Idle Latency: . milliseconds\n",
    CAPTURE_HEAD + "api 2/2, github 2/2 connected; TLS done at: 0.1230.456 s\n",
    CAPTURE_HEAD + f"api {'9' * 400}/2, github 2/2 connected; TLS done at: 0.1 s\n",
    CAPTURE_HEAD + "9" * 5000 + " packets transmitted, 5 packets received, 0.0% packet loss\n",
    "### venue on en0  2026-13-45T99:99:99Z\nip: 10.0.0.2  default via: 10.0.0.1\n",
], ids=["loss", "round trip", "endless round trip", "capacity", "idle latency", "times run together",
        "endless connection count", "huge count", "date"])
def test_import_reports_a_damaged_capture_and_goes_on(tmp_path, body):
    bad = tmp_path / "nettest_bad.txt"
    bad.write_text(body)
    rc, text, store = run_cli(["import", str(bad), CAPTURES[0]], tmp_path=tmp_path)
    assert rc == 0 and f"{bad}: not a nettest.sh capture, or a damaged one" in text
    assert "imported 1 measurement(s)" in text and store.load()[1] == 0


@given(which=st.sampled_from(CAPTURES), keep=st.floats(0.2, 1.0),
       hits=st.lists(st.tuples(st.integers(0, 10 ** 6),
                               st.sampled_from(["1.2.3", ".", "..", "9" * 5000, "9" * 400, "-1", "x", ""])), max_size=6))
def test_no_damage_to_a_capture_breaks_import_or_the_history(which, keep, hits):
    text = pathlib.Path(which).read_text()
    numbers = list(re.finditer(r"[\d.]+", text))
    for i, word in sorted({i % len(numbers): word for i, word in hits}.items(), reverse=True):
        text = text[:numbers[i].start()] + word + text[numbers[i].end():]
    with tempfile.TemporaryDirectory() as d:
        capture = pathlib.Path(d) / "nettest.txt"
        capture.write_text(text[:int(len(text) * keep)])
        rc, _, store = run_cli(["import", str(capture)], tmp_path=pathlib.Path(d))
        assert rc == 0 and store.load()[1] == 0
        for view in (["history"], ["history", "--rank"], ["history", "--by-network"], ["history", "--json"]):
            assert run_cli(view, store=store)[0] == 0


def test_naming_an_interface_twice_measures_it_once(tmp_path):
    """It gave two rows for en0, each counting 16 connections, and a recommendation that tied with itself."""
    mac = FakeMac([wifi(), tether()])
    rc, text, store = run_cli(["now", "--quick", "--interfaces", "en0,en0"], mac, tmp_path)
    recs = store.load()[0]
    assert rc == 0 and [r["interface"] for r in recs] == ["en0"] and recs[0]["conns"]["attempted"] == 8


@pytest.mark.parametrize("words", [[], [" "]], ids=["no name", "a blank name"])
def test_name_without_a_name_keeps_the_one_it_has(tmp_path, words):
    store = NP.Store(tmp_path / "history.jsonl")
    store.set_name("34849952", "APPAM")
    rc, text, _ = run_cli(["name", "34849952", *words], store=store)
    assert rc == 2 and "--clear" in text and store.names() == {"34849952": "APPAM"}
    rc, text, _ = run_cli(["name", "34849952", "--clear"], store=store)
    assert rc == 0 and store.names() == {}


@pytest.mark.parametrize("how", ["flag", "environment"])
def test_a_history_path_under_a_user_that_doesnt_exist_gets_one_line(how, monkeypatch):
    path = "~no-such-user-netpick/history.jsonl"
    argv = ["history"]
    if how == "flag":
        argv += ["--history", path]
    else:
        monkeypatch.setenv("NETPICK_HISTORY", path)
    lines = []
    assert NP.main(argv, out=lines.append) == 2
    assert len(lines) == 1 and "can't use that history path" in lines[0]


def test_a_names_file_that_is_a_named_pipe_holds_up_nothing(tmp_path):
    """Round-3 review: reading names.json waited forever for a writer, even
    for `watch --minutes 0`."""
    fifo = tmp_path / "names.json"
    os.mkfifo(fifo)
    store = NP.Store(tmp_path / "history.jsonl")
    got = {}
    t = threading.Thread(target=lambda: got.update(names=store.names()), daemon=True)
    t.start()
    t.join(10)
    assert not t.is_alive() and got["names"] == {}
    rc, text, _ = run_cli(["name", "--list"], store=store)
    assert rc == 1 and "it isn't a regular file" in text
    rc, text, _ = run_cli(["name", "34849952", "x"], store=store)
    assert rc == 1 and fifo.is_fifo()
    assert run_cli(["history"], store=store)[0] == 0
    mac = FakeMac([wifi()])
    assert NP.watch_loop(make_prober(mac), store, minutes=0, out=lambda s="": None) == 0


@pytest.mark.parametrize("cmd", [["import", CAPTURES[1]], ["name", "34849952", "x"], ["history"], ["now", "--quick"]],
                         ids=lambda c: c[0])
def test_a_history_that_links_through_another_names_file_is_refused(tmp_path, cmd):
    """Round-3 review: history.jsonl -> other/names.json -> other/actual.json
    passed the guard, and import appended a record to that names object."""
    other, config = tmp_path / "other", tmp_path / "config"
    other.mkdir()
    config.mkdir()
    names = '{"34849952": "APPAM"}\n'
    (other / "actual.json").write_text(names)
    (other / "names.json").symlink_to("actual.json")
    (config / "history.jsonl").symlink_to(other / "names.json")
    mac = FakeMac([wifi()])
    lines = []
    rc = NP.main([*cmd, "--history", str(config / "history.jsonl")], prober=make_prober(mac), out=lines.append)
    assert rc == 2 and "netpick keeps network names in names.json files" in lines[0] and not mac.calls
    assert (other / "actual.json").read_text() == names


def test_two_name_updates_at_once_keep_both(tmp_path):
    """Round-3 review: each read the names, then replaced the file with its own
    copy, so one update vanished. With the lock, the second read waits for the
    first update, the barrier times out, and the second read sees the first name."""
    store = NP.Store(tmp_path / "history.jsonl")
    read = store.read_names
    gate = threading.Barrier(2, timeout=0.5)

    def read_then_wait():
        names = read()
        with contextlib.suppress(threading.BrokenBarrierError):
            gate.wait()
        return names

    store.read_names = read_then_wait
    threads = [threading.Thread(target=store.set_name, args=(nid, "x")) for nid in ("aaaa1111", "bbbb2222")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert set(read()) == {"aaaa1111", "bbbb2222"}


@pytest.mark.parametrize("report", ["0 inf 100 0 0 1", "0 1e400 100 0 0 1", "0 -5 100 0 0 1", "0 nan 100 0 0 1"])
def test_a_transfer_report_with_an_impossible_count_charges_the_planned_size(report):
    class OddMac(FakeMac):
        def answer(self, a, stdin):
            got = super().answer(a, stdin)
            return NP.Proc(0, report) if a[0] == "curl" and "__down" in a[-1] else got

    mac = OddMac([wifi()])
    prober = make_prober(mac, budget_mb=12.5, nq=False)
    rec = prober.measure(prober.candidates(), rounds=4)[0]
    assert len([k for k, _ in kinds(mac) if k == "stream"]) == 2  # one transfer: its 7.5 MB leaves too little for another
    assert any("charged the budget the planned 5 MB" in n for n in rec["notes"])


def run_script(*argv, **kw):
    return subprocess.Popen([sys.executable, str(SCRIPT), *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, **kw)


def test_a_reader_that_closes_the_pipe_early_gets_no_traceback(tmp_path):
    history = tmp_path / "history.jsonl"
    history.write_text("".join(json.dumps(dict(appam_record(), notes=["x" * 2000])) + "\n" for _ in range(300)))
    p = run_script("history", "--json", "--history", str(history))
    p.stdout.read(10)
    p.stdout.close()
    err = p.stderr.read()
    assert p.wait(timeout=30) == 141 and err == ""


def test_ctrl_c_ends_a_command_with_no_traceback(tmp_path):
    fifo = tmp_path / "capture.txt"
    os.mkfifo(fifo)
    p = run_script("import", "--history", str(tmp_path / "history.jsonl"), str(fifo))
    deadline = time.monotonic() + 30
    while True:  # the write end opens once netpick holds the read end, and staying open keeps the read waiting
        try:
            writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError:
            assert time.monotonic() < deadline and p.poll() is None
            time.sleep(0.05)
    try:
        err = None
        for _ in range(6):
            p.send_signal(signal.SIGINT)  # netpick's own test child, by pid
            try:
                _, err = p.communicate(timeout=5)
                break
            except subprocess.TimeoutExpired:
                pass  # a signal that lands just before Python's read blocks wakes nothing: send another
    finally:
        os.close(writer)
    assert p.wait(timeout=30) == 130 and err is not None and "Traceback" not in err
