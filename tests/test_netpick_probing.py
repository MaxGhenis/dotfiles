"""bin/netpick measuring, watching and the CLI, driven through a fake Mac.

FakeMac (tests/netpick_fakes.py) answers every command netpick runs from a
script and passes each one through netpick's own read-only allowlist first,
so these tests also show that a whole run stays inside it.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

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


# ---------------------------------------------------------------- offline links and failures


def test_offline_link_is_identified_but_never_probed_and_ranks_last():
    mac = FakeMac([wifi(), tether(online_after=1e9)], primary="en13")
    recs = make_prober(mac).measure(make_prober(mac).candidates())
    probed = {(k, i) for k, i in kinds(mac)}
    assert not {i for _k, i in probed} - {"en0"}
    assert [a for a in mac.argvs("curl", "en13")] == [a for a in mac.argvs("curl", "en13") if NP.CAPTIVE_URL in a]
    off = by_iface(recs)["en13"]
    assert not off["online"] and off["egress"] is None
    assert "no internet (captive portal not signed in?)" in off["notes"]
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
    assert "Measured one at a time" in tail
    for _t, _gw, argv in mac.calls:  # nothing but reads and en0-bound probes
        assert argv[0] in NP.READ_ONLY
        if argv[0] in PROBES:
            assert bound(argv) == "en0"


def test_watch_skips_gateways_already_tested(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 60, wifi(**B))]
    rc, text, store = watch(mac, tmp_path, seen=[B["gateway"]], max_new=1, minutes=5)
    assert "back on gateway 10.243.10.226 (tested already)" in text
    assert "API check: 4/4 Claude API, 4/4 GitHub connections" in text
    assert store.load() == ([], 0) and not mac.argvs("ping")


def test_watch_gives_up_on_a_portal_nobody_signs_in_to(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 60, wifi(online_after=1e9, **C))]
    rc, text, store = watch(mac, tmp_path, portal_wait=120, max_new=1, minutes=5)
    assert "still no internet after 2 min (portal not signed in?); skipped" in text
    assert "done: measured 0 network(s)" in text and not mac.argvs("ping")


def test_watch_follows_a_second_switch_during_the_portal_wait(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(**A)), (T0 + 60, wifi(online_after=1e9, **C)), (T0 + 90, wifi(**B))]
    rc, text, store = watch(mac, tmp_path, max_new=1, minutes=5, settle=10)
    assert "the network changed while waiting for internet" in text
    assert "new network: gateway 10.243.10.226" in text
    assert [r["gateway"] for r in store.load()[0]] == [B["gateway"]]


def test_watch_baseline_without_internet_is_skipped(tmp_path):
    mac = FakeMac([], primary="en0")
    mac.wifi_schedule = [(T0, wifi(online_after=1e9, **C))]
    rc, text, store = watch(mac, tmp_path, baseline=True, max_new=1, minutes=1)
    assert "baseline skipped: the current Wi-Fi network has no internet" in text and rc == 0


def test_watch_without_wifi_hardware(tmp_path):
    class NoWifi(FakeMac):
        def answer(self, a, stdin):
            if a[0] == "networksetup":
                return NP.Proc(0, "\nHardware Port: USB 10/100/1000 LAN\nDevice: en5\n")
            return super().answer(a, stdin)

    rc, text, _ = watch(NoWifi([tether()]), tmp_path)
    assert rc == 3 and "No Wi-Fi interface found." in text


# ---------------------------------------------------------------- CLI


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
    assert len(text.splitlines()) == 1 + 3 + 1 and "Medians over" in text
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
    assert "(3 unreadable line(s) skipped)" in run_cli(["history"], store=store)[1]


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
    assert "Measured earlier (within 2h), not now:" in text
    assert "gw 10.243.10.226" in text and "10m ago" in text
    assert "10.9.9.1" not in text and "10.8.8.1" not in text
    assert "Wi-Fi WPA3 gw 10.243.10.226 beat Wi-Fi WPA2 gw 172.21.112.1" in text and "on packet loss" in text
    assert "netpick watch --baseline" in text
    rc, text, _ = run_cli(["--quick", "--no-history", "--recent", "0"], mac, store=store)
    assert "Measured earlier" not in text


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

