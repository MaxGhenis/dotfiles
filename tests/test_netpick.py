"""bin/netpick: parsers, the ranking rule, the data budget and the read-only guard.

Parser tests run against real captures: the three nettest.sh outputs from
2026-11-05 (APPAM venue Wi-Fi in Boston, the Pixel hotspot over Wi-Fi, a
Starbucks behind a captive portal) and command output read on this Mac the
same day (identifiers replaced). Ranking regressions use those captures and
the 11/04-05 Amtrak numbers in docs/netpick.md. The ranking invariants run
as Hypothesis properties.
"""
from __future__ import annotations

import ast
import json
import math
import os
import socket
import statistics
import struct
import sys
import threading

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from netpick_fakes import FIXTURES, NP, SCRIPT

# Quick by default; NETPICK_HYPOTHESIS=thorough runs 25 times the examples.
settings.register_profile("netpick", max_examples=200, deadline=None)
settings.register_profile("thorough", max_examples=5000, deadline=None)
settings.load_profile(os.environ.get("NETPICK_HYPOTHESIS", "netpick"))


def fixture(name):
    return (FIXTURES / name).read_text()


def capture(name):
    return NP.parse_capture(fixture(name), source=name)


# ---------------------------------------------------------------- captures


def test_capture_appam_venue_wifi():
    r = capture("nettest_appam.txt")
    assert (r["source_label"], r["interface"], r["time"]) == ("appam", "en0", "2026-11-05T19:56:47Z")
    assert (r["ip"], r["gateway"], r["kind"], r["online"]) == ("172.21.114.244", "172.21.112.1", "wifi", True)
    assert (r["security"], r["security_class"]) == ("WPA2 Personal", "wpa2")
    assert r["wifi"] == {"channel": 64, "band": "5GHz", "width_mhz": 40, "rssi": -48, "noise": -95, "tx_rate": 573}
    assert r["ping"] == {"sent": 40, "received": 40, "loss_pct": 0.0, "min_ms": 6.972, "avg_ms": 29.56,
                         "max_ms": 86.817, "stddev_ms": 21.554}
    assert (r["conns"]["attempted"], r["conns"]["ok"]) == (8, 8)
    assert r["conns"]["by_host"] == {"api.anthropic.com": [4, 4], "github.com": [4, 4]}
    assert r["conns"]["tls_s"] == [0.07, 0.09, 0.07, 0.08, 0.01, 0.09, 0.07, 0.09]
    assert r["nq"] == {"up_mbps": 113.685, "down_mbps": 12.715, "rpm": 47.0, "responsiveness": "Low",
                       "base_rtt_ms": 26.747}
    m = r["metrics"]
    assert (m["conn_ratio"], m["loss_pct"], m["latency_ms"]) == (1.0, 0.0, 51.1)  # 29.56 avg + 21.554 sd
    assert (m["up_mbps"], m["down_mbps"], m["rpm"], m["via"]) == (113.685, 12.715, 47.0, "nq")


def test_capture_pixel_hotspot_wpa3():
    r = capture("nettest_net1_wpa3.txt")
    assert (r["source_label"], r["gateway"]) == ("net1_wpa3", "10.243.10.226")
    assert (r["security"], r["security_class"]) == ("WPA2/WPA3 Personal", "wpa3")
    assert r["wifi"] == {"channel": 161, "band": "5GHz", "width_mhz": 80, "rssi": -45, "noise": -92, "tx_rate": 960}
    assert (r["ping"]["avg_ms"], r["ping"]["stddev_ms"], r["ping"]["max_ms"]) == (152.117, 73.516, 299.874)
    assert r["nq"]["up_mbps"] == 32.359 and r["nq"]["down_mbps"] == 10.211 and r["nq"]["rpm"] == 58.0
    assert r["nq"]["base_rtt_ms"] == 101.21


def test_capture_open_network_ignores_the_supported_channels_list():
    """nettest.sh grepped 'Channel' unanchored, so the Starbucks capture's
    wifi line also holds a 100-entry 'Supported Channels:' list."""
    text = fixture("nettest_net1_open.txt")
    assert "Supported Channels: 1 (2GHz)" in text
    r = NP.parse_capture(text)
    assert r["wifi"] == {"channel": 112, "band": "5GHz", "width_mhz": 40, "rssi": -67, "noise": -92, "tx_rate": 108}
    assert (r["security"], r["security_class"]) == ("None", "open")
    assert (r["ping"]["avg_ms"], r["ping"]["max_ms"]) == (132.069, 678.557)
    assert (r["nq"]["up_mbps"], r["nq"]["down_mbps"], r["nq"]["rpm"]) == (15.036, 4.47, 34.0)


def test_wifi_link_takes_only_fields_that_start_a_segment():
    assert NP.parse_wifi_link("Supported Channels: 1 (2GHz), 36 (5GHz);Channel: 36 (5GHz, 80MHz)") == {
        "channel": 36, "band": "5GHz", "width_mhz": 80}
    assert NP.parse_wifi_link("Supported Channels: 1 (2GHz), 6 (2GHz)") == {}
    assert NP.parse_wifi_link("Channel: 6 (2GHz, 20MHz);Channel: 11 (2GHz, 20MHz)") == {
        "channel": 6, "band": "2.4GHz", "width_mhz": 20}


def test_capture_import_needs_the_header():
    assert NP.parse_capture("random text\n40 packets transmitted, 40 packets received, 0.0% packet loss") is None


# ---------------------------------------------------------------- command output


def test_ping_parser_variants():
    full = NP.parse_ping("40 packets transmitted, 40 packets received, 0.0% packet loss\n"
                         "round-trip min/avg/max/stddev = 6.972/29.560/86.817/21.554 ms\n")
    assert full["loss_pct"] == 0.0 and full["avg_ms"] == 29.56
    lost = NP.parse_ping("--- 1.1.1.1 ping statistics ---\n40 packets transmitted, 0 packets received, 100.0% packet loss\n")
    assert lost == {"sent": 40, "received": 0, "loss_pct": 100.0}
    dup = NP.parse_ping("40 packets transmitted, 41 packets received, +1 duplicates, 0.0% packet loss\n"
                        "round-trip min/avg/max/stddev = 1.0/2.0/3.0/0.5 ms")
    assert dup["received"] == 41 and dup["loss_pct"] == 0.0
    assert NP.parse_ping("ping: bad interface name\n") is None
    assert NP.parse_ping("") is None


def test_networkquality_text_units_and_formats():
    got = NP.parse_nq_text("==== SUMMARY ====\nUplink capacity: 950.5 Kbps\nDownlink capacity: 1.2 Gbps\n"
                           "Responsiveness: High (68.123 milliseconds | 880 RPM)\nIdle Latency: 0.05 seconds | 1200 RPM\n")
    assert got == {"up_mbps": 0.951, "down_mbps": 1200.0, "rpm": 880.0, "responsiveness": "High", "base_rtt_ms": 50.0}
    assert NP.parse_nq_text("Responsiveness: Medium (561 RPM)") == {"rpm": 561.0, "responsiveness": "Medium"}
    assert NP.parse_nq_text("Error: no route") is None


def test_networkquality_json_from_this_mac():
    """networkQuality -I en0 -M 6 -c on the APPAM Wi-Fi, 11/05 (arrays cut to 3)."""
    got = NP.parse_nq_json(fixture("networkquality_c_en0.json"))
    assert got["down_mbps"] == 35.782 and got["up_mbps"] == 156.005
    assert got["rpm"] == 415.0 and got["base_rtt_ms"] == 27.4
    assert got["bytes"] == 24197713 + 106430464  # 130 MB in a 6 s run: why -M alone caps nothing
    assert got["seconds"] == 5.8 and got["interface_type"] == "wifi"
    assert "error" not in got
    assert NP.parse_nq_json("") is None and NP.parse_nq_json("[]") is None
    assert NP.parse_nq_json('{"error_code": -1}')["error"] == "-1"


def test_routes_one_link_and_two():
    assert NP.parse_default_routes(fixture("netstat_rn_en0.txt")) == {"en0": {"gateway": "172.21.112.1", "flags": "UGScg"}}
    two = NP.parse_default_routes(fixture("netstat_rn_tether_and_wifi.txt"))
    assert two == {"en13": {"gateway": "192.168.42.129", "flags": "UGScg"},
                   "en0": {"gateway": "172.21.112.1", "flags": "UGScIg"}}
    older = "Destination  Gateway  Flags  Refs  Use  Netif Expire\ndefault  10.0.0.1  UGSc  3  0  en5\n"
    assert NP.parse_default_routes(older) == {"en5": {"gateway": "10.0.0.1", "flags": "UGSc"}}
    assert NP.parse_default_routes("default  link#22  UCSIg  utun3\n") == {"utun3": {"gateway": None, "flags": "UCSIg"}}


def test_interface_byte_counters():
    assert NP.parse_if_bytes(fixture("netstat_ibn_en0.txt"), "en0") == (8431698381, 1882638951)
    assert NP.parse_if_bytes(fixture("netstat_ibn_en0.txt"), "en13") is None
    no_addr = "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\nen13 1500 <Link#24> 5 0 700 6 0 800 0\n"
    assert NP.parse_if_bytes(no_addr, "en13") == (700, 800)


def test_hardware_ports_summary_route_and_wifi_stats():
    assert NP.parse_hardware_ports(fixture("hardware_ports_with_tether.txt")) == {
        "en3": "Ethernet Adapter (en3)", "bridge0": "Thunderbolt Bridge", "en0": "Wi-Fi", "en1": "Thunderbolt 1",
        "en13": "Pixel 11 Pro Fold"}
    assert NP.parse_summary(fixture("getsummary_en0.txt")) == {"security": "WPA2_PSK", "interfacetype": "WiFi"}
    assert NP.parse_wlan_json(fixture("wlan_en0.json")) == {
        "rssi": -46, "noise": -93, "tx_rate": 458, "channel": 108, "band": "5GHz", "width_mhz": 40,
        "security": "WPA2 Personal"}
    assert NP.parse_wlan_json("null") is None


def test_ipinfo_keeps_only_coarse_fields():
    assert NP.parse_ipinfo(fixture("ipinfo.json")) == {
        "ip": "203.0.113.7", "org": "AS64500 Example Venue Networks", "city": "Boston", "region": "Massachusetts",
        "country": "US"}
    assert NP.parse_ipinfo("<html>portal</html>") is None


def test_curl_write_out_parsers():
    assert NP.parse_curl_w("0 404 0.005725 0.070004") == {"exit": 0, "http_code": "404", "connect_s": 0.005725,
                                                          "tls_s": 0.070004}
    assert NP.parse_curl_w("") is None
    # curl prints -w on a timeout too (exit 28): a partial transfer still gives a rate
    assert NP.parse_stream_w("28 12996792 12923027 0 0 1.005708")["speed_download"] == 12923027.0
    assert NP.parse_stream_w("45 0 0 0 0 0.03") == {"exit": 45, "size_download": 0, "speed_download": 0.0,
                                                    "size_upload": 0, "speed_upload": 0.0, "time_total": 0.03}


@pytest.mark.parametrize("raw, cls", [
    ("WPA2_PSK", "wpa2"), ("WPA2 Personal", "wpa2"), ("WPA2/WPA3 Personal", "wpa3"), ("WPA3_SAE", "wpa3"),
    ("SAE", "wpa3"), ("None", "open"), ("NONE", "open"), ("OWE", "open"), ("OWE Transition", "open"),
    ("WPA2 Enterprise", "enterprise"), ("WEP", "wep"), ("spairport_security_mode_wpa2_personal", "wpa2"),
    ("", None), (None, None), ("Personal", "personal"),
])
def test_security_class(raw, cls):
    assert NP.security_class(raw) == cls


def test_dns_packets():
    q = NP.dns_query_packet(0x1234, "api.anthropic.com")
    assert q[:2] == b"\x12\x34" and q[12:] == b"\x03api\x09anthropic\x03com\x00\x00\x01\x00\x01"
    reply = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q[12:]
    assert NP.dns_parse_response(reply, 0x1234) == (0, 1)
    assert NP.dns_parse_response(reply, 0x4321) is None  # another query's reply
    assert NP.dns_parse_response(q, 0x1234) is None  # a query, not a reply
    assert NP.dns_parse_response(reply[:6], 0x1234) is None
    assert NP.dns_parse_response(struct.pack(">HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0), 0x1234) == (3, 0)


@pytest.mark.skipif(sys.platform != "darwin", reason="IP_BOUND_IF is a macOS socket option")
def test_dns_lookup_binds_to_the_interface_and_skips_stray_replies():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def serve():
        data, addr = srv.recvfrom(512)
        qid = struct.unpack(">H", data[:2])[0]
        srv.sendto(struct.pack(">HHHHHH", qid ^ 0xFFFF, 0x8180, 1, 1, 0, 0) + data[12:], addr)  # wrong id first
        srv.sendto(struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + data[12:], addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        ok, ms, detail = NP.dns_lookup("127.0.0.1", "api.anthropic.com", "lo0", timeout=3, port=port)
    finally:
        t.join(3)
        srv.close()
    assert (ok, detail) == (True, "ok") and ms is not None
    ok, ms, detail = NP.dns_lookup("127.0.0.1", "github.com", "en99", timeout=1, port=port)
    assert not ok and ms is None  # no such interface: an error, never a silent unbound query


# ---------------------------------------------------------------- ranking: field data


def rec(ok, att, loss, avg, sd=0.0, up=None, down=None, label="", kind="wifi"):
    r = {"kind": kind, "online": True, "label": label, "conns": {"attempted": att, "ok": ok},
         "ping": {"sent": 40, "received": round(40 * (1 - loss / 100)), "loss_pct": loss, "avg_ms": avg,
                  "stddev_ms": sd, "min_ms": avg, "max_ms": avg},
         "nq": {"up_mbps": up, "down_mbps": down}}
    r["metrics"] = NP.compute_metrics(r)
    return r


def test_appam_three_way_matches_the_field_call():
    """11/05 at APPAM: venue Wi-Fi won (30 ms, 12.7/114). The hotspot (152 ms,
    10.2/32) beats Starbucks (132 ms average but spikes to 679, 4.5/15)."""
    recs = [capture(n) for n in ("nettest_net1_open.txt", "nettest_net1_wpa3.txt", "nettest_appam.txt")]
    ranked = NP.rank(recs)
    assert [r["source_label"] for r in ranked] == ["appam", "net1_wpa3", "net1_open"]
    appam, hotspot, starbucks = ranked
    assert NP.deciding(appam["metrics"], hotspot["metrics"]) == ("latency_ms", True)
    assert NP.deciding(hotspot["metrics"], starbucks["metrics"]) == ("latency_ms", True)  # 226 vs 286 with jitter
    assert NP.recommend(ranked, appam)["action"] == "stay"
    move = NP.recommend(ranked, starbucks)
    assert move["action"] == "switch" and move["pick"] is appam
    assert "~51 ms vs ~286 ms" in move["text"] and "Wi-Fi menu" in move["text"]


def test_1105_hotspot_beats_amtrak():
    """11/05 ~01:00Z: hotspot 8/8, 5% loss, ~135 ms, 25/16.5 against Amtrak
    5/8, 22.5%, ~550 ms, 6/22 thirteen minutes earlier."""
    amtrak = rec(5, 8, 22.5, 550, up=22, down=6, label="amtrak")
    hotspot = rec(8, 8, 5.0, 135, up=16.5, down=25, label="hotspot")
    assert [r["label"] for r in NP.rank([amtrak, hotspot])] == ["hotspot", "amtrak"]
    assert NP.deciding(hotspot["metrics"], amtrak["metrics"]) == ("conn_ratio", True)


def test_1104_tether_with_clean_pings_loses_on_connections():
    """11/04: the USB tether pinged clean (0%, ~37 ms) but about half its new
    connections failed and networkQuality failed; Amtrak had 10-28% loss,
    ~330 ms and 10/10 handshakes. Amtrak won, and connection success decides."""
    tether = rec(4, 8, 0.0, 37, sd=5, label="tether", kind="wired")
    amtrak = rec(10, 10, 19.0, 330, sd=80, up=22, down=6, label="amtrak")
    ranked = NP.rank([tether, amtrak])
    assert [r["label"] for r in ranked] == ["amtrak", "tether"]
    move = NP.recommend(ranked, tether)
    assert move["action"] == "switch" and "10/10 connections vs 4/8" in move["text"]


def test_icmp_blocked_is_unknown_loss_not_total_loss():
    r = {"online": True, "conns": {"attempted": 8, "ok": 8}, "ping": {"sent": 40, "received": 0, "loss_pct": 100.0}}
    m = NP.compute_metrics(r)
    assert m["loss_pct"] is None and m["latency_ms"] is None
    dead = NP.compute_metrics({"online": True, "conns": {"attempted": 8, "ok": 0},
                               "ping": {"sent": 40, "received": 0, "loss_pct": 100.0}})
    assert dead["loss_pct"] == 100.0


def test_throughput_falls_back_to_the_bounded_transfer():
    m = NP.compute_metrics({"nq": {"error": "x"}, "stream": {"down_mbps": 9.0, "up_mbps": 4.0}})
    assert (m["down_mbps"], m["up_mbps"], m["via"]) == (9.0, 4.0, "stream")
    m = NP.compute_metrics({"nq": {"down_mbps": 30.0, "up_mbps": None}, "stream": {"down_mbps": 9.0, "up_mbps": 4.0}})
    assert (m["down_mbps"], m["up_mbps"], m["via"]) == (30.0, 4.0, "mixed")
    assert NP.compute_metrics({})["via"] is None


# ---------------------------------------------------------------- ranking: invariants


def finite(lo, hi):
    return st.floats(lo, hi, allow_nan=False, allow_infinity=False)


def metric(lo, hi, cuts):
    return st.one_of(st.none(), finite(lo, hi), st.sampled_from(cuts))


CONN = st.one_of(st.none(), st.sampled_from(NP.CONN_CUTS),
                 st.integers(1, 16).flatmap(lambda n: st.integers(0, n).map(lambda k: k / n)))
METRICS = st.fixed_dictionaries({
    "conn_ratio": CONN,
    "loss_pct": metric(0, 100, NP.LOSS_CUTS),
    "latency_ms": metric(0, 3000, NP.LATENCY_CUTS),
    "up_mbps": metric(0, 1000, NP.UP_CUTS),
    "down_mbps": metric(0, 1000, NP.DOWN_CUTS),
    "rpm": st.one_of(st.none(), finite(0, 6000)),
})
HIGHER = ("conn_ratio", "up_mbps", "down_mbps", "rpm")
LOWER = ("loss_pct", "latency_ms")
TOP = {"conn_ratio": 1.0, "up_mbps": 1000.0, "down_mbps": 1000.0, "rpm": 6000.0, "loss_pct": 100.0,
       "latency_ms": 3000.0}


def items(ms):
    return [{"id": i, "metrics": m} for i, m in enumerate(ms)]


def order(ms):
    return [r["id"] for r in NP.rank(items(ms))]


def better_value(field, old):
    """A value at least as good as old (missing is the worst value)."""
    if field in HIGHER:
        return finite(0.0 if old is None else old, TOP[field])
    return finite(0.0, TOP[field] if old is None else old)


def worse_or_equal(field, old):
    if old is None:
        return st.none()
    if field in HIGHER:
        return st.one_of(st.none(), finite(0.0, old))
    return st.one_of(st.none(), finite(old, TOP[field]))


@given(st.lists(METRICS, min_size=1, max_size=8))
def test_rank_is_deterministic(ms):
    assert order(ms) == order([dict(m) for m in ms])
    assert [NP.rank_key(m) for m in ms] == [NP.rank_key(dict(m)) for m in ms]


@given(st.lists(METRICS, min_size=2, max_size=8), st.randoms(use_true_random=False))
def test_rank_depends_on_input_order_only_through_exact_ties(ms, rnd):
    keys = [NP.rank_key(m) for m in ms]
    assume(len(set(keys)) == len(keys))
    shuffled = list(ms)
    rnd.shuffle(shuffled)
    assert [NP.rank_key(ms[i]) for i in order(ms)] == [NP.rank_key(shuffled[i]) for i in order(shuffled)]


@given(METRICS, st.lists(METRICS, max_size=6), st.integers(2, 4), st.randoms(use_true_random=False))
def test_exact_ties_keep_input_order(m, others, copies, rnd):
    pool = [{"id": i, "metrics": x} for i, x in enumerate(others)]
    for c in range(copies):
        pool.insert(rnd.randint(0, len(pool)), {"id": f"tie{c}", "metrics": dict(m)})
    ties_in = [r["id"] for r in pool if str(r["id"]).startswith("tie")]
    ties_out = [r["id"] for r in NP.rank(pool) if str(r["id"]).startswith("tie")]
    assert ties_out == ties_in


@given(st.lists(METRICS, min_size=1, max_size=8), st.data())
def test_improving_one_metric_never_lowers_a_networks_rank(ms, data):
    i = data.draw(st.integers(0, len(ms) - 1), label="network")
    field = data.draw(st.sampled_from(HIGHER + LOWER), label="metric")
    improved = [dict(m) for m in ms]
    improved[i][field] = data.draw(better_value(field, ms[i][field]), label="new value")
    assert order(improved).index(i) <= order(ms).index(i)


@given(METRICS, st.data())
def test_no_worse_on_every_metric_means_no_lower_rank(a, data):
    b = {f: data.draw(worse_or_equal(f, a[f]), label=f) for f in HIGHER + LOWER}
    assert NP.rank_key(a) <= NP.rank_key(b)
    assert order([b, a]).index(1) == 0 or NP.rank_key(a) == NP.rank_key(b)


@given(METRICS, METRICS)
def test_connection_success_band_outranks_every_other_metric(a, b):
    assume(NP.band_high(a["conn_ratio"], NP.CONN_CUTS) < NP.band_high(b["conn_ratio"], NP.CONN_CUTS))
    assert order([b, a]) == [1, 0]


@given(METRICS, st.sampled_from(HIGHER + LOWER), st.sampled_from([math.nan, math.inf, -math.inf, "12", True]))
def test_unusable_values_count_as_missing(m, field, bad):
    assert NP.rank_key(dict(m, **{field: bad})) == NP.rank_key(dict(m, **{field: None}))


@given(finite(-10, 5000), finite(-10, 5000))
def test_bands_are_monotone(x, y):
    lo, hi = min(x, y), max(x, y)
    for cuts in (NP.CONN_CUTS, NP.UP_CUTS, NP.DOWN_CUTS):
        assert NP.band_high(hi, cuts) <= NP.band_high(lo, cuts) <= NP.band_high(None, cuts)
    for cuts in (NP.LOSS_CUTS, NP.LATENCY_CUTS):
        assert NP.band_low(lo, cuts) <= NP.band_low(hi, cuts) <= NP.band_low(None, cuts)


def link(name, m, kind="wifi"):
    return {"online": True, "kind": kind, "label": name, "metrics": m, "conns": {}, "interface": name}


@given(METRICS, METRICS)
def test_recommendation_never_switches_inside_one_band(a, b):
    cur, other = link("cur", a), link("other", b)
    ranked = NP.rank([cur, other])
    got = NP.recommend(ranked, cur)
    if NP.rank_key(a)[:5] == NP.rank_key(b)[:5]:
        assert got["action"] == "stay" and got["pick"] is cur
    if got["action"] == "switch":
        assert got["pick"] is other and NP.rank_key(b)[:5] < NP.rank_key(a)[:5]
    if ranked[0] is cur:
        assert got["action"] == "stay"


def test_recommendation_edge_cases():
    up = link("up", {"conn_ratio": 1.0})
    down = dict(link("down", {"conn_ratio": 1.0}), online=False)
    assert NP.recommend([], None)["action"] == "none"
    assert NP.recommend([down], down)["action"] == "none"
    assert NP.recommend([up, down], down)["action"] == "switch"
    assert NP.recommend([up], None)["action"] == "use"
    assert NP.recommend([up], up)["text"].endswith("(the only link measured).")
    twin = link("twin", {"conn_ratio": 1.0})
    assert NP.recommend([up, twin], twin)["text"] == "Stay on twin: up ties with it."


# ---------------------------------------------------------------- data budget


@given(budget=finite(0, 500), used=finite(0, 6e8), down=st.one_of(st.none(), finite(0, 3000)),
       up=st.one_of(st.none(), finite(0, 3000)), longest=st.integers(1, 60))
def test_networkquality_plan_fits_the_budget(budget, used, down, up, longest):
    opts = NP.Options(budget_mb=budget, nq_seconds=longest)
    secs, why = NP.nq_plan(opts, used, {"down_mbps": down, "up_mbps": up})
    remaining = budget * 1e6 - used
    if secs is None:
        assert why
        return
    assert NP.NQ_MIN_SECONDS <= secs <= longest and remaining > 0
    mbps = (down or 0) + (up or 0)
    if mbps > 0:
        assert secs * NP.NQ_SAFETY * mbps * 1e6 / 8 <= remaining * (1 + 1e-9)
    else:
        assert secs <= NP.NQ_BLIND_SECONDS


def test_networkquality_plan_examples():
    o = NP.Options()
    assert NP.nq_plan(NP.Options(nq=False), 0, None) == (None, "off")
    # Pixel hotspot speeds (11/05: 25 down / 16.5 up): 8 s at twice 41.5 Mbps is 83 MB of the 92.5 left
    assert NP.nq_plan(o, 7.5e6, {"down_mbps": 25, "up_mbps": 16.5}) == (8, None)
    assert NP.nq_plan(o, 0, {"down_mbps": 4, "up_mbps": 1}) == (20, None)
    # APPAM speeds (one connection ~38 down / ~60 up) would pass 100 MB in under 5 s
    secs, why = NP.nq_plan(o, 7.5e6, {"down_mbps": 38, "up_mbps": 60})
    assert secs is None and "100 MB budget" in why
    assert NP.nq_plan(o, 0, {}) == (NP.NQ_BLIND_SECONDS, None)
    assert NP.nq_plan(o, 2e8, {})[0] is None


# ---------------------------------------------------------------- pooling rounds


def ping_stats(samples, sent):
    mean = statistics.fmean(samples)
    return {"sent": sent, "received": len(samples), "loss_pct": 100.0 * (sent - len(samples)) / sent,
            "min_ms": min(samples), "avg_ms": mean, "max_ms": max(samples), "stddev_ms": statistics.pstdev(samples)}


@given(st.lists(st.tuples(st.lists(finite(1, 900), min_size=1, max_size=40), st.integers(0, 10)), min_size=2,
                max_size=4))
def test_pooled_rounds_match_the_raw_samples(rounds):
    """Differential: pooling per-round ping summaries (macOS prints the
    population sd) equals computing over all samples at once."""
    parts = [{"ping": ping_stats(s, len(s) + extra)} for s, extra in rounds]
    pooled = NP.combine_rounds(parts)["ping"]
    every = [x for s, _ in rounds for x in s]
    sent = sum(len(s) + e for s, e in rounds)
    assert (pooled["sent"], pooled["received"]) == (sent, len(every))
    assert pooled["loss_pct"] == pytest.approx(100.0 * (sent - len(every)) / sent)
    assert pooled["avg_ms"] == pytest.approx(statistics.fmean(every), abs=1e-3)
    assert pooled["stddev_ms"] == pytest.approx(statistics.pstdev(every), abs=1e-3)
    assert (pooled["min_ms"], pooled["max_ms"]) == (min(every), max(every))


def test_pooled_connections_dns_and_throughput():
    a = {"conns": {"attempted": 8, "ok": 8, "by_host": {h: [4, 4] for h in NP.HOSTS}, "tls_s": [0.1], "failures": []},
         "dns": {"server": "10.0.0.1", "attempts": 4, "ok": 4, "times_ms": [10.0, 20.0, 30.0, 40.0], "failures": []},
         "stream": {"down_mbps": 10.0, "up_mbps": 5.0, "bytes": 7_500_000},
         "nq": {"down_mbps": 20.0, "up_mbps": 9.0, "rpm": 100.0, "base_rtt_ms": 30.0, "bytes": 50_000_000}}
    b = {"conns": {"attempted": 8, "ok": 4, "by_host": {h: [2, 4] for h in NP.HOSTS}, "tls_s": [0.2],
                   "failures": [{"host": "github.com", "exit": 7}]},
         "dns": {"server": "10.0.0.1", "attempts": 4, "ok": 2, "times_ms": [50.0, 60.0], "failures": ["x", "y"]},
         "stream": {"down_mbps": 30.0, "up_mbps": 7.0, "bytes": 7_500_000},
         "nq": {"skipped": "budget", "bytes": 0}}
    got = NP.combine_rounds([a, b])
    assert got["rounds"] == 2
    assert (got["conns"]["attempted"], got["conns"]["ok"]) == (16, 12)
    assert got["conns"]["by_host"] == {h: [6, 8] for h in NP.HOSTS}
    assert (got["dns"]["attempts"], got["dns"]["ok"], got["dns"]["median_ms"], got["dns"]["max_ms"]) == (8, 6, 35.0, 60.0)
    assert (got["stream"]["down_mbps"], got["stream"]["up_mbps"], got["stream"]["bytes"]) == (20.0, 6.0, 15_000_000)
    assert (got["nq"]["down_mbps"], got["nq"]["runs"], got["nq"]["bytes"]) == (20.0, 1, 50_000_000)
    assert NP.combine_rounds([a]) == dict(a, rounds=1)


# ---------------------------------------------------------------- never switch, never write


FORBIDDEN = [
    ["networksetup", "-setairportnetwork", "en0", "Max's Pixel"],
    ["networksetup", "-setairportpower", "en0", "off"],
    ["networksetup", "-ordernetworkservices", "Pixel 11 Pro Fold", "Wi-Fi"],
    ["networksetup", "-setnetworkserviceenabled", "Wi-Fi", "off"],
    ["networksetup", "-removepreferredwirelessnetwork", "en0", "Amtrak_WiFi"],
    ["networksetup", "-listallhardwareports", "-x"],
    ["ipconfig", "set", "en0", "DHCP"],
    ["ipconfig", "getoption", "en0", "router"],
    ["route", "add", "default", "192.168.42.129"],
    ["route", "-n", "delete", "default"],
    ["route", "-n", "change", "default", "-interface", "en13"],
    ["pkill", "-f", "networkQuality"],
    ["killall", "networkQuality"],
    ["kill", "-9", "4242"],
    ["security", "find-generic-password", "-D", "AirPort network password"],
    ["sudo", "ping", "-b", "en0", "1.1.1.1"],
    ["ifconfig", "en0", "down"],
    ["scutil", "--set", "HostName", "x"],
    ["log", "show"],
    ["ping", "1.1.1.1"],
    ["ping", "-b", "utun3", "1.1.1.1"],
    ["curl", "https://api.anthropic.com/"],
    ["curl", "--interface", "lo0", "https://api.anthropic.com/"],
    ["networkQuality", "-M", "20"],
    ["netstat", "-rn"],
    ["osascript", "-e", 'do shell script "networksetup -setairportpower en0 off"'],
    ["osascript", "-l", "JavaScript", "-e", "$.CWWiFiClient.sharedWiFiClient.interface.disassociate", "en0"],
    ["osascript", "-l", "JavaScript", "-e", NP.WLAN_JXA, "en0; rm -rf ~"],
    ["/sbin/ping", "-b", "en0", "1.1.1.1"],
    [],
]


@pytest.mark.parametrize("argv", FORBIDDEN, ids=lambda a: " ".join(a[:3]) or "empty")
def test_guard_refuses_anything_but_bound_reads(argv):
    with pytest.raises(NP.UnsafeCommand):
        NP.check_command(argv)


def test_guard_allows_the_reads_and_bound_probes():
    for argv in (["ping", "-b", "en13", "-c", "40", "1.1.1.1"], ["curl", "-s", "--interface", "en0", "https://x/"],
                 ["networkQuality", "-I", "en0", "-M", "8", "-c"], ["netstat", "-rn", "-f", "inet"],
                 ["netstat", "-ibn", "-I", "en0"], ["ipconfig", "getifaddr", "en0"],
                 ["ipconfig", "getoption", "en13", "domain_name_server"], ["networksetup", "-listallhardwareports"],
                 ["route", "-n", "get", "default"], ["osascript", "-l", "JavaScript", "-e", NP.WLAN_JXA, "en0"]):
        NP.check_command(argv)
    assert all(p.startswith(("/sbin/", "/usr/bin/", "/usr/sbin/")) for p in NP.TOOL_PATHS.values())
    assert set(NP.TOOL_PATHS) == set(NP.READ_ONLY)


def test_source_has_no_switching_or_secret_reading_command():
    text = SCRIPT.read_text()
    for bad in ("-setairportnetwork", "-setairportpower", "-ordernetworkservices", "-setnetworkserviceenabled",
                "removepreferredwireless", "associateToNetwork", "disassociate", "setPower", "commitConfiguration",
                "pkill", "killall", "find-generic-password", "find-internet-password", "SecItem", "/usr/bin/python3",
                "os.system", "os.popen", "os.kill", "killpg", "shell=True", "/usr/bin/log"):
        assert bad not in text, bad
    for word in ("associate", "setPower", "commit", "scan", "disconnect"):
        assert word not in NP.WLAN_JXA


def test_only_the_runner_starts_processes():
    tree = ast.parse(SCRIPT.read_text())
    runner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Runner")
    inside = {id(n) for n in ast.walk(runner)}
    starters = {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput", "system",
                "popen", "execv", "execvp", "execve", "spawnv", "posix_spawn", "kill", "killpg", "fork"}
    found = 0
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id in ("subprocess", "os") and node.attr in starters):
            found += 1
            assert id(node) in inside, f"{node.value.id}.{node.attr} outside Runner, line {node.lineno}"
    assert found == 2  # subprocess.run and subprocess.Popen


def test_runner_kills_its_own_child_on_timeout_and_budget(tmp_path, monkeypatch):
    """The real Runner, with ping mapped to a slow stand-in script."""
    slow = tmp_path / "slow"
    slow.write_text("#!/bin/sh\nexec sleep 30\n")  # one process, like networkQuality
    slow.chmod(0o755)
    monkeypatch.setitem(NP.TOOL_PATHS, "ping", str(slow))
    r = NP.Runner()
    got = r.run(["ping", "-b", "en0", "1.1.1.1"], timeout=0.5)
    assert (got.stopped, got.rc) == ("timeout", -9) and got.seconds < 5
    got = r.run_watched(["ping", "-b", "en0", "1.1.1.1"], timeout=20, should_stop=lambda t: "budget" if t > 0.6 else None,
                        poll=0.2)
    assert got.stopped == "budget" and got.rc == -9 and got.seconds < 5
    got = r.run_watched(["ping", "-b", "en0", "1.1.1.1"], timeout=0.5, should_stop=lambda t: None, poll=0.1)
    assert got.stopped == "timeout"
    # a grandchild that keeps the pipes open cannot hold the watchdog past its grace second
    slow.write_text("#!/bin/sh\nsleep 4\n")
    got = r.run_watched(["ping", "-b", "en0", "1.1.1.1"], timeout=20, should_stop=lambda t: "budget", poll=0.2)
    assert got.stopped == "budget" and got.seconds < 3


def test_runner_feeds_stdin_and_reports_missing_tools(tmp_path, monkeypatch):
    echo = tmp_path / "count"
    echo.write_text("#!/bin/sh\nwc -c | tr -d ' '\n")
    echo.chmod(0o755)
    monkeypatch.setitem(NP.TOOL_PATHS, "curl", str(echo))
    got = NP.Runner().run(["curl", "--interface", "en0", "--data-binary", "@-", "https://x/"], 5, stdin=bytes(1234))
    assert (got.rc, got.out.strip(), got.stopped) == (0, "1234", None)
    monkeypatch.setitem(NP.TOOL_PATHS, "curl", str(tmp_path / "missing"))
    assert NP.Runner().run(["curl", "--interface", "en0", "https://x/"], 5).rc == 127


def test_windows():
    assert NP.parse_window("90s") == 90 and NP.parse_window("2h") == 7200 and NP.parse_window("7d") == 604800
    assert NP.parse_window("all") is None and NP.parse_window("0") is None and NP.parse_window(None) is None
    with pytest.raises(ValueError):
        NP.parse_window("2 hours")


def test_labels_and_ids_without_ssids():
    r = capture("nettest_appam.txt")
    assert r["label"] == "Wi-Fi WPA2 gw 172.21.112.1"
    assert r["network_id"] == NP.network_id({"kind": "wifi", "gateway": "172.21.112.1", "security_class": "wpa2"})
    same_place_new_ip = dict(r, ip="172.21.121.112", egress={"org": "AS6079 RCN"})
    assert NP.network_id(same_place_new_ip) == r["network_id"]
    assert NP.make_label(same_place_new_ip) == "Wi-Fi WPA2 gw 172.21.112.1 · AS6079 RCN"
    t = {"kind": "wired", "port": "Pixel 11 Pro Fold", "gateway": "192.168.42.129", "interface": "en13",
         "egress": {"org": "AS6167 Cellco Partnership DBA Verizon Wireless"}}
    assert NP.make_label(t) == "Pixel 11 Pro Fold · AS6167 Cellco Partnership DBA…"
    assert NP.network_id(t) == NP.network_id(dict(t, gateway="192.168.99.1"))  # tether subnets change
    assert NP.network_id(t) != r["network_id"]


def test_history_record_is_json_round_trippable():
    r = capture("nettest_net1_open.txt")
    assert json.loads(json.dumps(r)) == r
