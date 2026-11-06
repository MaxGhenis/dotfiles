"""Shared helpers for the netpick tests.

load_netpick() imports bin/netpick (no .py suffix) as a module. FakeMac is a
Mac whose links answer netpick's read-only commands from a script: every
command goes through netpick's own allowlist first, and every call is kept in
FakeMac.calls with the fake time and the Wi-Fi gateway at that moment.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import importlib.machinery
import importlib.util
import json
import math
import os
import pathlib
import sys
import threading

from hypothesis import settings

# Quick by default; NETPICK_HYPOTHESIS=thorough runs 25 times the examples.
settings.register_profile("netpick", max_examples=200, deadline=None)
settings.register_profile("thorough", max_examples=5000, deadline=None)
settings.load_profile(os.environ.get("NETPICK_HYPOTHESIS", "netpick"))

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "netpick"
FIXTURES = ROOT / "tests" / "fixtures" / "netpick"


def load_netpick():
    loader = importlib.machinery.SourceFileLoader("netpick", str(SCRIPT))
    spec = importlib.util.spec_from_loader("netpick", loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["netpick"] = mod  # dataclasses look the module up by name
    write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True  # leave no __pycache__ in bin/
    try:
        loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = write_bytecode
    return mod


NP = load_netpick()
T0 = dt.datetime(2026, 11, 5, 20, 0, tzinfo=dt.timezone.utc).timestamp()


@dataclasses.dataclass
class Link:
    iface: str
    port: str
    ip: str
    gateway: str
    security: str | None = None  # ipconfig getsummary spelling (Wi-Fi only)
    online_after: float = 0.0  # fake seconds after the link appears before the captive check passes
    loss_pct: float = 0.0
    rtt_ms: float = 30.0
    rtt_sd: float = 5.0
    conn_fail: object = None  # callable(n) -> True when the n-th HTTPS connection fails
    down_mbps: float = 20.0  # bounded one-connection transfer
    up_mbps: float = 10.0
    nq: str = "ok"  # "ok", "fail" or "hang"
    nq_down: float = 25.0
    nq_up: float = 15.0
    rpm: float = 300.0
    org: str = "AS64500 Example Networks"
    dns_ok: bool = True
    dns_reply: str | None = None  # ipconfig getoption domain_name_server output; None: the gateway
    appeared: float = -math.inf  # set by FakeMac when the link comes up


class FakeMac:
    """A Mac with some links. wired links are static; set wifi_schedule to
    [(time, Link or None), ...] to move en0 between Wi-Fi networks."""

    def __init__(self, links, primary=None, now=T0):
        self.static = {lk.iface: lk for lk in links}
        for lk in links:
            lk.appeared = now
        self.primary = primary or links[0].iface
        self.now = now
        self.calls = []  # (time, en0 gateway, argv)
        self.octets = {}  # iface -> (bytes in, bytes out), what netpick's counter reader sees
        self.conn_n = {}
        self.wifi_schedule = None
        self.lock = threading.RLock()

    # -- time
    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(seconds, 0)

    # -- which links are up
    def link(self, iface):
        if iface == "en0" and self.wifi_schedule is not None:
            current = None
            for t, lk in self.wifi_schedule:
                if t <= self.now:
                    current = (t, lk)
            if current is None or current[1] is None:
                return None
            t, lk = current
            lk.appeared = t
            return lk
        return self.static.get(iface)

    def links(self):
        ifaces = set(self.static) | ({"en0"} if self.wifi_schedule is not None else set())
        return [lk for lk in (self.link(i) for i in sorted(ifaces)) if lk is not None]

    def online(self, lk):
        return self.now - lk.appeared >= lk.online_after

    # -- netpick's Runner interface
    def run(self, argv, timeout, stdin=None):
        NP.check_command(argv)
        with self.lock:
            gw = (self.link("en0") or Link("", "", "", None)).gateway
            self.calls.append((self.now, gw, list(argv)))
        return self.answer(list(argv), stdin)

    def run_watched(self, argv, timeout, should_stop, poll=0.5):
        NP.check_command(argv)
        with self.lock:
            gw = (self.link("en0") or Link("", "", "", None)).gateway
            self.calls.append((self.now, gw, list(argv)))
        iface = argv[argv.index("-I") + 1]
        secs = int(argv[argv.index("-M") + 1])
        lk = self.link(iface)
        elapsed = 0.0
        limit = timeout if lk is None or lk.nq == "hang" else secs
        while elapsed < limit:
            elapsed += poll
            if lk is not None and lk.nq != "hang":
                self.bump(iface, lk.nq_down * 1e6 / 8 * poll, lk.nq_up * 1e6 / 8 * poll)
            if elapsed >= timeout:
                return NP.Proc(-9, "", "", elapsed, "timeout")
            reason = should_stop(elapsed)
            if reason:
                return NP.Proc(-9, "", "", elapsed, reason)
        if lk.nq == "fail":
            return NP.Proc(1, "", "Error: the test could not complete")
        payload = {
            "dl_throughput": lk.nq_down * 1e6,
            "ul_throughput": lk.nq_up * 1e6,
            "responsiveness": lk.rpm,
            "base_rtt": lk.rtt_ms,
            "dl_bytes_transferred": int(lk.nq_down * 1e6 / 8 * secs),
            "ul_bytes_transferred": int(lk.nq_up * 1e6 / 8 * secs),
            "dl_phase_duration": float(secs),
            "ul_phase_duration": float(secs),
            "other": {"interface-type": {"wifi" if lk.port == "Wi-Fi" else "wiredEthernet": 9}},
        }
        return NP.Proc(0, json.dumps(payload))

    def bump(self, iface, down_bytes, up_bytes):
        with self.lock:
            ib, ob = self.octets.get(iface, (8_000_000_000, 1_000_000_000))
            self.octets[iface] = (ib + int(down_bytes), ob + int(up_bytes))

    # -- netpick's counters hook (the kernel's interface byte counters)
    def if_counters(self, iface):
        if self.link(iface) is None:
            return None
        with self.lock:
            return self.octets.get(iface, (8_000_000_000, 1_000_000_000))

    # -- netpick's dns and resolve hooks
    def dns(self, server, host, iface):
        lk = self.link(iface)
        if lk is None or not lk.dns_ok or server != (NP.first_ipv4(lk.dns_reply) or lk.gateway):
            return False, None, "timeout"
        return True, 20.0, "ok"

    @staticmethod
    def resolve(host):
        return NP.FALLBACK_IPS[host]

    # -- command answers
    def answer(self, a, stdin):
        P = NP.Proc
        cmd = a[0]
        if cmd == "netstat" and a[1] == "-rn":
            lines = ["Routing tables", "", "Internet:",
                     "Destination        Gateway            Flags               Netif Expire"]
            for lk in sorted(self.links(), key=lambda x: x.iface != self.primary):
                flags = "UGScg" if lk.iface == self.primary else "UGScIg"
                lines.append(f"default            {lk.gateway:<18} {flags:<19} {lk.iface:>5}")
            return P(0, "\n".join(lines) + "\n")
        if cmd == "route":
            if self.link(self.primary):
                return P(0, f"   route to: default\n  interface: {self.primary}\n")
            return P(1, "", "route: writing to routing socket: not in table")
        if cmd == "networksetup":
            ports = {"en0": "Wi-Fi", **{i: lk.port for i, lk in self.static.items()}}
            body = "".join(f"\nHardware Port: {p}\nDevice: {d}\nEthernet Address: 00:00:5e:00:53:99\n" for d, p in ports.items())
            return P(0, body)
        if cmd == "ipconfig":
            lk = self.link(a[2])
            if lk is None:
                return P(1, "", "")
            if a[1] == "getifaddr":
                return P(0, lk.ip + "\n")
            if a[1] == "getsummary":
                kind = "WiFi" if lk.port == "Wi-Fi" else "Ethernet"
                sec = f"  Security : {lk.security}\n" if lk.security else ""
                return P(0, f"<dictionary> {{\n  InterfaceType : {kind}\n  SSID : <redacted>\n{sec}}}\n")
            return P(0, lk.dns_reply or lk.gateway + "\n")  # getoption domain_name_server: the router answers DNS
        if cmd == "osascript":
            lk = self.link(a[5])
            if lk is None or lk.port != "Wi-Fi":
                return P(0, "null\n")
            return P(0, json.dumps({"rssi": -50, "noise": -92, "tx_rate": 573, "channel": 36, "band": 2, "width": 3,
                                    "security": 4}) + "\n")
        if cmd == "ping":
            lk = self.link(a[a.index("-b") + 1])
            if lk is None:
                return P(1, "", "ping: bad interface name\n")
            count = int(a[a.index("-c") + 1])
            recv = round(count * (1 - lk.loss_pct / 100))
            loss = 100.0 * (count - recv) / count
            text = f"--- 1.1.1.1 ping statistics ---\n{count} packets transmitted, {recv} packets received, {loss:.1f}% packet loss\n"
            if recv:
                lo, hi = max(lk.rtt_ms - lk.rtt_sd, 1.0), lk.rtt_ms + 2 * lk.rtt_sd
                text += f"round-trip min/avg/max/stddev = {lo:.3f}/{lk.rtt_ms:.3f}/{hi:.3f}/{lk.rtt_sd:.3f} ms\n"
            return P(0 if recv else 2, text)
        if cmd == "curl":
            iface = a[a.index("--interface") + 1]
            lk = self.link(iface)
            url = a[-1]
            if lk is None:
                return P(45, "45 000 0.000000 0.000000" if "-I" in a else "")
            if url == NP.CAPTIVE_URL:
                page = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
                return P(0, page if self.online(lk) else "<html><title>Sign in to Wi-Fi</title></html>")
            if not self.online(lk):
                return P(28, "28 000 0.000000 0.000000" if "-I" in a else "")
            if url == NP.IPINFO_URL:
                return P(0, json.dumps({"ip": "203.0.113.9", "org": lk.org, "city": "Boston", "region": "Massachusetts",
                                        "country": "US", "loc": "0,0", "postal": "00000"}))
            if "-I" in a:
                with self.lock:
                    n = self.conn_n.get(iface, 0)
                    self.conn_n[iface] = n + 1
                if lk.conn_fail is not None and lk.conn_fail(n):
                    return P(7, "7 000 0.000000 0.000000")
                return P(0, "0 404 0.010000 0.070000")
            if url.startswith("https://speed.cloudflare.com/__down"):
                n = int(url.split("bytes=")[1])
                speed = lk.down_mbps * 1e6 / 8
                self.bump(iface, n, 0)
                return P(0, f"0 {n} {speed:.0f} 0 0 {n / speed:.3f}")
            if url == NP.STREAM_UP_URL:
                n = len(stdin or b"")
                speed = lk.up_mbps * 1e6 / 8
                self.bump(iface, 0, n)
                return P(0, f"0 0 0 {n} {speed:.0f} {n / speed:.3f}")
        raise AssertionError(f"FakeMac has no answer for {a}")

    # -- helpers for assertions
    def argvs(self, tool=None, iface=None):
        out = []
        for _t, _gw, argv in self.calls:
            if tool and argv[0] != tool:
                continue
            if iface and iface not in argv:
                continue
            out.append(argv)
        return out


def make_prober(mac, **opts):
    return NP.Prober(runner=mac, opts=NP.Options(**opts), dns=mac.dns, resolve=mac.resolve,
                     counters=mac.if_counters, clock=mac.clock, sleep=mac.sleep)


def wifi(**kw):
    """The APPAM venue Wi-Fi as seen on 11/05 (gateway and security spelling)."""
    base = dict(iface="en0", port="Wi-Fi", ip="172.21.121.112", gateway="172.21.112.1", security="WPA2_PSK")
    base.update(kw)
    return Link(**base)


def tether(**kw):
    """A USB-tethered Pixel, listed as its own hardware port."""
    base = dict(iface="en13", port="Pixel 11 Pro Fold", ip="192.168.42.10", gateway="192.168.42.129",
                org="AS6167 Cellco Partnership DBA Verizon Wireless")
    base.update(kw)
    return Link(**base)
