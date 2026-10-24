"""openmessage-watchdog skips staleness alerts for unlinked platforms, alerts
once when a paired platform becomes unlinked, and the alerts it keeps still
respect their 6 h cooldown.

On 2026-10-07 /api/status reported WhatsApp and Signal as paired=false, yet
behind_<name> and proj_<name> had re-notified every 6 h since 2026-09-03 and
drowned the channel during a real 4-day SMS outage. paired=false is also what
an involuntary logout looks like, so losing a pairing is announced once.

These tests run the real script the way launchd does (/bin/bash <script>)
against a fixture daemon: http.server on an ephemeral port serving /api/status.
Everything it could touch is sandboxed: a throwaway HOME/TMPDIR, temp state
dir, log and app bundle, a pinned clock, and stub osascript/open/pgrep/pkill
first on PATH that record their argv instead of posting banners or touching
the real app. DRYRUN would not be enough on its own, since it still writes
cooldown epochs. The decision rule in the python block is also checked
directly over thousands of generated payloads.

A damaged counter or cooldown file, or an epoch later than the run clock,
reads as missing (read_state, from the parked watchdog-hardening branch and
extended), and banner text from the daemon stays inside its AppleScript
string literal.
Every run, skipped ones included, rewrites health.txt in the state dir with
what it did and every condition it currently sees.

Daemon text cannot add, cut or rename a line of the python block's output
(the line protocol section at the end): before, a newline in Signal's
last_issue_reason cut its alert short there, and the rest became a line of
its own, an alert with its own cooldown stamp when shaped like one.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from hypothesis import HealthCheck, Phase, example, given, settings
from hypothesis import strategies as st

SCRIPT = Path(__file__).resolve().parent.parent / "bin" / "openmessage-watchdog"

HOUR = 3600
DAY = 24 * HOUR
COOLDOWN = 6 * HOUR
T0 = 1_791_460_000  # 2026-10-08, the pinned clock (epoch seconds)

# Default exit codes: osascript and open succeed; pgrep and pkill match nothing.
STUBS = {"osascript": 0, "open": 0, "pgrep": 1, "pkill": 1}
STUB = """#!/usr/bin/python3
import json, os, sys
name = os.path.basename(sys.argv[0])
with open(os.path.join(os.environ["WATCHDOG_STUB_CALLS"], name + ".jsonl"), "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\\n")
sys.exit({code})
"""
BANNER = re.compile(r'display notification "(.*)" with title "OpenMessage watchdog"')


class Daemon:
    """Serves a mutable /api/status payload (a dict, or raw bytes) and counts
    the probes."""

    def __init__(self):
        self.payload: dict | bytes = {}
        self.hits = 0
        daemon = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/api/status":
                    self.send_error(404)
                    return
                daemon.hits += 1
                body = daemon.payload if isinstance(daemon.payload, bytes) else json.dumps(daemon.payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Sandbox:
    def __init__(self, root: Path, daemon: Daemon):
        self.daemon = daemon
        self.home = root / "home"
        self.state = root / "state"
        self.log = root / "watchdog.log"
        self.app = root / "Applications" / "OpenMessage.app"
        self.stubs = root / "stubs"
        self.calls_dir = root / "calls"
        for d in (self.home, root / "tmp", self.app, self.stubs, self.calls_dir):
            d.mkdir(parents=True)
        for name, code in STUBS.items():
            stub = self.stubs / name
            stub.write_text(STUB.format(code=code))
            stub.chmod(0o755)
        self.env = {
            "PATH": f"{self.stubs}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.home),
            "TMPDIR": str(root / "tmp"),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "OPENMESSAGE_WATCHDOG_PORT": str(daemon.port),
            "OPENMESSAGE_WATCHDOG_STATE": str(self.state),
            "OPENMESSAGE_WATCHDOG_LOG": str(self.log),
            "OPENMESSAGE_WATCHDOG_APP": str(self.app),
            "OPENMESSAGE_WATCHDOG_DRYRUN": "0",
            "WATCHDOG_STUB_CALLS": str(self.calls_dir),
        }
        # Never the live watchdog's state, log, daemon, banners or app.
        for key in ("HOME", "OPENMESSAGE_WATCHDOG_STATE", "OPENMESSAGE_WATCHDOG_LOG", "OPENMESSAGE_WATCHDOG_APP"):
            assert Path(self.env[key]).is_relative_to(root), key
        assert daemon.port != 7007
        for name in STUBS:
            assert shutil.which(name, path=self.env["PATH"]) == str(self.stubs / name), name

    def launch(self, clock: str, script: Path = SCRIPT, **env) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["/bin/bash", str(script)],
            env={**self.env, "OPENMESSAGE_WATCHDOG_NOW": clock, **env},
            cwd=self.home, capture_output=True, text=True, timeout=60,
        )

    def run(self, status: dict | bytes | None = None, at: int = T0, **env) -> subprocess.CompletedProcess:
        if status is not None:
            self.daemon.payload = status
        proc = self.launch(str(at), **env)
        assert proc.returncode == 0, proc.stderr
        assert proc.stderr == "", proc.stderr
        return proc

    def calls(self, name: str) -> list[list[str]]:
        path = self.calls_dir / f"{name}.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def banners(self) -> list[str]:
        return [m.group(1) for argv in self.calls("osascript") if (m := BANNER.fullmatch(argv[-1]))]

    def log_lines(self, needle: str = "") -> list[str]:
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return [line[20:] for line in lines if needle in line]  # drop the wall-clock stamp

    def stored(self, name: str) -> str | None:
        path = self.state / name
        return path.read_text().strip() if path.exists() else None


@pytest.fixture
def daemon():
    d = Daemon()
    yield d
    d.close()


@pytest.fixture
def box(tmp_path, daemon) -> Sandbox:
    return Sandbox(tmp_path, daemon)


def status(at: int = T0, **platforms: dict) -> dict:
    """An /api/status body whose newest message arrived at `at`. Google is
    paired, connected and current unless overridden. Each platform spec takes
    paired/connected (omitted keys stay absent), behind (seconds its last
    message trails the newest), proj (projection stalled) and block=False to
    drop its status block altogether."""
    newest = at * 1000
    body: dict = {"connected": True, "freshness": {"newest_ms": newest}}
    for name, spec in {"google": {"paired": True, "connected": True}, **platforms}.items():
        if spec.get("block", True):
            body[name] = {k: spec[k] for k in ("paired", "connected") if k in spec}
        latest = newest - spec.get("behind", 0) * 1000
        body["freshness"][name] = {
            "latest_received_ms": latest,
            "latest_ms": latest,
            "projection_stalled": spec.get("proj", False),
        }
    return body


# The 2026-10-07 shape: WhatsApp and Signal unlinked and ~7 weeks behind,
# Signal's projection stalled, Google healthy (plus the daemon's aggregate flag).
UNLINKED = {"paired": False, "connected": False}
LIVE_2026_10_07 = status(
    whatsapp={**UNLINKED, "behind": 48 * DAY},
    signal={**UNLINKED, "behind": 50 * DAY, "proj": True},
)
LIVE_2026_10_07["freshness"]["projection_stalled"] = True
PAIRED = {"paired": True, "connected": True}


# ---------- the unpaired gate ----------

UNLINK_BANNER = "No longer paired: whatsapp - check the app; relink unless that was intended"
PAUSED = "staleness alerts paused until it is relinked"


def test_unpaired_far_behind_never_notifies(box):
    for at in (T0, T0 + 7 * HOUR, T0 + 13 * HOUR):  # the old script fired at each 6 h mark
        box.run(LIVE_2026_10_07, at=at)
    assert box.banners() == []
    assert box.log_lines("ALERT") == []
    assert box.log_lines("suppressed") == []
    assert sorted(p.name for p in box.state.glob("alert_*")) == []
    # First seen unpaired (no paired history): logged once, never announced.
    assert box.log_lines("unpaired:") == [f"unpaired: signal - {PAUSED}", f"unpaired: whatsapp - {PAUSED}"]
    assert [box.stored(f"paired_{p}") for p in ("google", "signal", "whatsapp")] == ["1", "0", "0"]
    assert box.log_lines("disconnected") == []  # DISC already required paired


def test_paired_far_behind_notifies_once(box):
    box.run(status(whatsapp={**PAIRED, "behind": 3 * DAY}))
    assert box.banners() == ["whatsapp received nothing for 3.0d while other platforms flow"]
    assert box.stored("alert_behind_whatsapp") == str(T0)


def test_paired_projection_stall_still_notifies(box):
    box.run(status(signal={**PAIRED, "proj": True}))
    assert box.banners() == ["signal projection stalled"]


def test_only_the_paired_platform_alerts_in_a_mixed_run(box):
    box.run(status(signal={**UNLINKED, "behind": 50 * DAY, "proj": True},
                   whatsapp={**PAIRED, "behind": 3 * DAY}))
    # One banner and no "(+N more)": the unlinked platform added nothing.
    assert box.banners() == ["whatsapp received nothing for 3.0d while other platforms flow"]


@pytest.mark.parametrize("spec", [
    {"block": False},                   # no status block at all
    {"connected": True},                # block without a paired key
    {"paired": None, "connected": True},
    {"paired": 0, "connected": True},   # not a JSON boolean
])
def test_only_an_explicit_paired_false_pauses(box, spec):
    box.run(status(imessage={**spec, "behind": 3 * DAY}))
    assert box.banners() == ["imessage received nothing for 3.0d while other platforms flow"]
    assert box.log_lines("unpaired") == []


def test_losing_a_pairing_is_announced_once(box):
    """paired=false is also what an involuntary logout looks like, so a
    platform seen paired and then unpaired gets one banner, and its staleness
    alerts then stay quiet across cooldown windows."""
    box.run(status(whatsapp=PAIRED))
    box.run(status(T0 + 300, whatsapp=UNLINKED), at=T0 + 300)
    assert box.banners() == [UNLINK_BANNER]
    assert box.log_lines("unpaired:") == [f"unpaired: whatsapp - was paired; {PAUSED}"]
    for at in (T0 + 7 * HOUR, T0 + 3 * DAY):
        box.run(status(at, whatsapp={**UNLINKED, "behind": 3 * DAY - 300}), at=at)
    assert box.banners() == [UNLINK_BANNER]
    assert box.stored("alert_unlinked_whatsapp") == str(T0 + 300)


def test_a_loss_inside_the_cooldown_waits_and_is_still_announced(box):
    """A second loss within 6 h of the first banner is not dropped: it stays
    pending and is announced on the first run 6 h after that banner, if the
    platform is still unpaired then."""
    first = T0 + 300
    schedule = [(T0, PAIRED), (first, UNLINKED), (T0 + 600, PAIRED), (T0 + 900, UNLINKED),
                (T0 + 1200, PAIRED), (T0 + 1500, UNLINKED), (first + COOLDOWN - 1, UNLINKED)]
    for at, spec in schedule:
        box.run(status(at, whatsapp=spec), at=at)
    assert box.banners() == [UNLINK_BANNER]
    assert box.log_lines("suppressed") == ["suppressed (cooldown): unlinked_whatsapp"] * 3
    box.run(status(first + COOLDOWN, whatsapp=UNLINKED), at=first + COOLDOWN)  # exactly 6 h
    box.run(status(first + COOLDOWN + 300, whatsapp=UNLINKED), at=first + COOLDOWN + 300)
    assert box.banners() == [UNLINK_BANNER, UNLINK_BANNER]
    assert box.stored("alert_unlinked_whatsapp") == str(first + COOLDOWN)
    assert len(box.log_lines("paired again: whatsapp")) == 1


def test_a_lost_pairing_leads_the_banner(box):
    """Only the first alert reaches the banner and the loss is not repeated,
    so it goes ahead of the run's other alerts and names every platform lost."""
    box.run(status(whatsapp=PAIRED, signal=PAIRED))
    both_lost = status(T0 + 300, whatsapp=UNLINKED, signal=UNLINKED)
    both_lost["projection_stalled"] = True
    box.run(both_lost, at=T0 + 300)
    assert box.banners() == [
        "No longer paired: signal, whatsapp - check the app; relink unless that was intended (+1 more - see log)"]


def test_relinking_resumes_alerts_at_once(box):
    """Alerts resume on the first run that sees paired=true; a platform still
    behind then alerts right away (unchanged paired behavior)."""
    box.run(status(whatsapp={**UNLINKED, "behind": 48 * DAY}))
    box.run(status(T0 + 300, whatsapp={**PAIRED, "behind": 48 * DAY}), at=T0 + 300)
    assert box.log_lines("paired again") == ["paired again: whatsapp - staleness alerts resume"]
    assert box.banners() == ["whatsapp received nothing for 48.0d while other platforms flow"]


def test_a_garbled_status_does_not_fake_a_relink(box):
    box.run(LIVE_2026_10_07)
    box.run(b'{"connected": true, "freshness": ', at=T0 + 300)  # passes the class-A probe, fails JSON
    box.run(LIVE_2026_10_07, at=T0 + 600)
    assert len(box.log_lines("status parse error")) == 1
    assert box.log_lines("paired again") == []
    assert len(box.log_lines("unpaired:")) == 2  # signal and whatsapp, once each
    assert box.banners() == []


def test_paired_disconnect_still_escalates_on_the_third_check(box):
    for i in range(4):
        box.run(status(T0 + 300 * i, whatsapp={"paired": True, "connected": False}), at=T0 + 300 * i)
        assert len(box.banners()) == (1 if i >= 2 else 0)
    assert box.banners() == ["whatsapp disconnected 15+ min - in-app recovery may be stuck"]


# ---------- cooldown ----------

def test_cooldown_holds_for_six_hours(box):
    def run_at(at):
        box.run(status(at, whatsapp={**PAIRED, "behind": 3 * DAY}), at=at)
        return len(box.banners())

    assert run_at(T0) == 1
    assert run_at(T0 + HOUR) == 1
    assert run_at(T0 + COOLDOWN - 1) == 1
    assert box.log_lines("suppressed") == ["suppressed (cooldown): behind_whatsapp"] * 2
    assert run_at(T0 + COOLDOWN) == 2  # re-notifies at exactly 6 h
    assert run_at(T0 + COOLDOWN + 300) == 2
    assert box.stored("alert_behind_whatsapp") == str(T0 + COOLDOWN)


def test_cooldown_matches_a_reference_model(tmp_path, daemon):
    """Over random run schedules, a paired platform that stays behind gets a
    banner exactly when the model says: on the first run, then on the first
    run at least 6 h after the last banner. Every schedule starts with runs
    6 h - 1 s and then exactly 6 h after the first banner."""
    rng = random.Random(20261008)
    gaps = [300, HOUR, COOLDOWN - 1, COOLDOWN, COOLDOWN + 1, 9 * HOUR, DAY]
    for trial in range(4):
        box = Sandbox(tmp_path / f"trial{trial}", daemon)
        at, last, expected, since_banner = T0, None, 0, set()
        for gap in [0, COOLDOWN - 1, 1] + [rng.choice(gaps) for _ in range(4)]:
            at += gap
            box.run(status(at, whatsapp={**PAIRED, "behind": 3 * DAY}), at=at)
            if last is not None:
                since_banner.add(at - last)
            if last is None or at - last >= COOLDOWN:
                last, expected = at, expected + 1
            assert len(box.banners()) == expected, (trial, at - T0)
        assert {COOLDOWN - 1, COOLDOWN} <= since_banner


# ---------- test seams ----------

def test_clock_override_drives_the_python_checks(box):
    box.run(status(T0 - 25 * HOUR), at=T0)
    assert box.banners() == ["No messages on ANY platform for 25h - likely silent global failure"]


@pytest.mark.parametrize("clock", ["soon", "-1", "1.5", "0" + str(T0), "9" * 12])
def test_rejects_a_clock_that_is_not_epoch_seconds(box, daemon, clock):
    proc = box.launch(clock)
    assert proc.returncode == 2
    assert "OPENMESSAGE_WATCHDOG_NOW must be epoch seconds" in proc.stderr
    assert daemon.hits == 0 and not box.log.exists() and not box.state.exists()


def test_accepts_the_longest_allowed_clock(box, daemon):
    at = int("9" * 11)
    box.run(status(at), at=at)
    assert daemon.hits == 1 and box.banners() == []


def test_missing_app_bundle_skips_the_run(box, daemon):
    missing = box.app.parent / "Missing.app"
    box.run(status(whatsapp={**PAIRED, "behind": 3 * DAY}), OPENMESSAGE_WATCHDOG_APP=str(missing))
    assert box.log_lines("skip") == [f"skip: {missing} not installed"]
    assert daemon.hits == 0
    assert box.calls("osascript") == [] and box.calls("open") == []


def test_dead_daemon_relaunches_through_the_stubs(box):
    dead = {}  # no "connected" key: the class-A probe counts it as down
    box.run(dead, at=T0)
    assert box.calls("open") == []
    box.run(dead, at=T0 + 300)
    assert box.calls("open") == [["-ga", "OpenMessage"]]
    assert box.calls("pgrep")[:2] == [["-f", PAIRING_PATTERN], ["-x", "OpenMessage"]]
    assert box.banners() == ["Daemon was down - relaunched the app. Messages were not syncing."]
    assert box.stored("last_action_epoch") == str(T0 + 300)
    box.run(dead, at=T0 + 600)
    box.run(dead, at=T0 + 900)
    assert box.log_lines("throttled") == ["action throttled (10m since last; need 30m)"]
    assert len(box.calls("open")) == 1


def test_dryrun_posts_nothing_but_still_writes_cooldowns(box):
    box.run(status(whatsapp={**PAIRED, "behind": 3 * DAY}), OPENMESSAGE_WATCHDOG_DRYRUN="1")
    assert box.calls("osascript") == []
    assert box.log_lines("NOTIFY") == ["NOTIFY: whatsapp received nothing for 3.0d while other platforms flow"]
    assert box.stored("alert_behind_whatsapp") == str(T0)  # why tests never point it at the live state


# ---------- the watchdog's own silence estimate ----------

SILENT_GOOGLE = ("google silent {}h while connected (normally active in {} of those hours)"
                 " - check or restart the phone (watchdog estimate)")


def v2_store(data_dir: Path, received: list[int]) -> None:
    """data_dir/v2/store.sqlite3 with one google.protobuf inbox frame per
    epoch second in `received`. The table keeps the inbox columns from
    openmessage's 0004_messages_inbox.sql that a frame needs here; the
    watchdog reads only codec and received_at_ms."""
    (data_dir / "v2").mkdir(parents=True)
    con = sqlite3.connect(data_dir / "v2" / "store.sqlite3")
    with con:
        con.execute("create table inbox (inbox_id text primary key, account_id text not null,"
                    " codec text not null, received_at_ms integer not null)")
        con.executemany("insert into inbox values (?, 'google', 'google.protobuf', ?)",
                        [(f"frame-{i}", at * 1000) for i, at in enumerate(received)])
    con.close()


@pytest.mark.parametrize("baseline_days, alert_h", [
    (14, 6),   # 14 active days: alerts once 6 normally-active hours pass silent
    (5, 16),   # busy, but under 7 active days: alerts after 16 h
    (0, 72),   # no baseline: alerts after 72 h
], ids=["evaluated-baseline", "busy-baseline", "no-baseline"])
def test_silence_estimate_runs_on_the_pinned_clock(box, tmp_path, baseline_days, alert_h):
    """On a daemon that does not report silence itself, the watchdog computes
    Google's verdict from the v2 inbox, and that verdict follows
    OPENMESSAGE_WATCHDOG_NOW like every other check. Two runs seconds apart on
    one store, pinned a minute either side of the rule's threshold, get
    opposite verdicts, which a wall-clock reading could not produce.

    Google's last frame is at T0. A baseline has a frame in every hour of the
    baseline_days whole days before T0's day, so every hour counts as
    normally active and the expected-active hours equal the silent hours;
    with none they stay 0 and only the 72 h rule applies. TZ=UTC fixes the
    day and hour buckets."""
    data_dir = tmp_path / "openmessage-data"
    day0 = T0 - T0 % DAY
    v2_store(data_dir, [day0 - k * HOUR for k in range(baseline_days * 24, 0, -1)] + [T0])
    body = status(T0)  # Google paired, connected, newest at T0, no silence block
    body["v2_ingest"] = {"enabled": True}
    body["auth"] = {"data_dir": str(data_dir)}

    quiet, loud = T0 + alert_h * HOUR - 60, T0 + alert_h * HOUR + 60
    box.run(body, at=quiet, TZ="UTC")
    assert box.log_lines("google silent") == []
    assert box.stored("alert_silent_google") is None
    box.run(body, at=loud, TZ="UTC")
    msg = SILENT_GOOGLE.format(alert_h, alert_h if baseline_days else 0)
    assert box.log_lines("google silent") == [f"ALERT: {msg}", f"NOTIFY: {msg}"]
    assert box.banners()[-1] == msg  # at 72 h, all_quiet fired on the quiet run and is cooling down
    assert box.stored("alert_silent_google") == str(loud)
    assert box.log_lines("could not read the v2 inbox") == []


def test_silence_verdict_is_a_step_in_the_pinned_clock(tmp_path):
    """For any v2 inbox whose last Google frame is at L, and pinned clocks N:
      1. at N = L (no silence yet) there is no silent_google alert;
      2. from N = L + 72 h on there always is one;
      3. as N grows the verdict never returns to quiet;
      4. the alert reports floor((N - L) / 3600) silent hours and leads the
         block's output.
    Checked on the script's python block over random inboxes and clocks. An
    estimate read off the wall clock gives every N of an inbox the same
    verdict, so each inbox breaks 1 or 2."""
    rng = random.Random(20261009)
    cases, stores = [], []
    for i in range(60):
        last = T0 + rng.randint(0, DAY)  # vary the hour of day
        density = rng.choice([0.0, 0.1, 0.5, 0.9, 1.0])
        earlier = [last - k * HOUR - rng.randint(0, HOUR - 1)
                   for k in range(1, rng.randint(0, 16) * 24 + 1) if rng.random() < density]
        data_dir = tmp_path / f"store{i}"
        v2_store(data_dir, earlier + [last])
        body = {"connected": True, "google": {"paired": True, "connected": True},
                "freshness": {"newest_ms": last * 1000, "google": {"latest_received_ms": last * 1000}},
                "v2_ingest": {"enabled": True}, "auth": {"data_dir": str(data_dir)}}
        clocks = sorted({last, last + 72 * HOUR, last + 72 * HOUR + rng.randint(1, 3 * DAY)}
                        | {last + h * HOUR + d for h in (6, 16, 72) for d in (-60, 60)}
                        | {last + rng.randint(1, 72 * HOUR - 1) for _ in range(12)})
        cases += [{"status": body, "now": n} for n in clocks]
        stores.append((last, density, clocks))
    results = iter(evaluate(cases, tmp_path))
    early = 0
    for last, density, clocks in stores:
        verdicts = []
        for n in clocks:
            out = next(results)
            assert not any(line.startswith("ALERT|silence_check|") for line in out), out
            silent = [line for line in out if line.startswith("ALERT|silent_google|")]
            if silent:
                assert out[0] == silent[0], out
                assert silent[0].startswith(f"ALERT|silent_google|google silent {(n - last) // HOUR}h "), (n - last, out)
            verdicts.append(bool(silent))
        ctx = (last, density, clocks, verdicts)
        assert verdicts[0] is False, ctx
        assert all(v for n, v in zip(clocks, verdicts) if n >= last + 72 * HOUR), ctx
        assert verdicts == sorted(verdicts), ctx  # False... then True...
        early += any(v for n, v in zip(clocks, verdicts) if n < last + 72 * HOUR)
    assert 10 <= early <= len(stores) - 10, early  # both the baseline rules and the 72 h rule decide some inboxes


# ---------- damaged state files ----------

def shell_function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}\n", SCRIPT.read_text(), re.M | re.S)
    assert match, f"{name}() not found"
    return match.group(0)


def as_bash_reads(content: bytes) -> bytes:
    """What `$(head -c 64 FILE)` hands bash 3.2: the first 64 bytes, NULs
    dropped, trailing newlines stripped."""
    return content[:64].replace(b"\0", b"").rstrip(b"\n")


def canonical(value: bytes) -> bool:
    return re.fullmatch(rb"0|[1-9][0-9]{0,17}", value) is not None


@pytest.mark.parametrize("mode", ["count", "epoch"])
def test_read_state_returns_canonical_values_and_removes_the_rest(tmp_path, mode):
    """For every file content C, with V = what bash reads of it: read_state
    prints V and leaves the file alone when V is a canonical decimal of at
    most 18 digits (and, for an epoch, no later than the run clock NOW).
    Otherwise it prints 0, logs the file's name once and removes it, so it
    reads as missing from then on. A missing file reads as 0, silently."""
    rng = random.Random(20261009)
    alphabet = b"0123456789 -+.\n\t\0xZ\xff\xc3\xa9"
    contents = [b"", b"0", b"7", str(T0).encode(), str(T0 + 1).encode(), b"9" * 18, b"9" * 19, b"08", b"00",
                b"-5", b"+5", b"1 2", b"12\n34", b"5\n", b"5\n\n", b"5\0", b"\n5", b" 5", b"abc", b"1e3", b"0x10",
                b"\xff\xfe", b"5" + b"\n" * 63 + b"x", b"1" * 70]
    contents += [bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 24))) for _ in range(400)]
    contents += [str(T0 + rng.randint(-DAY, DAY)).encode() for _ in range(50)]
    files = []
    for i, content in enumerate(contents):
        path = tmp_path / f"state_{i}"
        path.write_bytes(content)
        files.append(path)
    missing = tmp_path / "state_missing"
    log = tmp_path / "log"
    driver = (shell_function("read_state") + 'log() { echo "$*" >> "$LOGF"; }\n'
              'for f in "$@"; do printf "%s\\n" "$(read_state "$f" "$MODE")"; done\n')
    proc = subprocess.run(["/bin/bash", "-c", "set -u\n" + driver, "bash", *map(str, files), str(missing)],
                          env={"LOGF": str(log), "NOW": str(T0), "MODE": mode if mode == "epoch" else "",
                               "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                          capture_output=True, timeout=60)
    assert proc.returncode == 0 and proc.stderr == b"", proc.stderr
    out = proc.stdout.decode().splitlines()
    assert len(out) == len(files) + 1
    logged = log.read_text(errors="replace").splitlines() if log.exists() else []
    removed = future = 0
    for path, content, printed in zip(files, contents, out):
        assert re.fullmatch(r"0|[1-9][0-9]{0,17}", printed), (content, printed)
        value = as_bash_reads(content)
        ahead = canonical(value) and mode == "epoch" and int(value) > T0
        if canonical(value) and not ahead:
            assert printed.encode() == value and path.read_bytes() == content, content
            assert not any(f"state file {path.name} " in line for line in logged), content
        else:
            removed += 1
            future += ahead
            why = "in the future" if ahead else "damaged"
            assert printed == "0" and not path.exists(), content
            assert sum(f"state file {path.name} was {why}" in line for line in logged) == 1, content
    assert out[-1] == "0" and not missing.exists()
    assert len(logged) == removed > 300  # the property is not vacuous
    assert (future > 20) if mode == "epoch" else (future == 0)


def test_a_damaged_cooldown_stamp_no_longer_drops_the_runs_alerts(box):
    """Before read_state, '08' in alert_all_quiet made bash abandon the alert
    loop when all_quiet came up: that alert and every later one in the loop
    were lost, every run, and the stamp was never rewritten. Alerts read
    before it (behind_whatsapp here) still reached the banner."""
    (box.state).mkdir()
    (box.state / "alert_all_quiet").write_text("08")
    box.run(status(T0 - 25 * HOUR, whatsapp={**PAIRED, "behind": 3 * DAY}))
    assert box.banners() == ["whatsapp received nothing for 3.0d while other platforms flow (+1 more - see log)"]
    assert box.log_lines("ALERT: No messages on ANY platform") != []
    assert box.log_lines("state file") == ["state file alert_all_quiet was damaged ('08') - removed, read as 0"]
    assert box.stored("alert_all_quiet") == str(T0)


@pytest.mark.parametrize("name", ["consecutive_fails", "last_action_epoch"])
def test_a_damaged_relaunch_counter_no_longer_blocks_relaunches(box, name):
    """Before read_state, 'zz' in either file ended every class-A run before
    the relaunch, for good: the dead daemon stayed dead, and the main log
    never named the cause."""
    box.state.mkdir()
    (box.state / name).write_text("zz")
    box.run({}, at=T0)
    box.run({}, at=T0 + 300)
    assert box.calls("open") == [["-ga", "OpenMessage"]]
    assert box.log_lines("state file") == [f"state file {name} was damaged ('zz') - removed, read as 0"]


DAMAGED = st.binary(max_size=24).filter(lambda b: not canonical(as_bash_reads(b)))
EPOCH_FILES = ("last_action_epoch", "alert_unlinked_signal", "alert_all_quiet", "alert_behind_whatsapp",
               "down_since", "disc_since_whatsapp", "repair_since_google")
STATE_FILES = ("consecutive_fails", "disc_google", "disc_whatsapp", "disc_signal", "repair_google") + EPOCH_FILES


def run_every_state_read(box: Sandbox) -> tuple:
    """Two dead-daemon runs (a relaunch), then three healthy runs that hit the
    disconnect, repair, lost-pairing and cooldown counters."""
    box.state.mkdir(exist_ok=True)
    (box.state / "paired_signal").write_text("1")
    box.run({}, at=T0)
    box.run({}, at=T0 + 300)
    for i in range(3):
        at = T0 + 600 + 300 * i
        body = status(at - 25 * HOUR, whatsapp={"paired": True, "connected": False, "behind": 3 * DAY},
                      signal=UNLINKED)
        body["google"]["needs_repair"] = True
        box.run(body, at=at)
    stored = {p.name: p.read_text() for p in sorted(box.state.iterdir())}
    return box.banners(), box.calls("open"), stored, [l for l in box.log_lines() if not l.startswith("state file")]


@settings(max_examples=3, deadline=None, derandomize=True, phases=[Phase.explicit, Phase.generate],
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(damage=st.dictionaries(st.sampled_from(STATE_FILES), DAMAGED, min_size=1))
@example(damage={name: b"" for name in STATE_FILES})  # a write cut off after the truncate
@example(damage={name: b"08" for name in STATE_FILES})
@example(damage={name: str(T0 + DAY).encode() for name in EPOCH_FILES})  # stamps from a clock that went back
def test_damaged_state_behaves_like_missing_state(tmp_path_factory, daemon, damage):
    """Differential: whatever damaged bytes sit in whichever state files, the
    run sequence makes the same banners, relaunches, final state and log as it
    does with those files absent, plus one damage line per file."""
    clean = Sandbox(tmp_path_factory.mktemp("clean"), daemon)
    hurt = Sandbox(tmp_path_factory.mktemp("hurt"), daemon)
    hurt.state.mkdir()
    for name, content in damage.items():
        (hurt.state / name).write_bytes(content)
    assert run_every_state_read(hurt) == run_every_state_read(clean)
    assert sorted(l.split()[2] for l in hurt.log_lines("state file")) == sorted(damage)


def test_a_future_relaunch_stamp_no_longer_blocks_relaunches(box):
    """Before, a last_action_epoch a day ahead of the clock (a clock that went
    back) throttled every relaunch for that day: "action throttled (-1425m
    since last; need 30m)"."""
    box.state.mkdir()
    (box.state / "last_action_epoch").write_text(str(T0 + DAY))
    (box.state / "consecutive_fails").write_text("1")
    box.run({}, at=T0)
    assert box.calls("open") == [["-ga", "OpenMessage"]]
    assert box.log_lines("state file") == [f"state file last_action_epoch was in the future ('{T0 + DAY}') - removed, read as 0"]


# ---------- banner text from the daemon ----------

STRICT_BANNER = re.compile(r'display notification "([^"\\]*)" with title "OpenMessage watchdog"')
INJECTION = 'x" & (do shell script "echo ran") & "'


def test_notify_puts_any_message_inside_one_literal(tmp_path):
    """For every message M, notify() hands osascript one `display
    notification` statement whose only string literals are M without its
    double quotes and backslashes, and the title. It logs M unchanged."""
    rng = random.Random(20261010)
    pieces = ['"', "\\", "\\\\", '\\"', INJECTION, "é", "—", "\t", "\r", " ", "(", ")", "&", "'", "a", "7", "¬", "\u2028"]
    messages = ["", '"', "\\", INJECTION, 'decrypt "failed"', "C:\\path\\"]
    messages += ["".join(rng.choice(pieces) for _ in range(rng.randint(0, 12))) for _ in range(300)]
    calls, log = tmp_path / "calls", tmp_path / "log"
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    (stubs / "osascript").write_text('#!/bin/bash\nprintf "%s\\0" "$2" >> "$CALLS"\n')
    (stubs / "osascript").chmod(0o755)
    driver = shell_function("notify") + 'log() { printf "%s\\0" "$*" >> "$LOGF"; }\nDRYRUN=0\nfor m in "$@"; do notify "$m"; done\n'
    proc = subprocess.run(["/bin/bash", "-c", "set -u\n" + driver, "bash", *messages],
                          env={"CALLS": str(calls), "LOGF": str(log), "PATH": f"{stubs}:/usr/bin:/bin",
                               "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"},
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0 and proc.stderr == "", proc.stderr
    scripts = calls.read_bytes().decode().split("\0")[:-1]  # bytes: text mode would turn \r into \n
    logged = log.read_bytes().decode().split("\0")[:-1]
    assert len(scripts) == len(logged) == len(messages)
    for message, script, line in zip(messages, scripts, logged):
        match = STRICT_BANNER.fullmatch(script)
        assert match, (message, script)
        assert match.group(1) == message.replace('"', "").replace("\\", ""), message
        assert line == f"NOTIFY: {message}"


def test_a_quoted_signal_reason_still_reaches_the_banner(box, tmp_path):
    """signal last_issue_reason comes from the daemon verbatim. With a quote
    in it, the banner used to fail to compile (lost); with a crafted one, the
    rest ran as AppleScript. Checked with osacompile, which compiles and never
    runs, where macOS provides it."""
    reason = f'decrypt "failed" \\ {INJECTION}'
    body = status(signal=PAIRED)
    body["signal"]["receive_recovery"] = {"pending_count": 6, "last_issue_reason": reason}
    box.run(body)
    shown = f"Signal receive-recovery backlog: 6 pending ({reason})".replace('"', "").replace("\\", "")
    assert box.banners() == [shown]
    script = box.calls("osascript")[0][-1]
    assert STRICT_BANNER.fullmatch(script)
    assert box.log_lines("NOTIFY") == [f"NOTIFY: Signal receive-recovery backlog: 6 pending ({reason})"]
    if shutil.which("osacompile"):
        compiled = subprocess.run(["osacompile", "-o", str(tmp_path / "banner.scpt"), "-e", script],
                                  capture_output=True, text=True, timeout=60)
        assert compiled.returncode == 0, compiled.stderr


# ---------- the pairing-in-flight guard ----------

PAIRING_PATTERN = re.search(r"pgrep -f '([^']*)'", SCRIPT.read_text()).group(1)


@pytest.mark.parametrize("cmdline, matches", [
    ("./openmessage pair", True),
    ("/Users/me/openmessage/openmessage pair --google-file /tmp/c.json", True),
    ("openmessage pair --google", True),
    ("/usr/bin/python3 /tmp/x/stubs/pgrep -f " + PAIRING_PATTERN, False),  # a test's own stub
    ("pgrep -f openmessage pair", False),
    ("grep -rn openmessage pair /Users/me/notes", False),
    ("/Applications/OpenMessage.app/Contents/MacOS/openmessage serve --web", False),
    ("openmessage pairing-helper", False),
], ids=["relative-path", "absolute-path-with-flag", "bare-name", "stub-passing-the-pattern",
        "old-pgrep", "grep-for-the-phrase", "serve", "longer-word"])  # ids keep the phrase out of pytest argv
def test_pairing_guard_matches_only_the_pair_command(cmdline, matches):
    """Checked with grep -E (the same POSIX ERE as macOS pgrep -f) against
    command lines, without starting any process the live watchdog could see.
    A stub whose argv held the literal phrase made the live watchdog skip
    runs on 2026-10-08."""
    assert "openmessage pair" not in PAIRING_PATTERN
    hit = subprocess.run(["/usr/bin/grep", "-Eq", PAIRING_PATTERN], input=cmdline, text=True).returncode == 0
    assert hit is matches


# ---------- the rule itself, over generated payloads ----------

DRIVER = r"""
import contextlib, io, json, os, sys
job = json.load(sys.stdin)
code = compile(job["code"], "openmessage-watchdog:python", "exec")
results = []
for case in job["cases"]:
    os.environ["OPENMESSAGE_WATCHDOG_NOW"] = str(case["now"])
    sys.stdin = io.StringIO(json.dumps(case["status"]))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            exec(code, {"__name__": "__main__"})
        except SystemExit:
            pass
    results.append([line for line in buf.getvalue().splitlines() if line])  # bash skips blank lines
print(json.dumps(results))
"""
NAMES = ("google", "whatsapp", "signal", "imessage")  # imessage: a platform the script does not list


def python_block() -> str:
    # The block is one single-quoted bash word, so it ends at the next quote.
    match = re.search(r"/usr/bin/python3 -c '([^']*)'", SCRIPT.read_text())
    assert match, "python block not found"
    return match.group(1)


def evaluate(cases: list[dict], home: Path) -> list[list[str]]:
    """Run the script's python block over many payloads in one /usr/bin/python3
    (the interpreter the script uses)."""
    proc = subprocess.run(
        ["/usr/bin/python3", "-I", "-c", DRIVER],
        input=json.dumps({"code": python_block(), "cases": cases}),
        env={"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def random_status(rng: random.Random, now: int) -> dict:
    newest = (now - rng.choice([0, rng.randint(0, 72 * HOUR)])) * 1000
    body: dict = {"connected": True}
    for name in NAMES:
        if rng.random() < (0.5 if name == "imessage" else 0.1):
            continue
        block: dict = {}
        for key, values in (("paired", [True, False, None, 0, 1]), ("connected", [True, False])):
            if rng.random() < 0.85:
                block[key] = rng.choice(values)
        if name == "google":
            block["needs_repair"] = rng.random() < 0.2
            block["repairs_paced"] = rng.choice([0, 0, 3, 5])
        if name == "signal" and rng.random() < 0.2:
            block["receive_recovery"] = {"pending_count": rng.randint(0, 8), "last_issue_reason": "x"}
        body[name] = block
    fresh: dict = {}
    if rng.random() < 0.9:
        fresh["newest_ms"] = newest
    if rng.random() < 0.3:
        fresh["projection_stalled"] = rng.random() < 0.5  # the daemon's aggregate, not a dict
    for name in NAMES:
        if rng.random() < 0.15:
            continue
        if rng.random() < 0.05:
            fresh[name] = "junk"
            continue
        lag = rng.choice([0, rng.randint(0, 47 * HOUR), 48 * HOUR, 48 * HOUR + 1, rng.randint(2 * DAY, 100 * DAY)])
        f: dict = {}
        if rng.random() < 0.8:
            f["latest_received_ms"] = newest - lag * 1000
        if rng.random() < 0.5:
            f["latest_ms"] = newest - rng.randint(0, 100 * DAY) * 1000
        if rng.random() < 0.3:
            f["projection_stalled"] = True
        fresh[name] = f
    if rng.random() < 0.95:
        body["freshness"] = fresh
    if rng.random() < 0.2:
        body["projection_stalled"] = True
    if rng.random() < 0.2:
        body["v2_ingest"] = {"per_account": {"a": {"quarantined": rng.randint(0, 2)}}}
    return body


def test_rule_skips_exactly_the_unpaired_staleness_alerts(tmp_path):
    """For every payload P, with U = platforms whose status block says
    paired=false (the JSON boolean) and P' = P with those paired keys deleted
    (unknown, which keeps alerting):
      1. P yields no behind_/proj_ alert for any platform in U;
      2. apart from the UNPAIRED lines, P yields exactly P' minus those
         alerts, so nothing else (DISC, cooldown keys, ordering) moves;
      3. P reports pairing, in name order, for exactly the platforms the
         script looks at whose paired is a boolean: UNPAIRED for U, PAIRED
         for paired=true.
    """
    rng = random.Random(20261007)
    cases, variants, unpaired_sets = [], [], []
    for _ in range(3000):
        now = T0 + rng.randint(0, 30 * DAY)
        body = random_status(rng, now)
        unpaired = {n for n, b in body.items() if isinstance(b, dict) and b.get("paired") is False}
        relaxed = copy.deepcopy(body)
        for n in unpaired:
            del relaxed[n]["paired"]
        cases.append({"status": body, "now": now})
        variants.append({"status": relaxed, "now": now})
        unpaired_sets.append(unpaired)
    results = evaluate(cases + variants, tmp_path)
    gated_somewhere = 0
    for i, unpaired in enumerate(unpaired_sets):
        got, ungated = results[i], results[len(cases) + i]
        body = cases[i]["status"]

        def gated(line):
            return any(line.startswith((f"ALERT|behind_{n}|", f"ALERT|proj_{n}|")) for n in unpaired)

        ctx = json.dumps(cases[i])
        assert not any(gated(line) for line in got), ctx
        assert [l for l in got if not l.startswith("UNPAIRED|")] == [l for l in ungated if not gated(l)], ctx
        looked_at = {"google", "whatsapp", "signal"} | set(body.get("freshness") or {})
        expected = [f"{'PAIRED' if body[n]['paired'] else 'UNPAIRED'}|{n}" for n in sorted(looked_at)
                    if isinstance(body.get(n), dict) and isinstance(body[n].get("paired"), bool)]
        assert [l for l in got if l.startswith(("PAIRED|", "UNPAIRED|"))] == expected, ctx
        assert not any(l.startswith("UNPAIRED|") for l in ungated), ctx
        gated_somewhere += any(gated(line) for line in ungated)
    assert gated_somewhere > 300, gated_somewhere  # the property is not vacuous


# ---------- health.txt ----------

def health(box: Sandbox) -> dict:
    """health.txt as {key: value}, plus its "alert" and "note" lines. Lines
    end in \n only (a value may hold U+2028, which str.splitlines would
    split), alerts come before notes, and the file ends with "# end"."""
    out: dict = {"alert": [], "note": []}
    lines = (box.state / "health.txt").read_bytes().decode().split("\n")
    assert lines[-2:] == ["# end", ""], lines[-3:]
    kinds = []
    for line in lines[:-2]:
        assert not any(ord(ch) < 32 or ord(ch) == 127 for ch in line), repr(line)
        if line.startswith("#"):
            continue
        if line.startswith(("alert: ", "note: ")):
            kind, _, text = line.partition(": ")
            out[kind].append(text)
            kinds.append(kind)
            continue
        key, sep, value = line.partition("=")
        assert sep and key not in out, line
        out[key] = value
    assert kinds == sorted(kinds)  # "alert" < "note": every alert line first
    assert int(out["alerts"]) == len(out["alert"])
    assert not list(box.state.glob("health.txt.tmp.*"))  # written through a temp file and mv
    return out


def utc(at: int, fmt: str = "%Y-%m-%d %H:%M") -> str:
    return time.strftime(fmt, time.gmtime(at))


def test_a_clean_run_leaves_health_as_its_only_trace(box):
    box.run(status(), TZ="UTC")
    assert box.log_lines() == []
    assert health(box) == {"updated": utc(T0, "%Y-%m-%d %H:%M:%S"), "updated_epoch": str(T0),
                           "watchdog": "active", "watchdog_detail": "no banner this run",
                           "daemon": "up", "daemon_detail": "answered /api/status",
                           "alerts": "0", "alert": [], "note": []}


def test_health_keeps_listing_a_condition_the_cooldown_keeps_off_the_banner(box):
    def body(at):
        return status(at, whatsapp={**PAIRED, "behind": 3 * DAY}, signal={**UNLINKED, "behind": 50 * DAY})

    box.run(body(T0))
    first = health(box)
    assert first["watchdog_detail"] == "banner: whatsapp received nothing for 3.0d while other platforms flow"
    box.run(body(T0 + HOUR), at=T0 + HOUR)
    assert len(box.banners()) == 1
    h = health(box)
    assert h["alert"] == first["alert"] == ["whatsapp received nothing for 3.0d while other platforms flow"]
    assert h["note"] == ["signal unpaired - its staleness checks are paused"]
    assert (h["watchdog_detail"], h["updated_epoch"]) == ("no banner this run", str(T0 + HOUR))
    box.run(body(T0 + 7 * HOUR), at=T0 + 7 * HOUR, OPENMESSAGE_WATCHDOG_DRYRUN="1")
    assert health(box)["watchdog_detail"] == "would banner: whatsapp received nothing for 3.0d while other platforms flow"


def test_health_lists_a_disconnect_or_repair_with_its_start_from_the_third_check_on(box):
    for i in range(5):
        at = T0 + 300 * i
        body = status(at, whatsapp={"paired": True, "connected": False})
        body["google"]["needs_repair"] = True
        box.run(body, at=at, TZ="UTC")
        h = health(box)
        if i < 2:
            assert h["alert"] == [] and "disconnected_since_whatsapp" not in h
            continue
        assert h["alert"] == [f"whatsapp disconnected since {utc(T0)} ({i + 1} checks in a row)",
                              f"Google needs repair since {utc(T0)} ({i + 1} checks in a row)"]
        assert (h["disconnected_since_whatsapp"], h["repair_since_google"]) == (str(T0), str(T0))
    assert len(box.banners()) == 1  # the banner itself still fires once, on the third
    box.run(status(T0 + 1500), at=T0 + 1500)  # both clear
    assert box.stored("disc_since_whatsapp") is None and box.stored("repair_since_google") is None
    assert health(box)["alert"] == []


def test_an_episode_already_running_without_a_start_starts_its_clock_now(box):
    """A watchdog upgraded mid-episode finds a counter but no since-file; the
    episode is then timed from that run."""
    box.state.mkdir()
    (box.state / "disc_whatsapp").write_text("4")
    (box.state / "repair_google").write_text("7")
    body = status(whatsapp={"paired": True, "connected": False})
    body["google"]["needs_repair"] = True
    box.run(body, TZ="UTC")
    h = health(box)
    assert h["alert"] == [f"whatsapp disconnected since {utc(T0)} (5 checks in a row)",
                          f"Google needs repair since {utc(T0)} (8 checks in a row)"]
    assert (box.stored("disc_since_whatsapp"), box.stored("repair_since_google")) == (str(T0), str(T0))


def test_a_parked_watchdog_reports_the_flag_age_and_reason_without_probing(box, daemon):
    flag = box.home / "Library" / "Application Support" / "OpenMessage" / "watchdog-disabled"
    flag.parent.mkdir(parents=True)
    flag.write_text("\n   re-pairing Google\nsecond line\n")
    set_at = T0 - 3 * HOUR - 60
    os.utime(flag, (set_at, set_at))
    box.run(status(), TZ="UTC")
    assert daemon.hits == 0
    assert box.log_lines("skip") == ["skip: disable flag present (set 3h ago; reason: re-pairing Google)"]
    h = health(box)
    assert (h["watchdog"], h["daemon"], h["daemon_detail"], h["alert"]) == ("disabled", "unknown", "not probed", [])
    assert h["paused_since"] == str(set_at)
    assert h["watchdog_detail"] == (f"disable flag set {utc(set_at)} (3h ago); reason: re-pairing Google;"
                                    " no probe, relaunch or alert until it is removed")
    flag.write_text("")  # an empty flag, touched after the pinned clock
    box.run(status(), TZ="UTC")
    assert box.log_lines("skip")[-1] == "skip: disable flag present (set 0h ago)"


def test_a_pairing_in_flight_or_a_missing_app_reports_why_checks_paused(box, daemon):
    (box.stubs / "pgrep").write_text(STUB.format(code="0 if sys.argv[1:2] == ['-f'] else 1"))
    box.run(status())
    h = health(box)
    assert (h["watchdog"], h["watchdog_detail"], h["daemon"]) == (
        "pairing", "a pairing process is running; checks paused", "unknown")
    (box.stubs / "pgrep").write_text(STUB.format(code=1))
    missing = box.app.parent / "Missing.app"
    box.run(status(), OPENMESSAGE_WATCHDOG_APP=str(missing))
    assert health(box)["watchdog"] == "app-missing"
    assert health(box)["watchdog_detail"] == f"{missing} not installed; checks paused"
    assert daemon.hits == 0


def test_the_outage_clock_runs_from_the_first_failed_probe_to_the_first_answer(box):
    def down(at, fails):
        box.run({}, at=at, TZ="UTC")
        h = health(box)
        assert (h["watchdog"], h["daemon"]) == ("active", "down"), h
        assert h["alert"] == [f"daemon not answering since {utc(T0)} ({fails} failed probe(s) in a row)"
                              " - messages are not syncing"]
        assert h["daemon_down_since"] == str(T0)
        return h

    assert down(T0, 1)["daemon_detail"] == "dead (no app process); 1/2 failed probes, no action yet"
    assert health(box)["watchdog_detail"] == "no banner this run"
    h = down(T0 + 300, 2)
    assert box.calls("open") == [["-ga", "OpenMessage"]]
    assert (h["daemon_detail"], h["watchdog_detail"]) == (
        "dead (no app process); relaunched the app",
        "banner: Daemon was down - relaunched the app. Messages were not syncing.")
    down(T0 + 2 * HOUR, 1)  # still dead: the fail count restarted, the clock did not
    down(T0 + 2 * HOUR + 60, 2)  # a second relaunch
    down(T0 + 2 * HOUR + 120, 1)
    h = down(T0 + 2 * HOUR + 180, 2)
    assert len(box.calls("open")) == 2
    assert h["daemon_detail"] == "dead (no app process); relaunch throttled (2m since the last; one per 30m)"
    assert h["watchdog_detail"] == "no banner this run"
    box.run(status(T0 + 3 * HOUR), at=T0 + 3 * HOUR, TZ="UTC")  # answered right after a relaunch (fails 0)
    assert box.stored("down_since") is None
    h = health(box)
    assert (h["daemon"], h["alert"], "daemon_down_since" in h) == ("up", [], False)


def test_a_relaunch_then_an_answer_clears_the_clock(box):
    box.run({}, at=T0)
    box.run({}, at=T0 + 300)  # relaunch: consecutive_fails back to 0
    box.run(status(T0 + 600), at=T0 + 600)
    assert box.stored("down_since") is None
    box.run({}, at=T0 + DAY)
    assert box.stored("down_since") == str(T0 + DAY)


@pytest.mark.parametrize("skip", ["disabled", "pairing", "app-missing"])
def test_a_skipped_run_clears_the_outage_clock(box, skip):
    """The daemon is not watched while a run is skipped, so an outage seen
    after the skip is timed from its own first failed probe."""
    box.run({}, at=T0)
    assert box.stored("down_since") == str(T0)
    flag = box.home / "Library" / "Application Support" / "OpenMessage" / "watchdog-disabled"
    env = {}
    if skip == "disabled":
        flag.parent.mkdir(parents=True)
        flag.write_text("")
    elif skip == "pairing":
        (box.stubs / "pgrep").write_text(STUB.format(code="0 if sys.argv[1:2] == ['-f'] else 1"))
    else:
        env["OPENMESSAGE_WATCHDOG_APP"] = str(box.app.parent / "Missing.app")
    box.run({}, at=T0 + HOUR, **env)
    assert health(box)["watchdog"] == skip
    assert box.stored("down_since") is None
    flag.unlink(missing_ok=True)
    (box.stubs / "pgrep").write_text(STUB.format(code=1))
    box.run({}, at=T0 + 2 * HOUR)
    assert box.stored("down_since") == str(T0 + 2 * HOUR)


def test_a_dry_class_a_run_says_what_it_would_have_done(box):
    for at in (T0, T0 + 300):
        box.run({}, at=at, OPENMESSAGE_WATCHDOG_DRYRUN="1")
    h = health(box)
    assert (h["watchdog"], h["watchdog_detail"]) == ("active", "DRYRUN: no relaunch, no banner")
    assert h["daemon_detail"] == "dead (no app process); DRYRUN: would relaunch"
    assert box.calls("open") == [] and box.calls("osascript") == []


def test_a_python_failure_is_logged_listed_and_leaves_the_counters_alone(box):
    """9/15-9/20: /usr/bin/python3 refused to run, every class-B check was off
    and the main log said nothing. A JSON array that mentions "connected"
    passes the class-A probe and then crashes the block (d.get on a list);
    if the block learns to handle it, use another payload that makes it exit
    non-zero. With no data, the run must not read every platform as
    reconnected."""
    box.state.mkdir()
    for name, value in (("disc_whatsapp", "2"), ("disc_since_whatsapp", str(T0 - 600)), ("repair_google", "4")):
        (box.state / name).write_text(value)
    box.daemon.payload = b'["connected"]'
    proc = box.launch(str(T0))
    assert proc.returncode == 0
    assert "AttributeError" in proc.stderr  # the traceback still reaches the launchd log
    why = "staleness checks did not run: python3 exited 1 (AttributeError: 'list' object has no attribute 'get')"
    assert box.log_lines() == [why]
    assert health(box)["alert"] == [why]
    assert [box.stored(n) for n in ("disc_whatsapp", "disc_since_whatsapp", "repair_google")] == ["2", str(T0 - 600), "4"]


def test_a_garbled_status_leaves_the_counters_alone(box):
    box.state.mkdir()
    (box.state / "disc_whatsapp").write_text("2")
    box.run(b'{"connected": true, "freshness": ')  # passes the class-A probe, fails JSON
    assert [a.split(":")[0] for a in health(box)["alert"]] == ["status parse error"]
    assert box.stored("disc_whatsapp") == "2" and box.log_lines("reconnected") == []


@pytest.mark.parametrize("where, daemon_state", [
    ('\nH_WATCHDOG=active H_WATCHDOG_DETAIL="no banner this run"\n', "up"),  # class B, before its last lines
    ('\n  log "relaunching OpenMessage.app"\n', "down"),                     # class A, before the relaunch
])
def test_a_run_that_dies_partway_leaves_watchdog_error(box, tmp_path, where, daemon_state):
    source = SCRIPT.read_text()
    assert source.count(where) == 1
    broken = tmp_path / "openmessage-watchdog-broken"
    broken.write_text(source.replace(where, '\n: "$WATCHDOG_TEST_UNSET"' + where))  # set -u ends the run here
    box.daemon.payload = status() if daemon_state == "up" else {}
    for at in (T0, T0 + 300):
        proc = box.launch(str(at), script=broken)
    assert "WATCHDOG_TEST_UNSET" in proc.stderr
    h = health(box)
    assert (h["watchdog"], h["daemon"]) == ("error", daemon_state)
    assert h["watchdog_detail"] == "the run stopped before it finished; its stderr is in the launchd log"


def test_a_lost_pairing_is_a_health_alert_until_it_is_announced(box):
    lost = "whatsapp no longer paired - check the app; relink unless that was intended"
    note = "whatsapp unpaired - its staleness checks are paused"
    box.run(status(whatsapp=PAIRED))
    box.run(status(T0 + 300, whatsapp=UNLINKED), at=T0 + 300)
    h = health(box)
    assert (h["alert"], h["note"]) == ([lost], [note])
    assert h["watchdog_detail"] == "banner: No longer paired: whatsapp - check the app; relink unless that was intended"
    box.run(status(T0 + 600, whatsapp=UNLINKED), at=T0 + 600)  # announced: now only the note
    assert (health(box)["alert"], health(box)["note"]) == ([], [note])
    box.run(status(T0 + 900, whatsapp=PAIRED), at=T0 + 900)
    box.run(status(T0 + 1200, whatsapp=UNLINKED), at=T0 + 1200)  # lost again inside the 6 h cooldown
    assert box.log_lines("suppressed (cooldown): unlinked") != []
    assert (health(box)["alert"], health(box)["note"]) == ([lost], [note])


def test_daemon_text_cannot_break_a_health_line(box):
    """ASCII control characters in daemon text become spaces (C1 controls and
    U+2028 stay: lines split on \\n only), and two OpenMessage processes (a
    multi-line pgrep) stay on one daemon_detail line."""
    reason = "a\rb\x0bc\x1cd\te\x7ff\u2028g\u0085h"
    body = status(signal=PAIRED)
    body["signal"]["receive_recovery"] = {"pending_count": 6, "last_issue_reason": reason}
    box.run(body)
    assert health(box)["alert"] == ["Signal receive-recovery backlog: 6 pending (a b c d e f\u2028g\u0085h)"]
    (box.stubs / "pgrep").write_text(STUB.format(code="0 if sys.argv[1:2] == ['-x'] else 1").replace(
        "sys.exit(", "print('111\\n222') if sys.argv[1:2] == ['-x'] else None\nsys.exit("))
    box.run({}, at=T0 + 300)
    assert health(box)["daemon_detail"] == "hung (app pid 111 222, port dead); 1/3 failed probes, no action yet"


def test_the_python_block_still_closes_with_a_bare_quote_paren():
    """Sibling test files (pull_health) find the block by its closing "\n')";
    stderr is redirected around the assignment instead."""
    assert re.search(r"/usr/bin/python3 -c '\n(.*?)\n'\)", SCRIPT.read_text(), re.S)


def test_health_alerts_do_not_depend_on_cooldowns(tmp_path, daemon):
    """For generated payloads P: a fresh run lists, as health alerts, exactly
    the alert texts it logs, in order; and a second run of P one second later,
    with every cooldown now running and no banner, lists the same alerts and
    notes."""
    rng = random.Random(20261011)
    listed = 0
    for i in range(12):
        box = Sandbox(tmp_path / f"case{i}", daemon)
        body = random_status(rng, T0)
        box.run(body, at=T0)
        first = health(box)
        assert first["alert"] == [l[len("ALERT: "):] for l in box.log_lines("ALERT: ")], body
        banners = len(box.banners())
        box.run(body, at=T0 + 1)
        second = health(box)
        assert len(box.banners()) == banners, body
        assert (second["alert"], second["note"]) == (first["alert"], first["note"]), body
        listed += len(first["alert"])
    assert listed >= 10  # not vacuous


def test_a_daemon_reported_silence_is_a_health_note(box):
    body = status()
    body["freshness"]["google"].update(stale_reason="silent", silence={
        "stalled": True, "silent_ms": 20 * HOUR * 1000, "expected_active_hours": 9})
    box.run(body)
    h = health(box)
    assert h["alert"] == [] and box.banners() == []  # the app and the Telegram watcher own this one
    assert h["note"] == ["google silent 20h while connected (normally active in 9 of those hours)"
                         " - check or restart the phone"]


def test_a_write_that_does_not_finish_keeps_the_previous_health(box):
    """A full disk cuts the write short. A tr stub that writes three lines
    and fails stands in for it: the previous health.txt stays, and no temp
    file is left behind."""
    box.run(status(), at=T0)
    before = (box.state / "health.txt").read_bytes()
    (box.stubs / "tr").write_text("#!/usr/bin/python3\nimport sys\n"
                                  "sys.stdout.write(''.join(sys.stdin.readlines()[:3]))\nsys.exit(1)\n")
    (box.stubs / "tr").chmod(0o755)
    box.run(status(T0 + 300), at=T0 + 300)
    assert (box.state / "health.txt").read_bytes() == before
    assert health(box)["updated_epoch"] == str(T0)


# ---------- the line protocol between the python block and bash ----------
#
# The block prints one line per finding; bash reads them with read -r and
# splits their fields on "|". Invariant, for every /api/status payload P
# whose fields have the types the daemon sends, with any string wherever a
# string goes (a block that is not an object still crashes it, as before):
#   1. the block exits cleanly, and its output, split on \n alone (as bash
#      splits it), is UTF-8 lines that each match GRAMMAR;
#   2. the lines are exactly those of P's plain twin (every daemon string the
#      block prints swapped for a sentinel), with each sentinel read back:
#      a platform name as ref_plat(name), Signal's reason as ref_line(reason).
#      Only the PAIRED/UNPAIRED lines may change places (they come sorted
#      by the raw name). So no daemon string adds, drops, cuts or splits a
#      line, and the only stamp files a name keys are alert_proj_, alert_behind_,
#      alert_unlinked_ and paired_ plus its encoded name;
#   3. distinct names never share an encoded name, even ignoring case (the
#      macOS volume ignores it), unless both are cut and their 64-bit hashes
#      collide.
# "Types the daemon sends" includes finite numbers: Python's json accepts
# NaN and Infinity, and those still crash the block where it formats a count.

FORGED = "x\nALERT|forged|forged alert text"  # the 2026-10-09 repro
FIXED = ("google", "whatsapp", "signal")
ALERT_KEYS = {"repairs_paced", "pull_empty", "projection_stalled", "all_quiet", "quarantine",
              "signal_recovery", "silence_check", "silent_google"}
TEXT = r"[^\x00-\x1f\x7f\ud800-\udfff]*"
GRAMMAR = re.compile(rf"PARSEERR\|{TEXT}|NOTE\|{TEXT}|DISC\|(?:google|whatsapp|signal)|REPAIR\|google"
                     rf"|(?:UN)?PAIRED\|(?P<plat>[^|]*)|ALERT\|(?P<key>[^|]*)\|{TEXT}"
                     rf"|APPEND\|(?:0|[1-9][0-9]*)\|(?:0|[1-9][0-9]*)\|{TEXT}")
# Keys of /api/status (or of its freshness block) that are not platforms.
NOT_PLATFORMS = {"connected", "freshness", "v2_ingest", "auth", "projection_stalled", "newest_ms", *FIXED}


def ref_plat(name: str) -> str:
    """plat() as its comment specifies it: lowercase ASCII letters, digits and
    ._- as they are, every other UTF-8 byte as %XX; past 64 characters, the
    first 40 of that, ~ and 16 hex digits of the name's sha256."""
    raw = name.encode("utf-8", "surrogatepass")
    k = "".join(chr(b) if re.fullmatch(r"[a-z0-9._-]", chr(b)) else f"%{b:02X}" for b in raw)
    return k if len(k) <= 64 else f"{k[:40]}~{hashlib.sha256(raw).hexdigest()[:16]}"


RAW_DRIVER = r"""
import io, json, os, sys, types
job = json.load(sys.stdin)
if job["sqlite_error"]:
    def connect(*args, **kwargs):
        raise RuntimeError(job["sqlite_error"])
    sys.modules["sqlite3"] = types.SimpleNamespace(connect=connect)
code = compile(job["code"], "openmessage-watchdog:python", "exec")
real_stdout, results = sys.stdout, []
for case in job["cases"]:
    os.environ["OPENMESSAGE_WATCHDOG_NOW"] = str(case["now"])
    sys.stdin = io.StringIO(json.dumps(case["status"]))
    buf = io.BytesIO()
    # The stdout launchd gives the block: the C locale, so UTF-8 with surrogateescape.
    sys.stdout = io.TextIOWrapper(buf, encoding="utf-8", errors="surrogateescape", newline="\n", write_through=True)
    crash = None
    try:
        exec(code, {"__name__": "__main__"})
    except SystemExit as e:
        if e.code not in (None, 0):
            crash = "SystemExit(%r)" % (e.code,)
    except Exception as e:
        crash = repr(e)
    sys.stdout.flush()
    sys.stdout.detach()
    results.append({"out": buf.getvalue().decode("latin-1"), "crash": crash})
sys.stdout = real_stdout
print(json.dumps(results))
"""


def evaluate_raw(cases: list[dict], home: Path, sqlite_error: str = "") -> list[tuple[bytes, str | None]]:
    """Like evaluate(), but each case's output is the bytes the block wrote to
    a stdout like launchd's, with the exception it raised, if any.
    sqlite_error makes every sqlite3.connect raise it."""
    proc = subprocess.run(
        ["/usr/bin/python3", "-I", "-c", RAW_DRIVER],
        input=json.dumps({"code": python_block(), "cases": cases, "sqlite_error": sqlite_error}),
        env={"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        cwd=home, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return [(r["out"].encode("latin-1"), r["crash"]) for r in json.loads(proc.stdout)]


def protocol_lines(out: bytes) -> list[str]:
    """The lines bash reads from the block's output, each checked against
    GRAMMAR. bash skips an empty one (a run with no findings prints one)."""
    assert out.endswith(b"\n"), out
    lines = [raw.decode("utf-8") for raw in out.split(b"\n")[:-1] if raw]  # strict: no surrogates
    for line in lines:
        assert GRAMMAR.fullmatch(line), line
    return lines


def ref_line(text: str) -> str:
    """line() as its comment specifies it: C0 controls, DEL and lone
    surrogates become spaces."""
    return re.sub(r"[\x00-\x1f\x7f\ud800-\udfff]", " ", text)


SENTINEL = re.compile(r"zqp(\d+)zq|zqreasonzq")  # what plain_twin() puts in; plat() leaves both as they are


def read_back(twin_lines: list[str], body: dict, extra: list[str]) -> list[str]:
    """The lines body should make: its plain twin's, with each sentinel
    replaced in one pass by what the block prints for the string it stands
    for."""
    reason = body["signal"]["receive_recovery"]["last_issue_reason"]
    return [SENTINEL.sub(lambda m: ref_plat(extra[int(m[1])]) if m[1] else ref_line(reason), line)
            for line in twin_lines]


def in_place(lines: list[str]) -> tuple[list[str], list[str]]:
    """The lines in order, and apart the PAIRED/UNPAIRED ones, sorted: the
    block sorts those by the raw name, so a renaming reorders them."""
    pairing = ("PAIRED|", "UNPAIRED|")
    return [l for l in lines if not l.startswith(pairing)], sorted(l for l in lines if l.startswith(pairing))


def plat_labels(extra: list[str], twin: bool = False) -> dict[str, str]:
    """Encoded platform name -> label, for a payload's extra platforms (or its
    plain twin's sentinels) and the fixed three. The encoded names are
    distinct even ignoring case, and each decodes to its name unless cut."""
    labels = {(f"zqp{i}zq" if twin else ref_plat(n)): f"#{i}" for i, n in enumerate(extra)}
    labels.update({n: n for n in FIXED})
    assert len({k.lower() for k in labels}) == len(labels) == len(extra) + len(FIXED)
    for n in extra:
        k = ref_plat(n)
        assert "~" in k or urllib.parse.unquote_to_bytes(k) == n.encode("utf-8", "surrogatepass")
    return labels


# Daemon strings, weighted toward what splits or confuses a line: line
# breaks bash honours (\n) and ones it does not, C0 controls, the field
# separator, lone surrogates, path parts, capitals, and names long enough to
# be cut once encoded.
PIECES = ["\n", "\r", "\r\n", "|", "\x00", "\t", "\x0b", "\x0c", "\x1b", "\x1c", "\x1e", "\x7f", "\x85",
          "\N{LINE SEPARATOR}", "\N{PARAGRAPH SEPARATOR}", "\ud800", "\udc80", "\udfff", "%", "~", "/", "..",
          " ", "A", "\N{LATIN SMALL LETTER E WITH ACUTE}", "e\N{COMBINING ACUTE ACCENT}",
          "ALERT|forged|forged alert text", "NOTE|", "PAIRED|", "PARSEERR|", "google"]
daemon_text = st.one_of(
    st.text(max_size=12),
    st.lists(st.sampled_from(PIECES), max_size=6).map("".join),
    st.text(st.characters(max_codepoint=127), min_size=40, max_size=80),
    st.just(FORGED),
)


@st.composite
def protocol_payloads(draw) -> tuple[dict, list[str]]:
    """(status, its extra platform names): every daemon string drawn from
    daemon_text (extra platform names, Signal's last_issue_reason, the
    pull_health fields, v2 ingest account names), every other field
    well-typed."""
    newest = T0 * 1000
    # Distinct once JSON joins a surrogate pair (see as_sent).
    extra = draw(st.lists(daemon_text.filter(lambda s: s not in NOT_PLATFORMS), unique_by=as_sent, max_size=3))
    names = draw(st.permutations(extra + draw(st.lists(st.sampled_from(FIXED), unique=True, max_size=3))))
    body: dict = {"connected": True}
    for n in (*FIXED, *extra):
        if n in FIXED or draw(st.booleans()):
            body[n] = {"paired": draw(st.sampled_from([True, False, None])), "connected": draw(st.booleans())}
    fresh: dict = {"newest_ms": newest}
    for n in names:
        fresh[n] = {"latest_received_ms": newest - draw(st.sampled_from([0, 3 * DAY])) * 1000,
                    "projection_stalled": draw(st.booleans())}
        if n in FIXED and draw(st.booleans()):
            fresh[n].update(stale_reason="silent", silence={
                "stalled": True, "silent_ms": 20 * HOUR * 1000, "expected_active_hours": 9})
    body["freshness"] = fresh
    body["google"].update(needs_repair=draw(st.booleans()), repairs_paced=draw(st.sampled_from([0, 3])))
    body["google"]["pull_health"] = draw(st.fixed_dictionaries({
        "empty_with_local_history": st.one_of(st.just(True), daemon_text),
        "account_switch": st.one_of(st.booleans(), daemon_text),
        "local_conversations": st.one_of(st.integers(0, 2000), daemon_text),
        "last_attempt_ms": st.one_of(st.integers(newest - DAY * 1000, newest), daemon_text),
        **{k: daemon_text for k in ("last_error", "last_trigger", "last_folder", "last_outcome")},
    }))
    body["signal"]["receive_recovery"] = {"pending_count": draw(st.sampled_from([0, 6])),
                                          "last_issue_reason": draw(daemon_text)}
    if draw(st.booleans()):
        accounts = draw(st.lists(daemon_text.filter(lambda s: "zq" not in s), unique=True, max_size=2))
        body["v2_ingest"] = {"enabled": draw(st.booleans()), "per_account": {
            a: {"append_errors": draw(st.integers(0, 3)), "appended": 5, "quarantined": draw(st.integers(0, 1))}
            for a in accounts}}
    return body, extra


def as_sent(value):
    """value as the block receives it: JSON joins two lone surrogates that
    form a pair into one character."""
    return json.loads(json.dumps(value))


def sent_case(body: dict, extra: list[str]) -> tuple[dict, list[str]]:
    """A case as the block receives it. Names that JSON makes equal
    ("\\ud800\\udc80" and "\\U00010080") are one platform there, as are
    their keys in the body."""
    return as_sent(body), list(dict.fromkeys(as_sent(extra)))


def plain_twin(body: dict, extra: list[str]) -> dict:
    """body with every daemon string the block prints swapped for a
    sentinel: extra platform i becomes zqp<i>zq, Signal's last_issue_reason
    zqreasonzq. The pull_health strings, which it never prints, become "t".
    Account names stay: APPEND lists them in their own sort order, and
    test_account_ids_cannot_break_the_notification_or_the_line_format covers
    their filter."""
    twin = copy.deepcopy(body)
    rename = {n: f"zqp{i}zq" for i, n in enumerate(extra)}
    twin["freshness"] = {rename.get(k, k): v for k, v in twin["freshness"].items()}
    blocks = {n: twin.pop(n) for n in rename if n in twin}
    twin.update({rename[n]: block for n, block in blocks.items()})
    pull_health = twin["google"]["pull_health"]
    pull_health.update({k: "t" for k, v in pull_health.items() if isinstance(v, str)})
    twin["signal"]["receive_recovery"]["last_issue_reason"] = "zqreasonzq"
    return twin


NASTY_NAMES = ("zz\nALERT|forged|forged alert text", "../../escape", "a|b", "Signal", "\ud800", "\r", "",
               "x" * 300, "é")


def nasty_status(reason: str = FORGED, names: tuple[str, ...] = NASTY_NAMES) -> tuple[dict, list[str]]:
    """Every platform paired and connected, each named one 3 days behind with
    its projection stalled, Signal's backlog and Google's pull_health
    carrying reason."""
    body = status(signal=PAIRED, whatsapp=PAIRED, **{n: {**PAIRED, "behind": 3 * DAY, "proj": True} for n in names})
    body["signal"]["receive_recovery"] = {"pending_count": 6, "last_issue_reason": reason}
    body["google"]["pull_health"] = {"empty_with_local_history": True, "local_conversations": 40,
                                     "last_error": reason, "account_switch": reason}
    return body, list(names)


@settings(max_examples=15, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(batch=st.lists(protocol_payloads(), min_size=1, max_size=25))
@example(batch=[nasty_status(), nasty_status("\r\n|\ud800\x00\N{LINE SEPARATOR}", ("A", "a"))])
@example(batch=[nasty_status(names=("\ud800\udc80", "\U00010080"))])  # one name once sent
def test_no_daemon_string_adds_cuts_or_renames_a_line(tmp_path_factory, batch):
    """Invariants 1-3 above, for each payload in the batch against its plain
    twin (one /usr/bin/python3 for the whole batch)."""
    home = tmp_path_factory.mktemp("protocol")
    batch = [sent_case(body, extra) for body, extra in batch]
    cases = [{"status": body, "now": T0} for body, _ in batch]
    twins = [{"status": plain_twin(body, extra), "now": T0} for body, extra in batch]
    results = evaluate_raw(cases + twins, home)
    for (body, extra), (out, crash), (twin_out, twin_crash) in zip(batch, results, results[len(batch):]):
        assert crash is None and twin_crash is None, (crash, twin_crash, body)
        plat_labels(extra)  # invariant 3
        expected = read_back(protocol_lines(twin_out), body, extra)
        assert in_place(protocol_lines(out)) == in_place(expected), body


def test_a_newline_in_a_signal_reason_cannot_forge_an_alert(box):
    """The repro on ffda554: the alert was cut at the newline, and the rest
    became an alert of its own, with its own alert_forged stamp and a
    "(+1 more - see log)" on the banner."""
    body = status(signal=PAIRED)
    body["signal"]["receive_recovery"] = {"pending_count": 6, "last_issue_reason": FORGED}
    box.run(body)
    shown = "Signal receive-recovery backlog: 6 pending (x ALERT|forged|forged alert text)"
    assert box.banners() == [shown]
    assert health(box)["alert"] == [shown]
    assert box.log_lines("ALERT: ") == [f"ALERT: {shown}"]
    assert sorted(p.name for p in box.state.glob("alert_*")) == ["alert_signal_recovery"]


def test_platform_names_are_encoded_into_one_line_and_one_stamp_file(box):
    """Freshness keys name platforms, and a platform names stamp files. A
    newline, |, / or capital in one is encoded, so the name stays on its line,
    keys a file inside the state dir and still says which platform it is."""
    names = {"zz\nALERT|forged|forged alert text": "zz%0A%41%4C%45%52%54%7Cforged%7Cforged%20alert%20text",
             "../../escape": "..%2F..%2Fescape", "a|b": "a%7Cb"}
    box.run(status(**{n: {**PAIRED, "behind": 3 * DAY} for n in names}))
    first = next(iter(names.values()))
    assert box.banners() == [f"{first} received nothing for 3.0d while other platforms flow (+2 more - see log)"]
    assert sorted(p.name for p in box.state.glob("alert_*")) == sorted(f"alert_behind_{k}" for k in names.values())
    assert sorted(p.name for p in box.state.glob("paired_*")) == sorted(
        ["paired_google"] + [f"paired_{k}" for k in names.values()])
    assert sorted(p.name for p in box.home.parent.iterdir()) == [
        "Applications", "calls", "home", "state", "stubs", "tmp", "watchdog.log"]


def test_case_variants_of_a_name_keep_their_own_pairing_state(box):
    """On a case-insensitive volume (the macOS default) paired_Signal and
    paired_signal were one file. A status naming both flipped it on every run
    outside the cooldown and announced "No longer paired: Signal" every 6 h."""
    body = status(signal=PAIRED, Signal=UNLINKED)
    for at in (T0, T0 + 300, T0 + COOLDOWN + 600):
        box.run(body, at=at)
    assert box.banners() == [] and box.log_lines("paired again") == []
    assert (box.stored("paired_signal"), box.stored("paired_%53ignal")) == ("1", "0")


def test_a_long_platform_name_keys_a_stamp_file_that_fits(box):
    """A name past the 255-byte file-name limit failed every stamp write
    ("File name too long"), so its alert notified on every run."""
    name = "x" * 300
    body = status(**{name: {**PAIRED, "behind": 3 * DAY}})
    box.run(body)
    box.run(body, at=T0 + 300)
    k = "x" * 40 + "~" + hashlib.sha256(name.encode()).hexdigest()[:16]
    assert box.banners() == [f"{k} received nothing for 3.0d while other platforms flow"]
    assert (box.stored(f"alert_behind_{k}"), box.stored(f"paired_{k}")) == (str(T0), "1")


def test_a_lone_surrogate_no_longer_stops_the_checks(box):
    """A \\ud800 escape in daemon text made the block's print raise under
    launchd's C locale (UTF-8, surrogateescape): python3 exited 1, and that
    run's staleness checks did not run."""
    body = status(whatsapp={**PAIRED, "behind": 3 * DAY}, signal=PAIRED)
    body["signal"]["receive_recovery"] = {"pending_count": 6, "last_issue_reason": "a\ud800b"}
    box.run(body)
    behind = "whatsapp received nothing for 3.0d while other platforms flow"
    assert box.banners() == [f"{behind} (+1 more - see log)"]
    assert health(box)["alert"] == [behind, "Signal receive-recovery backlog: 6 pending (a b)"]


def test_an_inbox_read_error_stays_on_one_line(tmp_path):
    """silence_check quotes the exception from reading the v2 inbox."""
    body = status()
    body["v2_ingest"] = {"enabled": True}
    [(out, crash)] = evaluate_raw([{"status": body, "now": T0}], tmp_path, sqlite_error="disk I/O error\r\n" + FORGED)
    assert crash is None
    assert protocol_lines(out) == [
        "PAIRED|google", "ALERT|silence_check|watchdog could not read the v2 inbox: disk I/O error  x ALERT|forged|forged alert text"]


STATE_FILE = re.compile(
    r"consecutive_fails|last_action_epoch|down_since|health\.txt|python\.stderr|append_errors"
    r"|repair_google|repair_since_google|disc_(?:since_)?(?:google|whatsapp|signal)"
    rf"|alert_(?:{'|'.join(sorted(ALERT_KEYS | {'append_errors'}))})"
    r"|(?P<slot>alert_proj_|alert_behind_|alert_unlinked_|paired_)(?P<plat>.*)", re.S)


def log_entries(box: Sandbox) -> list[str]:
    """The log's entries without their wall-clock stamp. Split on \\n alone,
    and matched by prefix, not substring: daemon text in an entry may hold
    U+2028 (which str.splitlines splits on) or "ALERT: " itself."""
    return [l[20:] for l in box.log.read_bytes().decode().split("\n") if l] if box.log.exists() else []


def run_unlinking(box: Sandbox, body: dict, labels: dict[str, str]) -> tuple:
    """A run on body, then one with every paired platform unpaired. Returns
    what they did, platform names left out. For each run: its banners (does
    it announce a lost pairing, and for how many platforms) and its ALERT and
    suppressed log entries (bash logs each of the run's alerts, so the
    banner's "+N more" is the ALERT count less one). Then health.txt's keys
    and alert and note counts, the state files (each a known name, or a slot
    and a platform label) and the sandbox's top level."""
    lost = copy.deepcopy(body)
    for block in lost.values():
        if isinstance(block, dict) and block.get("paired") is True:
            block["paired"] = False
    runs = []
    for at, payload in ((T0, body), (T0 + 300, lost)):
        seen_banners, seen_log = len(box.banners()), len(log_entries(box))
        box.run(payload, at=at)
        lost_banner = "No longer paired: "  # bash's own text; encoded names hold no ", " or " - "
        banners = [(b.startswith(lost_banner), b.split(" - ")[0].count(", ") if b.startswith(lost_banner) else 0)
                   for b in box.banners()[seen_banners:]]
        entries = log_entries(box)[seen_log:]
        runs.append((banners, sum(e.startswith("ALERT: ") for e in entries),
                     sum(e.startswith("suppressed (cooldown): ") for e in entries)))
    h = health(box)
    files = []
    for path in box.state.iterdir():
        m = STATE_FILE.fullmatch(path.name)
        assert m, path.name
        files.append((m["slot"], labels[m["plat"]]) if m["slot"] else (path.name, ""))
    return (runs, sorted(h), len(h["alert"]), len(h["note"]), sorted(files),
            sorted(p.name for p in box.home.parent.iterdir()))


@settings(max_examples=4, deadline=None, phases=[Phase.explicit, Phase.generate],
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(case=protocol_payloads())
@example(case=nasty_status())
@example(case=nasty_status("ALERT: suppressed (cooldown): x\N{LINE SEPARATOR}ALERT: (+1 more - see log)", ("p",)))
def test_daemon_strings_change_none_of_a_runs_decisions(tmp_path_factory, daemon, case):
    """End to end, differential: the real script, run on a payload and then
    with its platforms unpaired, makes as many banners, ALERT and suppressed
    log entries per run, the same lost-pairing announcements, the same
    health.txt keys and alert and note counts, and the same state files (up
    to platform names) as on the payload's plain twin. The texts are the
    block-level property's job; each run here takes about 2 s, hence few
    examples."""
    body, extra = sent_case(*case)
    nasty = Sandbox(tmp_path_factory.mktemp("nasty"), daemon)
    plain = Sandbox(tmp_path_factory.mktemp("plain"), daemon)
    assert run_unlinking(nasty, body, plat_labels(extra)) == run_unlinking(
        plain, plain_twin(body, extra), plat_labels(extra, twin=True))
