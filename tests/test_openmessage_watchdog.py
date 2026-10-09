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
"""
from __future__ import annotations

import copy
import json
import random
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
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

    def launch(self, clock: str, **env) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["/bin/bash", str(SCRIPT)],
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
EPOCH_FILES = ("last_action_epoch", "alert_unlinked_signal", "alert_all_quiet", "alert_behind_whatsapp")
STATE_FILES = ("consecutive_fails", "last_action_epoch", "disc_google", "disc_whatsapp", "disc_signal",
               "repair_google", "alert_unlinked_signal", "alert_all_quiet", "alert_behind_whatsapp")


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
