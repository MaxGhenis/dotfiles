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
"""
from __future__ import annotations

import copy
import json
import random
import re
import shutil
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

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
