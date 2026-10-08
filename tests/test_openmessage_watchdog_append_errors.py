"""openmessage-watchdog alerts when v2 ingest append_errors grows.

append_errors counts failed attempts to append a frame a Google, WhatsApp or
Signal transport captured to the v2 inbox (encode fault, SQLite append error,
tee panic; a replayed Signal line that fails again counts again). The daemon only started counting them in openmessage PR #195; before
that the field always read 0. Like every ingest counter it only grows while
the daemon process lives and starts again at 0 after a restart, so the
watchdog alerts when the sum passes the count it already reported, never
re-alerts on a flat count, and goes back to a 0 baseline when the backend
restarts (a new process listening on the port, or either the append_errors or
the appended sum falling). Errors it saw but had not reported yet when the
backend restarted carry over into the next alert. Because the banner shows
only a run's first alert, the append alert waits for a run where it leads.

These tests run the real script the way launchd does (/bin/bash <script>)
against a fixture daemon (http.server on an ephemeral port serving
/api/status) with OPENMESSAGE_WATCHDOG_DRYRUN=1, a throwaway HOME (so the
disable flag is a temp path), and temp state and log paths. The 6 h cooldown
is exercised by back-dating the alert_append_errors epoch in the temp state
dir. A property test drives random counter histories through the script and
checks every run against a reference model of the rule.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "bin" / "openmessage-watchdog"
APP = Path("/Applications/OpenMessage.app")  # the script requires it to exist
COOLDOWN = 6 * 3600

pytestmark = pytest.mark.skipif(
    not APP.is_dir() or not Path("/bin/bash").exists() or not Path("/usr/bin/python3").exists(),
    reason="the script needs /Applications/OpenMessage.app, /bin/bash and /usr/bin/python3",
)


class _Daemon:
    """Serves whatever payload is current at GET /api/status, in-process."""

    def __init__(self) -> None:
        self.payload: dict = {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 (http.server API)
                body = json.dumps(owner.payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


_PROC_SERVER = r"""
import http.server, sys
path = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = open(path, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer.allow_reuse_address = True
s = http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H)
print("ready", flush=True)
s.serve_forever()
"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ProcDaemon:
    """A fixture daemon in its own process, so a test can restart it on the
    same port and the watchdog sees a new listener there."""

    def __init__(self, tmp: Path, port: int | None = None) -> None:
        self.file = tmp / "status.json"
        self.file.write_text("{}")
        self.port = port or _free_port()
        self.proc: subprocess.Popen | None = None
        self.restart()

    @property
    def payload(self) -> dict:
        return json.loads(self.file.read_text())

    @payload.setter
    def payload(self, value: dict) -> None:
        self.file.write_text(json.dumps(value))

    def restart(self) -> None:
        self.close()
        self.proc = subprocess.Popen(
            [sys.executable, "-I", "-c", _PROC_SERVER, str(self.port), str(self.file)],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self.proc.stdout.readline().strip() == "ready"

    def close(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.proc = None


def status(per_account: dict | None, *, quarantined: int = 0, projection_stalled: bool = False) -> dict:
    """A healthy status: everything paired, connected and fresh, so the only
    thing that can alert is the v2 ingest block under test."""
    now_ms = int(time.time() * 1000)
    payload = {
        "connected": True,
        "google": {"paired": True, "connected": True},
        "whatsapp": {"paired": True, "connected": True},
        "signal": {"paired": True, "connected": True},
        "freshness": {
            "newest_ms": now_ms,
            # A reported silence verdict keeps the script off the v2 inbox.
            "google": {"latest_received_ms": now_ms, "silence": {"stalled": False}},
            "whatsapp": {"latest_received_ms": now_ms},
            "signal": {"latest_received_ms": now_ms},
        },
    }
    if projection_stalled:
        payload["projection_stalled"] = True
    if per_account is not None:
        per = {k: dict(v) for k, v in per_account.items()}
        if quarantined:
            per.setdefault("google-primary", {})["quarantined"] = quarantined
        payload["v2_ingest"] = {"enabled": True, "per_account": per}
    return payload


def google(errors, appended=120) -> dict:
    return {"google-primary": {"appended": appended, "append_errors": errors, "quarantined": 0}}


def banner(errs, new=None, carry=0, detail=None) -> str:
    """The notification text the rule should produce."""
    if errs == 0 and carry:
        return "%d failed attempt(s) to append to v2 ingest before the backend restarted" % carry
    text = "%d failed attempt(s) to append to v2 ingest" % errs
    if new is not None:
        text += ", %d since the last alert" % new
    text += " (%s)" % (detail or "google-primary %d" % errs)
    if carry:
        text += ", and %d more seen before the backend restarted" % carry
    return text


class Watchdog:
    def __init__(self, tmp: Path, daemon) -> None:
        self.daemon = daemon
        self.home = tmp / "home"
        self.state = tmp / "state"
        self.log = tmp / "watchdog.log"
        self.home.mkdir()
        self.state.mkdir()
        self.log.touch()

    def run(self, payload: dict, env: dict | None = None, path_prefix: Path | None = None) -> list[str]:
        """One launchd-style run; returns the log lines it wrote."""
        self.daemon.payload = payload
        extra = env or {}
        env = {
            "PATH": (f"{path_prefix}:" if path_prefix else "") + "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.home),
            "TMPDIR": str(self.home),
            "OPENMESSAGE_WATCHDOG_PORT": str(self.daemon.port),
            "OPENMESSAGE_WATCHDOG_DRYRUN": "1",
            "OPENMESSAGE_WATCHDOG_STATE": str(self.state),
            "OPENMESSAGE_WATCHDOG_LOG": str(self.log),
            **extra,
        }
        for _ in range(5):
            before = self.log.read_text().splitlines()
            proc = subprocess.run(["/bin/bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30)
            assert proc.returncode == 0, proc.stderr
            assert proc.stderr == "", proc.stderr
            lines = [line[20:] for line in self.log.read_text().splitlines()[len(before):]]
            # A real pairing run (or any process the pairing guard matches)
            # makes the script skip the whole run. Try again.
            if lines != ["skip: pairing in flight"]:
                return lines
            time.sleep(1)
        pytest.skip("a process matching the pairing guard kept the script skipping")

    def notified(self, lines: list[str]) -> list[str]:
        return [line[len("NOTIFY: "):] for line in lines if line.startswith("NOTIFY: ")]

    def alerts(self, lines: list[str]) -> list[str]:
        return [line[len("ALERT: "):] for line in lines if line.startswith("ALERT: ")]

    def baseline(self) -> str | None:
        """errs, appended, reported count and carry, as stored."""
        f = self.state / "append_errors"
        return " ".join(f.read_text().split()[:4]) if f.exists() else None

    def ident(self) -> str | None:
        fields = (self.state / "append_errors").read_text().split()
        return fields[4] if len(fields) > 4 else None

    def health_alerts(self) -> list[str]:
        lines = (self.state / "health.txt").read_text().splitlines()
        return [line[len("alert: "):] for line in lines if line.startswith("alert: ")]

    def age_last_alert(self, seconds: int) -> None:
        """Pretend the last append_errors alert fired `seconds` ago."""
        f = self.state / "alert_append_errors"
        assert f.exists(), "no append_errors alert has fired yet"
        f.write_text("%d\n" % (int(time.time()) - seconds))


@pytest.fixture
def daemon():
    d = _Daemon()
    yield d
    d.close()


@pytest.fixture
def wd(tmp_path, daemon):
    return Watchdog(tmp_path, daemon)


def test_zero_errors_never_alert_and_record_the_baseline(wd):
    lines = wd.run(status(google(0)))
    assert wd.alerts(lines) == [] and wd.notified(lines) == []
    assert wd.baseline() == "0 120 0 0"


def test_three_errors_alert_once_with_the_per_account_breakdown(wd):
    wd.run(status(google(0)))
    lines = wd.run(status(google(3)))
    assert wd.notified(lines) == [banner(3)] == ["3 failed attempt(s) to append to v2 ingest (google-primary 3)"]
    assert wd.alerts(lines) == [banner(3)]
    assert wd.baseline() == "3 120 3 0"


def test_the_listener_identity_is_recorded(wd):
    wd.run(status(google(0)))
    pid, _, started = (wd.ident() or "").partition("@")
    assert pid.isdigit() and started, wd.ident()


def test_a_flat_count_never_re_alerts_even_after_the_cooldown(wd):
    wd.run(status(google(3)))
    wd.age_last_alert(COOLDOWN + 3600)
    for _ in range(2):
        lines = wd.run(status(google(3, appended=130)))
        assert wd.notified(lines) == [] and lines == []


def test_growth_inside_the_cooldown_waits_and_is_then_reported(wd):
    wd.run(status(google(3)))
    lines = wd.run(status(google(5)))
    assert wd.notified(lines) == []
    assert lines == ["suppressed (cooldown): append_errors (5, last alert reported 3)"]
    wd.age_last_alert(COOLDOWN - 60)
    assert wd.notified(wd.run(status(google(5)))) == []
    wd.age_last_alert(COOLDOWN)
    lines = wd.run(status(google(5)))
    assert wd.notified(lines) == [banner(5, new=2)]
    assert banner(5, new=2) == "5 failed attempt(s) to append to v2 ingest, 2 since the last alert (google-primary 5)"
    assert wd.baseline() == "5 120 5 0"


def test_a_daemon_restart_resets_the_baseline(wd):
    wd.run(status(google(3, appended=500)))
    lines = wd.run(status(google(1, appended=10)))
    assert "append_errors baseline reset: backend restarted (0 seen before it and not yet reported)" in lines
    assert wd.notified(lines) == []  # still inside the cooldown of the old alert
    wd.age_last_alert(COOLDOWN)
    lines = wd.run(status(google(1, appended=12)))
    assert wd.notified(lines) == [banner(1)]


def test_a_restart_is_seen_through_appended_when_errors_land_on_the_old_count(wd):
    wd.run(status(google(3, appended=500)))
    wd.age_last_alert(COOLDOWN)
    lines = wd.run(status(google(3, appended=7)))
    assert any(line.startswith("append_errors baseline reset") for line in lines)
    assert wd.notified(lines) == [banner(3)]


def test_a_restart_back_to_zero_then_new_errors_alert_from_zero(wd):
    wd.run(status(google(4, appended=500)))
    assert wd.run(status(google(0, appended=3))) == [
        "append_errors baseline reset: backend restarted (0 seen before it and not yet reported)"
    ]
    assert wd.baseline() == "0 3 0 0"
    wd.age_last_alert(COOLDOWN)
    lines = wd.run(status(google(2, appended=40)))
    assert wd.notified(lines) == [banner(2)]


def test_growth_held_back_by_the_cooldown_survives_a_restart(wd):
    wd.run(status(google(3, appended=500)))  # alert at 3
    assert wd.notified(wd.run(status(google(10, appended=510)))) == []  # 7 more, suppressed
    lines = wd.run(status(google(0, appended=4)))  # restart, nothing new yet
    assert "append_errors baseline reset: backend restarted (7 seen before it and not yet reported)" in lines
    assert wd.baseline() == "0 4 0 7"
    lines = wd.run(status(google(0, appended=9)))
    assert lines == ["suppressed (cooldown): append_errors (0, last alert reported 0, 7 from before a restart)"]
    wd.age_last_alert(COOLDOWN)
    lines = wd.run(status(google(0, appended=20)))
    assert wd.notified(lines) == [banner(0, carry=7)]
    assert banner(0, carry=7) == "7 failed attempt(s) to append to v2 ingest before the backend restarted"
    assert wd.baseline() == "0 20 0 0"
    assert wd.run(status(google(0, appended=25))) == []


def test_carried_errors_join_new_ones_in_one_alert(wd):
    wd.run(status(google(2, appended=300)))
    wd.run(status(google(6, appended=320)))  # 4 suppressed
    wd.run(status(google(1, appended=5)))  # restart with 1 new
    wd.age_last_alert(COOLDOWN)
    lines = wd.run(status(google(1, appended=8)))
    assert wd.notified(lines) == [banner(1, carry=4)]
    assert banner(1, carry=4) == (
        "1 failed attempt(s) to append to v2 ingest (google-primary 1), and 4 more seen before the backend restarted"
    )
    assert wd.baseline() == "1 8 1 0"


def test_a_new_listener_is_a_restart_even_when_the_sums_do_not_fall(tmp_path):
    proc = _ProcDaemon(tmp_path)
    try:
        wd = Watchdog(tmp_path, proc)
        wd.run(status(google(3, appended=0)))  # appends failing wholesale
        first = wd.ident()
        proc.restart()
        lines = wd.run(status(google(3, appended=0)))  # same sums, new process
        assert wd.ident() != first
        assert "append_errors baseline reset: backend restarted (0 seen before it and not yet reported)" in lines
        wd.age_last_alert(COOLDOWN)
        assert wd.notified(wd.run(status(google(3, appended=0)))) == [banner(3)]
        # same listener again: a flat count stays quiet
        wd.age_last_alert(COOLDOWN)
        assert wd.run(status(google(3, appended=0))) == []
    finally:
        proc.close()


def test_another_alert_in_the_same_run_defers_it_to_a_run_it_leads(wd):
    lines = wd.run(status(google(2), quarantined=1))
    assert wd.alerts(lines) == ["1 ingested frame(s) quarantined"]
    assert wd.notified(lines) == ["1 ingested frame(s) quarantined"]
    assert "deferred: append_errors - another alert leads this run's notification" in lines
    assert wd.baseline() == "2 120 0 0"
    assert not (wd.state / "alert_append_errors").exists()
    lines = wd.run(status(google(2), quarantined=1))  # quarantine is in its cooldown now
    assert wd.notified(lines) == [banner(2)]
    assert wd.baseline() == "2 120 2 0"


def test_it_never_delays_an_alert_that_leads(wd):
    # projection_stalled is listed before quarantine and append_errors; with
    # the cooldown over for both others, the append alert waits exactly one run
    lines = wd.run(status(google(1), projection_stalled=True))
    assert wd.notified(lines) == ["v2 read projection stalled - reads are stale while ingest continues"]
    lines = wd.run(status(google(1), projection_stalled=True))
    assert wd.notified(lines) == [banner(1)]


def test_a_lost_pairing_banner_also_defers_it(wd):
    # The unpaired gate prepends its "No longer paired" banner after the loop,
    # so the append arm has to see it coming through `unlinked`.
    wd.run(status(google(0)))  # every platform paired: recorded as paired
    payload = status(google(2))
    payload["whatsapp"]["paired"] = False
    lines = wd.run(payload)
    (note,) = wd.notified(lines)
    assert note.startswith("No longer paired: whatsapp"), lines
    assert "deferred: append_errors - another alert leads this run's notification" in lines
    assert wd.notified(wd.run(payload)) == [banner(2)]


def test_health_lists_the_count_whether_or_not_it_reached_a_banner(wd):
    in_process = "failed attempt(s) to append to v2 ingest in this backend process"
    wd.run(status(google(0)))
    assert not any(in_process in a for a in wd.health_alerts())
    wd.run(status(google(2), quarantined=1))  # quarantine leads: deferred
    assert wd.health_alerts() == ["1 ingested frame(s) quarantined", "2 %s (google-primary 2)" % in_process]
    wd.run(status(google(2), quarantined=1))  # reported now
    assert "2 %s (google-primary 2)" % in_process in wd.health_alerts()
    wd.age_last_alert(COOLDOWN + 60)
    lines = wd.run(status(google(2)))  # flat: no banner, still listed
    assert wd.notified(lines) == []
    assert wd.health_alerts() == ["2 %s (google-primary 2)" % in_process]


def test_health_lists_carried_attempts_until_they_are_reported(wd):
    wd.run(status(google(3, appended=500)))
    wd.run(status(google(5, appended=510)))  # 2 suppressed
    wd.run(status(google(0, appended=4)))  # restart
    carried = "2 failed attempt(s) to append to v2 ingest before the backend restarted"
    assert wd.health_alerts() == [carried]
    wd.age_last_alert(COOLDOWN)
    wd.run(status(google(0, appended=6)))  # reported in this run's banner
    assert wd.health_alerts() == [carried]
    wd.run(status(google(0, appended=7)))
    assert wd.health_alerts() == []


def test_a_damaged_baseline_file_is_logged(wd):
    (wd.state / "append_errors").write_text("08 1x 2 3 4@x")
    lines = wd.run(status(google(2)))
    assert "state file append_errors was damaged ('08 1x 2 3 4@x') - bad fields read as 0" in lines


def test_a_time_zone_change_is_not_a_restart(wd):
    wd.run(status(google(3)))
    first = wd.ident()
    wd.age_last_alert(COOLDOWN + 60)
    for tz in ("Europe/Madrid", "Asia/Tokyo", "UTC"):
        lines = wd.run(status(google(3)), env={"TZ": tz, "LC_ALL": "de_DE.UTF-8"})
        assert lines == [], (tz, lines)
        assert wd.ident() == first


def _helper_listener(port: int) -> subprocess.Popen:
    """A second process listening on the same port, on IPv6 loopback."""
    code = (
        "import socket, sys, time\n"
        "s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n"
        "s.bind(('::1', int(sys.argv[1]))); s.listen(1)\n"
        "print('ready', flush=True); time.sleep(60)\n"
    )
    proc = subprocess.Popen([sys.executable, "-I", "-c", code, str(port)], stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "ready"
    return proc


def test_a_second_listener_makes_the_identity_unknown_not_new(wd, daemon):
    wd.run(status(google(3)))
    first = wd.ident()
    wd.age_last_alert(COOLDOWN + 60)
    helper = _helper_listener(daemon.port)
    try:
        assert wd.run(status(google(3))) == []
        assert wd.ident() == first  # kept while unknown
    finally:
        helper.terminate()
        helper.wait(timeout=10)
    assert wd.run(status(google(3))) == []
    assert wd.ident() == first


def test_a_lower_pid_second_listener_going_away_is_not_a_restart(tmp_path):
    # The helper starts first, so it has the lower PID: picking the lowest
    # listener would take its identity, then the daemon's when it leaves.
    port = _free_port()
    helper = _helper_listener(port)
    proc = _ProcDaemon(tmp_path, port=port)
    try:
        wd = Watchdog(tmp_path, proc)
        wd.run(status(google(3)))  # two listeners: identity unknown
        assert wd.ident() is None
        helper.terminate()
        helper.wait(timeout=10)
        wd.age_last_alert(COOLDOWN + 60)
        assert wd.run(status(google(3))) == []  # first known identity: no restart
        assert wd.ident().startswith("%d@" % proc.proc.pid)
    finally:
        helper.kill()
        proc.close()


def _failing_lsof(tmp: Path) -> Path:
    stub = tmp / "stub-bin"
    stub.mkdir(exist_ok=True)
    (stub / "lsof").write_text("#!/bin/sh\nexit 1\n")
    (stub / "lsof").chmod(0o755)
    return stub


def test_a_failed_lsof_is_unknown_not_a_restart(wd, tmp_path):
    wd.run(status(google(3)))
    first = wd.ident()
    wd.age_last_alert(COOLDOWN + 60)
    stub = _failing_lsof(tmp_path)
    assert wd.run(status(google(3)), path_prefix=stub) == []
    assert wd.ident() == first
    assert wd.run(status(google(3))) == []


def test_a_restart_while_the_identity_was_unknown_is_still_seen(tmp_path):
    proc = _ProcDaemon(tmp_path)
    try:
        wd = Watchdog(tmp_path, proc)
        wd.run(status(google(3, appended=0)))  # alert at 3, identity known
        first = wd.ident()
        stub = _failing_lsof(tmp_path)
        assert wd.run(status(google(3, appended=0)), path_prefix=stub) == []
        proc.restart()
        lines = wd.run(status(google(3, appended=0)))  # same sums, new process
        assert wd.ident() != first
        assert any(line.startswith("append_errors baseline reset") for line in lines), lines
    finally:
        proc.close()


def test_a_restart_seen_through_the_sums_with_lsof_down_is_counted_once(tmp_path):
    proc = _ProcDaemon(tmp_path)
    try:
        wd = Watchdog(tmp_path, proc)
        wd.run(status(google(3, appended=500)))  # alert at 3
        wd.run(status(google(4, appended=510)))  # 1 held back by the cooldown
        proc.restart()
        stub = _failing_lsof(tmp_path)
        lines = wd.run(status(google(1, appended=2)), path_prefix=stub)  # sums fall, identity unknown
        resets = [line for line in lines if "baseline reset" in line]
        lines = wd.run(status(google(1, appended=3)))  # identity known again
        resets += [line for line in lines if "baseline reset" in line]
        assert resets == ["append_errors baseline reset: backend restarted (1 seen before it and not yet reported)"]
        assert wd.baseline() == "1 3 0 1"
        wd.age_last_alert(COOLDOWN)
        lines = wd.run(status(google(1, appended=4)))
        assert wd.notified(lines) == [banner(1, carry=1)]  # 3 + 1 + 1 = the 4 old and 1 new attempts
    finally:
        proc.close()


def test_huge_sums_across_accounts_stay_in_range(wd):
    per = {"acct-%04d" % i: {"appended": 10 ** 15, "append_errors": 10 ** 15} for i in range(9300)}  # sum past 2^63 without the cap
    lines = wd.run(status(per))
    (note,) = wd.notified(lines)
    assert note.startswith("%d failed attempt(s) to append to v2 ingest" % 10 ** 15)
    assert wd.baseline() == "%d %d %d 0" % (10 ** 15, 10 ** 15, 10 ** 15)


@pytest.mark.parametrize("ident", ["bogus!", "0@x", "12@", "@abc", "12@ab cd", "12@a@b"])
def test_a_damaged_identity_is_logged_and_never_reads_as_a_restart(wd, ident):
    wd.run(status(google(3)))
    fields = (wd.state / "append_errors").read_text().split()
    (wd.state / "append_errors").write_text(" ".join(fields[:4] + [ident]) + "\n")
    wd.age_last_alert(COOLDOWN + 60)
    lines = wd.run(status(google(3)))
    assert [line for line in lines if "baseline reset" in line] == []
    assert wd.notified(lines) == []
    assert any(line.startswith("state file append_errors was damaged") for line in lines), lines
    assert wd.ident() not in (None, ident)


def test_unreported_attempts_stay_in_health_while_the_new_backend_has_no_accounts(wd):
    wd.run(status(google(3, appended=500)))
    wd.run(status(google(5, appended=510)))  # 2 held back by the cooldown
    wd.run(status({}))  # restarted backend, nothing ingested yet
    assert wd.health_alerts() == [
        "2 failed attempt(s) to append to v2 ingest not yet reported (no ingest accounts this run)"
    ]
    wd.run(status(None))
    assert wd.health_alerts() == [
        "2 failed attempt(s) to append to v2 ingest not yet reported (no ingest accounts this run)"
    ]


@pytest.mark.parametrize("v2_ingest", [[{"enabled": True}], "on", 1, True],
                         ids=["list", "string", "number", "true"])
def test_odd_v2_ingest_shapes_without_a_silence_verdict(wd, v2_ingest):
    payload = status(None, projection_stalled=True)
    del payload["freshness"]["google"]["silence"]  # reach the watchdog's own silence estimate
    payload["auth"] = {"data_dir": str(wd.home / "no-such-dir")}
    payload["v2_ingest"] = v2_ingest
    lines = wd.run(payload)
    assert wd.notified(lines) == ["v2 read projection stalled - reads are stale while ingest continues"], lines


def test_accounts_are_summed_and_only_failing_ones_are_named(wd):
    per = {
        "whatsapp-primary": {"appended": 40, "append_errors": 0},
        "signal-primary": {"appended": 9, "append_errors": 1},
        "google-primary": {"appended": 120, "append_errors": 2},
    }
    lines = wd.run(status(per))
    assert wd.notified(lines) == [banner(3, detail="google-primary 2, signal-primary 1")]
    assert wd.baseline() == "3 169 3 0"


@pytest.mark.parametrize(
    "payload",
    [
        status(None),  # an older daemon without v2_ingest
        status({}),  # a fresh daemon with no ingest yet
        {**status(None), "v2_ingest": {"enabled": True}},
        {**status(None), "v2_ingest": {"enabled": True, "per_account": None}},
    ],
    ids=["no-v2_ingest", "empty-per_account", "no-per_account", "null-per_account"],
)
def test_nothing_to_count_leaves_the_baseline_alone(wd, payload):
    wd.run(status(google(2, appended=50)))
    assert wd.baseline() == "2 50 2 0"
    lines = wd.run(payload)
    assert lines == [] and wd.baseline() == "2 50 2 0"
    assert not any("append to v2 ingest" in a for a in wd.health_alerts())  # all reported


@pytest.mark.parametrize(
    "v2_ingest",
    [[{"append_errors": 3}], "per", 7, True, {"enabled": True, "per_account": [1, 2]}, {"per_account": "x"}],
    ids=["list", "string", "number", "true", "per_account-list", "per_account-string"],
)
def test_odd_v2_ingest_shapes_do_not_silence_the_other_alerts(wd, v2_ingest):
    payload = {**status(None, projection_stalled=True), "v2_ingest": v2_ingest}
    lines = wd.run(payload)
    assert wd.notified(lines) == ["v2 read projection stalled - reads are stale while ingest continues"]
    assert wd.baseline() is None


@pytest.mark.parametrize("bad", ["7", True, -2, 1.5, None, [3], {"n": 3}])
def test_non_count_values_read_as_zero(wd, bad):
    per = {
        "google-primary": {"appended": bad, "append_errors": bad},
        "signal-primary": {"appended": 4, "append_errors": 1},
    }
    lines = wd.run(status(per))
    assert wd.notified(lines) == [banner(1, detail="signal-primary 1")]
    assert wd.baseline() == "1 4 1 0"


def test_absurd_counts_are_capped_not_crashed_on(wd):
    lines = wd.run(status(google(2 ** 64 - 1, appended=2 ** 64 - 1)))
    cap = 10 ** 15
    assert wd.notified(lines) == ["%d failed attempt(s) to append to v2 ingest (google-primary %d)" % (cap, cap)]


def test_account_ids_cannot_break_the_notification_or_the_line_format(wd):
    per = {'go"ogle|x\\y\n': {"appended": 5, "append_errors": 2}}
    lines = wd.run(status(per))
    (note,) = wd.notified(lines)
    assert note == "2 failed attempt(s) to append to v2 ingest (go?ogle?x?y? 2)"
    assert '"' not in note and "|" not in note


@pytest.mark.parametrize(
    "junk",
    ["garbage", "3", "-1 -1 -1", "1 2 3 4 5 6", "x 2 2", "8 100 08", "08 100 2",
     "99999999999999999999 1 99999999999999999999", "1 1 1 x", ""],
)
def test_a_damaged_baseline_file_never_hides_errors(wd, junk):
    # Unparseable fields (including leading zeros and values bash can't do
    # arithmetic on) read as 0 and the reported count is clamped to the last
    # seen count, so the 2 live errors always reach a banner. A damaged file
    # can make it over-report (a phantom carry), never under-report.
    (wd.state / "append_errors").write_text(junk)
    lines = wd.run(status(google(2)))
    (note,) = wd.notified(lines)
    assert note.startswith("2 failed attempt(s) to append to v2 ingest"), lines
    assert wd.baseline() == "2 120 2 0"


@pytest.mark.parametrize("stamp", ["abc", "12 34", "08", "", "99999999999999999999", "4102444800"])
def test_a_damaged_cooldown_stamp_reads_as_expired(wd, stamp):
    (wd.state / "alert_append_errors").write_text(stamp)
    lines = wd.run(status(google(2)))
    assert wd.notified(lines) == [banner(2)], lines


def test_a_damaged_stamp_does_not_cost_the_later_alerts(wd):
    (wd.state / "alert_append_errors").write_text("abc")
    payload = status(google(2))
    payload["signal"]["receive_recovery"] = {"pending_count": 9, "last_issue_reason": "test"}
    lines = wd.run(payload)
    assert wd.alerts(lines) == [banner(2), "Signal receive-recovery backlog: 9 pending (test)"]


def test_the_other_alert_cooldowns_are_untouched(wd):
    wd.run(status(google(2), quarantined=1))  # quarantine leads, append defers
    wd.run(status(google(2), quarantined=1))  # append leads
    assert sorted(p.name for p in wd.state.iterdir() if p.name.startswith("alert_")) == [
        "alert_append_errors",
        "alert_quarantine",
    ]
    # quarantine keeps its old >0 rule: it re-alerts once its own cooldown passes
    (wd.state / "alert_quarantine").write_text("%d\n" % (int(time.time()) - COOLDOWN))
    lines = wd.run(status(google(2), quarantined=1))
    assert wd.alerts(lines) == ["1 ingested frame(s) quarantined"]


# ---------- property: the script follows the rule for any counter history ----------

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

# One step of a daemon's life as the watchdog sees it at a 5-minute probe:
# ("grow", d_errors, d_appended) keeps the process and adds to both counters;
# ("restart", errors, appended) is a new process whose counters started at 0
# and have reached these values. The fixture daemon here never changes
# process, so a restart is only visible through a falling sum, as when lsof
# can't see the listener. cooldown_over says whether 6 h have passed since the
# last append_errors banner when this probe runs.
step = st.tuples(
    st.one_of(
        st.tuples(st.just("grow"), st.integers(0, 3), st.integers(0, 40)),
        st.tuples(st.just("restart"), st.integers(0, 4), st.integers(0, 60)),
    ),
    st.booleans(),
)


def model(history):
    """Reference rule: per probe, the state the script should store and the
    banner it should post (None = silent). Also checks conservation at every
    step: each error the watchdog observed (a finished process counted at its
    last observed value) is either reported in a banner or still pending
    (live count above the reported one, plus carry)."""
    errs = appended = 0
    last_errs = last_appended = alerted = carry = 0
    closed = reported = 0
    fired = False
    out = []
    for (kind, a, b), cooldown_over in history:
        if kind == "grow":
            errs, appended = errs + a, appended + b
        else:
            errs, appended = a, b
        if errs < last_errs or appended < last_appended:
            closed += last_errs
            carry += last_errs - alerted
            alerted = 0
        text = None
        if (errs > alerted or carry) and (not fired or cooldown_over):
            text = banner(errs, new=errs - alerted if alerted else None, carry=carry)
            reported += errs - alerted + carry
            alerted, carry, fired = errs, 0, True
        assert closed + errs == reported + (errs - alerted) + carry
        assert 0 <= alerted <= errs and carry >= 0
        last_errs, last_appended = errs, appended
        out.append((errs, appended, alerted, carry, text))
    return out


@settings(max_examples=500, deadline=None)
@given(history=st.lists(step, min_size=1, max_size=15))
def test_the_rule_never_loses_an_error_it_saw(history):
    model(history)  # asserts conservation and bounds at every step


@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(history=st.lists(step, min_size=1, max_size=6))
def test_every_probe_matches_the_reference_rule(tmp_path_factory, daemon, history):
    wd = Watchdog(tmp_path_factory.mktemp("prop"), daemon)
    for (errs, appended, alerted, carry, text), (_, cooldown_over) in zip(model(history), history):
        if (wd.state / "alert_append_errors").exists():
            wd.age_last_alert(COOLDOWN + 60 if cooldown_over else COOLDOWN - 600)
        lines = wd.run(status(google(errs, appended)))
        assert wd.notified(lines) == ([text] if text else []), (history, lines)
        assert wd.baseline() == "%d %d %d %d" % (errs, appended, alerted, carry), (history, lines)


health_payload = st.fixed_dictionaries({
    "errs": st.integers(0, 4),
    "carry_first": st.booleans(),
    "quarantined": st.integers(0, 2),
    "stalled": st.booleans(),
})


@settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(case=health_payload)
def test_health_does_not_depend_on_cooldowns_or_deferral(tmp_path_factory, daemon, case):
    """A run's health.txt alerts list what it sees, whatever the banners did:
    re-running the same payload at once (cooldowns now running, a deferred
    append alert now posting) lists the same alerts. Unlike master's property
    for the other alerts, the first run's health alerts can hold an append
    entry with no ALERT line: the alert was deferred, or already reported."""
    wd = Watchdog(tmp_path_factory.mktemp("health"), daemon)
    if case["carry_first"]:
        wd.run(status(google(2, appended=400)))
        wd.run(status(google(4, appended=410)))  # 2 held back
        wd.run(status(google(0, appended=3)))  # restart: carry 2
    payload = status(google(case["errs"], appended=500), quarantined=case["quarantined"],
                     projection_stalled=case["stalled"])
    wd.run(payload)
    first = wd.health_alerts()
    wd.run(payload)
    assert wd.health_alerts() == first, (case, first, wd.health_alerts())
    in_process = [a for a in first if "in this backend process" in a]
    assert in_process == (["%d failed attempt(s) to append to v2 ingest in this backend process "
                           "(google-primary %d)" % (case["errs"], case["errs"])] if case["errs"] else [])

