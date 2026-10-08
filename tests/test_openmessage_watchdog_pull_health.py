"""openmessage-watchdog's pull_empty alert (google.pull_health, openmessage PR #193).

Needs Hypothesis, which plain `pytest` here lacks. Run:
    uv run --no-project --with pytest --with hypothesis pytest tests/test_openmessage_watchdog_pull_health.py

Two layers:

* The inline Python block that turns /api/status into alert lines is lifted
  out of the script and executed in-process, so Hypothesis can throw many
  status shapes at it quickly.
* End-to-end runs of the real script against a local fake /api/status, in
  dry-run mode with a throwaway HOME, state dir and log, check that the line
  becomes a notification and that the 6h cooldown holds. Dry run logs
  "NOTIFY: ..." and never calls osascript.

Invariants (for every status payload):

1. A pull_empty alert is emitted iff google.pull_health is an object, its
   empty_with_local_history is exactly true, and google.paired is not
   exactly false (a missing or odd paired key keeps alerting).
2. The alert names the Google-account switch and d1088 iff
   pull_health.account_switch is exactly true.
3. The alert states the conversation count iff local_conversations is an
   integer (not a bool).
4. The alert text carries no double quote or backslash, so it is safe inside
   the osascript string notify() builds.
5. pull_health never changes the other lines: the output with pull_health
   present, minus the pull_empty line, equals the output with it removed.
6. A pull_empty notification repeats at most once per 6h cooldown.
7. The alert gives the age of the last pull iff last_attempt_ms is a finite
   number (not a bool) in (0, now]: whole minutes (floored) under an hour,
   whole hours (floored) from an hour up.
8. No status payload makes the block raise. An uncaught exception there would
   print nothing and drop every other alert of that run.

Exact-text checks run the block against a frozen clock, so they do not depend
on when the tests run.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

SCRIPT = Path(
    os.environ.get(
        "OPENMESSAGE_WATCHDOG_SCRIPT",
        Path(__file__).resolve().parent.parent / "bin" / "openmessage-watchdog",
    )
)
APP = Path("/Applications/OpenMessage.app")  # hard-coded in the script
COOLDOWN = 21600

SWITCH_TEXT = "phone switched to Google-account pairing; re-link or switch back to QR (d1088)"

NOW_MS = int(time.time() * 1000)  # only bounds the generated timestamps
FROZEN_S = 1791500000.0  # the pinned clock for exact-text checks
FROZEN_MS = 1791500000000
# The live 2026-10-08 google.pull_health, last_error truncated (no account
# data), with the last pull 2.5 h before the pinned clock.
AGE = " (last pull 2h ago)"
HEAD = "Google pulls return no data while the store holds 1045 conversations"
LIVE_PULL_HEALTH = {
    "last_attempt_ms": FROZEN_MS - 150 * 60_000,
    "last_trigger": "reconcile:phone_responding_again",
    "last_folder": "INBOX",
    "last_outcome": "no_payload",
    "last_count": 0,
    "last_error": "LIST_CONVERSATIONS: no response payload; the phone sent a "
    "Google-account switch notice instead after 1 frame(s) in 16.635s",
    "account_switch": True,
    "consecutive_dataless": 3,
    "local_conversations": 1045,
    "empty_with_local_history": True,
    "threshold": 10,
}


def status(pull_health=..., paired=True, connected=True, **google_extra):
    """A minimal healthy status. Leaves out v2_ingest so the watchdog's own
    inbox silence estimate (which reads the real store) stays off."""
    google = {"paired": paired, "connected": connected, "phone_responding": True}
    google.update(google_extra)
    if pull_health is not ...:
        google["pull_health"] = pull_health
    return {
        "connected": True,
        "google": google,
        "whatsapp": {"paired": False, "connected": False},
        "signal": {"paired": False, "connected": False},
    }


# ---------------------------------------------------------------- in-process


def health_source() -> str:
    text = SCRIPT.read_text()
    m = re.search(r"/usr/bin/python3 -c '\n(.*?)\n'\)", text, re.S)
    assert m, "inline python block not found"
    src = m.group(1)
    # The block sits inside a single-quoted bash string: a stray single quote
    # in it would end the string early and cut the block short.
    assert src.rstrip().endswith('print("\\n".join(silent_alerts + out))'), "python block cut short"
    return src


HEALTH_SRC = health_source()


def health_lines(payload, now_s=None) -> list[str]:
    """Run the block on a payload. now_s pins the clock the block reads."""
    stdin, stdout = io.StringIO(json.dumps(payload)), io.StringIO()
    real = time.time
    if now_s is not None:
        time.time = lambda: now_s
    try:
        with contextlib.redirect_stdout(stdout), _stdin(stdin):
            try:
                exec(compile(HEALTH_SRC, "openmessage-watchdog:health", "exec"), {"__name__": "__main__"})
            except SystemExit:
                pass
    finally:
        time.time = real
    return [l for l in stdout.getvalue().splitlines() if l]


def frozen_msg(pull_health=..., **status_kw):
    """The pull_empty text for a payload at the pinned clock (None if absent)."""
    return pull_empty(health_lines(status(pull_health, **status_kw), now_s=FROZEN_S))


@contextlib.contextmanager
def _stdin(stream):
    import sys

    saved, sys.stdin = sys.stdin, stream
    try:
        yield
    finally:
        sys.stdin = saved


def pull_empty(lines):
    hits = [l for l in lines if l.startswith("ALERT|pull_empty|")]
    assert len(hits) <= 1
    return hits[0].split("|", 2)[2] if hits else None


def test_live_shape_alerts_with_account_switch():
    assert frozen_msg(LIVE_PULL_HEALTH) == HEAD + AGE + " - " + SWITCH_TEXT


def test_without_account_switch_names_no_cause():
    ph = dict(LIVE_PULL_HEALTH, account_switch=False, last_outcome="empty")
    assert frozen_msg(ph) == HEAD + AGE
    ph.pop("account_switch")  # the daemon omits it when false
    assert frozen_msg(ph) == HEAD + AGE


@pytest.mark.parametrize(
    "payload",
    [
        status(),  # daemon before PR #193
        status(None),  # pull_health: null
        status(dict(LIVE_PULL_HEALTH, empty_with_local_history=False)),
        status(LIVE_PULL_HEALTH, paired=False),
        status("garbage"),
    ],
    ids=["missing", "null", "flag-false", "unpaired", "non-object"],
)
def test_no_alert(payload):
    lines = health_lines(payload)
    assert pull_empty(lines) is None
    assert not any(l.startswith("PARSEERR") for l in lines)


@pytest.mark.parametrize("flag", [1, 1.0, "true", [True], None], ids=["one", "one-float", "string", "list", "null"])
def test_flag_must_be_exactly_true(flag):
    assert frozen_msg(dict(LIVE_PULL_HEALTH, empty_with_local_history=flag)) is None


@pytest.mark.parametrize("paired", [..., None, 0, "", "false"], ids=["missing", "null", "zero", "empty", "string"])
def test_only_explicit_unpaired_silences(paired):
    payload = status(LIVE_PULL_HEALTH)
    if paired is ...:
        payload["google"].pop("paired")
    else:
        payload["google"]["paired"] = paired
    assert pull_empty(health_lines(payload, now_s=FROZEN_S)) == HEAD + AGE + " - " + SWITCH_TEXT


@pytest.mark.parametrize(
    "extra",
    [dict(connected=False), dict(phone_responding=False), dict(needs_repair=True),
     dict(connected=False, phone_responding=False)],
    ids=["disconnected", "phone-silent", "needs-repair", "both"],
)
def test_alert_does_not_depend_on_other_google_fields(extra):
    assert frozen_msg(LIVE_PULL_HEALTH, **extra) == HEAD + AGE + " - " + SWITCH_TEXT


@pytest.mark.parametrize("switch", [1, 1.0, "true", [True], {"x": True}])
def test_account_switch_must_be_exactly_true(switch):
    assert frozen_msg(dict(LIVE_PULL_HEALTH, account_switch=switch)) == HEAD + AGE


@pytest.mark.parametrize("outcome", ["empty", "ok", "error", None, ...], ids=["empty", "ok", "error", "null", "missing"])
def test_switch_clause_does_not_depend_on_last_outcome(outcome):
    ph = dict(LIVE_PULL_HEALTH)
    if outcome is ...:
        ph.pop("last_outcome")
    else:
        ph["last_outcome"] = outcome
    assert frozen_msg(ph) == HEAD + AGE + " - " + SWITCH_TEXT


@pytest.mark.parametrize("count", [True, False, "1045", 1045.0, None])
def test_count_shown_only_for_integers(count):
    assert frozen_msg(dict(LIVE_PULL_HEALTH, local_conversations=count)) == (
        "Google pulls return no data while the store holds its Google conversations" + AGE + " - " + SWITCH_TEXT
    )


def test_any_integer_count_is_stated():
    for n in (0, -3, 10**12):
        msg = frozen_msg(dict(LIVE_PULL_HEALTH, local_conversations=n))
        assert msg.startswith("Google pulls return no data while the store holds %d conversations (" % n)


@pytest.mark.parametrize(
    "ago_ms, text",
    [
        (0, "0m"), (1, "0m"), (59_999, "0m"), (60_000, "1m"),
        (5 * 60_000 + 45_000, "5m"),  # floored, not rounded
        (3_599_999, "59m"), (3_600_000, "1h"),  # exactly an hour is hours
        (7_199_999, "1h"), (7_200_000, "2h"),
        (49 * 3_600_000 + 60_000, "49h"),
    ],
)
@pytest.mark.parametrize("as_float", [False, True], ids=["int", "float"])
def test_age_exact_boundaries(ago_ms, text, as_float):
    last = FROZEN_MS - ago_ms
    ph = dict(LIVE_PULL_HEALTH, last_attempt_ms=float(last) if as_float else last)
    assert frozen_msg(ph) == HEAD + " (last pull %s ago) - " % text + SWITCH_TEXT


@pytest.mark.parametrize(
    "last",
    [..., None, True, False, "1791468947780", 0, -0.0, -5, 1e30, [1], {"ms": 1},
     FROZEN_MS + 1, FROZEN_MS + 0.5, float("nan"), float("inf"), float("-inf"), 10**400, -(10**400)],
    ids=["missing", "null", "true", "false", "string", "zero", "neg-zero", "negative", "huge-float", "list", "object",
         "1ms-future", "half-ms-future", "nan", "inf", "-inf", "huge-int", "huge-negative-int"],
)
def test_age_omitted_without_a_usable_timestamp(last):
    # Invariant 8 too: an exception in the block would propagate out of here.
    ph = dict(LIVE_PULL_HEALTH)
    if last is ...:
        ph.pop("last_attempt_ms")
    else:
        ph["last_attempt_ms"] = last
    assert frozen_msg(ph) == HEAD + " - " + SWITCH_TEXT


def test_daemon_strings_never_reach_the_text():
    nasty = 'say "hi" \\ | $(x) `y`'
    ph = dict(LIVE_PULL_HEALTH, last_error=nasty, last_trigger=nasty, last_folder=nasty, last_outcome=nasty)
    assert frozen_msg(ph) == HEAD + AGE + " - " + SWITCH_TEXT


json_scalar = st.one_of(
    st.none(), st.booleans(), st.integers(-(2**63), 2**63), st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=8),
)
json_value = st.recursive(
    json_scalar,
    lambda kids: st.one_of(st.lists(kids, max_size=3), st.dictionaries(st.text(max_size=5), kids, max_size=3)),
    max_leaves=6,
)
# Weight the decisive fields toward their boundary values (exact true/false,
# ints vs bools vs look-alikes) so the strict checks are exercised often.
near_bool = st.one_of(st.booleans(), st.sampled_from([0, 1, "true", "false", None, [True]]), json_value)
pull_health_obj = st.fixed_dictionaries(
    {},
    optional={
        "empty_with_local_history": st.one_of(st.just(True), near_bool),
        "account_switch": near_bool,
        "local_conversations": st.one_of(st.integers(0, 5000), near_bool),
        "last_outcome": json_value,
        "last_error": json_value,
        "consecutive_dataless": json_value,
        "threshold": json_value,
        "last_attempt_ms": st.one_of(
            st.integers(NOW_MS - 30 * 86_400_000, NOW_MS + 86_400_000),
            st.floats(NOW_MS - 86_400_000, NOW_MS + 86_400_000),
            near_bool,
        ),
    },
)
MISSING = object()


@settings(max_examples=400, deadline=None)
@given(
    ph=st.one_of(st.just(MISSING), json_value, pull_health_obj),
    paired=st.one_of(st.just(MISSING), near_bool),
    repairs_paced=st.one_of(st.none(), st.integers(0, 5)),
    projection_stalled=st.booleans(),
)
# The live shape at each paired boundary, so the gate is checked every run.
@example(ph=LIVE_PULL_HEALTH, paired=False, repairs_paced=None, projection_stalled=False)
@example(ph=LIVE_PULL_HEALTH, paired=MISSING, repairs_paced=3, projection_stalled=True)
@example(ph=dict(LIVE_PULL_HEALTH, account_switch=1, local_conversations=True), paired=0,
         repairs_paced=None, projection_stalled=False)
# Age boundaries: a bool, zero and the future (the exact minute/hour edges
# are pinned by test_age_exact_boundaries on the frozen clock).
@example(ph=dict(LIVE_PULL_HEALTH, last_attempt_ms=True), paired=True, repairs_paced=None, projection_stalled=False)
@example(ph=dict(LIVE_PULL_HEALTH, last_attempt_ms=0), paired=True, repairs_paced=None, projection_stalled=False)
@example(ph=dict(LIVE_PULL_HEALTH, last_attempt_ms=NOW_MS + 3_600_000), paired=True, repairs_paced=None,
         projection_stalled=False)
def test_properties(ph, paired, repairs_paced, projection_stalled):
    payload = status()
    google = payload["google"]
    google.pop("paired")
    if paired is not MISSING:
        google["paired"] = paired
    if repairs_paced is not None:
        google["repairs_paced"] = repairs_paced
    payload["projection_stalled"] = projection_stalled
    if ph is not MISSING:
        google["pull_health"] = ph

    before_ms = time.time() * 1000
    lines = health_lines(payload)
    after_ms = time.time() * 1000
    msg = pull_empty(lines)
    is_obj = isinstance(ph, dict)

    # 1. iff
    expect = is_obj and ph.get("empty_with_local_history") is True and google.get("paired") is not False
    assert (msg is not None) == expect
    if msg is None:
        return
    # 2. account switch clause iff exactly true
    assert (SWITCH_TEXT in msg) == (ph.get("account_switch") is True)
    # 3. count iff a real integer
    n = ph.get("local_conversations")
    if isinstance(n, int) and not isinstance(n, bool):
        assert ("holds %d conversations" % n) in msg
    else:
        assert "holds its Google conversations" in msg
    # 4. safe inside the osascript string
    assert '"' not in msg and "\\" not in msg
    # 7. age of the last pull iff a usable timestamp
    last = ph.get("last_attempt_ms")
    usable = isinstance(last, (int, float)) and not isinstance(last, bool)
    has_age = "last pull" in msg
    m = re.search(r" \(last pull (\d+)(m|h) ago\)", msg)
    assert msg.count("last pull") == (1 if m else 0)  # only ever this exact form
    if usable and 0 < last <= before_ms:
        assert m
        lo, hi = int((before_ms - last) / 60000), int((after_ms - last) / 60000)
        value, unit = int(m.group(1)), m.group(2)
        if unit == "m":
            assert lo <= value <= hi and value < 60
        else:
            assert lo // 60 <= value <= hi // 60 and hi >= 60
    elif not usable or not 0 < last <= after_ms:
        assert not has_age

    # 5. differential: pull_health only ever adds its own line
    without = json.loads(json.dumps(payload))
    without["google"].pop("pull_health", None)
    assert [l for l in lines if not l.startswith("ALERT|pull_empty|")] == health_lines(without)


# ---------------------------------------------------------------- end-to-end


class FakeDaemon:
    def __init__(self):
        self.body = b"{}"
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200 if self.path == "/api/status" else 404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def serve(self, payload):
        self.body = json.dumps(payload).encode()


@pytest.fixture
def daemon():
    d = FakeDaemon()
    yield d
    d.server.shutdown()


@pytest.fixture
def run(tmp_path, daemon):
    if not APP.is_dir():
        pytest.skip("the script exits early without /Applications/OpenMessage.app")
    home, state, log = tmp_path / "home", tmp_path / "state", tmp_path / "watchdog.log"
    home.mkdir()
    # The script skips while any process matches `pgrep -f 'openmessage pair'`,
    # which other shells on the machine can trip by mentioning it. A pgrep
    # stub that finds nothing keeps the run independent of the process table.
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    (stubs / "pgrep").write_text("#!/bin/sh\nexit 1\n")
    (stubs / "pgrep").chmod(0o755)

    def _run(payload):
        daemon.serve(payload)
        env = {
            "PATH": f"{stubs}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(home),  # the disable flag lives under HOME
            "OPENMESSAGE_WATCHDOG_PORT": str(daemon.port),
            "OPENMESSAGE_WATCHDOG_DRYRUN": "1",
            "OPENMESSAGE_WATCHDOG_STATE": str(state),
            "OPENMESSAGE_WATCHDOG_LOG": str(log),
        }
        before = log.read_text() if log.exists() else ""
        # A run takes well under a second; the long timeout only absorbs a
        # heavily loaded machine (python startup alone took 20 s at load 130).
        r = subprocess.run(["/bin/bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=300)
        assert r.returncode == 0, r.stderr
        assert r.stderr == "", r.stderr
        new = (log.read_text() if log.exists() else "")[len(before):]
        return [l.split(" ", 2)[2] for l in new.splitlines()]

    _run.state = state
    return _run


def test_e2e_notifies_once_then_cools_down(run):
    # The script reads the real clock: 2.5 h ago floors to "2h" for the next
    # 30 minutes, far longer than this test runs.
    payload = status(dict(LIVE_PULL_HEALTH, last_attempt_ms=int(time.time() * 1000) - 150 * 60_000))
    expected = HEAD + AGE + " - " + SWITCH_TEXT

    t0 = int(time.time())
    first = run(payload)
    t1 = int(time.time())
    assert "ALERT: " + expected in first
    assert "NOTIFY: " + expected in first
    stamp = int((run.state / "alert_pull_empty").read_text())
    assert t0 <= stamp <= t1

    second = run(payload)
    assert "suppressed (cooldown): pull_empty" in second
    assert not any(l.startswith("NOTIFY") for l in second)

    # Age the stamp past the cooldown: it alerts again.
    (run.state / "alert_pull_empty").write_text(str(stamp - COOLDOWN - 1))
    third = run(payload)
    assert "NOTIFY: " + expected in third


def test_e2e_older_daemon_stays_quiet(run):
    lines = run(status())
    assert not any("pull_empty" in l or "Google pulls" in l for l in lines)
    assert not any(l.startswith(("NOTIFY", "ALERT", "status parse error")) for l in lines)
    assert not (run.state / "alert_pull_empty").exists()


def test_e2e_cleared_flag_stays_quiet(run):
    lines = run(status(dict(LIVE_PULL_HEALTH, empty_with_local_history=False, last_outcome="ok")))
    assert not any(l.startswith(("NOTIFY", "ALERT")) for l in lines)
