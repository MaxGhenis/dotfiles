"""openmessage-watchdog sends the daemon's control token and never relaunches
a daemon that answers 401.

Since openmessage#261 the daemon refuses every /api/ request without its
control token. A bare probe would get 401, which the class-A check used to
read as "not answering", so the watchdog would have quit and relaunched a
healthy app every 30 minutes. Now the probe sends the token from the app's
data dir as a Bearer header, read by curl from stdin so it never appears on a
command line (any local user's `ps` shows argv), and a 401 counts as an
answering daemon with a token problem: no relaunch, an alert in health.txt,
and one banner per 6 h.

Runs the real script against a fixture daemon, in the sandbox the main
watchdog tests use.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from test_openmessage_watchdog import HOUR, T0, Sandbox, status

TOKEN = "ab" * 32


class TokenDaemon:
    """Serves /api/status only to a request carrying `required` as a Bearer
    token (or to anyone when required is None) and records each request's
    Authorization header."""

    def __init__(self, required: str | None = TOKEN):
        self.required = required
        self.payload: dict | bytes = {}
        self.hits = 0
        self.auth: list[str | None] = []
        daemon = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/api/status":
                    self.send_error(404)
                    return
                daemon.hits += 1
                header = self.headers.get("Authorization")
                daemon.auth.append(header)
                if daemon.required is not None and header != f"Bearer {daemon.required}":
                    body = b'{"error":"unauthorized"}\n'
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Bearer realm="openmessage"')
                else:
                    body = daemon.payload if isinstance(daemon.payload, bytes) else (json.dumps(daemon.payload) + "\n").encode()
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


@pytest.fixture
def daemon():
    d = TokenDaemon()
    yield d
    d.close()


@pytest.fixture
def box(tmp_path, daemon) -> Sandbox:
    sandbox = Sandbox(tmp_path, daemon)
    token_dir = sandbox.home / "Library" / "Application Support" / "OpenMessage"
    token_dir.mkdir(parents=True)
    sandbox.token_file = token_dir / "control.token"
    sandbox.token_file.write_text(TOKEN + "\n")
    sandbox.token_file.chmod(0o600)
    # A curl first on PATH that records its argv, then runs the real one.
    (sandbox.stubs / "curl").write_text(
        "#!/bin/bash\n"
        'printf "%s\\0" "$@" >> "$WATCHDOG_STUB_CALLS/curl.argv"\n'
        'exec /usr/bin/curl "$@"\n'
    )
    (sandbox.stubs / "curl").chmod(0o755)
    return sandbox


def health(box: Sandbox) -> str:
    return (box.state / "health.txt").read_text()


def test_the_probe_sends_the_token_from_the_default_data_dir(box, daemon):
    box.run(status())
    assert daemon.auth == [f"Bearer {TOKEN}"]
    assert "daemon=up" in health(box)
    assert box.calls("open") == []


def test_the_token_never_reaches_a_command_line(box, daemon):
    box.run(status())
    argv = (box.calls_dir / "curl.argv").read_bytes().split(b"\0")
    assert argv, "the curl wrapper recorded nothing"
    assert not any(TOKEN.encode() in arg for arg in argv), argv


def test_without_a_token_file_the_probe_goes_out_bare(box, daemon):
    daemon.required = None   # a daemon from before enforcement
    box.token_file.unlink()
    box.run(status())
    assert daemon.auth == [None]
    assert "daemon=up" in health(box)


@pytest.mark.parametrize("token_state", ["missing", "wrong", "not hex"])
def test_a_refusing_daemon_is_never_relaunched(box, daemon, token_state):
    if token_state == "missing":
        box.token_file.unlink()
    elif token_state == "wrong":
        box.token_file.write_text("cd" * 32)
    else:
        box.token_file.write_text("zz" * 32)
    # Seven runs 5 minutes apart: past both relaunch thresholds and the 30-min
    # throttle, with no app process (the 2-probe threshold) on every run.
    for i in range(7):
        box.run(status(), at=T0 + i * 300)
    assert box.calls("open") == [], "a 401 must not relaunch the app"
    assert box.calls("osascript") == [] or all("quit app" not in " ".join(a) for a in box.calls("osascript"))
    assert box.stored("consecutive_fails") == "0"
    text = health(box)
    assert "daemon=up" in text
    assert "answered /api/status with 401" in text
    assert "alert: Watchdog can't read OpenMessage status" in text
    assert box.banners() == [box.banners()[0]], "one banner per 6 h"
    assert "platform checks are paused" in box.banners()[0]
    if token_state == "wrong":
        assert "was refused" in box.banners()[0]
    else:
        assert "no readable control token" in box.banners()[0]
        assert all(header is None for header in daemon.auth), "a malformed token must not be sent"


def test_the_refusal_banner_repeats_after_six_hours_and_clears_on_a_good_token(box, daemon):
    box.token_file.write_text("cd" * 32)
    box.run(status(), at=T0)
    box.run(status(), at=T0 + 6 * HOUR - 1)
    assert len(box.banners()) == 1
    box.run(status(), at=T0 + 6 * HOUR)
    assert len(box.banners()) == 2
    box.token_file.write_text(TOKEN)
    box.run(status(), at=T0 + 7 * HOUR)
    text = health(box)
    assert "answered /api/status" in text and "401" not in text
    assert "Watchdog can't read" not in text


def test_a_daemon_that_is_down_still_relaunches(box, daemon):
    port = daemon.port
    daemon.close()
    box.env["OPENMESSAGE_WATCHDOG_PORT"] = str(port)
    box.run(at=T0)
    box.run(at=T0 + 300)
    assert len(box.calls("open")) == 1, "a refused connection is still a dead daemon"
