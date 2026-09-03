"""Tests for bin/openmessage-watchdog.

Run the real bash script against a mock daemon and temp state/flag/health
paths. Covers the 2026-09-03 hardening: disable-flag expiry and reminders,
sustained-darkness re-alerting and telegram escalation, health.txt being
written on every code path, and which notifier posts banners.
"""

import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
WATCHDOG = REPO_ROOT / "bin" / "openmessage-watchdog"
SUBPROCESS_TIMEOUT = 30

HOUR = 3600
DAY = 86400


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class MockDaemon:
    """Tiny HTTP server serving a mutable /api/status payload."""

    def __init__(self):
        self.payload = {}
        mock = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(mock.payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def status_payload(
    google_connected=True,
    signal_connected=True,
    whatsapp_connected=True,
    signal_paired=True,
    whatsapp_paired=True,
    freshness=None,
    **extra,
):
    now_ms = int(time.time() * 1000)
    if freshness is None:
        freshness = {
            "newest_ms": now_ms,
            "google": {"latest_received_ms": now_ms},
            "signal": {"latest_received_ms": now_ms},
            "whatsapp": {"latest_received_ms": now_ms},
        }
    payload = {
        "connected": True,
        "google": {"paired": True, "connected": google_connected},
        "signal": {"paired": signal_paired, "connected": signal_connected},
        "whatsapp": {"paired": whatsapp_paired, "connected": whatsapp_connected},
        "freshness": freshness,
    }
    payload.update(extra)
    return payload


class WatchdogTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temp_path = Path(self.temporary_directory.name).resolve()
        self.state = self.temp_path / "state"
        self.state.mkdir()
        self.log = self.temp_path / "watchdog.log"
        self.flag = self.temp_path / "watchdog-disabled"
        self.health = self.temp_path / "health.txt"
        self.app = self.temp_path / "FakeOMWatchdogTest.app"
        self.app.mkdir()
        # Stubs that record their invocations for non-dryrun tests.
        self.banner_calls = self.temp_path / "banner_calls"
        banner_stub = self.temp_path / "banner-stub"
        banner_stub.write_text(
            "#!/bin/bash\necho \"$@\" >> '%s'\n" % self.banner_calls
        )
        banner_stub.chmod(0o755)
        self.banner_stub = banner_stub
        self.tg_calls = self.temp_path / "tg_calls"
        tg_stub = self.temp_path / "tg-stub"
        tg_stub.write_text("#!/bin/bash\necho \"$@\" >> '%s'\n" % self.tg_calls)
        tg_stub.chmod(0o755)
        self.tg_stub = tg_stub
        self.port = free_port()  # closed unless a MockDaemon replaces it

    def run_watchdog(self, dryrun=True, port=None, env_extra=None):
        env = os.environ.copy()
        env.update(
            {
                "OPENMESSAGE_WATCHDOG_PORT": str(port or self.port),
                "OPENMESSAGE_WATCHDOG_DRYRUN": "1" if dryrun else "0",
                "OPENMESSAGE_WATCHDOG_STATE": str(self.state),
                "OPENMESSAGE_WATCHDOG_LOG": str(self.log),
                "OPENMESSAGE_WATCHDOG_FLAG": str(self.flag),
                "OPENMESSAGE_WATCHDOG_HEALTH": str(self.health),
                "OPENMESSAGE_WATCHDOG_APP": str(self.app),
                "OPENMESSAGE_WATCHDOG_BANNER_CMD": str(self.banner_stub),
                "OPENMESSAGE_WATCHDOG_TG_BIN": str(self.tg_stub),
            }
        )
        env.update(env_extra or {})
        return subprocess.run(
            ["/bin/bash", str(WATCHDOG)],
            check=False,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            env=env,
        )

    def start_daemon(self, payload):
        daemon = MockDaemon()
        daemon.payload = payload
        self.addCleanup(daemon.close)
        return daemon

    def log_text(self):
        return self.log.read_text() if self.log.exists() else ""

    def health_text(self):
        self.assertTrue(self.health.exists(), "health.txt was not written")
        return self.health.read_text()

    def set_flag(self, content="", age_seconds=0):
        self.flag.write_text(content)
        if age_seconds:
            past = time.time() - age_seconds
            os.utime(self.flag, (past, past))

    def set_state(self, name, value):
        (self.state / name).write_text(str(value))


class DisableFlagTests(WatchdogTestCase):
    def test_fresh_flag_skips_probes_but_writes_health_and_reminds(self):
        self.set_flag("Disabled for re-pair test\n")
        result = self.run_watchdog()
        self.assertEqual(result.returncode, 0)
        log = self.log_text()
        self.assertIn("skip: disable flag present", log)
        self.assertIn("reason: Disabled for re-pair test", log)
        self.assertIn("NOTIFY: OpenMessage watchdog disabled 0h", log)
        health = self.health_text()
        self.assertIn("watchdog=disabled", health)
        self.assertIn("daemon=down", health)  # nothing listening on the port
        self.assertIn("alert: watchdog disabled 0h", health)
        # No Class-A action while disabled.
        self.assertNotIn("probe failed", log)
        self.assertNotIn("would relaunch", log)

    def test_disabled_probe_up_clears_stale_outage_clock(self):
        self.set_flag()
        self.set_state("down_since", int(time.time()) - 2 * HOUR)
        daemon = self.start_daemon(status_payload())
        self.run_watchdog(port=daemon.port)
        self.assertIn("daemon=up", self.health_text())
        self.assertFalse((self.state / "down_since").exists())

    def test_disabled_probe_down_keeps_outage_clock(self):
        self.set_flag()
        self.set_state("down_since", int(time.time()) - 2 * HOUR)
        self.run_watchdog()
        self.assertIn("daemon=down", self.health_text())
        self.assertTrue((self.state / "down_since").exists())

    def test_leading_zero_max_age_is_decimal(self):
        # "08" is bad octal to bash arithmetic; it must still mean 8 hours.
        self.set_flag("max-age=08h\n", age_seconds=7 * HOUR)
        self.run_watchdog()
        self.assertIn("skip: disable flag present (age 7h, max 8h", self.log_text())
        self.set_flag("max-age=08h\n", age_seconds=9 * HOUR)
        self.run_watchdog()
        self.assertIn("disable flag expired (age 9h >= max 8h)", self.log_text())

    def test_oversized_max_age_is_capped_at_seven_days(self):
        self.set_flag("max-age=99999999999999999999h\n", age_seconds=HOUR)
        self.run_watchdog()
        self.assertIn("skip: disable flag present (age 1h, max 168h", self.log_text())
        self.set_flag("max-age=30d\n", age_seconds=8 * DAY)
        self.run_watchdog()
        self.assertIn("disable flag expired (age 192h >= max 168h)", self.log_text())

    def test_reminder_respects_six_hour_cooldown(self):
        self.set_flag()
        self.run_watchdog()
        self.run_watchdog()
        self.assertEqual(self.log_text().count("NOTIFY:"), 1)

    def test_flag_older_than_default_max_age_expires(self):
        self.set_flag(age_seconds=13 * HOUR)
        self.run_watchdog()
        log = self.log_text()
        self.assertIn("disable flag expired (age 13h >= max 12h)", log)
        self.assertIn("NOTIFY: Watchdog re-enabled after flag expiry", log)
        self.assertIn("TG: OpenMessage watchdog re-enabled itself", log)

    def test_max_age_override_in_flag_file(self):
        self.set_flag("max-age=48h\nlong maintenance window\n", age_seconds=13 * HOUR)
        self.run_watchdog()
        log = self.log_text()
        self.assertIn("skip: disable flag present (age 13h, max 48h", log)
        self.assertNotIn("expired", log)

    def test_flag_disabled_over_24h_telegrams_daily(self):
        self.set_flag("max-age=48h\n", age_seconds=25 * HOUR)
        self.run_watchdog()
        self.assertIn("TG: OpenMessage watchdog has been disabled 25h", self.log_text())
        self.run_watchdog()
        self.assertIn("tg suppressed (cooldown): flag_disabled", self.log_text())
        self.assertEqual(self.log_text().count("TG: OpenMessage watchdog has been"), 1)

    def test_dryrun_expiry_keeps_flag_and_continues_run(self):
        self.set_flag(age_seconds=13 * HOUR)
        self.run_watchdog()
        log = self.log_text()
        self.assertIn("DRYRUN: would archive flag", log)
        self.assertTrue(self.flag.exists())
        # Run resumed: the (dead) daemon probe happened.
        self.assertIn("probe failed", log)

    def test_real_expiry_archives_flag_and_uses_stubs(self):
        self.set_flag("old maintenance\n", age_seconds=13 * HOUR)
        self.run_watchdog(dryrun=False)
        self.assertFalse(self.flag.exists())
        archived = list((self.state / "expired-flags").iterdir())
        self.assertEqual(len(archived), 1)
        self.assertEqual(archived[0].read_text(), "old maintenance\n")
        self.assertIn(
            "Watchdog re-enabled after flag expiry", self.banner_calls.read_text()
        )
        self.assertIn(
            "watchdog re-enabled itself after the disable flag expired",
            self.tg_calls.read_text(),
        )
        # ~/bin/tg only logs a bare message; alerts must use its --alert mode.
        self.assertTrue(self.tg_calls.read_text().startswith("--alert "))

    def test_telegram_send_that_ignores_term_is_killed(self):
        stubborn = self.temp_path / "tg-stubborn"
        stubborn.write_text("#!/bin/bash\ntrap '' TERM\nsleep 60\n")
        stubborn.chmod(0o755)
        self.set_flag(age_seconds=13 * HOUR)
        started = time.time()
        result = self.run_watchdog(
            dryrun=False,
            env_extra={
                "OPENMESSAGE_WATCHDOG_TG_BIN": str(stubborn),
                "OPENMESSAGE_WATCHDOG_TG_TIMEOUT": "1",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(time.time() - started, 20)
        self.assertIn("tg send timed out: flag_expiry", self.log_text())
        self.assertTrue(self.health.exists())


class BannerChannelTests(WatchdogTestCase):
    """Which notifier posts the banner when no BANNER_CMD override is set.

    osascript is shadowed by a PATH stub so no real banner reaches the desktop.
    """

    def setUp(self):
        super().setUp()
        stub_bin = self.temp_path / "stub-bin"
        stub_bin.mkdir()
        self.osascript_calls = self.temp_path / "osascript_calls"
        osascript_stub = stub_bin / "osascript"
        osascript_stub.write_text(
            "#!/bin/bash\necho \"$@\" >> '%s'\n" % self.osascript_calls
        )
        osascript_stub.chmod(0o755)
        self.stub_path = "%s:%s" % (stub_bin, os.environ.get("PATH", ""))
        self.tn_calls = self.temp_path / "tn_calls"
        self.tn_stub = self.temp_path / "terminal-notifier"
        self.write_tn_stub(exit_code=0)

    def write_tn_stub(self, exit_code):
        self.tn_stub.write_text(
            "#!/bin/bash\necho \"$@\" >> '%s'\nexit %d\n" % (self.tn_calls, exit_code)
        )
        self.tn_stub.chmod(0o755)

    def post_reminder_banner(self, notifier=None, tn_bin=None):
        # A fresh disable flag posts one reminder banner and no telegram.
        self.set_flag()
        env = {
            "OPENMESSAGE_WATCHDOG_BANNER_CMD": "",
            "OPENMESSAGE_WATCHDOG_TERMINAL_NOTIFIER": str(tn_bin or self.tn_stub),
            "PATH": self.stub_path,
        }
        if notifier is not None:
            env["OPENMESSAGE_WATCHDOG_NOTIFIER"] = notifier
        result = self.run_watchdog(dryrun=False, env_extra=env)
        self.assertEqual(result.returncode, 0, result.stderr)

    def calls(self, path):
        return path.read_text() if path.exists() else ""

    def test_default_is_osascript_even_with_terminal_notifier_installed(self):
        self.post_reminder_banner()
        self.assertIn("display notification", self.calls(self.osascript_calls))
        self.assertIn("OpenMessage watchdog disabled", self.calls(self.osascript_calls))
        self.assertEqual(self.calls(self.tn_calls), "")

    def test_terminal_notifier_only_when_opted_in(self):
        self.post_reminder_banner(notifier="terminal-notifier")
        self.assertIn("-message OpenMessage watchdog disabled", self.calls(self.tn_calls))
        self.assertEqual(self.calls(self.osascript_calls), "")

    def test_opted_in_terminal_notifier_failure_falls_back_to_osascript(self):
        self.write_tn_stub(exit_code=1)
        self.post_reminder_banner(notifier="terminal-notifier")
        self.assertNotEqual(self.calls(self.tn_calls), "")
        self.assertIn("display notification", self.calls(self.osascript_calls))
        self.assertIn("terminal-notifier post failed", self.log_text())

    def test_opted_in_but_missing_terminal_notifier_uses_osascript(self):
        self.post_reminder_banner(
            notifier="terminal-notifier", tn_bin=self.temp_path / "absent"
        )
        self.assertIn("display notification", self.calls(self.osascript_calls))
        self.assertIn("terminal-notifier opted in but", self.log_text())

    def test_osascript_message_is_stripped_of_quotes_and_backslashes(self):
        daemon = self.start_daemon(
            status_payload(
                signal={
                    "paired": True,
                    "connected": True,
                    "receive_recovery": {
                        "pending_count": 7,
                        "last_issue_reason": 'bad "quote" \\ here',
                    },
                }
            )
        )
        result = self.run_watchdog(
            dryrun=False,
            port=daemon.port,
            env_extra={"OPENMESSAGE_WATCHDOG_BANNER_CMD": "", "PATH": self.stub_path},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            'display notification "Signal receive-recovery backlog: 7 pending'
            ' (bad quote  here)" with title',
            self.calls(self.osascript_calls),
        )

    def test_unknown_notifier_value_uses_osascript(self):
        self.post_reminder_banner(notifier="growl")
        self.assertIn("display notification", self.calls(self.osascript_calls))
        self.assertEqual(self.calls(self.tn_calls), "")
        self.assertIn("unknown OPENMESSAGE_WATCHDOG_NOTIFIER=growl", self.log_text())


class ClassATests(WatchdogTestCase):
    def test_dead_daemon_relaunches_after_two_probes(self):
        self.run_watchdog()
        log = self.log_text()
        self.assertIn("probe failed (1/2): dead (no app process)", log)
        self.assertNotIn("would relaunch", log)
        self.assertIn("daemon=down", self.health_text())
        self.run_watchdog()
        self.assertIn("DRYRUN: would relaunch", self.log_text())

    def test_relaunch_throttled_to_one_per_30m(self):
        self.set_state("consecutive_fails", 2)
        self.set_state("last_action_epoch", int(time.time()) - 60)
        self.run_watchdog()
        log = self.log_text()
        self.assertIn("action throttled", log)
        self.assertIn("relaunch throttled", self.health_text())

    def test_down_over_an_hour_telegrams(self):
        self.set_state("consecutive_fails", 5)
        self.set_state("down_since", int(time.time()) - 2 * HOUR)
        self.set_state("last_action_epoch", int(time.time()) - 60)
        self.run_watchdog()
        self.assertIn("TG: OpenMessage daemon has been down 2h", self.log_text())

    def test_outage_clock_survives_relaunch_attempts(self):
        # A relaunch resets consecutive_fails to 0 but the daemon stays down:
        # the outage clock must keep running from the episode's first failure.
        self.set_state("consecutive_fails", 0)
        self.set_state("down_since", int(time.time()) - 2 * HOUR)
        self.set_state("last_action_epoch", int(time.time()) - 10 * 60)
        self.run_watchdog()
        log = self.log_text()
        self.assertIn("probe failed (1/2)", log)
        self.assertIn("TG: OpenMessage daemon has been down 2h", log)
        self.assertIn("alert: daemon down ~2h", self.health_text())

    def test_first_failed_probe_starts_outage_clock(self):
        self.run_watchdog()
        since = int((self.state / "down_since").read_text())
        self.assertLessEqual(abs(since - int(time.time())), 60)
        self.assertNotIn("TG:", self.log_text())

    def test_daemon_down_telegram_is_daily_not_six_hourly(self):
        now = int(time.time())
        self.set_state("consecutive_fails", 5)
        self.set_state("down_since", now - 10 * HOUR)
        self.set_state("last_action_epoch", now - 60)
        self.set_state("tg_daemon_down", now - 7 * HOUR)
        self.run_watchdog()
        self.assertIn("tg suppressed (cooldown): daemon_down", self.log_text())
        self.assertNotIn("TG: OpenMessage daemon has been down", self.log_text())

    def test_thrash_telegram_after_third_relaunch_in_24h(self):
        now = int(time.time())
        (self.state / "relaunch_epochs").write_text(
            "%d\n%d\n" % (now - 2 * HOUR, now - HOUR)
        )
        self.set_state("consecutive_fails", 1)  # this run reaches the 2-probe threshold
        self.run_watchdog(dryrun=False)
        log = self.log_text()
        self.assertIn("relaunching FakeOMWatchdogTest.app", log)
        self.assertIn("TG: OpenMessage daemon relaunched 3 times in 24h", log)
        self.assertIn("Daemon was down", self.banner_calls.read_text())


class ClassBTests(WatchdogTestCase):
    def test_disconnect_alerts_on_third_consecutive_check(self):
        daemon = self.start_daemon(status_payload(signal_connected=False))
        for _ in range(2):
            self.run_watchdog(port=daemon.port)
        self.assertNotIn("NOTIFY", self.log_text())
        self.run_watchdog(port=daemon.port)
        log = self.log_text()
        self.assertIn("NOTIFY: signal disconnected 15+ min", log)
        self.assertIn("alert: signal disconnected ~0h (3 consecutive checks)", self.health_text())

    def test_sustained_disconnect_realerts_with_duration(self):
        daemon = self.start_daemon(status_payload(signal_connected=False))
        now = int(time.time())
        self.set_state("disc_signal", 100)
        self.set_state("disc_since_signal", now - 8 * HOUR)
        self.set_state("alert_disc_signal", now - 7 * HOUR)
        self.run_watchdog(port=daemon.port)
        self.assertIn(
            "NOTIFY: signal still disconnected ~8h - in-app recovery is NOT recovering it",
            self.log_text(),
        )

    def test_sustained_disconnect_within_cooldown_suppressed_but_in_health(self):
        daemon = self.start_daemon(status_payload(signal_connected=False))
        now = int(time.time())
        self.set_state("disc_signal", 100)
        self.set_state("disc_since_signal", now - 8 * HOUR)
        self.set_state("alert_disc_signal", now - HOUR)
        self.run_watchdog(port=daemon.port)
        log = self.log_text()
        self.assertIn("suppressed (cooldown): disc_signal", log)
        self.assertNotIn("NOTIFY", log)
        self.assertIn("alert: signal disconnected ~8h", self.health_text())

    def test_disconnect_over_48h_telegrams_daily(self):
        daemon = self.start_daemon(status_payload(signal_connected=False))
        now = int(time.time())
        self.set_state("disc_signal", 100)
        self.set_state("disc_since_signal", now - 3 * DAY)
        self.run_watchdog(port=daemon.port)
        self.assertIn(
            "TG: OpenMessage: signal has been disconnected 3d", self.log_text()
        )
        self.run_watchdog(port=daemon.port)
        self.assertIn("tg suppressed (cooldown): disc_signal", self.log_text())

    def test_missing_since_file_mid_episode_is_persisted(self):
        # State loss / first run after upgrade during an ongoing episode:
        # the clock must start now and PERSIST so escalation can still accrue.
        daemon = self.start_daemon(status_payload(signal_connected=False))
        self.set_state("disc_signal", 2700)
        self.run_watchdog(port=daemon.port)
        self.assertTrue((self.state / "disc_since_signal").exists())

    def test_failed_telegram_send_retries_next_run(self):
        failing_tg = self.temp_path / "tg-failing"
        failing_tg.write_text(
            "#!/bin/bash\necho \"$@\" >> '%s'\nexit 1\n" % self.tg_calls
        )
        failing_tg.chmod(0o755)
        env = {"OPENMESSAGE_WATCHDOG_TG_BIN": str(failing_tg)}
        self.set_flag("max-age=48h\n", age_seconds=25 * HOUR)
        self.run_watchdog(dryrun=False, env_extra=env)
        self.assertIn("tg send failed: flag_disabled", self.log_text())
        self.run_watchdog(dryrun=False, env_extra=env)
        self.assertEqual(len(self.tg_calls.read_text().splitlines()), 2)

    def test_reconnect_resets_counters_and_episode_state(self):
        now = int(time.time())
        self.set_state("disc_signal", 700)
        self.set_state("disc_since_signal", now - 3 * DAY)
        self.set_state("alert_disc_signal", now - HOUR)
        self.set_state("tg_disc_signal", now - HOUR)
        daemon = self.start_daemon(status_payload())
        self.run_watchdog(port=daemon.port)
        self.assertIn("reconnected: signal", self.log_text())
        self.assertEqual((self.state / "disc_signal").read_text().strip(), "0")
        for leftover in ("disc_since_signal", "alert_disc_signal", "tg_disc_signal"):
            self.assertFalse((self.state / leftover).exists(), leftover)

    def test_platform_dark_behind_others_banners_and_telegrams(self):
        now_ms = int(time.time() * 1000)
        daemon = self.start_daemon(
            status_payload(
                freshness={
                    "newest_ms": now_ms,
                    "google": {"latest_received_ms": now_ms},
                    "signal": {"latest_received_ms": now_ms - 3 * DAY * 1000},
                    "whatsapp": {"latest_received_ms": now_ms},
                }
            )
        )
        self.run_watchdog(port=daemon.port)
        log = self.log_text()
        self.assertIn("NOTIFY: signal received nothing for 3.0d", log)
        self.assertIn("TG: OpenMessage: signal received nothing for 3.0d", log)
        self.assertIn("alert: signal received nothing for 3.0d", self.health_text())

    def test_global_silence_banners_and_telegrams(self):
        stale = int(time.time() * 1000) - 30 * HOUR * 1000
        daemon = self.start_daemon(
            status_payload(
                freshness={"newest_ms": stale, "google": {"latest_received_ms": stale}}
            )
        )
        self.run_watchdog(port=daemon.port)
        log = self.log_text()
        self.assertIn("NOTIFY: No messages on ANY platform for 30h", log)
        self.assertIn("TG: OpenMessage: No messages on ANY platform for 30h", log)

    def test_projection_stall_is_severe(self):
        daemon = self.start_daemon(status_payload(projection_stalled=True))
        self.run_watchdog(port=daemon.port)
        log = self.log_text()
        self.assertIn("NOTIFY: v2 read projection stalled", log)
        self.assertIn("TG: OpenMessage: v2 read projection stalled", log)

    def test_quarantine_is_warn_tier_no_telegram(self):
        daemon = self.start_daemon(
            status_payload(v2_ingest={"per_account": {"a": {"quarantined": 2}}})
        )
        self.run_watchdog(port=daemon.port)
        log = self.log_text()
        self.assertIn("NOTIFY: 2 ingested frame(s) quarantined", log)
        self.assertNotIn("TG:", log)

    def test_healthy_run_writes_clean_health(self):
        daemon = self.start_daemon(status_payload())
        self.run_watchdog(port=daemon.port)
        health = self.health_text()
        self.assertIn("watchdog=active", health)
        self.assertIn("daemon=up", health)
        self.assertIn("alerts=0", health)
        self.assertNotIn("NOTIFY", self.log_text())

    def test_recovery_after_fails_logs_healthy_again(self):
        self.set_state("consecutive_fails", 4)
        (self.state / "down_since").write_text(str(int(time.time()) - HOUR))
        daemon = self.start_daemon(status_payload())
        self.run_watchdog(port=daemon.port)
        self.assertIn("healthy again (was 4 fails)", self.log_text())
        self.assertFalse((self.state / "down_since").exists())


if __name__ == "__main__":
    unittest.main()
