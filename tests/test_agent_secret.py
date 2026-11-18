"""agent-secret must survive securityd's stale-master-key state.

Background (2026-09-19): a wrong password typed into a macOS keychain unlock
dialog leaves securityd holding a wrong master key for that keychain path.
`security unlock-keychain -p <correct>` is then rejected, because it is
pre-checked against the held key, and `lock-keychain` does not clear it. Every
agent-secret call failed for an hour. agent-secret now falls back to a
credential-path unlock (~/bin/agent-secret-cred-unlock) that re-keys securityd.

These tests run against a throwaway byte copy of the real agent keychain at a
temp path: nothing here touches the real keychain, the search list, or any
keychain setting. No step can raise a dialog: every unlock carries a password.
The argv checks at the end read the unlock password into memory to look for it
(never printed; see Hidden there); the rest never see it.

The second half covers the retired store (2026-10-20). The login keychain's
"claude-env" items moved into agent-secrets: `search` must still find
anything left there, and every migrated name must be in agent-secrets. The
names come from a local manifest (AGENT_SECRETS_MIGRATION_MANIFEST), never from
this public repo, and the live checks read names only.
"""
from __future__ import annotations

import contextlib
import ctypes
import inspect
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

AGENT_SECRET = Path(os.environ.get("AGENT_SECRET_BIN", Path.home() / "bin" / "agent-secret"))
CRED_UNLOCK = Path.home() / "bin" / "agent-secret-cred-unlock"
REAL_KEYCHAIN = Path.home() / "Library" / "Keychains" / "agent-secrets.keychain-db"
MANIFEST = Path(os.environ.get(
    "AGENT_SECRETS_MIGRATION_MANIFEST",
    Path.home() / "reviews" / "fleet-ops" / "secrets-consolidation-2026-10-20" / "manifest.json"))

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" or not REAL_KEYCHAIN.is_file() or not AGENT_SECRET.is_file(),
    reason="needs macOS with the agent-secrets keychain and ~/bin/agent-secret",
)


def agent_secret(probe: Path, *args: str, cred_unlock: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ, AGENT_SECRETS_KEYCHAIN=str(probe))
    if not cred_unlock:
        env["AGENT_SECRETS_CRED_UNLOCK"] = "/nonexistent/agent-secret-cred-unlock"
    return subprocess.run([str(AGENT_SECRET), *args], env=env, capture_output=True,
                          text=True, timeout=60)


def lock(probe: Path) -> None:
    subprocess.run(["security", "lock-keychain", str(probe)], capture_output=True, timeout=30)


def poison(probe: Path) -> None:
    """Drive securityd's decode(passphrase) with a wrong passphrase, which is
    what a wrong password typed into the unlock dialog does."""
    out = subprocess.run([sys.executable, str(CRED_UNLOCK), str(probe)],
                         input="not-the-keychain-password", capture_output=True,
                         text=True, timeout=30)
    assert out.returncode == 1 and out.stdout.strip() == "locked", out


@contextlib.contextmanager
def held_copy(path: Path):
    """A byte copy of the agent keychain at `path`, held open by a second process.

    securityd keeps per-path state only while some process has the keychain
    open. The real keychain is always held (it is in the search list), so the
    copy needs a holder too or the stale key would vanish between commands.
    The copy holds real (encrypted) items, so it is deleted however the test ends."""
    holder = None
    try:
        shutil.copy2(REAL_KEYCHAIN, path)
        holder = subprocess.Popen(["security", "-i"], stdin=subprocess.PIPE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        holder.stdin.write(f'find-generic-password -s zzz-no-such-item "{path}"\n')
        holder.stdin.flush()
        time.sleep(1.0)
        yield path
    finally:
        try:
            lock(path)
            if holder is not None:
                holder.stdin.close()
                holder.wait(timeout=10)
        finally:
            path.unlink(missing_ok=True)


@pytest.fixture
def probe(tmp_path: Path):
    """A locked byte copy of the agent keychain, held open by a second process."""
    with held_copy(tmp_path / "probe.keychain-db") as path:
        yield path


def test_plain_unlock_and_relock(probe: Path):
    assert agent_secret(probe, "unlock", cred_unlock=False).returncode == 0
    lock(probe)
    assert agent_secret(probe, "unlock", cred_unlock=False).returncode == 0


def test_cred_unlock_is_a_noop_on_an_unlocked_keychain(probe: Path):
    assert agent_secret(probe, "unlock", cred_unlock=False).returncode == 0
    # Force the fallback while already unlocked: a bogus `security` first on
    # PATH makes the plain unlock fail, so unlock_keychain takes the credential path.
    # The plain unlock is `security -i` with the command on stdin (2026-10-20);
    # `unlock` runs no other `security -i`.
    shim = probe.parent / "shim"
    shim.mkdir()
    fake = shim / "security"
    fake.write_text('#!/bin/sh\ncase "$1" in -i|unlock-keychain) exit 51 ;; esac\nexec /usr/bin/security "$@"\n')
    fake.chmod(0o755)
    env = dict(os.environ, AGENT_SECRETS_KEYCHAIN=str(probe), PATH=f"{shim}:{os.environ['PATH']}")
    out = subprocess.run([str(AGENT_SECRET), "unlock"], env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr


def test_unlock_heals_stale_master_key(probe: Path):
    poison(probe)
    plain = agent_secret(probe, "unlock", cred_unlock=False)
    if plain.returncode == 0:
        pytest.skip("this securityd no longer rejects the correct passphrase after a wrong one")
    assert "agent-secret doctor" in plain.stderr

    assert agent_secret(probe, "unlock").returncode == 0
    lock(probe)
    # Healed, not merely unlocked: the plain path works again from locked.
    assert agent_secret(probe, "unlock", cred_unlock=False).returncode == 0


def test_get_works_through_stale_master_key(probe: Path):
    names = agent_secret(probe, "list").stdout.splitlines()
    assert names, "agent keychain copy lists no items"
    service = names[0].split("\t")[0]
    lock(probe)
    poison(probe)
    got = agent_secret(probe, "get", service)
    ok = got.returncode == 0 and bool(got.stdout.strip())
    del got  # a real value: never let a failure (or -l) print it
    assert ok


def test_doctor_reports_and_repairs(probe: Path):
    healthy = agent_secret(probe, "doctor")
    assert healthy.returncode == 0 and "ok    unlocks with the stored password" in healthy.stdout

    # securityd sometimes drops the stale key between the check and doctor's own
    # unlock (2 in 30 runs on 2026-10-20, with or without the legacy scan), so
    # doctor then sees a healthy keychain. Retry rather than fail on that race.
    for _ in range(4):
        lock(probe)
        poison(probe)
        if agent_secret(probe, "unlock", cred_unlock=False).returncode == 0:
            pytest.skip("this securityd no longer rejects the correct passphrase after a wrong one")
        sick = agent_secret(probe, "doctor")
        assert sick.returncode == 0, sick.stdout
        if "stale master key" in sick.stdout:
            break
        assert "ok    unlocks with the stored password" in sick.stdout, sick.stdout
    else:
        pytest.skip("securityd dropped the stale key before doctor ran, 4 times in a row")
    assert "fixed" in sick.stdout

    broken = agent_secret(probe, "doctor", cred_unlock=False)
    assert broken.returncode == 0 and "ok    unlocks" in broken.stdout  # stays healed


# ---------- the retired "claude-env" store ----------

def add_item(keychain: Path, service: str, account: str, value: str) -> None:
    """Write through `security -i` on stdin (synthetic values; keychain already unlocked)."""
    q = lambda t: '"' + t.replace("\\", "\\\\").replace('"', '\\"') + '"'
    cmd = f"add-generic-password -a {q(account)} -s {q(service)} -l {q(service)} -T /usr/bin/security -w {q(value)} {q(str(keychain))}\n"
    assert subprocess.run(["security", "-i"], input=cmd, capture_output=True, text=True, timeout=30).returncode == 0


@pytest.fixture
def legacy(tmp_path: Path, probe: Path):
    """A second byte copy standing in for the login keychain, holding two synthetic
    claude-env items. `probe` plays the agent keychain."""
    with held_copy(tmp_path / "legacy.keychain-db") as path:
        assert agent_secret(path, "unlock").returncode == 0
        add_item(path, "claude-env", "ZZ_LEGACY_ONLY_TOKEN", "synthetic-1")
        add_item(path, "claude-env", "ZZ_SECOND_LEGACY", "synthetic-2")
        yield path


def with_legacy(probe: Path, legacy: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, AGENT_SECRETS_KEYCHAIN=str(probe), AGENT_SECRETS_LEGACY_KEYCHAIN=str(legacy))
    return subprocess.run([str(AGENT_SECRET), *args], env=env, capture_output=True, text=True, timeout=60)


def test_search_reports_a_legacy_only_item(probe: Path, legacy: Path):
    """The 2026-10-20 miss: a search for a key that lived only in claude-env returned nothing."""
    out = with_legacy(probe, legacy, "search", "zz_legacy_only")
    assert out.returncode == 0, out.stderr
    rows = [l.split("\t") for l in out.stdout.splitlines()]
    assert rows == [["claude-env", "ZZ_LEGACY_ONLY_TOKEN", rows[0][2]]]
    assert rows[0][2].startswith("LEGACY") and "find-generic-password -s claude-env -a ZZ_LEGACY_ONLY_TOKEN" in rows[0][2]
    assert "synthetic" not in out.stdout  # names only, never values


def test_list_stays_agent_only_and_list_legacy_names_the_rest(probe: Path, legacy: Path):
    plain = with_legacy(probe, legacy, "list").stdout
    assert "ZZ_LEGACY_ONLY_TOKEN" not in plain and plain.strip()
    old = with_legacy(probe, legacy, "list", "--legacy").stdout.splitlines()
    assert sorted(l.split("\t")[1] for l in old) == ["ZZ_LEGACY_ONLY_TOKEN", "ZZ_SECOND_LEGACY"]


def test_search_misses_exit_nonzero_and_agent_hits_still_win(probe: Path, legacy: Path):
    assert with_legacy(probe, legacy, "search", "zz-no-such-name-anywhere").returncode == 1
    service = with_legacy(probe, legacy, "list").stdout.splitlines()[0].split("\t")[0]
    hit = with_legacy(probe, legacy, "search", service)
    assert hit.returncode == 0 and any(l.split("\t")[0] == service for l in hit.stdout.splitlines())


def test_doctor_warns_while_legacy_items_remain(probe: Path, legacy: Path):
    out = with_legacy(probe, legacy, "doctor")
    assert out.returncode == 0 and "warn  2 item(s) still in the retired store" in out.stdout


def manifest() -> dict:
    if not MANIFEST.is_file():
        pytest.skip(f"no migration manifest at {MANIFEST}")
    return json.loads(MANIFEST.read_text())


def test_search_finds_every_migrated_name():
    """Live, names only: each name moved out of claude-env is an agent-secrets service now."""
    m = manifest()
    names = m["copy"] + m["delete_identical"] + m["delete_stale"]
    assert names
    missing = []
    for n in names:
        out = subprocess.run([str(AGENT_SECRET), "search", n], capture_output=True, text=True, timeout=60)
        if not any(l.split("\t")[0] == n for l in out.stdout.splitlines()):
            missing.append(n)
    assert not missing, f"agent-secret search finds no agent-secrets row for {missing}"


def test_retired_store_holds_nothing_unplanned():
    """Live, names only: the claude-env service holds no name outside the manifest's held list."""
    held = set(manifest().get("held", []))
    out = subprocess.run([str(AGENT_SECRET), "list", "--legacy"], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    left = sorted({l.split("\t")[1] for l in out.stdout.splitlines()} - held)
    assert not left, f"items still in the retired claude-env store: {left}"


def test_unreadable_legacy_store_reports_incomplete_not_missing(probe: Path, tmp_path: Path):
    """dump-keychain exits 0 with no output for a bad file; a miss there is exit 2, not 1."""
    bogus = tmp_path / "bogus.keychain-db"
    bogus.write_bytes(b"not a keychain")
    out = with_legacy(probe, bogus, "search", "zz-no-such-name-anywhere")
    assert out.returncode == 2 and "incomplete" in out.stderr


def test_missing_legacy_store_reports_incomplete(probe: Path, tmp_path: Path):
    """A configured legacy store that isn't there was not searched: exit 2, never 1."""
    out = with_legacy(probe, tmp_path / "absent.keychain-db", "search", "zz-no-such-name-anywhere")
    assert out.returncode == 2 and "incomplete" in out.stderr


# ---------- no secret on a command line (2026-10-20) ----------
#
# Until 2026-10-20 every agent-secret call unlocked with `security
# unlock-keychain -p <password>`, and `set` wrote with `add-generic-password -w
# <value>`. `ps` shows every process's argv to every user, and the disk-writer
# samplers record argv to disk (d1063). Both now go to `security -i` on stdin.
#
# Invariants checked here:
#   I1 no process agent-secret runs carries the unlock password or a value
#      (raw, hex, quoted or a 16-byte prefix) in its argv or environment;
#   I2 split_line(sec_quote(s)) == [s] for every s without NUL or LF, in Apple's
#      parser itself (`security -v -i` prints what it parsed) and in a port of it;
#   I3 `set` succeeds only if the stored bytes equal the input bytes;
#   I4 a `set` refused before writing (too long, a line break) leaves the old item;
#   I5 every `security -i` line is one line of at most 4,000 bytes.
#
# These tests know the real unlock password (read from the login keychain into
# memory, as agent-secret does) so they can look for it. They never print it.
# pytest prints a failing test's fixture arguments, every operand of a failed
# assert, and with -l every local, so the password, anything derived from it,
# every argv record and every captured agent-secret output live in Hidden
# (repr "<hidden>"), and asserts compare counts and flags computed beforehand.
# Argv records stay in memory (a FIFO, never a file). Synthetic values only for
# `set`. (Origin: a draft of these tests printed the password in a traceback on
# 2026-10-20, and the password was rotated.)
#
# What the argv checks do not cover: a command run by absolute path skips the
# PATH tap (agent-secret runs only python3 for the credential fallback that
# way, and passes the password on stdin); the sampler is statistical and
# watches only the test's own process groups.

LOGIN_KEYCHAIN = Path.home() / "Library" / "Keychains" / "login.keychain-db"
PASSWORD_SERVICE = "agent-secrets/keychain-password"
SEC_LINE_MAX = 4000  # agent-secret's limit for one `security -i` line


class Hidden:
    """Secret material. Its repr never shows the value."""
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def __repr__(self) -> str:
        return "<hidden>"

    __str__ = __repr__


def q(text: str) -> str:
    """One argument for `security -i` (split_line): quoted, \\ and " escaped."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def split_line(line: bytes) -> list[bytes]:
    """Port of split_line() in SecurityTool/macOS/security.c (Apple), byte for byte."""
    space = b" \t\n\v\f\r"
    args, cur, state, quote = [], bytearray(), "skip", 0
    for c in line:
        if state == "skip":
            if c in space:
                continue
            if c in b"\"'":
                quote, state, cur = c, "quoted", bytearray()
                continue
            state, cur = "arg", bytearray()
        if state == "arg":
            if c == 0x5C:
                state = "arg_esc"
                continue
            if c in space:
                args.append(bytes(cur))
                state = "skip"
            else:
                cur.append(c)
        if state == "quoted":
            if c == 0x5C:
                state = "quoted_esc"
                continue
            if c == quote:
                args.append(bytes(cur))
                state = "skip"
            else:
                cur.append(c)
        if state == "arg_esc":
            cur.append(c)
            state = "arg"
        if state == "quoted_esc":
            cur.append(c)
            state = "quoted"
    if state != "skip":
        args.append(bytes(cur))
    return args


def sec_i(line: Hidden) -> int:
    """One `security -i` command on stdin; the line may hold a password."""
    return subprocess.run(["/usr/bin/security", "-i"], input=(line.value + "\n").encode(),
                          capture_output=True, timeout=30).returncode


def unlocked(path: Path) -> bool:
    sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    sec.SecKeychainOpen.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    sec.SecKeychainGetStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    sec.SecKeychainSetUserInteractionAllowed(False)
    kc, st = ctypes.c_void_p(), ctypes.c_uint32()
    assert sec.SecKeychainOpen(str(path).encode(), ctypes.byref(kc)) == 0
    assert sec.SecKeychainGetStatus(kc, ctypes.byref(st)) == 0
    return bool(st.value & 1)


@pytest.fixture(scope="module")
def unlock_password() -> Hidden:
    """The agent keychain's unlock password, in memory only (never printed)."""
    if not unlocked(LOGIN_KEYCHAIN):
        pytest.skip("login keychain is locked; reading it would raise a dialog")
    out = subprocess.run(["/usr/bin/security", "find-generic-password", "-a", os.environ.get("USER", ""),
                          "-s", PASSWORD_SERVICE, "-g", str(LOGIN_KEYCHAIN)], capture_output=True, timeout=30)
    lines = [l for l in out.stderr.splitlines() if l.startswith(b'password: "')]
    secret = Hidden(lines[0][len(b'password: "'):-1]) if out.returncode == 0 and len(lines) == 1 else None
    del out, lines
    if secret is None:
        pytest.skip("cannot read the stored unlock password")
    return secret


def forms(secret: Hidden) -> Hidden:
    """What a leak could look like: as is, hex either case, quoted, a cut prefix."""
    v = secret.value
    out = {v, v.hex().encode(), v.hex().upper().encode(), q(v.decode("utf-8", "replace")).encode()}
    if len(v) >= 24:
        out.add(v[:16])
    return Hidden(out)


def run(args, env: dict, stdin: bytes = b"") -> Hidden:
    """agent-secret, its CompletedProcess Hidden: the output may hold a value."""
    return Hidden(subprocess.run([str(AGENT_SECRET), *args], input=stdin, capture_output=True,
                                 env=env, timeout=120))


def rc(r: Hidden) -> int:
    return r.value.returncode


def says(r: Hidden, text: bytes) -> bool:
    return text in r.value.stderr


def outputs(r: Hidden, value: bytes) -> bool:
    return r.value.stdout.rstrip(b"\n") == value


def probe_env(probe: Path, **extra) -> dict:
    return dict(os.environ, AGENT_SECRETS_KEYCHAIN=str(probe), **extra)


# --- I1, first view: an exec tap in front of every command ---

TAP = r'''#!/bin/bash
# argv tap (test_agent_secret.py): hand this command's argv to the test's FIFO
# (memory only, never a file), then run the real command. Each record is
# written under a lock (lockf by absolute path, so the tap never taps itself):
# commands that run at once, as in a pipeline, can't interleave their records.
# PATH keeps the tap first, so every descendant is tapped too.
name=${0##*/}
rec=$(printf '%s\037' "$name" "$@")
/usr/bin/lockf -k "$ARGV_TAP_FIFO.lock" /bin/bash -c 'printf "%s\036" "$1" > "$ARGV_TAP_FIFO"' _ "$rec"
IFS=:
for d in $ARGV_TAP_PATH; do
  if [ -f "$d/$name" ] && [ -x "$d/$name" ]; then
    exec "$d/$name" "$@"
  fi
done
echo "argv tap: $name not found" >&2
exit 127
'''


class ArgvTap:
    """Every command run through PATH (each `security`, `od`, `lockf`, the
    re-exec'd bash ...) reports its full argv here before it runs."""

    def __init__(self, root: Path):
        self.shim = root / "tap-bin"
        self.shim.mkdir()
        tap = self.shim / ".tap"
        tap.write_text(TAP)
        tap.chmod(0o755)
        self.real_path = os.environ["PATH"]
        seen = set()
        for d in self.real_path.split(":"):
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for n in names:
                p = os.path.join(d, n)
                if n in seen or n.startswith(".") or not os.path.isfile(p) or not os.access(p, os.X_OK):
                    continue
                seen.add(n)
                (self.shim / n).symlink_to(tap)
        self.fifo = root / "argv.fifo"
        os.mkfifo(self.fifo, 0o600)
        self.rfd = os.open(self.fifo, os.O_RDONLY | os.O_NONBLOCK)
        self.wfd = os.open(self.fifo, os.O_WRONLY)  # keeps EOF away while no command runs
        os.set_blocking(self.rfd, True)
        self.buf = bytearray()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        while True:
            chunk = os.read(self.rfd, 1 << 16)
            if not chunk:
                return
            self.buf += chunk

    def env(self, **extra) -> dict:
        return dict(os.environ, PATH=f"{self.shim}:{self.real_path}", ARGV_TAP_FIFO=str(self.fifo),
                    ARGV_TAP_PATH=self.real_path, **extra)

    def records(self) -> Hidden:
        """Hidden list of argv lists (bytes). An argv byte 0x1E or 0x1F would
        break the framing; agent-secret never passes one."""
        time.sleep(0.2)  # let the last writes land
        return Hidden([r.split(b"\x1f")[:-1] for r in bytes(self.buf).split(b"\x1e") if r])

    def close(self):
        os.close(self.wfd)
        self.thread.join(timeout=10)
        os.close(self.rfd)
        self.buf = bytearray()


@pytest.fixture
def tap(tmp_path: Path):
    t = ArgvTap(tmp_path)
    try:
        yield t
    finally:
        t.close()


def hits(records: Hidden, needles: Hidden) -> int:
    return sum(1 for r in records.value for n in needles.value if n in b"\x00".join(r))


def count(records: Hidden, pred) -> int:
    return sum(1 for r in records.value if pred(r))


def tapped(tap: ArgvTap, probe: Path, *args: str, stdin: bytes = b"", **env) -> Hidden:
    return run(args, tap.env(AGENT_SECRETS_KEYCHAIN=str(probe), **env), stdin)


def test_argv_tap_sees_what_runs(tap: ArgvTap, probe: Path):
    """Positive control: a canary on a command line shows up, a 1,000-byte one
    arrives whole, and so does the `security -i` behind an unlock."""
    canary = b"zz-canary-" + secrets.token_hex(8).encode()
    long_canary = b"zz-long-" + secrets.token_hex(496).encode()
    subprocess.run(["sh", "-c", ":", canary.decode(), long_canary.decode()], env=tap.env(), timeout=30)
    unlock_rc = rc(tapped(tap, probe, "unlock"))
    recs = tap.records()
    seen = hits(recs, Hidden({canary, long_canary}))
    stdin_cmds = count(recs, lambda r: r[0] == b"security" and r[1:2] == [b"-i"])
    scripts = count(recs, lambda r: r[0] == b"bash")  # the script itself, via env bash
    assert (unlock_rc, seen, stdin_cmds > 0, scripts > 0) == (0, 2, True, True)


def test_no_secret_on_any_command_line(tap: ArgvTap, probe: Path, unlock_password: Hidden):
    """Every path that handles the password or a value, run under the tap:
    unlock from locked, get, list, search, set through both write forms,
    delete, get through a stale master key (credential fallback), and doctor
    (healthy, then repairing a stale master key)."""
    values = {
        "hex": b"zz-" + secrets.token_hex(24).encode() + b' q"uo\\te $HOME `x` -p',
        "quoted": b"zz-" + secrets.token_hex(8).encode() + b"-" + b"Q\"\\ " * 480,  # -X would not fit
    }
    needles = Hidden(set(forms(unlock_password).value))
    for v in values.values():
        needles.value |= forms(Hidden(v)).value
    service = "zz-test/argv-" + secrets.token_hex(4)
    lock(probe)
    runs = [tapped(tap, probe, "unlock"), tapped(tap, probe, "list"), tapped(tap, probe, "search", "zz-none")]
    round_trips = []
    for v in values.values():
        runs.append(tapped(tap, probe, "set", service, stdin=v + b"\n"))
        got = tapped(tap, probe, "get", service)
        round_trips.append(outputs(got, v))
        runs.append(got)
    runs.append(tapped(tap, probe, "delete", service))
    lock(probe)
    poison(probe)
    runs.append(tapped(tap, probe, "list"))    # plain unlock refused: credential fallback
    runs.append(tapped(tap, probe, "doctor"))
    lock(probe)
    poison(probe)
    runs.append(tapped(tap, probe, "doctor"))  # stale key: probe copy unlock + credential repair
    runs.append(tapped(tap, probe, "get", "zz-no-such-item"))
    codes = [rc(r) for r in runs]
    recs = tap.records()
    security_runs = count(recs, lambda r: r[0] == b"security")
    leaks = hits(recs, needles)
    printed = sum(1 for r in runs for n in forms(unlock_password).value if n in r.value.stdout + r.value.stderr)
    del runs, got
    assert codes == [0, 0, 1] + [0] * 8 + [44]
    assert round_trips == [True, True]
    assert security_runs >= 15
    assert (leaks, printed) == (0, 0)


def test_init_puts_its_new_password_on_stdin_only(tmp_path: Path):
    """init, end to end against a stand-in `security` that parses each stdin
    line with the split_line port and keeps state in a scratch file (it never
    creates a keychain or touches the search list). The generated password must
    reach create-keychain, the login item (as hex) and the unlock intact, and
    no command line."""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    state = tmp_path / "fake-security.json"
    fake = bin_dir / "security"
    fake.write_text(FAKE_SECURITY.replace("@SPLIT_LINE@", inspect.getsource(split_line)))
    fake.chmod(0o755)
    keychain = tmp_path / "new-agent.keychain-db"
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", FAKE_SECURITY_STATE=str(state),
               AGENT_SECRETS_KEYCHAIN=str(keychain), AGENT_SECRETS_LOGIN_KEYCHAIN=str(tmp_path / "pwstore"),
               AGENT_SECRETS_CRED_UNLOCK="/nonexistent/agent-secret-cred-unlock")
    out = run(["init"], env)
    st = json.loads(state.read_text())
    pw = st.get("created", {}).get("password", "")
    argv_hits = sum(1 for a in st["argv"] if pw and pw in "\0".join(a))
    assert rc(out) == 0, out.value.stderr[-300:]
    assert len(pw) == 64 and st["created"]["path"] == str(keychain)
    assert st["stored"] == {"account": os.environ["USER"], "service": PASSWORD_SERVICE,
                            "label": "Agent Secrets keychain password", "password": pw, "update": True,
                            "trusted": "/usr/bin/security"}
    assert st["unlocked_with"] == [pw]
    assert st["search_list"] == [str(keychain)]  # empty list before: no unbound-array error
    assert argv_hits == 0


FAKE_SECURITY = r'''#!/opt/homebrew/bin/python3 -I
"""Stand-in for security(1) in test_init_puts_its_new_password_on_stdin_only."""
import json, os, sys
STATE = os.environ["FAKE_SECURITY_STATE"]
try:
    st = json.load(open(STATE))
except FileNotFoundError:
    st = {"argv": [], "unlocked_with": [], "search_list": []}
@SPLIT_LINE@
args = sys.argv[1:]
st["argv"].append(args)
rc = 0
if args == ["-i"]:
    line = sys.stdin.buffer.readline()
    assert line.endswith(b"\n") and not sys.stdin.buffer.read(), "more than one line on stdin"
    words = [w.decode() for w in split_line(line[:-1])]
    cmd, opts = words[0], words[1:]
    if cmd == "create-keychain":
        assert opts[0] == "-p" and len(opts) == 3
        st["created"] = {"password": opts[1], "path": opts[2]}
        open(opts[2], "w").close()
    elif cmd == "add-generic-password":
        o = dict(zip(opts[1:-1:2], opts[2:-1:2])) if opts[0] == "-U" else {}
        st["stored"] = {"account": o["-a"], "service": o["-s"], "label": o["-l"],
                        "password": bytes.fromhex(o["-X"]).decode(), "update": opts[0] == "-U",
                        "trusted": o["-T"]}
    elif cmd == "unlock-keychain":
        st["unlocked_with"].append(opts[1])
    else:
        rc = 1
elif args[:1] == ["find-generic-password"] and "-w" in args and "stored" in st:
    print(st["stored"]["password"])
elif args[:3] == ["list-keychains", "-d", "user"]:
    if "-s" in args:
        st["search_list"] = args[4:]
elif args[:1] == ["set-keychain-settings"]:
    pass
else:
    rc = 44
json.dump(st, open(STATE, "w"))
sys.exit(rc)
'''


# --- I1, second view: argv and environment read from outside ---

class ArgvSampler:
    """Reads the argv and environment of every process in the watched process
    groups through sysctl KERN_PROCARGS2, the call behind `ps -ww` and the
    disk-writer samplers, about once a millisecond. Keeps only (pgid, needle
    index) of a match, never the bytes.

    Not `ps -axww` in a loop: with ~1,700 processes one pass takes ~100 ms and
    reads each argv after listing them all, so a 10 ms process is gone before
    its turn (0 catches of a canary in 400 tries, 2026-10-20)."""

    def __init__(self, needles: Hidden):
        self.needles, self.groups, self.found, self.samples = needles, [], [], 0
        self.libc = ctypes.CDLL(None)
        self.libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        self.libproc.proc_listpgrppids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self.buf = ctypes.create_string_buffer(1 << 20)  # kern.argmax
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def watch(self, pgid: int) -> None:
        self.groups.append(pgid)

    def _procargs(self, pid: int) -> bytes:
        mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
        size = ctypes.c_size_t(len(self.buf))
        if self.libc.sysctl(mib, 3, self.buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
            return b""
        return self.buf.raw[:size.value]

    def _run(self):
        pids = (ctypes.c_int * 256)()
        while not self.stop.is_set():
            for pg in tuple(self.groups[-4:]):
                ctypes.memset(pids, 0, ctypes.sizeof(pids))
                self.libproc.proc_listpgrppids(pg, pids, ctypes.sizeof(pids))
                for pid in pids:
                    if pid <= 0:
                        continue
                    args = self._procargs(pid)
                    self.samples += 1
                    for i, n in enumerate(self.needles.value):
                        if n in args:
                            self.found.append((pg, i))
            time.sleep(0.0005)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=60)


def test_argv_sampler_never_sees_the_password_or_a_value(probe: Path, unlock_password: Hidden):
    """Watch argv and environment from outside, as any local process can,
    while unlock (from locked), set and get run, after proving that a 10 ms
    canary and an argv unlock of the old shape (synthetic password) are caught.
    Half the runs come from a hostile caller: xtrace and allexport inherited
    through SHELLOPTS, and exported variables named like agent-secret's own."""
    canary = b"zz-canary-" + secrets.token_hex(8).encode()
    value = b"zz-" + secrets.token_hex(24).encode()
    needles = Hidden([canary] + sorted(forms(unlock_password).value | forms(Hidden(value)).value))
    plain = probe_env(probe)
    hostile = probe_env(probe, SHELLOPTS="xtrace:allexport", password="zz-placeholder",
                        secret="zz-placeholder", hex="zz-placeholder", line="zz-placeholder", s="zz-placeholder")
    service = "zz-test/argv-sampler-" + secrets.token_hex(4)
    sampler = ArgvSampler(needles)
    canary_groups, ours, rcs, printed = [], [], [], 0
    try:
        for _ in range(20):
            p = subprocess.Popen(["/usr/bin/perl", "-e", "select(undef,undef,undef,0.01)", canary.decode()],
                                 start_new_session=True)
            sampler.watch(p.pid)
            canary_groups.append(p.pid)
            p.wait(timeout=30)
        # The exact shape of the old leak, with a synthetic password: an argv
        # unlock (of a keychain that doesn't exist, so nothing can prompt).
        absent = probe.parent / "absent.keychain-db"
        for _ in range(10):
            p = subprocess.Popen(["/usr/bin/security", "unlock-keychain", "-p", canary.decode(), str(absent)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            sampler.watch(p.pid)
            canary_groups.append(p.pid)
            p.wait(timeout=30)
        time.sleep(0.05)
        caught = len({pg for pg, i in sampler.found if i == 0 and pg in set(canary_groups[:20])})
        caught_old_shape = len({pg for pg, i in sampler.found if i == 0 and pg in set(canary_groups[20:])})
        for i in range(40):
            if i % 2 == 0:
                lock(probe)
            args = ["set", service] if i % 4 == 1 else ["get", service] if i % 4 == 3 else ["unlock"]
            p = subprocess.Popen([str(AGENT_SECRET), *args], env=hostile if i % 8 >= 4 else plain,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
            sampler.watch(p.pid)
            ours.append(p.pid)
            out = Hidden(p.communicate(value + b"\n" if args[0] == "set" else b"", timeout=120))
            printed += sum(1 for n in forms(unlock_password).value if n in out.value[1])  # stderr: xtrace
            rcs.append(p.returncode)
            del out
    finally:
        sampler.close()
        subprocess.run([str(AGENT_SECRET), "delete", service], env=plain, capture_output=True, timeout=60)
    leaks = sum(1 for pg, i in sampler.found if pg in set(ours))
    assert caught >= 15, f"positive control: caught the canary in {caught} of 20 runs"
    assert caught_old_shape >= 7, f"positive control: caught {caught_old_shape} of 10 argv unlocks"
    assert rcs == [0] * 40
    assert (leaks, printed) == (0, 0)


# --- I2: quoting, against Apple's parser ---

def apple_parse(arg_line: bytes) -> bytes | None:
    """What `security -i` parses `help <arg_line>` into: `-v` prints each
    parsed argument as ` "ARG"`. Synthetic strings only."""
    out = subprocess.run(["/usr/bin/security", "-v", "-i"], input=b"help " + arg_line + b"\n",
                         capture_output=True, timeout=30).stderr
    first = out.split(b"\n", 1)[0]
    if not (first.startswith(b'help "') and first.endswith(b'"')):
        return None
    return first[len(b'help "'):-1]


def bash_quote(values: list[bytes]) -> list[bytes]:
    """agent-secret's own sec_quote, run by /bin/bash under a UTF-8 locale."""
    src = AGENT_SECRET.read_text()
    fn = src[src.index("sec_quote() {"):]
    fn = fn[:fn.index("\n}\n") + 3]
    # Length-prefixed output (a separator byte could occur in a value): N:BYTES.
    script = fn + 'for v in "$@"; do sec_quote "$v"; n=$(LC_ALL=C; printf %s "${#SEC_Q}"); printf "%s:%s" "$n" "$SEC_Q"; done'
    out = subprocess.run(["/bin/bash", "-c", script, "_", *values], capture_output=True, timeout=60,
                         env=dict(os.environ, LC_ALL="en_US.UTF-8")).stdout
    quoted, i = [], 0
    while i < len(out):
        j = out.index(b":", i)
        n = int(out[i:j])
        quoted.append(out[j + 1:j + 1 + n])
        i = j + 1 + n
    return quoted


QUOTE_CORPUS = [b"", b"plain", b'"', b"\\", b"\\\\", b'\\"', b'"\\', b"a\\", b"trailing\\", b" lead", b"trail ",
                b"\t\r\v\f", b"'single'", b"$HOME `x` $(id)", b"-p", b"--", b"#c", b";|&<>", b"\xc3\xa9\xe4\xb8\xad",
                b"\xff\xfe\x80", b"\x01\x02\x1f\x7f", "🔑".encode()]


def random_values(n: int, seed: int) -> list[bytes]:
    import random
    rnd = random.Random(seed)
    alphabet = [bytes([b]) for b in range(1, 256) if b != 0x0A] + [b'"', b"\\", b" "] * 20
    return [b"".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40))) for _ in range(n)]


def test_sec_quote_round_trips_through_apples_parser():
    values = QUOTE_CORPUS + random_values(150, seed=20261020)
    quoted = bash_quote(values)
    assert len(quoted) == len(values)
    port_ok = [split_line(qv) == [v] for v, qv in zip(values, quoted)]
    apple_ok = [apple_parse(qv) == v for v, qv in zip(values, quoted)]
    bad = [i for i, (a, b) in enumerate(zip(port_ok, apple_ok)) if not (a and b)]
    assert bad == []


def test_sec_quote_property_hypothesis():
    """The same property over Hypothesis-generated bytes (skipped when Hypothesis
    is absent; run with `uv run --with hypothesis --with pytest pytest ...`)."""
    hypothesis = pytest.importorskip("hypothesis")
    st = hypothesis.strategies

    @hypothesis.settings(max_examples=150, deadline=None, derandomize=True)
    @hypothesis.given(st.binary(max_size=60).filter(lambda b: b"\n" not in b and b"\0" not in b))
    def prop(v):
        (qv,) = bash_quote([v])
        assert split_line(qv) == [v]
        assert apple_parse(qv) == v

    prop()


# --- I3/I4: what `set` stores ---

AWKWARD = [
    'q"uo\\te $HOME `x` \'it\'s\' -p ;|&<> #',
    "-leading-dash",
    "  spaces  around  ",
    "\\",
    '"',
    "tab\there",           # not printable: `get` prints it as hex
    "é ü 中 🔑",            # not ASCII: hex too
    "\r\x01\x7f\xff-bytes",
]


@pytest.mark.parametrize("value", AWKWARD, ids=range(len(AWKWARD)))
def test_set_round_trips_awkward_values(probe: Path, value: str):
    raw = value.encode("utf-8") if "\xff" not in value else value.encode("latin-1")
    service = "zz-test/awkward-" + secrets.token_hex(4)
    wrote = run(["set", service], probe_env(probe), raw + b"\n")
    got = run(["get", service], probe_env(probe))
    printable = all(0x20 <= b <= 0x7E for b in raw)
    assert rc(wrote) == 0, wrote.value.stderr
    assert outputs(got, raw if printable else raw.hex().encode())


FORM_SPY = r'''#!/bin/bash
# Records which write form a `security -i` add line used (the option letter
# only, never the line), then runs it. With FORM_SPY_STORE_HEX_TEXT set, it
# rewrites `-X <hex>` to `-w "<hex>"`, storing the hex digits as text.
if [ "$1" = -i ]; then
  IFS= read -r line
  case "$line" in
    "add-generic-password "*" -X "*) echo X >> "$FORM_LOG"
      if [ -n "${FORM_SPY_STORE_HEX_TEXT:-}" ]; then
        pre=${line%% -X *}; rest=${line#* -X }; hex=${rest%% *}; kc=${rest#* }
        line="$pre -w \"$hex\" $kc"
      fi ;;
    "add-generic-password "*" -w "*) echo w >> "$FORM_LOG" ;;
  esac
  printf '%s\n' "$line" | /usr/bin/security -i
  exit $?
fi
exec /usr/bin/security "$@"
'''


def spy_env(probe: Path, tmp_path: Path, **extra) -> tuple[dict, Path]:
    spy = tmp_path / "spy"
    spy.mkdir()
    (spy / "security").write_text(FORM_SPY)
    (spy / "security").chmod(0o755)
    log = tmp_path / "forms.log"
    return probe_env(probe, PATH=f"{spy}:{os.environ['PATH']}", FORM_LOG=str(log), **extra), log


@pytest.mark.parametrize("size,form", [(1600, "X"), (1990, "w"), (3500, "w")])
def test_set_long_values_take_the_form_that_fits(probe: Path, tmp_path: Path, size: int, form: str):
    """-X hex while the line fits SEC_LINE_MAX, then the quoted -w argument."""
    env, log = spy_env(probe, tmp_path)
    value = (secrets.token_hex(size)[: size - 3] + 'x"\\').encode()
    service = "zz-test/long-" + secrets.token_hex(4)
    wrote = run(["set", service], env, value + b"\n")
    got = run(["get", service], env)
    assert rc(wrote) == 0, wrote.value.stderr
    assert log.read_text().split() == [form]
    assert outputs(got, value)


@pytest.mark.parametrize("value", [b"tab\tbyte", b"\xff\x01", b"back\\slash"], ids=["tab", "binary", "backslash"])
def test_set_rejects_stored_hex_text_for_bytes(probe: Path, tmp_path: Path, value: bytes):
    """I3, negative: if what lands in the keychain is the hex digits as text
    (which `security -w` prints exactly like the bytes they spell), the
    read-back must fail."""
    env, _ = spy_env(probe, tmp_path, FORM_SPY_STORE_HEX_TEXT="1")
    wrote = run(["set", "zz-test/hex-text-" + secrets.token_hex(4)], env, value + b"\n")
    assert (rc(wrote), says(wrote, b"stored value differs")) == (1, True)


def test_set_refuses_a_value_too_long_for_stdin_and_keeps_the_old_one(probe: Path):
    env = probe_env(probe)
    service = "zz-test/too-long-" + secrets.token_hex(4)
    old = b"zz-old-" + secrets.token_hex(8).encode()
    first = run(["set", service], env, old + b"\n")
    refused = run(["set", service], env, b"y" * 3990 + b"\n")
    got = run(["get", service], env)
    assert rc(first) == 0
    assert (rc(refused), says(refused, b"too long"), says(refused, b"old value kept")) == (1, True, True)
    assert outputs(got, old)


def test_set_refuses_a_line_break_in_a_name_and_keeps_the_old_one(probe: Path):
    """I4: an item whose account holds a line break (made directly, since no
    `security -i` line can carry one) survives a `set` that must refuse it, and
    the refusal comes before the delete."""
    env = probe_env(probe)
    account = "zz\nacct-" + secrets.token_hex(4)
    service = "zz-test/lf-" + secrets.token_hex(4)
    old = "zz-old-" + secrets.token_hex(8)
    unlock_rc = rc(run(["unlock"], env))
    made = subprocess.run(["/usr/bin/security", "add-generic-password", "-a", account, "-s", service,
                           "-w", old, "-T", "/usr/bin/security", str(probe)],  # synthetic value, on argv on purpose
                          capture_output=True, timeout=30).returncode
    refused = run(["set", service, account], env, b"zz-new\n")
    got = run(["get", service, account], env)
    assert (unlock_rc, made) == (0, 0)
    assert (rc(refused), says(refused, b"line break")) == (1, True)
    assert outputs(got, old.encode())


# --- the stored password, and the write lock ---

def test_unlock_quotes_an_awkward_password(tmp_path: Path, unlock_password: Hidden):
    """A keychain whose password holds quotes, backslashes, spaces and shell
    syntax still unlocks through `security -i`, with no credential fallback.
    (The stored password must be printable ASCII: `security -w` prints anything
    else as hex. init makes it base64.)"""
    awkward = 'zz "q" \\b\\ $HOME `x` \'s\' -p ' + secrets.token_hex(8)
    service = "zz-test/keychain-password-" + secrets.token_hex(4)
    # Not "login.keychain-db": Security treats that file name specially, and an
    # unlock of a copy so named fails (seen 2026-10-20).
    with held_copy(tmp_path / "agent.keychain-db") as agent, held_copy(tmp_path / "pwstore.keychain-db") as login:
        real = Hidden(q(unlock_password.value.decode()))
        rcs = (sec_i(Hidden(f"set-keychain-password -o {real.value} -p {q(awkward)} {q(str(agent))}")),
               sec_i(Hidden(f"unlock-keychain -p {real.value} {q(str(login))}")),
               sec_i(Hidden(f"add-generic-password -a {q(os.environ['USER'])} -s {q(service)} "
                            f"-T /usr/bin/security -X {awkward.encode().hex()} {q(str(login))}")))
        del real
        lock(agent)
        env = dict(os.environ, AGENT_SECRETS_KEYCHAIN=str(agent), AGENT_SECRETS_LOGIN_KEYCHAIN=str(login),
                   AGENT_SECRETS_PASSWORD_SERVICE=service,
                   AGENT_SECRETS_CRED_UNLOCK="/nonexistent/agent-secret-cred-unlock")
        out = run(["unlock"], env)
        assert rcs == (0, 0, 0)
        assert rc(out) == 0, out.value.stderr
        assert unlocked(agent)


def test_writes_wait_for_the_write_lock(probe: Path, tmp_path: Path):
    import fcntl
    lock_file = tmp_path / "write.lock"
    env = probe_env(probe, AGENT_SECRETS_LOCK_FILE=str(lock_file), AGENT_SECRETS_LOCK_WAIT="1")
    service = "zz-test/lock-" + secrets.token_hex(4)
    with open(lock_file, "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        blocked_set = run(["set", service], env, b"zz-v\n")
        blocked_delete = run(["delete", service], env)
    after = run(["set", service], env, b"zz-v\n")
    assert (rc(blocked_set), says(blocked_set, b"write lock")) == (1, True)
    assert (rc(blocked_delete), says(blocked_delete, b"write lock")) == (1, True)
    assert rc(after) == 0


# --- the source itself ---

def test_source_keeps_secrets_off_argv_and_out_of_temp_files():
    """Static guard for the two easy regressions: a secret-bearing security(1)
    command run directly (it belongs on a sec_stdin line), and a heredoc or
    here-string (bash 3.2 writes those to a temp file). Only `usage` may use a
    heredoc."""
    import re
    lines = AGENT_SECRET.read_text().splitlines()
    code = [(i + 1, l) for i, l in enumerate(lines) if not l.lstrip().startswith("#")]
    direct = [n for n, l in code if re.search(r"\bsecurity\s+(unlock-keychain|create-keychain|add-generic-password"
                                              r"|set-keychain-password)\b", l)]
    heredocs = [n for n, l in code if re.search(r"<<<|<<-?\s*['\"]?[A-Za-z_]", l) and "<<'USAGE'" not in l]
    assert (direct, heredocs) == ([], [])
