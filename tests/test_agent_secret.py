"""agent-secret must survive securityd's stale-master-key state.

Background (2026-09-19): a wrong password typed into a macOS keychain unlock
dialog leaves securityd holding a wrong master key for that keychain path.
`security unlock-keychain -p <correct>` is then rejected, because it is
pre-checked against the held key, and `lock-keychain` does not clear it. Every
agent-secret call failed for an hour. agent-secret now falls back to a
credential-path unlock (~/bin/agent-secret-cred-unlock) that re-keys securityd.

These tests run against a throwaway byte copy of the real agent keychain at a
temp path: nothing here touches the real keychain, the search list, or any
keychain setting, and the test never sees the unlock password (agent-secret
reads it itself). No step can raise a dialog: every unlock carries a password.

The second half covers the retired store (2026-10-20). The login keychain's
"claude-env" items moved into agent-secrets: `search` must still find
anything left there, and every migrated name must be in agent-secrets. The
names come from a local manifest (AGENT_SECRETS_MIGRATION_MANIFEST), never from
this public repo, and the live checks read names only.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
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
    shim = probe.parent / "shim"
    shim.mkdir()
    fake = shim / "security"
    fake.write_text('#!/bin/sh\n[ "$1" = unlock-keychain ] && exit 51\nexec /usr/bin/security "$@"\n')
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
    assert got.returncode == 0 and got.stdout.strip()


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
