"""sweep-worktrees must never touch a worktree pinned with `git worktree lock`.

Origin (2026-09-25): an unidentified cleanup deleted two Axiom engine
worktrees whose target/release binaries were pinned by SHA-256 in reviewed
launch plans. sweep-worktrees was a candidate: --prune-ignored and
--prune-venvs ran rm -rf inside kept worktrees without checking the lock, and
removal relied on `git worktree remove` refusing a locked worktree.

Invariants exercised here, for every invocation style (repo argument, root
argument, --discover), action (removal, --prune-ignored, --prune-venvs, both)
and dry/real run:

1. Every file under a locked worktree, tracked or ignored, is byte-identical
   afterwards; its admin dir, lock file and branch survive.
2. Each locked worktree yields exactly one report line, a LOCKED line carrying
   the lock reason ("(none)" when none was given), and no git failure.
3. Non-vacuity: an unlocked twin in the same repo is acted on in the same run.
4. The repo-mode (porcelain) and root-mode (lock file) readers report the same
   reason, and a reason cannot break the one-record-per-line TSV output.

All repos are throwaway repos under a temporary directory with HOME pointed
into it, so the script cannot reach a real worktree root.
"""

import hashlib
import itertools
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SWEEP = REPO_ROOT / "bin" / "sweep-worktrees"
SUBPROCESS_TIMEOUT = 120

ENGINE = Path("target/release/axiom-rules-engine")
RECEIPT = Path("target/release/axiom-rules-engine.provenance.json")
VENV_FILE = Path(".venv/pyvenv.cfg")

PINNED_REASON = "pinned evidence: engine sha256 in REPIN.md"

INVOCATIONS = ("repo", "root", "discover")
ACTIONS = {
    "remove": ["--force-dirty", "--remove-closed"],
    "prune-ignored": ["--prune-ignored"],
    "prune-venvs": ["--prune-venvs"],
    "prune-both": ["--prune-ignored", "--prune-venvs"],
}
STATUSES = {
    "LOCKED",
    "REMOVE",
    "WOULD-REMOVE",
    "BLOCKED",
    "MERGED-BUT-DIRTY",
    "REVIEW-CLOSED",
    "DETACHED",
    "KEEP",
    "PRUNE-IGNORED",
    "WOULD-PRUNE-IGNORED",
    "IGNORED-BLOCKED",
    "NO-IGNORED",
    "PRUNE-VENV",
    "WOULD-PRUNE-VENV",
    "VENV-BLOCKED",
    "VENV-SKIP",
    "NO-VENV",
}


def normalized_reason(raw):
    """What the report should show for a raw lock reason."""
    return re.sub(r"[\t\r\n]", " ", raw).strip(" ") or "(none)"


def snapshot(root):
    """Map every path under root to its type and content hash."""
    entries = {}
    for directory, directories, files in os.walk(root):
        for name in directories + files:
            path = Path(directory) / name
            relative = path.relative_to(root)
            if path.is_symlink():
                entries[relative] = ("link", os.readlink(path))
            elif path.is_dir():
                entries[relative] = ("dir",)
            else:
                entries[relative] = (
                    "file",
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
    return entries


class SweepWorktreesLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temp_path = Path(self.temporary_directory.name).resolve()
        self.home = self.temp_path / "home"
        self.home.mkdir()
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        self.environment.update(
            HOME=str(self.home),
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_AUTHOR_NAME="sweep test",
            GIT_AUTHOR_EMAIL="sweep@example.invalid",
            GIT_COMMITTER_NAME="sweep test",
            GIT_COMMITTER_EMAIL="sweep@example.invalid",
        )
        self.environment.pop("VIRTUAL_ENV", None)

    # -- helpers ---------------------------------------------------------

    def git(self, *arguments, cwd=None):
        completed = subprocess.run(
            ["git", *map(str, arguments)],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            env=self.environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout

    def sweep(self, *arguments):
        completed = subprocess.run(
            [str(SWEEP), "--recent-hours", "0", *map(str, arguments)],
            check=False,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            env=self.environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout

    def make_repo(self, base):
        repo = base / "repo"
        repo.mkdir(parents=True)
        self.git("init", "-q", "-b", "main", repo)
        (repo / ".gitignore").write_text("target/\n.venv/\n")
        (repo / "README").write_text("tracked\n")
        self.git("-C", repo, "add", "-A")
        self.git("-C", repo, "commit", "-q", "-m", "init")
        return repo

    def add_worktree(self, repo, path, branch, reason=None):
        """Add a linked worktree holding ignored build output and a venv.

        reason=None leaves it unlocked; "" locks it without a reason.
        """
        self.git("-C", repo, "worktree", "add", "-q", "-b", branch, path)
        (path / ENGINE).parent.mkdir(parents=True)
        (path / ENGINE).write_bytes(b"\x7fELF engine " + branch.encode())
        (path / RECEIPT).write_text('{"sha256": "abc"}\n')
        (path / VENV_FILE).parent.mkdir(parents=True)
        (path / VENV_FILE).write_text("home = /usr/bin\n")
        if reason is not None:
            lock = ["-C", repo, "worktree", "lock"]
            if reason:
                lock += ["--reason", reason]
            self.git(*lock, path)
        return path

    def admin_dir(self, worktree):
        return Path(
            self.git("-C", worktree, "rev-parse", "--absolute-git-dir").strip()
        )

    def pin_state(self, repo, worktree, branch, admin):
        """Everything a lock promises to keep, captured for comparison."""
        return {
            "tree": snapshot(worktree),
            "locked": (admin / "locked").read_bytes(),
            "gitdir": (admin / "gitdir").read_bytes(),
            "HEAD": (admin / "HEAD").read_bytes(),
            "branch": self.git(
                "-C", repo, "rev-parse", "--verify", f"refs/heads/{branch}"
            ),
        }

    def records(self, stdout):
        return [line.split("\t") for line in stdout.splitlines() if line]

    def lines_for(self, stdout, path):
        return [
            record
            for record in self.records(stdout)
            if len(record) > 1 and record[1] == str(path)
        ]

    def assert_only_locked(self, stdout, path, reason):
        lines = self.lines_for(stdout, path)
        self.assertEqual(
            [line[0] for line in lines], ["LOCKED"], f"{path}:\n{stdout}"
        )
        self.assertEqual(lines[0][-1], f"reason={normalized_reason(reason)}")

    def assert_well_formed(self, stdout):
        self.assertNotIn("fatal:", stdout)
        self.assertNotIn("locked working tree", stdout)
        for record in self.records(stdout):
            if record[0].startswith("  "):
                continue  # indented git output under a REMOVE line
            self.assertIn(record[0], STATUSES, f"stray line: {record}")

    def invocation_arguments(self, invocation, base, repo):
        return {
            "repo": [repo],
            "root": [base / "worktrees"],
            "discover": ["--discover", base],
        }[invocation]

    # -- tests -----------------------------------------------------------

    def test_prune_ignored_dry_and_real_runs_keep_locked_target(self):
        """The requested regression: a locked worktree's ignored target/."""
        base = self.temp_path / "incident"
        repo = self.make_repo(base)
        pinned = self.add_worktree(
            repo, base / "worktrees" / "pinned", "pinned", PINNED_REASON
        )
        control = self.add_worktree(repo, base / "worktrees" / "control", "control")
        engine_bytes = (pinned / ENGINE).read_bytes()

        dry = self.sweep("--prune-ignored", "--dry-run", repo)
        self.assert_only_locked(dry, pinned, PINNED_REASON)
        self.assertEqual((pinned / ENGINE).read_bytes(), engine_bytes)
        self.assertEqual(
            [line[0] for line in self.lines_for(dry, control)],
            ["WOULD-PRUNE-IGNORED"],
        )
        self.assertTrue((control / ENGINE).exists())

        real = self.sweep("--prune-ignored", repo)
        self.assert_only_locked(real, pinned, PINNED_REASON)
        self.assertEqual((pinned / ENGINE).read_bytes(), engine_bytes)
        self.assertTrue((pinned / RECEIPT).exists())
        self.assertEqual(
            [line[0] for line in self.lines_for(real, control)], ["PRUNE-IGNORED"]
        )
        self.assertFalse((control / "target").exists())

    def test_locked_worktrees_survive_every_mode(self):
        """Invariants 1-3 over the full invocation x action x dry-run grid."""
        grid = itertools.product(INVOCATIONS, ACTIONS, (True, False))
        for index, (invocation, action, dry_run) in enumerate(grid):
            with self.subTest(invocation=invocation, action=action, dry_run=dry_run):
                base = self.temp_path / f"grid-{index}"
                repo = self.make_repo(base)
                pinned = {
                    "pinned": PINNED_REASON,
                    # Locked without a reason and dirty, so removal would
                    # need --force (which git also refuses for a lock).
                    "pinned-noreason": "",
                }
                states = {}
                for branch, reason in pinned.items():
                    path = self.add_worktree(
                        repo, base / "worktrees" / branch, branch, reason
                    )
                    if not reason:
                        (path / "README").write_text("uncommitted edit\n")
                    admin = self.admin_dir(path)
                    states[branch] = (
                        path,
                        admin,
                        self.pin_state(repo, path, branch, admin),
                    )
                control = self.add_worktree(
                    repo, base / "worktrees" / "control", "control"
                )

                arguments = list(ACTIONS[action])
                if dry_run:
                    arguments.append("--dry-run")
                stdout = self.sweep(
                    *arguments, *self.invocation_arguments(invocation, base, repo)
                )

                self.assert_well_formed(stdout)
                for branch, (path, admin, before) in states.items():
                    self.assert_only_locked(stdout, path, pinned[branch])
                    self.assertEqual(
                        self.pin_state(repo, path, branch, admin), before
                    )

                statuses = sorted(line[0] for line in self.lines_for(stdout, control))
                prefix = "WOULD-" if dry_run else ""
                expected = {
                    "remove": [f"{prefix}REMOVE"],
                    "prune-ignored": [f"{prefix}PRUNE-IGNORED"],
                    "prune-venvs": [f"{prefix}PRUNE-VENV"],
                    "prune-both": sorted(
                        [f"{prefix}PRUNE-IGNORED", f"{prefix}PRUNE-VENV"]
                    ),
                }[action]
                self.assertEqual(statuses, expected, stdout)
                if not dry_run:
                    if action == "remove":
                        self.assertFalse(control.exists())
                    if action in ("prune-ignored", "prune-both"):
                        self.assertFalse((control / "target").exists())
                    if action in ("prune-venvs", "prune-both"):
                        self.assertFalse((control / ".venv").exists())

    def test_lock_reason_stays_one_field_and_both_readers_agree(self):
        """Invariant 4: awkward reasons, repo mode vs root mode."""
        reasons = [
            "line one\nline two",
            "tab\there",
            "  padded  ",
            "carriage\r\nreturn",
            "unicode ü ✓",
            "100% literal $HOME `x` \\n",
            "",
        ]
        base = self.temp_path / "reasons"
        repo = self.make_repo(base)
        paths = []
        for index, reason in enumerate(reasons):
            paths.append(
                self.add_worktree(
                    repo, base / "worktrees" / f"wt-{index}", f"wt-{index}", reason
                )
            )

        outputs = {
            "repo": self.sweep("--dry-run", repo),
            "root": self.sweep("--dry-run", base / "worktrees"),
        }
        for mode, stdout in outputs.items():
            with self.subTest(mode=mode):
                self.assert_well_formed(stdout)
                for path in paths:
                    raw = (self.admin_dir(path) / "locked").read_bytes()
                    stored = raw.decode("utf-8")  # keep \r, unlike read_text()
                    self.assert_only_locked(stdout, path, stored)
        repo_reasons = [self.lines_for(outputs["repo"], p)[0][-1] for p in paths]
        root_reasons = [self.lines_for(outputs["root"], p)[0][-1] for p in paths]
        self.assertEqual(repo_reasons, root_reasons)

    def test_locked_worktree_with_missing_directory_is_reported_and_kept(self):
        """A lock also protects a worktree whose directory is offline."""
        base = self.temp_path / "offline"
        repo = self.make_repo(base)
        pinned = self.add_worktree(
            repo, base / "worktrees" / "pinned", "pinned", "on the external drive"
        )
        self.add_worktree(repo, base / "worktrees" / "control", "control")
        admin = self.admin_dir(pinned)
        parked = base / "unmounted"
        pinned.rename(parked)

        stdout = self.sweep(*ACTIONS["remove"], repo)

        self.assert_well_formed(stdout)
        self.assert_only_locked(stdout, pinned, "on the external drive")
        # The control's removal triggers `git worktree prune`; the lock must
        # keep the offline worktree's registration.
        self.assertTrue((admin / "locked").exists())
        parked.rename(pinned)
        self.assertEqual((pinned / ENGINE).read_bytes(), b"\x7fELF engine pinned")
        self.assertIn(
            f"worktree {pinned}", self.git("-C", repo, "worktree", "list", "--porcelain")
        )

    def test_repo_mode_handles_worktree_paths_with_spaces(self):
        base = self.temp_path / "spaced"
        repo = self.make_repo(base)
        pinned = self.add_worktree(
            repo, base / "work trees" / "pinned wt", "pinned", PINNED_REASON
        )
        control = self.add_worktree(repo, base / "work trees" / "control wt", "control")

        stdout = self.sweep("--dry-run", repo)

        self.assert_well_formed(stdout)
        self.assert_only_locked(stdout, pinned, PINNED_REASON)
        self.assertEqual(
            [line[0] for line in self.lines_for(stdout, control)], ["WOULD-REMOVE"]
        )

    def test_prune_ignored_keeps_locked_worktree_nested_in_ignored_dir(self):
        """A plain clone swept as a root child must not rm -rf a nested pin."""
        base = self.temp_path / "nested"
        other = self.make_repo(base / "other")
        root = base / "clones"
        clone = root / "clone"
        clone.mkdir(parents=True)
        self.git("init", "-q", "-b", "main", clone)
        (clone / ".gitignore").write_text("cache/\n")
        (clone / "README").write_text("tracked\n")
        self.git("-C", clone, "add", "-A")
        self.git("-C", clone, "commit", "-q", "-m", "init")
        (clone / "cache").mkdir()
        (clone / "cache" / "junk.bin").write_bytes(b"junk")
        nested = self.add_worktree(
            other, clone / "cache" / "pinned", "pinned", PINNED_REASON
        )
        before = snapshot(nested)

        stdout = self.sweep("--prune-ignored", root)

        self.assert_well_formed(stdout)
        self.assertEqual(snapshot(nested), before)
        self.assertTrue((self.admin_dir(nested) / "locked").exists())
        self.assertFalse((clone / "cache" / "junk.bin").exists())


if __name__ == "__main__":
    unittest.main()
