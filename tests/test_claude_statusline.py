"""claude-statusline renders one line from Claude Code's statusLine payload and
writes nothing.

Its predecessor (subfleet v1's bin/subfleet-statusline) teed rate_limits into a
state dir on every render; subfleet v2 dropped that tap. These tests pin the
rendered line and prove the script has no side effects three ways: a
throwaway HOME/TMPDIR/cwd plus the state-dir env vars the old tap honoured must
be byte-for-byte untouched after every run; an in-process audit hook must see
no write-mode open, mkdir, rename, spawn or socket; and the source must contain
no write primitive at all.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "bin" / "claude-statusline"

SAMPLE = {
    "model": {"display_name": "Opus 5"},
    "rate_limits": {"five_hour": {"used_percentage": 12}, "seven_day": {"used_percentage": 40}},
    "cwd": "/tmp",
}

NON_ASCII = {"model": {"display_name": "Fable ✨ 5.1"}, "cwd": "/tmp/日本語 café"}
NON_ASCII_LINE = "Fable ✨ 5.1 · 日本語 café"


def _stat(p: Path) -> tuple[str, int, int]:
    st = p.lstat()
    return (str(p), st.st_size, st.st_mtime_ns)


def snapshot(tmp_path: Path) -> set[tuple[str, int, int]]:
    """Everything the script could plausibly touch: its sandbox, itself, and
    the bytecode cache next to it."""
    paths = list(tmp_path.rglob("*")) + [SCRIPT]
    cache = SCRIPT.parent / "__pycache__"
    if cache.exists():
        paths += [cache, *cache.rglob("*")]
    return {_stat(p) for p in paths}


def env_for(tmp_path: Path, extra: dict | None = None) -> dict:
    home = tmp_path / "home"
    tmpdir = tmp_path / "tmp"
    home.mkdir(exist_ok=True)
    tmpdir.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "SUBFLEET_STATE_DIR": str(tmp_path / "subfleet-state"),
        "CARPOOL_STATE_DIR": str(tmp_path / "carpool-state"),
        "LANG": "C",  # the worst case for the non-ASCII separator
        "LC_ALL": "C",
        # Apple's /usr/bin/python3 caches stdlib bytecode under $HOME/Library;
        # that is the interpreter, not the script, and must not fail the snapshot.
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env.update(extra or {})
    return env


def run(stdin: bytes | str | dict, tmp_path: Path, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    if isinstance(stdin, dict):
        stdin = json.dumps(stdin)
    if isinstance(stdin, str):
        stdin = stdin.encode()
    env = env_for(tmp_path, extra_env)
    before = snapshot(tmp_path)
    proc = subprocess.run(
        [str(SCRIPT)], input=stdin, capture_output=True, env=env, cwd=env["HOME"], timeout=10
    )
    assert snapshot(tmp_path) == before, "the statusline wrote to disk"
    return proc


def out(proc: subprocess.CompletedProcess) -> str:
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == b"", proc.stderr
    text = proc.stdout.decode("utf-8")
    assert text.endswith("\n") and text.count("\n") == 1, f"not one line: {text!r}"
    return text[:-1]


def test_renders_model_windows_and_dir(tmp_path):
    assert out(run(SAMPLE, tmp_path)) == "Opus 5 · 5h 12% · wk 40% · tmp"


def test_prefers_workspace_current_dir_over_cwd(tmp_path):
    payload = dict(SAMPLE, workspace={"current_dir": "/Users/me/chief-of-staff"})
    assert out(run(payload, tmp_path)) == "Opus 5 · 5h 12% · wk 40% · chief-of-staff"


def test_omits_missing_fields(tmp_path):
    assert out(run({"model": {"display_name": "Fable 5.1"}, "cwd": "/x/repo"}, tmp_path)) == "Fable 5.1 · repo"
    only_week = {
        "model": {"display_name": "Fable 5.1"},
        "rate_limits": {"seven_day": {"used_percentage": 101, "resets_at": 1790103600}},
    }
    assert out(run(only_week, tmp_path)) == "Fable 5.1 · wk 101%"
    assert out(run({}, tmp_path)) == "·"


def test_context_window_is_not_a_rate_limit(tmp_path):
    """The docs' own mock payload: context_window.used_percentage must not show as 5h/wk."""
    payload = {"model": {"display_name": "Opus"}, "workspace": {"current_dir": "/x/project"},
               "context_window": {"used_percentage": 25}}
    assert out(run(payload, tmp_path)) == "Opus · project"


@pytest.mark.parametrize("value, shown", [(12.4, "12"), (12.6, "13"), (0, "0"), (100, "100")])
def test_rounds_percentages(tmp_path, value, shown):
    payload = {"rate_limits": {"five_hour": {"used_percentage": value}}}
    assert out(run(payload, tmp_path)) == f"5h {shown}%"


@pytest.mark.parametrize("value", [True, "12", None, float("nan"), float("inf"), {"pct": 1}, [12]])
def test_ignores_non_numeric_percentages(tmp_path, value):
    payload = {"model": {"display_name": "M"}, "rate_limits": {"five_hour": {"used_percentage": value}}}
    assert out(run(payload, tmp_path)) == "M"


@pytest.mark.parametrize(
    "stdin",
    [b"", b"not json", b"[1, 2]", b"null", b'"str"', b"\xff\xfe\x00",
     b"[" * 100_000, b"[" * 100_000 + b"]" * 100_000, b"{" * 100_000],
)
def test_garbage_stdin_prints_a_dot(tmp_path, stdin):
    assert out(run(stdin, tmp_path)) == "·"


def test_odd_shapes_never_crash(tmp_path):
    payload = {"model": "Opus 5", "rate_limits": [1], "workspace": "x", "cwd": 7}
    assert out(run(payload, tmp_path)) == "·"


def test_root_dir_is_not_blank(tmp_path):
    assert out(run({"cwd": "/"}, tmp_path)) == "/"
    assert out(run({"cwd": "/a/b/"}, tmp_path)) == "b"


@pytest.mark.parametrize(
    "cwd, shown",
    [("/tmp/a\nb", "a b"), ("/tmp/a\rb", "a b"), ("/tmp/a\tb", "a b"),
     ("/tmp/\x1b[31mred\x1b[0m", " [31mred [0m"), ("/tmp/a\x85b", "a b")],
)
def test_control_characters_never_split_or_escape_the_row(tmp_path, cwd, shown):
    assert out(run({"model": {"display_name": "M"}, "cwd": cwd}, tmp_path)) == f"M · {shown}"
    assert out(run({"model": {"display_name": "M\nEVIL"}, "cwd": "/x"}, tmp_path)) == "M EVIL · x"


def test_stdin_bytes_are_decoded_as_json_not_locale(tmp_path):
    payload = json.dumps(NON_ASCII, ensure_ascii=False)
    assert out(run(payload.encode("utf-8"), tmp_path)) == NON_ASCII_LINE
    assert out(run(b"\xef\xbb\xbf" + payload.encode("utf-8"), tmp_path)) == NON_ASCII_LINE
    assert out(run(payload.encode("utf-16"), tmp_path)) == NON_ASCII_LINE


@pytest.mark.parametrize(
    "extra",
    [{"PYTHONIOENCODING": "ascii"}, {"PYTHONUTF8": "0"}, {"PYTHONIOENCODING": "latin-1"},
     {"LC_ALL": "en_US.ISO8859-1", "LANG": "en_US.ISO8859-1"}],
)
def test_output_is_utf8_whatever_the_environment_says(tmp_path, extra):
    assert out(run(NON_ASCII, tmp_path, extra)) == NON_ASCII_LINE


def test_reader_gone_is_silent(tmp_path):
    """Claude Code can close the pipe before the script writes; that must not
    become a non-zero exit with a BrokenPipeError traceback on stderr."""
    env = env_for(tmp_path)
    read_end, write_end = os.pipe()
    proc = subprocess.Popen(
        [str(SCRIPT)], stdin=subprocess.PIPE, stdout=write_end, stderr=subprocess.PIPE,
        env=env, cwd=env["HOME"],
    )
    os.close(write_end)
    os.close(read_end)  # nobody will ever read stdout
    _, err = proc.communicate(json.dumps(SAMPLE).encode(), timeout=10)
    assert proc.returncode == 0, err
    assert err == b"", err


AUDIT_HARNESS = r"""
import json, os, runpy, sys
seen = []
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
MUTATORS = ("os.mkdir", "os.makedirs", "os.rmdir", "os.rename", "os.remove", "os.unlink",
            "os.replace", "os.link", "os.symlink", "os.chmod", "os.chown", "os.truncate",
            "os.utime", "os.system", "os.exec", "os.posix_spawn", "os.fork", "os.spawn",
            "os.kill", "subprocess.", "socket.", "shutil.", "tempfile.")
def hook(name, args):
    if name == "open":
        path, mode, flags = (list(args) + [None, None, None])[:3]
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            mode is None and isinstance(flags, int) and flags & WRITE_FLAGS
        ):
            seen.append([name, str(path), str(mode), flags])
    elif name.startswith(MUTATORS):
        seen.append([name, repr(args)[:200]])
sys.addaudithook(hook)
runpy.run_path(sys.argv[1], run_name="__main__")
sys.stderr.write(json.dumps(seen))
"""


@pytest.mark.parametrize(
    "payload",
    [SAMPLE, NON_ASCII, {}, {"cwd": "/tmp/a\nb"}, {"rate_limits": {"five_hour": {"used_percentage": float("nan")}}}],
)
def test_audit_hook_sees_no_write_mkdir_spawn_or_socket(tmp_path, payload):
    """Run the script in-process under sys.addaudithook: the strongest cheap
    proof that it never opens anything for writing, creates, renames, removes,
    spawns, or connects."""
    env = env_for(tmp_path)
    proc = subprocess.run(
        ["python3", "-c", AUDIT_HARNESS, str(SCRIPT)], input=json.dumps(payload).encode(),
        capture_output=True, env=env, cwd=env["HOME"], timeout=20,
    )
    assert proc.returncode == 0, proc.stderr
    events = json.loads(proc.stderr.decode("utf-8"))
    assert events == [], events
    assert proc.stdout.decode("utf-8").count("\n") == 1


def test_source_has_no_write_primitives():
    """Structural guard: the render-only script must never grow the tap back."""
    tree = ast.parse(SCRIPT.read_text())
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            called.add(func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None))
    forbidden = {
        "open", "makedirs", "mkdir", "replace", "rename", "write", "write_text", "write_bytes",
        "mkstemp", "NamedTemporaryFile", "remove", "unlink", "touch", "system", "popen",
        "fdopen", "link", "symlink", "chmod", "chown", "__import__", "getattr", "exec",
        "eval", "fork", "spawn", "Popen", "connect",
    }
    assert not (called & forbidden), called & forbidden

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported == {"json", "math", "os", "sys"}, imported
    stdlib = getattr(sys, "stdlib_module_names", None)
    if stdlib is not None:
        assert imported <= stdlib, imported - stdlib


def test_one_render_is_fast(tmp_path):
    start = time.perf_counter()
    out(run(SAMPLE, tmp_path))
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"{elapsed:.3f}s for one render"


def git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    """Read-only git in `cwd`. Inherited GIT_* variables are dropped (a hook's
    GIT_DIR would point every call at its own repository), and
    GIT_OPTIONAL_LOCKS=0 keeps git from refreshing a live checkout's index."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True, env=env, timeout=20
    )


def same_path(a: Path | None, b: Path | None) -> bool:
    try:
        return a is not None and b is not None and os.path.samefile(a, b)
    except OSError:
        return False


def toplevel(path: Path) -> Path | None:
    proc = git(path, "rev-parse", "--show-toplevel")
    return Path(proc.stdout.strip()) if proc.returncode == 0 else None


def main_worktree(checkout: Path) -> Path | None:
    """The main worktree of `checkout`'s repository: `git worktree list` names it first."""
    proc = git(checkout, "worktree", "list", "--porcelain", "-z")
    first = proc.stdout.split("\0", 1)[0]
    if proc.returncode or not first.startswith("worktree "):
        return None
    return Path(first.removeprefix("worktree "))


def history_starts(checkout: Path) -> tuple[set[str], bool] | None:
    """The parentless commits in HEAD's history, and whether the clone is
    shallow: a full clone's are its repository's roots, a shallow clone's are
    where its history was cut off. None unless `checkout` is the top of a git
    checkout with a commit."""
    if not same_path(toplevel(checkout), checkout):
        return None
    starts = git(checkout, "rev-list", "--max-parents=0", "HEAD")
    shallow = git(checkout, "rev-parse", "--is-shallow-repository")
    if starts.returncode or shallow.returncode:
        return None
    return set(starts.stdout.split()), shallow.stdout.strip() == "true"


def holds_any(checkout: Path, commits: set[str]) -> bool:
    """Whether HEAD's history in `checkout` contains any of `commits`."""
    return any(git(checkout, "merge-base", "--is-ancestor", c, "HEAD").returncode == 0 for c in commits)


def assert_installed(link: Path, script: Path) -> None:
    """Fail unless `link` runs a maintained claude-statusline, whichever checkout
    of this repository `script` is in.

    A copy must be byte-for-byte `script`. A symlink must resolve to an executable
    bin/claude-statusline, tracked at the top of the main worktree of a clone of
    this repository: the deployed checkout (~/dotfiles on Max's Mac). That need
    not be `script`'s own checkout, since the suite also runs from linked
    worktrees and other clones. A linked worktree is never the deploy: sweeps
    remove them, and the link would dangle.
    """
    target = link.resolve()
    assert target.exists(), f"{link} dangles: {target} does not exist"
    assert target.is_file(), f"{link} resolves to {target}, which is not a file"
    assert os.access(target, os.X_OK), f"{target} is not executable, and Claude Code runs it directly"
    if not link.is_symlink():
        assert link.read_bytes() == script.read_bytes(), f"{link} is a stale copy of {script}"
        return

    checkout = target.parent.parent
    assert (target.parent.name, target.name) == ("bin", "claude-statusline"), (
        f"{link} resolves to {target}, not to a bin/claude-statusline"
    )
    assert same_path(toplevel(checkout), checkout), (
        f"{target} is not bin/claude-statusline at the top of a git checkout"
    )
    main = main_worktree(checkout)
    assert same_path(main, checkout), (
        f"{checkout} is not its repository's main worktree ({main}): sweeps remove "
        f"linked worktrees, so point {link} at the main worktree's bin/claude-statusline"
    )
    tracked = git(checkout, "ls-files", "--error-unmatch", "--", "bin/claude-statusline")
    assert tracked.returncode == 0, f"{target} is not tracked in {checkout}"

    # Same repository: one checkout's history holds a commit the other's starts
    # from. Two full clones that share nothing are different repositories; a
    # shallow history can hide the shared part, so then there is no verdict.
    under_test = script.parent.parent
    ours = history_starts(under_test)
    if ours is None:
        pytest.skip(f"{under_test} is not a git checkout with commits, so {checkout} can't be compared with it")
    theirs = history_starts(checkout)
    assert theirs is not None, f"{checkout} has no commits"
    if holds_any(checkout, ours[0]) or holds_any(under_test, theirs[0]):
        return
    if ours[1] or theirs[1]:
        pytest.skip(f"shallow history: no way to tell whether {checkout} and {under_test} share a repository")
    raise AssertionError(f"{checkout} is not a clone of this repository: no history in common with {under_test}")


def test_installed_via_home_bin_symlink():
    """~/bin/claude-statusline is how ~/.claude/settings.json reaches this script.
    It points at the deployed checkout, not at whichever checkout runs the suite."""
    link = Path.home() / "bin" / "claude-statusline"
    if not (link.is_symlink() or link.exists()):
        pytest.skip("not installed on this machine")
    assert_installed(link, SCRIPT)


def test_settings_run_the_home_bin_link():
    link = Path.home() / "bin" / "claude-statusline"
    if not (link.is_symlink() or link.exists()):
        pytest.skip("not installed on this machine")
    settings = Path.home() / ".claude" / "settings.json"
    if not settings.is_file():
        pytest.skip("no ~/.claude/settings.json")
    status_line = json.loads(settings.read_text()).get("statusLine") or {}
    if not status_line:
        pytest.skip("no statusLine configured")
    assert status_line.get("type") == "command"
    assert status_line.get("command") == str(link)


def build_git(cwd: Path, *args: str) -> None:
    """git for building fixture repositories, blind to the user's and system config."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "init.defaultBranch=main", *args],
        check=True, capture_output=True, env=env, timeout=30,
    )


@pytest.fixture(scope="module")
def checkouts(tmp_path_factory) -> Path:
    """One small repository checked out every way a machine might hold it, plus
    look-alikes that are not a deploy of it."""
    root = tmp_path_factory.mktemp("checkouts")

    def add_script(at: Path) -> None:
        at.parent.mkdir(parents=True, exist_ok=True)
        at.write_text("#!/bin/sh\necho statusline\n")
        at.chmod(0o755)

    upstream = root / "upstream"
    build_git(root, "init", "-q", "upstream")
    for rel in ("bin/claude-statusline", "bin/subfleet-statusline", "sub/bin/claude-statusline"):
        add_script(upstream / rel)
    build_git(upstream, "add", "-A")
    build_git(upstream, "commit", "-qm", "root")
    build_git(root, "clone", "-q", str(upstream), "early")  # a full clone from before the second commit
    (upstream / "README").write_text("second commit, so a depth-1 clone is shallow\n")
    build_git(upstream, "add", "-A")
    build_git(upstream, "commit", "-qm", "second")

    for name in ("deploy", "clone", "untracked", "noexec"):
        build_git(root, "clone", "-q", str(upstream), name)
    build_git(root, "clone", "-q", "--depth", "1", upstream.as_uri(), "shallow")
    build_git(root / "deploy", "worktree", "add", "-q", str(root / "wt"))
    build_git(root / "untracked", "rm", "-q", "--cached", "bin/claude-statusline")
    build_git(root / "untracked", "commit", "-qm", "stop tracking the script, keep the file")
    (root / "noexec" / "bin" / "claude-statusline").chmod(0o644)

    build_git(root, "init", "-q", "other")
    add_script(root / "other" / "bin" / "claude-statusline")
    build_git(root / "other", "add", "-A")
    build_git(root / "other", "commit", "-qm", "unrelated history")
    add_script(root / "plain" / "bin" / "claude-statusline")
    add_script(root / "other" / "vendored" / "bin" / "claude-statusline")  # untracked, inside "other"
    (root / "alias").symlink_to(root / "deploy", target_is_directory=True)
    return root


def outcome(check, *args) -> tuple[str, str]:
    """How `check` ended: pass, fail or skip, with its message. pytest.skip
    raises a BaseException that pytest.raises(AssertionError) lets through, so
    a check that wrongly skips would skip its test instead of failing it."""
    try:
        check(*args)
    except AssertionError as e:
        return "fail", str(e)
    except pytest.skip.Exception as e:
        return "skip", str(e)
    return "pass", ""


DEPLOYED = "deploy/bin/claude-statusline"

# (checkout under test, how ~/bin/claude-statusline is made, what it points at or copies,
#  expected outcome, the reason the check must give)
INSTALL_CASES = {
    "run-from-the-deploy": ("deploy", "link", DEPLOYED, "pass", ""),
    "run-from-a-linked-worktree": ("wt", "link", DEPLOYED, "pass", ""),
    "run-from-another-clone": ("clone", "link", DEPLOYED, "pass", ""),
    "relative-link": ("wt", "relative", DEPLOYED, "pass", ""),
    "chain-of-links": ("wt", "chain", DEPLOYED, "pass", ""),
    "through-a-directory-alias": ("wt", "link", "alias/bin/claude-statusline", "pass", ""),
    "exact-copy": ("wt", "copy", "wt/bin/claude-statusline", "pass", ""),
    "dangling": ("wt", "link", "gone/bin/claude-statusline", "fail", "dangles"),
    "into-a-linked-worktree": ("wt", "link", "wt/bin/claude-statusline", "fail", "not its repository's main worktree"),
    "into-a-linked-worktree-from-the-deploy": ("deploy", "link", "wt/bin/claude-statusline", "fail", "not its repository's main worktree"),
    "outside-any-checkout": ("wt", "link", "plain/bin/claude-statusline", "fail", "top of a git checkout"),
    "below-the-top-of-the-checkout": ("wt", "link", "deploy/sub/bin/claude-statusline", "fail", "top of a git checkout"),
    "another-script": ("wt", "link", "deploy/bin/subfleet-statusline", "fail", "not to a bin/claude-statusline"),
    "a-directory": ("wt", "link", "deploy/bin", "fail", "which is not a file"),
    "untracked-file": ("wt", "link", "untracked/bin/claude-statusline", "fail", "is not tracked in"),
    "not-executable": ("wt", "link", "noexec/bin/claude-statusline", "fail", "is not executable"),
    "another-repository": ("wt", "link", "other/bin/claude-statusline", "fail", "not a clone of this repository"),
    "stale-copy": ("wt", "stale-copy", "wt/bin/claude-statusline", "fail", "is a stale copy"),
    "non-executable-copy": ("wt", "noexec-copy", "wt/bin/claude-statusline", "fail", "is not executable"),
    "shallow-deploy": ("wt", "link", "shallow/bin/claude-statusline", "pass", ""),
    "run-from-a-shallow-clone": ("shallow", "link", DEPLOYED, "pass", ""),
    "shallow-deploy-ahead-of-the-checkout": ("early", "link", "shallow/bin/claude-statusline", "skip", "shallow history"),
    "run-from-a-shallow-clone-ahead-of-the-deploy": ("shallow", "link", "early/bin/claude-statusline", "skip", "shallow history"),
    "run-from-outside-git": ("plain", "link", DEPLOYED, "skip", "not a git checkout with commits"),
    "run-from-a-copy-inside-another-repository": ("other/vendored", "link", DEPLOYED, "skip", "not a git checkout with commits"),
}


@pytest.mark.parametrize(
    "under_test, kind, target, expected, reason", INSTALL_CASES.values(), ids=INSTALL_CASES.keys()
)
def test_install_check_follows_the_deploy_not_the_checkout(
    checkouts, tmp_path, under_test, kind, target, expected, reason
):
    """assert_installed accepts the deploy from any checkout and rejects every
    other place the link could land, each for its own reason."""
    source = checkouts / target
    link = tmp_path / "bin" / "claude-statusline"
    link.parent.mkdir()
    if kind == "link":
        link.symlink_to(source)
    elif kind == "relative":
        link.symlink_to(os.path.relpath(source, link.parent))
    elif kind == "chain":
        (tmp_path / "hop").symlink_to(source)
        link.symlink_to(tmp_path / "hop")
    else:
        shutil.copy2(source, link)
        if kind == "stale-copy":
            link.write_bytes(link.read_bytes() + b"# edited\n")
        elif kind == "noexec-copy":
            link.chmod(0o644)
    script = checkouts / under_test / "bin" / "claude-statusline"

    ended, message = outcome(assert_installed, link, script)
    assert (ended, reason in message) == (expected, True), f"{ended}: {message}"


def test_a_dangling_home_link_fails_instead_of_skipping(tmp_path, monkeypatch):
    """A dangling ~/bin/claude-statusline is a broken status line, not an absent one."""
    monkeypatch.setenv("HOME", str(tmp_path))
    link = tmp_path / "bin" / "claude-statusline"
    link.parent.mkdir()
    link.symlink_to(tmp_path / "gone")
    ended, message = outcome(test_installed_via_home_bin_symlink)
    assert (ended, "dangles" in message) == ("fail", True), f"{ended}: {message}"
    link.unlink()
    assert outcome(test_installed_via_home_bin_symlink) == ("skip", "not installed on this machine")


def test_install_check_ignores_inherited_git_variables(checkouts, tmp_path, monkeypatch):
    """Git hooks run with GIT_DIR and GIT_WORK_TREE set; they must not redirect
    the check to another repository."""
    monkeypatch.setenv("GIT_DIR", str(checkouts / "other" / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(checkouts / "other"))
    link = tmp_path / "claude-statusline"
    link.symlink_to(checkouts / DEPLOYED)
    assert outcome(assert_installed, link, checkouts / "wt" / "bin" / "claude-statusline") == ("pass", "")
