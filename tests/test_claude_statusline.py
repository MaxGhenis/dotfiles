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


def test_installed_via_home_bin_symlink():
    """~/bin/claude-statusline is how ~/.claude/settings.json reaches this script."""
    link = Path.home() / "bin" / "claude-statusline"
    if not link.exists():
        pytest.skip("not installed on this machine")
    if link.is_symlink():
        assert link.resolve() == SCRIPT.resolve()
    else:  # a copy is fine only while it is this exact script
        assert link.read_bytes() == SCRIPT.read_bytes(), "~/bin/claude-statusline is a stale copy"
    settings = Path.home() / ".claude" / "settings.json"
    if not settings.is_file():
        pytest.skip("no ~/.claude/settings.json")
    status_line = json.loads(settings.read_text()).get("statusLine") or {}
    if not status_line:
        pytest.skip("no statusLine configured")
    assert status_line.get("type") == "command"
    assert status_line.get("command") == str(link)
