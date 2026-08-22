"""Tests for the codex-run never-rules guard (unscoped-search side).

Covers bin/codex-guard-hook (the Codex PreToolUse hook), bin/codex-guard
(override / hash / key / check / preflight helper) and the guard block in
bin/codex-run. The unscoped-search rule, the trust identity, and the
codex-run/preflight wiring live here; the seven ported NEVER-rule blocks and
the hf-dest adapter are covered by tests/test_codex_guard_never_rules.py.
Runs under pytest and plain unittest (python 3.9+; the tomllib assertions are
skipped where tomllib is unavailable).

    /opt/homebrew/bin/pytest -q ~/dotfiles/tests
    python3 -m unittest discover -s ~/dotfiles/tests -p 'test_codex_guard.py'

Candidate copies of the two hooks can be tested before installing them:

    CLAUDE_GUARD_HOOK=/path/to/guard-never-rules.sh \
    CODEX_GUARD_HOOK=/path/to/codex-guard-hook \
    /opt/homebrew/bin/pytest -q ~/dotfiles/tests

(only `codex-guard check` and the hook-decision tests follow CODEX_GUARD_HOOK;
the hash/override/preflight tests are about the armed path and ignore it).

The unscoped-search rule is ONE shared region, byte-identical in both hooks;
DriftTests pins the region text and the decisions (see that class). Until the
guard-portback ~/.claude install lands, the Claude hook still carries the OLD
unscoped-search rule, so the Claude-side pins are skip-gated on
CLAUDE_PORTBACK_LANDED and lift automatically at install time. The decision
corpus below is module-level so HookDecisionTests and the parity test judge
the same commands; the sibling's 510-case guard-never-rules-test.sh carries
the same cases for the Claude side.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import unittest

try:
    import tomllib
except ImportError:  # python < 3.11
    tomllib = None


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN = REPO_ROOT / "bin"
# ARMED_HOOK: the path codex-run arms (override/hash/key/preflight tests);
# HOOK: the hook whose decisions are tested (a candidate when CODEX_GUARD_HOOK
# is set, otherwise the armed hook).
ARMED_HOOK = BIN / "codex-guard-hook"
HOOK = Path(os.environ.get("CODEX_GUARD_HOOK") or ARMED_HOOK)
HOOK_OVERRIDDEN = bool(os.environ.get("CODEX_GUARD_HOOK"))
GUARD = BIN / "codex-guard"
CODEX_RUN = BIN / "codex-run"
CLAUDE_HOOK = Path(
    os.environ.get("CLAUDE_GUARD_HOOK")
    or (Path.home() / ".claude" / "hooks" / "guard-never-rules.sh")
)
HOME = os.environ.get("HOME") or str(Path.home())
# The Claude-side test expands $HOME into the command; the broad-root regex
# only knows /Users/<user>, so pin a /Users home for that one case elsewhere.
USERS_HOME = HOME if HOME.startswith("/Users/") else "/Users/maxghenis"
KEY = "/<session-flags>/config.toml:pre_tool_use:0:0"
PINNED_HOOK_PATH = "/Users/maxghenis/dotfiles/bin/codex-guard-hook"
# OLD identity (matcher "Bash", statusMessage "unscoped-search guard",
# timeout 30): verified against a live codex 0.144.0 (`codex app-server` ->
# hooks/list) before the 2026-08-19 never-rules port; reproduced via the
# --matcher/--status flags. Independent of the installed codex.
PINNED_HASH = "sha256:b4dc07a4331d682563fb8de2c191549030f295366ac9481001583d5e9083fbb6"
# NEW identity (matcher "Bash|apply_patch", statusMessage "never-rules guard",
# timeout 30, pinned path): LIVE-VERIFIED 2026-08-19 via codex app-server
# hooks/list (trustStatus trusted) on codex-cli 0.144.0.
PINNED_HASH_V2 = "sha256:f902bedc6db14f83c8d2f7506fb6d9e86aac40d645a831ae718cc70d9e75f004"
STATUS_MESSAGE = "never-rules guard"
MATCHER = "Bash|apply_patch"
SUBPROCESS_TIMEOUT = 60


def shell_quote(path):
    """Mirror of codex-guard's shell_quote: Codex runs hook commands through a
    shell (`<local shell> -c`, or `$SHELL -lc` when none is known), so paths
    outside [[:alnum:]@%+=:,./_-] are single-quoted."""
    if path and re.fullmatch(r"[A-Za-z0-9@%+=:,./_-]+", path, re.ASCII):
        return path
    return "'" + path.replace("'", "'\\''") + "'"


def python_trust_hash(hook_path, timeout=60, matcher=MATCHER, status=STATUS_MESSAGE):
    """Reimplementation of Codex's fingerprint: sha256 over compact JSON with
    recursively sorted keys of the normalized hook identity."""
    identity = {
        "event_name": "pre_tool_use",
        "matcher": matcher,
        "hooks": [
            {
                "type": "command",
                "command": shell_quote(hook_path),
                "timeout": timeout,
                "async": False,
                "statusMessage": status,
            }
        ],
    }
    canonical = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def run(argv, env=None, cwd=None, stdin=None, timeout=SUBPROCESS_TIMEOUT):
    return subprocess.run(
        [str(a) for a in argv],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        cwd=cwd,
        check=False,
    )


# ---------------------------------------------------------------------------
# Decision corpus. Shared by HookDecisionTests (the codex hook) and
# DriftTests.test_decisions_match_claude_hook (both hooks, same payloads).
# Each entry is (command, cwd); cwd PLAIN means a per-test temp dir that is not
# a broad root. ~/.claude/tests/guard-never-rules-test.sh carries the same
# cases; extend both when the rule changes.
# ---------------------------------------------------------------------------
PLAIN = None

DENY_CASES = (
    # --- cases copied literally from ~/.claude/tests/guard-never-rules-test.sh
    # (the original unscoped-search block cases); "plain" cwd = temp dir ---
    ('find /Users/maxghenis/TheAxiomFoundation -path "*/target/release/axiom-rules-engine" -type f', PLAIN),
    ("find %s -path '*/site-packages/receipt/sign.py'" % USERS_HOME, PLAIN),
    ("find ~/TheAxiomFoundation -name x", PLAIN),
    ('find ~/RulesFoundation -name "*.rac"', PLAIN),
    ("find /private/tmp /tmp /Users/maxghenis/TheAxiomFoundation -type f -name y", PLAIN),
    ("rg --files /Users/maxghenis/TheAxiomFoundation /private/tmp", PLAIN),
    ('rg -l "13 passed" /tmp /private/tmp', PLAIN),
    ("grep -rn pattern ~/PolicyEngine", PLAIN),
    ('find ~/Library/Caches ~/.cache -name "receipt*.whl"', PLAIN),
    ('find . -path "*/.github/workflows/signed-apply.yml"', HOME + "/TheAxiomFoundation"),
    # --- 2026-08-18 incident commands (e8 sol batch, codex lanes) ---
    ("find / -type f \\( -iname '*a2*secondpass*' -o -iname '*1501-1800*' \\)", PLAIN),
    ("find /Users/maxghenis -iname '*a2*1501*1800*.md'", PLAIN),
    ('rg -l --hidden --no-ignore -S "1501-1800" /Users/maxghenis/PolicyEngine', PLAIN),
    ("find /Users -name '*.md'", PLAIN),
    ("find / -name x", PLAIN),
    ("rg --files /private/tmp | rg 'a2|secondpass|1801|2100' | sed -n '1,240p'", PLAIN),
    ("pwd && rg --files -g 'sol-ce-a2-rubric-note-composite-zero.md' -g '!**/.git/**' "
     "/Users/maxghenis/PolicyEngine/social-security-model-worktrees /Users/maxghenis/PolicyEngine 2>/dev/null", PLAIN),
    ("find /Users/maxghenis/PolicyEngine /Users/maxghenis/.claude-worktrees /private/tmp -type f "
     "\\( -name 'a.md' -o -name 'b.md' \\) -print 2>/dev/null", PLAIN),
    ("rg -l --hidden --no-messages --glob '!Library/**' --glob '!**/.git/**' "
     "'sol-ce-a2-repass-1801-2100-report|9b9edac5' /Users/maxghenis /tmp 2>/dev/null | head -500", PLAIN),
    ("rg --files /Users/maxghenis/PolicyEngine 2>/dev/null | rg '/sol-ce-a2-rubric-note-composite-zero\\.md$'", PLAIN),
    # --- every root spelling, quote- and position-aware (2026-08-19 rounds 3-5) ---
    ('find "/" -name x', PLAIN), ("find '/' -name x", PLAIN), ("sudo find / -name x", PLAIN),
    ("find -L / -name x", PLAIN), ("find -- / -name x", PLAIN), ("FOO=1 find / -name x", PLAIN),
    ("find /* -name x", PLAIN), ("find '/Users' -name x", PLAIN),
    ("find /Users/ -name x", PLAIN), ('find "/Users/" -name x', PLAIN), ("find /Users", PLAIN), ("find /Users;", PLAIN),
    ("find /etc / -name x", PLAIN), ("find /Users/maxghenis/x / -name y", PLAIN),
    ('find / -name "x', PLAIN),  # unbalanced quote
    ("rg pat /", PLAIN), ("rg 'pat' /", PLAIN), ('rg "pat" /Users', PLAIN), ("rg -n 'pat' -g '*.md' /Users/", PLAIN),
    ("rg pat /|head", PLAIN), ("rg pat / 2>/dev/null", PLAIN), ("rg x /*", PLAIN), ("rg -A 3 pat /", PLAIN),
    ("rg -e a -e b /", PLAIN), ("rg -f pats.txt /", PLAIN), ("rg --files /", PLAIN), ("rg -uu --files / | head", PLAIN),
    ("rg --files -g '*.md' /Users", PLAIN), ("rg --files-with-matches pat /", PLAIN),
    ("rg -g '*.py' pat /", PLAIN), ("rg --type py pat /", PLAIN), ("rg 'it'\"'\"'s' /", PLAIN), ("rg \"a \\\" b\" /", PLAIN),
    ("grep -r foo /", PLAIN), ("grep -E -r foo /Users", PLAIN), ("grep -rn -A 2 pat /", PLAIN),
    ("grep -r --include='*.py' foo /", PLAIN), ("grep -rl -F -- x /", PLAIN),
    ("cd / && find . -name x", PLAIN), ("cd / && rg pat .", PLAIN), ('cd "/Users" && rg pat .', PLAIN),
    ("cd /Users; find . -name x", PLAIN), ("(cd /Users && rg pat .)", PLAIN), ("pushd / && rg pat .", PLAIN),
    # cd right after an opening quote / after cd options, -e/-f roots before the
    # option, a downstream rg with a root path
    ('bash -c "cd / && find . -name x"', PLAIN), ("sh -c 'cd /; find . -name y'", PLAIN), ("cd -- / && find . -name x", PLAIN),
    ("cd -P / && rg pat .", PLAIN), ('eval "cd / && find . -name x"', PLAIN), ("rg / -e pat", PLAIN), ('rg -n "/Users/" . -e foo', PLAIN),
    ("find src -name x; rg pat /", PLAIN), ("find . -name x | rg pat /Users", PLAIN), ("rg -T py pat /", PLAIN), ("grep -r --color foo /", PLAIN),
    # trailing-slash / ${HOME} spellings of the Claude roots
    ("find ~/ -name x", PLAIN), ("find /Users/maxghenis/ -type d", PLAIN), ("find ~/PolicyEngine/ -name '*.py'", PLAIN),
    ("find $HOME/ -name x", PLAIN), ("find ${HOME} -name x", PLAIN), ("find ${HOME}/ -name x", PLAIN), ('find "/Users/maxghenis/" -name x', PLAIN),
    ("rg foo /tmp/", PLAIN), ("rg pat ~/TheAxiomFoundation/", PLAIN), ("grep -rn foo /private/tmp/", PLAIN), ("cd ~/ && find . -name x", PLAIN),
    ("rg -M 100 pat /", PLAIN), ("grep -r -E foo /", PLAIN),
    ('bash -c "cd x && find / -name x"', PLAIN), ('timeout 30 bash -c "nice find / -name x"', PLAIN),
    ('sh -c "cd /opt && rg pat /"', PLAIN), ("echo / | xargs rg pat", PLAIN), ("ls / | xargs -I{} rg pat {}", PLAIN),
    # `${HOME}` children, quote-then-slash, and quoted roots in rg/grep PATH
    # position (a quoted string whose whole content is a root is unquoted
    # before the position rules run)
    ('find "$HOME"/ -name x', PLAIN), ('find "${HOME}"/ -name x', PLAIN), ("find ${HOME}/PolicyEngine -name x", PLAIN),
    ("find ${HOME}/TheAxiomFoundation/ -name x", PLAIN), ("rg pat ${HOME}/PolicyEngine", PLAIN), ("grep -rn foo ${HOME}/.cache", PLAIN),
    ('find "$HOME"/PolicyEngine -name x', PLAIN), ("cd ${HOME}/PolicyEngine && rg pat .", PLAIN),
    ('rg pat "$HOME/"', PLAIN), ('rg pat "$HOME/PolicyEngine/"', PLAIN), ('grep -rn foo "$HOME/.cache/"', PLAIN),
    ('grep -rn foo "$HOME/Library/Caches/"', PLAIN), ('rg --files "/Users/maxghenis/"', PLAIN), ('rg pat "/tmp/"', PLAIN),
    ('rg pat "/private/tmp/"', PLAIN), ('rg pat "${HOME}"', PLAIN), ('rg pat "${HOME}/"', PLAIN), ('rg pat "/"', PLAIN), ('rg --files "/"', PLAIN),
    ("grep -r foo '/Users'", PLAIN), ('rg -n "it\'s" "/"', PLAIN), ("rg 'a|b' \"/\"", PLAIN), ('rg -n "/Users/" "$HOME/"', PLAIN),
    ('find /Users/"maxghenis" -name x', PLAIN), ("find . -name \"a|b\" '/'", PLAIN),
    # ... with -e/-f/--files (every positional is a path): a quoted root
    # after the option counts, the option's own value never does
    ('rg -e pat "/"', PLAIN), ('rg -e pat "$HOME/"', PLAIN), ("rg -e '/' \"$HOME/\"", PLAIN), ('rg -e a -e b "/Users/maxghenis/"', PLAIN),
    ('rg --files "$HOME/"', PLAIN), ('rg -f pats "/tmp/"', PLAIN), ('rg --files -g "*.md" "/Users"', PLAIN), ('grep -r --include="*.py" foo "/"', PLAIN),
    # nested quotes inside a visible `bash -c "..."` script
    ("bash -c \"cd x && find '/' -name y\"", PLAIN), ("bash -c \"cd x && rg pat '/'\"", PLAIN),
    # the rules are cumulative — a crawl that pipes into `xargs rg` is still
    # judged by the find/rg rules
    ('find "/" -name x | xargs rg pat', PLAIN), ('find "$HOME/" -name "*.md" | xargs rg pat', PLAIN),
    ("find '/tmp/' | xargs rg x", PLAIN), ('find "/Users/maxghenis/" -type f | xargs rg pat', PLAIN),
    ('rg -l pat "$HOME/" | xargs rg pat2', PLAIN), ("find / -name x | xargs rg pat", PLAIN),
    # --- Claude roots in every position the old anywhere-in-the-text regex
    # caught (the 2026-08-19 port-back must keep every one of these) ---
    ("find ~ -name x", PLAIN), ("find ~ -name x 2>/dev/null | head", PLAIN), ("rg pat ~", PLAIN), ("rg pat ~ | head", PLAIN),
    ("rg pat ~|head", PLAIN), ("rg -uu pat ~", PLAIN), ("grep -R pat ~", PLAIN), ('grep -rin pat "$HOME"', PLAIN),
    ('rg pat "${HOME}/PolicyEngine"', PLAIN), ('find "${HOME}" -name x', PLAIN), ("rg --files-with-matches pat ~/TheAxiomFoundation", PLAIN),
    ("rg pat ~/TheAxiomFoundation ~/PolicyEngine", PLAIN), ("rg -n pat -- ~/PolicyEngine", PLAIN), ("rg pat ~/PolicyEngine -g '*.py'", PLAIN),
    ("rg pat -g '*.py' ~/PolicyEngine", PLAIN), ("rg pat ~/PolicyEngine/", PLAIN), ("grep -rn pat ~/ 2>/dev/null", PLAIN),
    ("rg --files ~ | head", PLAIN), ("find ~/.cache ~/.local -name x", PLAIN), ("rg pat /private/tmp/", PLAIN), ("find /tmp/ -mmin -10", PLAIN),
    ("time find / -name x", PLAIN), ("nice -n 19 find ~ -name x", PLAIN), ("command find ~ -name x", PLAIN), ("env FOO=1 find ~ -name x", PLAIN),
    ("builtin cd ~ && find . -name x", PLAIN), ('find "$HOME/PolicyEngine" -name x', PLAIN), ("find $HOME/TheAxiomFoundation/ -type d", PLAIN),
    ("rg pat $HOME/PolicyEngine/", PLAIN), ("rg -e pat ~", PLAIN), ("rg ~ ~/PolicyEngine", PLAIN), ("rg pat ~ -e foo", PLAIN),
    ("rg -A3 pat ~", PLAIN), ("rg -tpy pat ~", PLAIN), ("rg -g '!*.md' pat ~", PLAIN), ("rg pat ~ --json", PLAIN), ("rg pat ~ < /dev/null", PLAIN),
    ("find ~ \\( -name x -o -name y \\)", PLAIN), ("find src -exec grep -rn pat ~ \\;", PLAIN), ("find ~ -name '*.py' -exec grep -l pat {} +", PLAIN),
    ("find . -exec rg pat ~ \\;", PLAIN), ("cd ~/PolicyEngine; rg pat .", PLAIN), ("pushd ~/TheAxiomFoundation >/dev/null && rg pat .", PLAIN),
    ('bash -c "cd ~ && find . -name x"', PLAIN), ("bash -c \"cd '/Users' && find . -name x\"", PLAIN),
    ('echo "find ~ -name x" > run.sh; find / -name y', PLAIN), ('find "/Users/maxghenis"/PolicyEngine -name x', PLAIN),
    ("xargs -0 rg pat ~ < list", PLAIN), ("ls | xargs rg pat ~", PLAIN), ("git ls-files | xargs rg pat ~/PolicyEngine", PLAIN),
    # --- backslash-newline continuations are joined before judging (2026-08-19) ---
    ("find \\\n~ -name x", PLAIN), ("rg pat \\\n/tmp", PLAIN), ("find /Users/maxghenis \\\n-name x", PLAIN),
    ("rg -l pat \\\n  -g '*.py' \\\n  ~/PolicyEngine", PLAIN),
    ("echo foo\\\\\nrg pat ~", PLAIN),  # an escaped backslash at EOL is not a continuation; the crawl on the next line still counts
    ("cd ~\nrg pat .", PLAIN), ("rg pat src\nfind ~ -name x", PLAIN),
    # Old-rule literals that are still executable search roots after shell
    # indirection: these are not any of the three intended FP classes.
    ('bash -c "cd "$HOME" && find . -name x"', PLAIN),
    ('bash -c "cd "/tmp" && find . -name x"', PLAIN),
    ('sh -lc \'cd \'"$HOME"\' && find . -name x\'', PLAIN),
    ('for d in /Users/; do find "$d" -name x; done', PLAIN),
    ('for d in /Users/maxghenis; do find "$d" -name x; done', PLAIN),
    ('echo "$HOME" | xargs rg pat', PLAIN),
    ('echo "/tmp" | xargs rg pat', PLAIN),
    ('bash -c \'echo \'"$HOME"\' | xargs rg pat\'', PLAIN),
)

# Commands the rule must ALLOW.
ALLOW_CASES = (
    # --- cases copied literally from the Claude harness ---
    ("find ~/TheAxiomFoundation -maxdepth 2 -type d -name releases", PLAIN),
    ("find ~/TheAxiomFoundation/axiom-corpus/releases -name manifest.json", PLAIN),
    ("rg -n TODO ~/TheAxiomFoundation/axiom-claude", PLAIN),
    ("rg --max-depth 2 -l pat /tmp", PLAIN),
    ('find . -name "*.rac"', PLAIN),
    ("grep pattern /tmp/build.log", PLAIN),
    ('find src -name "*.py"', PLAIN),
    ("grep -rn pattern ~/PolicyEngine/populace/src", PLAIN),
    # --- 2026-08-18 incident neighbours ---
    ("find /Users/maxghenis -maxdepth 4 -type d -name e8-ops", PLAIN),
    ("find /etc -name hosts", PLAIN),
    ("find /Users/maxghenis/PolicyEngine/social-security-model-worktrees/e19-repin -name '*.py'", PLAIN),
    ("rg foo /Users/maxghenis/m6-sol-lanes/e8-ops", PLAIN),
    ("git ls-files | grep secondpass", PLAIN),
    ("ls -la /", PLAIN),
    # --- a root token inside a PATTERN is not a root (three correctly scoped
    # rg calls with a ` / ` inside the pattern were denied on 2026-08-19) ---
    ("rg -n '`997 / Never`|\\[\"997\",\"Never\"\\]|already stopped' "
     "/Users/maxghenis/m6-sol-lanes/e8-ops/sol-ce-a2-x.md | head -300", PLAIN),
    ("rg -n -g 'sol-ce-a2-*report.md' '`997 / Never`|x' /Users/maxghenis/m6-sol-lanes/e8-ops", PLAIN),
    ('rg "income / 12" src', PLAIN), ('grep -rn " / " src/', PLAIN), ('rg -e "/ " src', PLAIN),
    ('rg -n "/Users" .', PLAIN), ('rg -n "/Users/" .', PLAIN), ("grep -rn '/' src", PLAIN), ("rg '/*' src", PLAIN),
    # Unquoted, in pattern position (first non-option token of rg/grep).
    ("rg /Users src", PLAIN), ("rg / src", PLAIN), ("rg -t py / src", PLAIN), ("rg -g '*.py' /Users src", PLAIN),
    ("grep -r -A 2 / src", PLAIN), ("rg --regexp=/ src", PLAIN),
    # A broad root belonging to another command of the pipeline (rg reads stdin).
    ("echo / | rg x", PLAIN), ("ls / && rg x .", PLAIN), ("rg x . && ls /", PLAIN),
    ("rg pat . | sort | uniq -c | sort -rn | head; ls /", PLAIN),
    # --- codex-roots neighbours ---
    ("find /etc /var -name x", PLAIN), ("find /Volumes -name x", PLAIN), ("find /Users/maxghenis/Desktop -name x", PLAIN),
    ("find /Users/maxghenis/x -name '/ '", PLAIN), ("rg pat /Users/maxghenis/PolicyEngine/populace/src", PLAIN),
    ("rg -n TODO -- src", PLAIN), ("rg -e '/' src", PLAIN), ("rg --files src", PLAIN), ("grep -n foo /", PLAIN),
    ("cd /opt && rg pat .", PLAIN), ("cd / && find . -maxdepth 2 -name x", PLAIN),
    ("rg \\/ src", PLAIN), ("git ls-files | xargs rg pat", PLAIN), ("git ls-files | xargs grep -rn pat", PLAIN),
    # a bare / belonging to ANOTHER command of the pipeline
    ("ls / && find . -name x", PLAIN), ("find src -name '*.py' | sed 's/\\.py$//' | tr / .", PLAIN),
    ("find . -type f | cut -d / -f2 | sort -u", PLAIN), ("find . -name '*.md' | awk -F / '{print $2}'", PLAIN),
    ("rg --files src | tr / .", PLAIN), ("rg -l pat src | xargs -n1 dirname | tr / .", PLAIN),
    ("stat -f %m / ; rg pat src", PLAIN), ("ls -f / | rg x", PLAIN), ('find . -name x | tr "/" .', PLAIN),
    # value-taking rg options whose value is not the pattern
    # (-r is deliberately NOT value-taking: `grep -r foo /` must stay a crawl,
    # so `rg -r REPL / src` is an accepted false positive; -E likewise.)
    ("rg -M 100 / src", PLAIN), ("rg -j 4 / src", PLAIN), ("rg --sort path / src", PLAIN),
    ("rg --max-columns 80 / src", PLAIN), ("rg -d 3 / src", PLAIN), ("rg --replace REPL / src", PLAIN),
    # a root-shaped PATTERN of a downstream / -exec grep, prose that merely
    # mentions a searcher, a `/` after `;`
    ("find . -type f | grep -c /", PLAIN), ("find . -type f | grep -c '/'", PLAIN), ("find . -name '*.py' | grep -v '/Users'", PLAIN),
    ("rg --files src | grep -v /", PLAIN), ("rg --files src | rg /", PLAIN), ("rg -e pat src | grep -c /", PLAIN),
    ('find . -name "*.py" -exec grep -l "/" {} +', PLAIN), ('find . -name "*.py" -exec grep -ln "/Users/" {} +', PLAIN),
    ('git commit -m "Add find / replace dialog"', PLAIN), ('echo "run: find / -name x" >> notes.md', PLAIN),
    ("rg pat; ls /", PLAIN), ("rg pat&& ls /", PLAIN),
    # trailing slash on a NON-broad subdirectory
    ("find /Users/maxghenis/PolicyEngine/populace/ -name x", PLAIN), ("rg pat ~/PolicyEngine/populace/", PLAIN),
    # quoted roots in PATTERN position, or as the value of
    # -e/-f/--regexp/--file, stay patterns; quoted non-broad paths and
    # quote-then-slash subdirectories pass
    ('rg -n "/" src', PLAIN), ('rg "/Users" src', PLAIN), ('rg -e "/" src', PLAIN), ("rg --regexp='/' src", PLAIN), ("rg -e / src", PLAIN),
    ('rg -n "/Users/" "$HOME/x/"', PLAIN), ('rg pat "/Users/maxghenis/x/"', PLAIN), ('rg pat "$HOME/PolicyEngine/populace/"', PLAIN),
    ('grep -rn foo "$HOME/.cache/x/"', PLAIN), ('find "$HOME"/x -name y', PLAIN), ('find "/tmp"/foo -name x', PLAIN),
    ('find "/Users/maxghenis/x" -name y', PLAIN), ('find "$HOME" -maxdepth 2 -name x', PLAIN),
    # a quoted root PATTERN of another rg/grep in the pipeline, and a quoted
    # root nested inside a non-searcher string
    ('rg --files src | grep -v "/"', PLAIN), ('rg -e foo src | rg "/"', PLAIN), ('find src -name "*.py" | xargs rg -n "/tmp/x"', PLAIN),
    ("find . -name \"a '/' b\"", PLAIN), ("bash -c \"cd x && rg -n '/' src\"", PLAIN),
    # the documented escape for `xargs rg /Users`: quote the pattern
    ('git ls-files | xargs rg "/Users"', PLAIN),
    # --- the three false-positive classes the 2026-08-19 port-back fixes ---
    # (1) the root belongs to a non-searcher command of the pipeline
    ("ls -1 /Users/maxghenis | rg '^(e8-ops|.*ops.*)$' || true", PLAIN),
    ("ls -1 /Users/maxghenis/PolicyEngine | rg 'social|psid' | sed -n '1,200p'", PLAIN),
    ("ls -1 /Users/maxghenis/PolicyEngine | rg 'psid|social|populace|missing|m6' | sed -n '1,160p' && "
     "ls -1 /Users/maxghenis/PolicyEngine/social-security-model-worktrees | sed -n '1,120p'", PLAIN),
    ("ls -1 /Users/maxghenis | rg -i 'psid|sol|report|scratch|task|codex|tmp|share|review|lane|data'", PLAIN),
    ("ls ~ | rg x", PLAIN), ("ls ~/PolicyEngine | rg -v '^_' | head", PLAIN),
    ("ls -la /Users/maxghenis | head; rg -l --hidden --glob '*.jsonl' 'report' /Users/maxghenis/.codex /Users/maxghenis/.codex-5 2>/dev/null", PLAIN),
    ("du -sh ~/PolicyEngine/* | sort -h; rg pat src", PLAIN), ("df -h / ; rg x src", PLAIN),
    ("cat ~/.zshrc | grep -n PATH; rg -n x src", PLAIN), ("find . -name x -exec cp {} /tmp \\;", PLAIN),
    ("find . -name x -print0 | xargs -0 cp -t /tmp", PLAIN), ("rg pat src | tee ~/out.txt", PLAIN),
    ("ls -R ~ | grep pat", PLAIN), ("git -C ~/PolicyEngine/populace grep -rn foo", PLAIN),
    ("ls ~\nrg pat src", PLAIN), ("cat <<EOF\nsee ~\nEOF\nrg pat src", PLAIN),
    # (2) the root is inside a quoted string that is not a sub-script
    # (patterns, awk programs, commit messages, prose)
    ("awk -F'|' '$2 ~ /^ [0-9]+\\/[0-9]+ / {n++} END{print n}' report.md; rg -n x src", PLAIN),
    ("git worktree list --porcelain | awk '/^branch /{b=$2; if (b ~ /(e8|e19)/) print b}'; rg -n x src", PLAIN),
    ("rg -n 'foo ~/PolicyEngine bar' src", PLAIN), ("rg -n \"os.path.join(HOME, '/tmp')\" src", PLAIN),
    ("rg '\\$HOME' ~/dotfiles/.zshrc", PLAIN), ("rg -e '~' src", PLAIN), ('rg -n "~" src', PLAIN), ('rg "~/PolicyEngine" src', PLAIN),
    ('git commit -m "see ~/PolicyEngine" && rg x src', PLAIN), ('git commit -m "guard: block find / crawls"', PLAIN),
    ('echo "run find ~ later" >> notes.md', PLAIN), ('echo "cd / && find . -name x" ; rg pat src', PLAIN),
    ("ssh host 'find ~ -name x'", PLAIN), ("python3 -c 'print(\"/Users/maxghenis\")'; rg x src", PLAIN),
    ("sed -i '' 's,/tmp,/var/tmp,g' x.py; rg pat src", PLAIN),
    # (3) the root is the unquoted PATTERN positional of rg/grep
    ("rg /tmp src", PLAIN), ("grep -r ~ src", PLAIN), ("rg ~/PolicyEngine src", PLAIN), ("rg -- / src", PLAIN),
    ("grep -r -- / src", PLAIN), ("rg -C 3 / src", PLAIN), ("rg pat -- /Users/maxghenis/x", PLAIN),
    ("rg -e pat src/ -e /", PLAIN), ("rg --regexp / src", PLAIN),
    # --- option values and scoped paths that merely contain a root prefix ---
    ("rg -f /tmp/pats src", PLAIN), ("grep -r -f /tmp/pats src", PLAIN), ("rg --ignore-file /tmp/ig pat src", PLAIN),
    ("rg --pre /usr/bin/cat pat src", PLAIN), ("find src -newer /tmp/stamp -name x", PLAIN), ("find src -path '*/tmp/*'", PLAIN),
    ("rg pat /tmp/build.log", PLAIN), ("grep -n x /Users/maxghenis/.zshrc", PLAIN), ("rg pat ~/.claude/settings.json", PLAIN),
    ("grep -rn x ~/.claude/hooks", PLAIN), ("rg pat /private/tmp/claude-501/x/y.log", PLAIN), ("rg pat src /Users/maxghenis/x", PLAIN),
    ("rg -g '!node_modules' pat ~/PolicyEngine/app", PLAIN), ('rg -n "def foo" ~/PolicyEngine/policyengine-us/policyengine_us/', PLAIN),
    ("find ~/TheAxiomFoundation/axiom-corpus/releases -name manifest.json", PLAIN),
    ("grep -rn TODO /Users/maxghenis/PolicyEngine/populace/src", PLAIN), ("rg pat $(git rev-parse --show-toplevel)", PLAIN),
    ('rg pat "$(pwd)"', PLAIN), ('for f in src/*.py; do grep -c def "$f"; done', PLAIN), ("rg pat src/ | head; ls ~", PLAIN),
    ("rg pat ./src", PLAIN), ("grep -rn pat ./", PLAIN), ("rg pat ~/PolicyEngine/populace src", PLAIN),
    ("cd /tmp && ls", PLAIN), ("cd ~ && ls", PLAIN), ("pushd /tmp >/dev/null && ls && popd", PLAIN),
    # Shell redirection targets are files, not search paths.
    ("rg pat src > '/Users'/out.txt", PLAIN), ("find src -name x > /tmp/out.txt", PLAIN),
    # --- continuations that stay scoped ---
    ("rg pat \\\nsrc", PLAIN), ("rg -n pat \\\n~/PolicyEngine/populace/src", PLAIN),
)

# The message names the searcher that fired.
SEARCHER_NAMED = {
    'find /Users/maxghenis/TheAxiomFoundation -path "*/target/release/axiom-rules-engine" -type f': "find",
    "find %s -path '*/site-packages/receipt/sign.py'" % USERS_HOME: "find",
    "rg --files /Users/maxghenis/TheAxiomFoundation /private/tmp": "rg",
    'rg -l "13 passed" /tmp /private/tmp': "rg",
    "grep -rn pattern ~/PolicyEngine": "recursive grep",
    "find / -type f \\( -iname '*a2*secondpass*' -o -iname '*1501-1800*' \\)": "find",
    'rg -l --hidden --no-ignore -S "1501-1800" /Users/maxghenis/PolicyEngine': "rg",
}

# `find .` / `rg pat .` judged by the cwd: (command, cwd).
CWD_DENY = tuple(
    (cmd, cwd)
    for cwd in ("/", "/Users", HOME, HOME + "/TheAxiomFoundation", HOME + "/RulesFoundation",
                HOME + "/PolicyEngine", "/tmp", "/private/tmp")
    for cmd in ("find . -name x", "rg pat .", "grep -rn pat ./")
)
CWD_ALLOW = tuple(
    (cmd, cwd)
    for cwd in (PLAIN, HOME + "/PolicyEngine/populace", HOME + "/.claude", HOME + "/dotfiles",
                "/private/tmp/claude-501/-Users-maxghenis/abc/scratchpad")
    for cmd in ("find . -name x", "rg pat .")
) + tuple(
    (cmd, cwd)
    for cwd in ("/", "/Users", HOME)
    for cmd in ("find . -maxdepth 1 -name x", "rg pat ./src")
) + (("rg pat", HOME),)  # bare `rg pattern` with no path in a broad cwd: known gap

# The block message ends with `Matched broad root: '<token>'.`: (command, cwd, token).
TOKEN_CASES = (
    ("find /Users -name '*.md'", PLAIN, "/Users"),
    ("find /Users/maxghenis -iname x", PLAIN, "/Users/maxghenis"),
    ("grep -rn pattern ~/PolicyEngine", PLAIN, "~/PolicyEngine"),
    ('find "$HOME" -name x', PLAIN, "$HOME"),
    ("rg pat /", PLAIN, "/"),
    ("find /* -name x", PLAIN, "/*"),
    ('find "/" -name x', PLAIN, "/"),
    ("cd /Users && rg pat .", PLAIN, "/Users (after cd)"),
    ('rg pat "$HOME/"', PLAIN, "$HOME/"),
    ('find "/" -name x | xargs rg pat', PLAIN, "/"),
    ("find ${HOME} -name x", PLAIN, "$HOME"),  # `${HOME}` is named in its `$HOME` form
    ("echo / | xargs rg pat", PLAIN, "/"),
    ("find ~/ -name x", PLAIN, "~/"),
    ("rg foo /tmp/", PLAIN, "/tmp/"),
    ("find \\\n~ -name x", PLAIN, "~"),
    ('bash -c "cd "$HOME" && find . -name x"', PLAIN, "$HOME (after cd)"),
    ('for d in /Users/; do find "$d" -name x; done', PLAIN, "/Users/"),
    ('echo "$HOME" | xargs rg pat', PLAIN, "$HOME"),
    # A root before a no-pattern option is still the path that fired; never
    # misname the later option (`-e`, `-f`, `--regexp`, `--file`, `--files`).
    ("rg / -e pat", PLAIN, "/"),
    ("rg / -f pats", PLAIN, "/"),
    ("rg / --regexp pat", PLAIN, "/"),
    ("rg / --file pats", PLAIN, "/"),
    ('rg "/" --files', PLAIN, "/"),
    ('rg -n "/" src -e foo', PLAIN, "/"),
    # A searcher immediately after a shell delimiter still names the root;
    # the leading delimiter consumed by the segment regex must not erase it.
    ("true;rg / -e pat", PLAIN, "/"),
    ("true|rg / --files", PLAIN, "/"),
    ("true&&grep -r / --file pats", PLAIN, "/"),
    ("true;rg /tmp/ --regexp=pat", PLAIN, "/tmp/"),
    ("true;rg -e pat /", PLAIN, "/"),
    ("true;find / -name x", PLAIN, "/"),
    ("true;cd /&&find .", PLAIN, "/ (after cd)"),
    ("find . -name x", "/Users", ". (cwd /Users)"),
    ("find . -name x", "/", ". (cwd /)"),
    ("rg pat .", HOME, ". (cwd %s)" % HOME),
)

ALL_CASES = tuple(
    sorted(
        {(c, cwd) for c, cwd in DENY_CASES}
        | {(c, cwd) for c, cwd in ALLOW_CASES}
        | set(CWD_DENY) | set(CWD_ALLOW)
        | {(c, cwd) for c, cwd, _ in TOKEN_CASES},
        key=lambda e: (e[1] or "", e[0]),
    )
)


def hook_payload(command, cwd, tool_name="Bash"):
    return json.dumps(
        {
            "session_id": "s",
            "turn_id": "t",
            "tool_use_id": "u",
            "hook_event_name": "PreToolUse",
            "permission_mode": "never",
            "tool_name": tool_name,
            "cwd": cwd,
            "tool_input": {"command": command},
        }
    )


def hook_reason(stdout):
    """(allowed, reason) from a hook's stdout; understands both output shapes
    (Claude: {decision, reason}; codex: hookSpecificOutput.permissionDecisionReason)."""
    out = stdout.strip()
    if not out:
        return True, ""
    parsed = json.loads(out)
    if "hookSpecificOutput" in parsed:
        spec = parsed["hookSpecificOutput"]
        if spec.get("permissionDecision") != "deny":
            raise AssertionError("unexpected codex decision: %r" % out)
        return False, spec["permissionDecisionReason"]
    if parsed.get("decision") != "block":
        raise AssertionError("unexpected Claude decision: %r" % out)
    return False, parsed["reason"]


class GuardTestCase(unittest.TestCase):
    """Temp dirs + an environment that keeps telemetry out of ~/.cache."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name).resolve()
        self.log_file = self.tmp_path / "denials.log"
        self.cache_dir = self.tmp_path / "guard-cache"
        self.env = os.environ.copy()
        self.env["CODEX_GUARD_LOG"] = str(self.log_file)
        self.env["CLAUDE_GUARD_LOG"] = str(self.tmp_path / "claude-denials.log")
        self.env["CODEX_RUN_GUARD_CACHE"] = str(self.cache_dir)
        self.env["AI_QUOTA_NO_AUTOPICK"] = "1"
        self.env.pop("CODEX_RUN_GUARD", None)

    def guard(self, *args, env=None):
        """Run bin/codex-guard. Only `check` runs the hook, so only `check`
        is pointed at a candidate (`--hook <HOOK>`) when CODEX_GUARD_HOOK is
        set; hash/override/key/preflight are about the armed path and never
        get --hook."""
        argv = [GUARD, *args]
        if HOOK_OVERRIDDEN and args and args[0] == "check":
            argv = [GUARD, "check", "--hook", HOOK, *args[1:]]
        return run(argv, env=env or self.env)

    def plain_cwd(self, cwd):
        return str(self.tmp_path / "plain") if cwd is None else cwd


def run_hook_many(hook, cases, env, cwd_of, workers=6):
    """Run one hook over [(command, cwd), ...] in parallel; returns
    {(command, cwd): (allowed, reason, completed)}. A hook is a standalone bash
    script, so the runs are independent."""
    def one(case):
        command, cwd = case
        completed = run(["/bin/bash", hook], env=env, stdin=hook_payload(command, cwd_of(cwd)))
        return case, completed

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for case, completed in pool.map(one, cases):
            results[case] = completed
    return results


class HookDecisionTests(GuardTestCase):
    def payload(self, command, cwd, tool_name="Bash"):
        return hook_payload(command, cwd, tool_name)

    def decide(self, command, cwd=None, tool_name="Bash", raw=None, env=None):
        """Returns (allowed, reason, completed)."""
        cwd = self.plain_cwd(cwd)
        data = self.payload(command, cwd, tool_name) if raw is None else raw
        completed = run([HOOK], env=env or self.env, stdin=data)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "", "hook wrote to stderr: %r" % completed.stderr)
        out = completed.stdout.strip()
        if not out:
            return True, "", completed
        self.assertEqual(len(out.splitlines()), 1, "more than one output line: %r" % out)
        parsed = json.loads(out)
        reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
        return False, reason, completed

    def assertDeny(self, command, cwd=None, searcher=None):
        allowed, reason, _ = self.decide(command, cwd)
        self.assertFalse(allowed, "expected deny for: %s" % command)
        self.assertTrue(reason.startswith("[unscoped-search]"), reason)
        if searcher:
            self.assertIn("Whole-tree %s over" % searcher, reason)

    def assertAllow(self, command, cwd=None):
        allowed, reason, _ = self.decide(command, cwd)
        self.assertTrue(allowed, "expected allow for: %s (got %s)" % (command, reason))

    def run_corpus(self, cases):
        """{(command, cwd): (allowed, reason)} for the codex hook, checking the
        I/O contract (exit 0, no stderr, at most one JSON line) on every run."""
        results = run_hook_many(HOOK, cases, self.env, self.plain_cwd)
        decided = {}
        for case, completed in results.items():
            with self.subTest(command=case[0], cwd=case[1]):
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "", "hook wrote to stderr for %r: %r" % (case, completed.stderr))
                out = completed.stdout.strip()
                self.assertLessEqual(len(out.splitlines()), 1, "more than one output line for %r: %r" % (case, out))
                decided[case] = hook_reason(completed.stdout)
        return decided

    # --- the corpus: every deny case denies (naming the searcher where listed)
    # and carries the token tail; every allow case allows ---
    def test_deny_corpus(self):
        decided = self.run_corpus(DENY_CASES)
        for case in DENY_CASES:
            allowed, reason = decided[case]
            with self.subTest(command=case[0], cwd=case[1]):
                self.assertFalse(allowed, "expected deny for: %r (cwd %s)" % case)
                self.assertTrue(reason.startswith("[unscoped-search] Whole-tree "), reason)
                self.assertRegex(reason, r"Matched broad root: '[^']+'\.$")
                searcher = SEARCHER_NAMED.get(case[0])
                if searcher:
                    self.assertIn("Whole-tree %s over" % searcher, reason)

    def test_allow_corpus(self):
        decided = self.run_corpus(ALLOW_CASES)
        for case in ALLOW_CASES:
            allowed, reason = decided[case]
            with self.subTest(command=case[0], cwd=case[1]):
                self.assertTrue(allowed, "expected allow for: %r (cwd %s), got %s" % (case[0], case[1], reason))

    def test_cwd_based_dot_searches(self):
        decided = self.run_corpus(CWD_DENY + CWD_ALLOW)
        for case in CWD_DENY:
            allowed, reason = decided[case]
            with self.subTest(command=case[0], cwd=case[1]):
                self.assertFalse(allowed, "expected deny for %r in cwd %s" % case)
                self.assertIn("Matched broad root: '. (cwd %s)'." % case[1], reason)
        for case in CWD_ALLOW:
            allowed, reason = decided[case]
            with self.subTest(command=case[0], cwd=case[1]):
                self.assertTrue(allowed, "expected allow for %r in cwd %s, got %s" % (case[0], case[1], reason))
        repo = self.tmp_path / "repo"
        repo.mkdir()
        self.assertAllow("find . -name x", cwd=str(repo))
        self.assertAllow("rg pat .", cwd=str(repo))

    def test_deny_reason_names_the_token_that_fired(self):
        decided = self.run_corpus(tuple((c, cwd) for c, cwd, _ in TOKEN_CASES))
        for command, cwd, token in TOKEN_CASES:
            allowed, reason = decided[(command, cwd)]
            with self.subTest(command=command, cwd=cwd):
                self.assertFalse(allowed, command)
                self.assertTrue(reason.endswith("Matched broad root: '%s'." % token),
                                "%s -> %s" % (command, reason))

    # --- the intended false-positive classes are allowed, the crawls next to
    # them still deny (the three classes the 2026-08-19 port-back fixed) ---
    def test_false_positive_classes_allowed_neighbours_denied(self):
        self.assertAllow("ls -1 /Users/maxghenis | rg '^(e8-ops|.*ops.*)$' || true")  # root belongs to ls
        self.assertDeny("ls -1 /Users/maxghenis | xargs rg pat")                      # ... unless xargs feeds it to rg
        self.assertDeny("rg pat /Users/maxghenis | head")
        self.assertAllow("rg -n 'foo ~/PolicyEngine bar' src")                         # root inside a pattern
        self.assertDeny("rg -n 'foo' ~/PolicyEngine")
        self.assertAllow("rg /tmp src")                                                 # root IS the pattern
        self.assertDeny("rg pat /tmp")
        self.assertAllow('git commit -m "see ~/PolicyEngine" && rg x src')              # prose
        self.assertDeny('git commit -m "see ~/PolicyEngine" && rg x ~/PolicyEngine')

    def test_tool_passthrough_and_input_shapes(self):
        # apply_patch is judged by the hf-dest adapter only (see
        # test_codex_guard_never_rules.py); a searcher command as patch text is
        # not a patch touching uk-data, so it allows with empty stdout. A tool
        # outside Bash/apply_patch is ignored outright.
        allowed, _, completed = self.decide("find / -name x", tool_name="apply_patch")
        self.assertTrue(allowed)
        self.assertEqual(completed.stdout, "")
        allowed, _, completed = self.decide("find / -name x", tool_name="Edit")
        self.assertTrue(allowed)
        self.assertEqual(completed.stdout, "")
        # argv-array command form is joined and judged.
        raw = json.dumps(
            {
                "tool_name": "Bash",
                "cwd": str(self.tmp_path),
                "tool_input": {"command": ["bash", "-lc", "find / -name x"]},
            }
        )
        allowed, reason, _ = self.decide("", raw=raw)
        self.assertFalse(allowed)
        self.assertIn("[unscoped-search]", reason)
        # Empty stdin, garbage stdin, missing command: allow, exit 0, no stdout.
        for raw in ("", "garbage {{ not json", '{"tool_name":"Bash","cwd":"/"}',
                    '{"tool_name":"Bash","cwd":"/","tool_input":{"command":null}}'):
            allowed, _, completed = self.decide("", raw=raw)
            self.assertTrue(allowed, "expected allow for raw input %r" % raw)
            self.assertEqual(completed.stdout, "")

    def test_deny_output_shape(self):
        completed = run([HOOK], env=self.env, stdin=self.payload("find / -name x", "/tmp/x"))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        lines = completed.stdout.strip().splitlines()
        self.assertEqual(len(lines), 1, completed.stdout)
        parsed = json.loads(lines[0])
        self.assertEqual(list(parsed.keys()), ["hookSpecificOutput"])
        spec = parsed["hookSpecificOutput"]
        self.assertEqual(spec["hookEventName"], "PreToolUse")
        self.assertEqual(spec["permissionDecision"], "deny")
        reason = spec["permissionDecisionReason"]
        self.assertTrue(reason.startswith(
            "[unscoped-search] Whole-tree find over a broad root (/, /Users, ~, ~/TheAxiomFoundation, ~/PolicyEngine, /tmp, caches)"))
        self.assertIn("drove load to 47", reason)
        self.assertIn("held load at 57 for hours", reason)
        self.assertIn("-maxdepth", reason)
        self.assertIn("git ls-files", reason)
        self.assertIn("axiom-locate", reason)
        self.assertNotIn("[codex lane:", reason)
        self.assertTrue(reason.endswith("Matched broad root: '/'."), reason)

    def test_denial_log_written_on_deny_only(self):
        self.assertAllow("git ls-files | grep x")
        self.assertFalse(self.log_file.exists(), "allow must not log")
        cmd = "find /Users\t-name\n'*.md'"
        allowed, _, _ = self.decide(cmd, cwd="/some/cwd")
        self.assertFalse(allowed)
        lines = self.log_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1, lines)
        stamp, cwd, logged = lines[0].split("\t")
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4}$")
        self.assertEqual(cwd, "/some/cwd")
        self.assertEqual(logged, "find /Users -name '*.md'")  # tabs/newlines squashed
        # Long commands are truncated to 300 chars; a second denial appends.
        long_cmd = "find / -name " + "x" * 400
        self.decide(long_cmd, cwd="/c")
        lines = self.log_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(len(lines[1].split("\t")[2]), 300)

    def test_log_failure_never_changes_decision(self):
        env = self.env.copy()
        env["CODEX_GUARD_LOG"] = "/nonexistent-root-dir-for-codex-guard-test/x/denials.log"
        allowed, reason, completed = self.decide("find / -name x", env=env)
        self.assertFalse(allowed)
        self.assertIn("[unscoped-search]", reason)
        self.assertEqual(completed.returncode, 0)

    def test_hook_is_executable_bash32_clean(self):
        self.assertTrue(os.access(str(HOOK), os.X_OK))
        completed = run(["/bin/bash", "-n", HOOK])
        self.assertEqual(completed.returncode, 0, completed.stderr)


REGION_BEGIN = "# >>> unscoped-search: shared region begin"
REGION_END = "# <<< unscoped-search: shared region end <<<"

# Split landing (2026-08-19): the ~/dotfiles half of the guard-portback landed
# (codex hook with the shared region + the seven ported NEVER rules), but the
# ~/.claude half (the sibling's guard-never-rules.sh candidate with the same
# region, plus its 510-case harness) is not installed yet. Tests that assert
# the NEW Claude-hook behavior are gated on the region marker appearing in the
# Claude hook; they lift automatically when that install lands.
CLAUDE_PORTBACK_LANDED = (
    CLAUDE_HOOK.is_file()
    and REGION_BEGIN in CLAUDE_HOOK.read_text(encoding="utf-8")
)
PENDING_CLAUDE_INSTALL = (
    "pending guard-portback ~/.claude install — see "
    "~/.cache/guard-portback-lane/final/_STOP-READ-FIRST.md"
)


def shared_region(text, label):
    """The unscoped-search shared region of a hook: the lines from the begin
    marker to the end marker, inclusive. Exactly one per file."""
    lines = text.split("\n")
    begins = [i for i, line in enumerate(lines) if line.startswith(REGION_BEGIN)]
    ends = [i for i, line in enumerate(lines) if line == REGION_END]
    if len(begins) != 1 or len(ends) != 1 or ends[0] <= begins[0]:
        raise AssertionError("%s: expected exactly one shared region, found begin=%s end=%s" % (label, begins, ends))
    return "\n".join(lines[begins[0]:ends[0] + 1])


class DriftTests(GuardTestCase):
    """The unscoped-search rule is ONE shared region, byte-identical in the
    Claude hook (~/.claude/hooks/guard-never-rules.sh, the source of truth)
    and the codex hook. Two pins: the region text, and the decisions + reasons
    both hooks produce over the whole corpus with identical payloads."""

    def setUp(self):
        super().setUp()
        if not CLAUDE_HOOK.is_file():
            self.skipTest("Claude hook not present: %s" % CLAUDE_HOOK)
        self.claude = CLAUDE_HOOK.read_text(encoding="utf-8")
        self.codex = HOOK.read_text(encoding="utf-8")

    @unittest.skipUnless(CLAUDE_PORTBACK_LANDED, PENDING_CLAUDE_INSTALL)
    def test_shared_region_identical(self):
        claude_region = shared_region(self.claude, str(CLAUDE_HOOK))
        codex_region = shared_region(self.codex, str(HOOK))
        self.assertEqual(
            codex_region, claude_region,
            "the unscoped-search shared region differs between %s and %s — edit the Claude hook, "
            "run its harness, then copy the region verbatim" % (CLAUDE_HOOK, HOOK))
        # The region is the whole rule: searcher detection, escape hatch,
        # roots, collapse, the position rules, the cwd rule and the message.
        for needle in (
            'searcher=""',
            "--?max-?depth",
            "broad_re=\"(/Users/[^/[:space:]'\\\"]+|~|\\\\\\$HOME)(/(TheAxiomFoundation|RulesFoundation|PolicyEngine|Library/Caches|\\.cache|\\.local))?|(/private)?/tmp\"",
            'root_core="/|/\\\\*|/Users/?|(${broad_re})/?"',
            "collapse_quotes()",
            "first_match()",
            "last_word_of_match()",
            "sed 's/\\$[{]HOME[}]/$HOME/g'",
            '"$HOME"|"$HOME/TheAxiomFoundation"|"$HOME/RulesFoundation"|"$HOME/PolicyEngine"|/tmp|/private/tmp|/|/Users)',
            "[unscoped-search] Whole-tree ${searcher} over a broad root (/, /Users, ~, ~/TheAxiomFoundation, ~/PolicyEngine, /tmp, caches)",
            "Matched broad root: '${matched}'.",
        ):
            self.assertIn(needle, claude_region, needle)
        # The codex-only fence is gone (both lanes judge the same roots), and the
        # region reads no environment knob: the only env var it touches is HOME.
        for fence_era in ("[codex lane:", "codex-lane additions", "codex_root_core", "claude_broad_re", "claude_msg"):
            self.assertNotIn(fence_era, claude_region)
        env_refs = set(re.findall(r"\$\{?([A-Z][A-Z0-9_]*)\}?", claude_region))
        self.assertEqual(env_refs, {"HOME"}, env_refs)

    def test_prefilter_term_present_in_both(self):
        term = "(^|[[:space:];&|(])(find|rg|grep)[[:space:]]"
        self.assertIn(term, self.claude)
        self.assertIn(term, self.codex)

    @unittest.skipUnless(CLAUDE_PORTBACK_LANDED, PENDING_CLAUDE_INSTALL)
    def test_decisions_match_claude_hook(self):
        """Both hooks over the whole corpus (same command, same cwd,
        tool_name Bash): the allow/deny decision and the reason text must be
        identical (Claude: {decision:block, reason}; codex:
        hookSpecificOutput.permissionDecisionReason)."""
        claude = run_hook_many(CLAUDE_HOOK, ALL_CASES, self.env, self.plain_cwd)
        codex = run_hook_many(HOOK, ALL_CASES, self.env, self.plain_cwd)
        self.assertEqual(len(claude), len(ALL_CASES))
        mismatches = []
        for case in ALL_CASES:
            c_run, x_run = claude[case], codex[case]
            with self.subTest(command=case[0], cwd=case[1]):
                for label, completed in (("claude", c_run), ("codex", x_run)):
                    self.assertEqual(completed.returncode, 0, "%s exit %s: %s" % (label, completed.returncode, completed.stderr))
                    self.assertEqual(completed.stderr, "", "%s stderr: %r" % (label, completed.stderr))
                c_allowed, c_reason = hook_reason(c_run.stdout)
                x_allowed, x_reason = hook_reason(x_run.stdout)
                if (c_allowed, c_reason) != (x_allowed, x_reason):
                    mismatches.append((case, c_allowed, c_reason, x_allowed, x_reason))
                self.assertEqual(c_allowed, x_allowed, "decision differs for %r: claude=%s codex=%s (%s | %s)" % (
                    case, "allow" if c_allowed else "block", "allow" if x_allowed else "deny", c_reason, x_reason))
                self.assertEqual(c_reason, x_reason, "reason differs for %r" % (case,))
        self.assertEqual(mismatches, [])
        # Sanity: the corpus exercises both outcomes through both hooks.
        self.assertTrue(any(not hook_reason(r.stdout)[0] for r in claude.values()))
        self.assertTrue(any(hook_reason(r.stdout)[0] for r in claude.values()))
        # Both telemetry logs stayed in the temp dir (never the real ones).
        self.assertTrue((self.tmp_path / "claude-denials.log").exists())
        self.assertTrue(self.log_file.exists())

    @unittest.skipUnless(CLAUDE_PORTBACK_LANDED, PENDING_CLAUDE_INSTALL)
    def test_claude_hook_decision_corpus(self):
        """The Claude hook itself over the corpus (belt and braces: the parity
        test would pass if both hooks were wrong the same way)."""
        results = run_hook_many(CLAUDE_HOOK, DENY_CASES + ALLOW_CASES, self.env, self.plain_cwd)
        for case in DENY_CASES:
            with self.subTest(command=case[0], cwd=case[1]):
                allowed, reason = hook_reason(results[case].stdout)
                self.assertFalse(allowed, "Claude hook: expected block for %r" % (case,))
                self.assertTrue(reason.startswith("[unscoped-search] "), reason)
        for case in ALLOW_CASES:
            with self.subTest(command=case[0], cwd=case[1]):
                allowed, reason = hook_reason(results[case].stdout)
                self.assertTrue(allowed, "Claude hook: expected allow for %r, got %s" % (case, reason))


class OverrideTests(GuardTestCase):
    # guard() is inherited from GuardTestCase: only `check` follows
    # CODEX_GUARD_HOOK; override/hash/key are about the armed path.

    def test_override_shape(self):
        completed = self.guard("override")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        override = completed.stdout.rstrip("\n")
        self.assertNotIn("\n", override)
        self.assertTrue(override.startswith("hooks={"), override)
        self.assertIn('command="%s"' % ARMED_HOOK, override)
        self.assertIn("timeout=60", override)
        self.assertIn('matcher="%s"' % MATCHER, override)
        self.assertIn('statusMessage="%s"' % STATUS_MESSAGE, override)
        self.assertIn('"%s"={trusted_hash="sha256:' % KEY, override)
        self.assertIn("enabled=true", override)

    @unittest.skipIf(tomllib is None, "tomllib unavailable (python < 3.11)")
    def test_override_parses_as_toml(self):
        override = self.guard("override").stdout.rstrip("\n")
        expected_hash = self.guard("hash").stdout.strip()
        parsed = tomllib.loads(override)
        group = parsed["hooks"]["PreToolUse"][0]
        self.assertEqual(group["matcher"], MATCHER)
        handler = group["hooks"][0]
        self.assertEqual(handler["type"], "command")
        self.assertEqual(handler["command"], str(ARMED_HOOK))
        self.assertEqual(handler["timeout"], 60)
        self.assertEqual(handler["statusMessage"], STATUS_MESSAGE)
        state = parsed["hooks"]["state"][KEY]
        self.assertEqual(state["trusted_hash"], expected_hash)
        self.assertIs(state["enabled"], True)

    @unittest.skipIf(tomllib is None, "tomllib unavailable (python < 3.11)")
    def test_override_escapes_and_shell_quotes_hook_path(self):
        for weird in (str(self.tmp_path / 'we"ird\\hook'), "/it's/a space", "/plain/path"):
            override = self.guard("override", "--hook", weird).stdout.rstrip("\n")
            parsed = tomllib.loads(override)
            command = parsed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            self.assertEqual(command, shell_quote(weird))
            # The quoted command round-trips through a POSIX shell to the raw path.
            echoed = run(["/bin/sh", "-c", "printf '%s' " + command]).stdout
            self.assertEqual(echoed, weird)
            self.assertEqual(
                parsed["hooks"]["state"][KEY]["trusted_hash"], python_trust_hash(weird)
            )
        self.assertEqual(shell_quote("/plain/path"), "/plain/path")

    def test_hash_pinned_to_live_codex_value(self):
        # New identity (the defaults): live-verified 2026-08-19.
        completed = self.guard("hash", "--hook", PINNED_HOOK_PATH, "--timeout", "30")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), PINNED_HASH_V2)
        self.assertEqual(python_trust_hash(PINNED_HOOK_PATH, timeout=30), PINNED_HASH_V2)
        # Old identity, reproduced via the --matcher/--status knobs.
        old = self.guard(
            "hash", "--hook", PINNED_HOOK_PATH, "--timeout", "30",
            "--matcher", "Bash", "--status", "unscoped-search guard")
        self.assertEqual(old.returncode, 0, old.stderr)
        self.assertEqual(old.stdout.strip(), PINNED_HASH)
        self.assertEqual(
            python_trust_hash(PINNED_HOOK_PATH, timeout=30,
                              matcher="Bash", status="unscoped-search guard"),
            PINNED_HASH)

    def test_hash_matches_python_reimplementation(self):
        completed = self.guard("hash")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), python_trust_hash(str(ARMED_HOOK)))
        for weird in ('/tmp/we"ird\\hook', "/it's/a space", "/h\u00e9llo/x"):
            self.assertEqual(
                self.guard("hash", "--hook", weird).stdout.strip(), python_trust_hash(weird)
            )
        self.assertNotEqual(completed.stdout.strip(), PINNED_HASH_V2)  # timeout 60 vs 30

    def test_override_embeds_hash(self):
        override = self.guard("override").stdout.rstrip("\n")
        self.assertIn('trusted_hash="%s"' % python_trust_hash(str(ARMED_HOOK)), override)

    def test_key(self):
        completed = self.guard("key")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), KEY)

    def test_usage_errors_exit_2(self):
        self.assertEqual(self.guard().returncode, 2)
        self.assertEqual(self.guard("bogus").returncode, 2)
        self.assertEqual(self.guard("hash", "--hook").returncode, 2)
        self.assertEqual(self.guard("hash", "--hook", "relative/path").returncode, 2)
        self.assertEqual(self.guard("hash", "--timeout", "abc").returncode, 2)
        self.assertEqual(self.guard("preflight", "-H", str(self.tmp_path)).returncode, 2)
        self.assertEqual(self.guard("check").returncode, 2)

    def test_check_deny_and_allow(self):
        env = self.env.copy()
        env["HOME"] = str(self.tmp_path / "home")
        env.pop("CODEX_GUARD_LOG")
        (self.tmp_path / "home").mkdir()
        deny = self.guard("check", "find / -type f -name x", env=env)
        self.assertEqual(deny.returncode, 1, deny.stderr)
        self.assertTrue(deny.stdout.startswith("deny: [unscoped-search] Whole-tree find"), deny.stdout)
        allow = self.guard("check", "find ~/TheAxiomFoundation -maxdepth 2 -type d", env=env)
        self.assertEqual(allow.returncode, 0, allow.stderr)
        self.assertEqual(allow.stdout.strip(), "allow")
        rg = self.guard("check", "rg -l --hidden --no-ignore -S x /Users/maxghenis/PolicyEngine", env=env)
        self.assertEqual(rg.returncode, 1)
        self.assertIn("Whole-tree rg over", rg.stdout)
        # cwd argument drives the dot-search rule.
        self.assertEqual(self.guard("check", "find . -name x", "/", env=env).returncode, 1)
        self.assertEqual(self.guard("check", "find . -name x", str(self.tmp_path), env=env).returncode, 0)
        # Dry runs never write the real denial log.
        self.assertFalse((self.tmp_path / "home" / ".cache" / "codex-run" / "guard-denials.log").exists())

    def test_scripts_are_bash32_clean_and_executable(self):
        for script in {HOOK, ARMED_HOOK, GUARD, CODEX_RUN}:
            self.assertTrue(os.access(str(script), os.X_OK), script)
            completed = run(["/bin/bash", "-n", script])
            self.assertEqual(completed.returncode, 0, "%s: %s" % (script, completed.stderr))


STUB_CODEX = r"""#!/bin/bash
# codex stub for tests: --version, app-server (canned hooks/list), exec (record argv).
# app-server records what it was started with (STUB_APPSERVER_INFO) and can
# misbehave on request (STUB_APPSERVER_MODE=dies|hang) to exercise the
# preflight's fail-fast and watchdog paths.
case "${1:-}" in
  --version) echo "codex-cli 0.0.0-stub"; exit 0 ;;
  app-server)
    if [ -n "${STUB_APPSERVER_INFO:-}" ]; then
      {
        printf 'CODEX_HOME=%s\n' "${CODEX_HOME:-}"
        for a in "$@"; do printf 'ARG=%s\n' "$a"; done
        ls -A "${CODEX_HOME:-/nonexistent}" 2>/dev/null | sed 's/^/FILE=/'
        sed 's/^/CFG=/' "${CODEX_HOME:-/nonexistent}/config.toml" 2>/dev/null
      } > "$STUB_APPSERVER_INFO"
    fi
    case "${STUB_APPSERVER_MODE:-}" in
      dies) read -r a; read -r b; read -r c; echo "stub app-server: dying without answering" >&2; exit 1 ;;
      hang) echo "$$" > "${STUB_PID_FILE:-/dev/null}"; sleep 977; exit 0 ;;
    esac
    printf '%s\n' '{"id":1,"result":{"userAgent":"stub"}}'
    printf '{"id":2,"result":{"data":[{"cwd":"x","hooks":[{"key":"__KEY__","eventName":"preToolUse","handlerType":"command","matcher":"Bash|apply_patch","command":"stub","timeoutSec":15,"statusMessage":"stub","sourcePath":"/<session-flags>/config.toml","source":"sessionFlags","pluginId":null,"displayOrder":0,"enabled":%s,"isManaged":false,"currentHash":"sha256:stub","trustStatus":"%s"}],"warnings":[%s],"errors":[]}]}}\n' \
      "${STUB_ENABLED:-true}" "${STUB_TRUST:-trusted}" "${STUB_WARNINGS:-}"
    exit 0 ;;
  exec)
    : > "$STUB_ARGV_FILE"
    for a in "$@"; do printf '%s\0' "$a" >> "$STUB_ARGV_FILE"; done
    out=""; prev=""
    for a in "$@"; do [ "$prev" = "-o" ] && out=$a; prev=$a; done
    [ -n "$out" ] && echo ok > "$out"
    exit 0 ;;
  *) echo "codex stub: unexpected argv: $*" >&2; exit 99 ;;
esac
"""


class CodexRunTests(GuardTestCase):
    def setUp(self):
        super().setUp()
        self.stub_dir = self.tmp_path / "stubbin"
        self.stub_dir.mkdir()
        stub = self.stub_dir / "codex"
        stub.write_text(STUB_CODEX.replace("__KEY__", KEY), encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.argv_file = self.tmp_path / "argv.bin"
        self.env["PATH"] = "%s%s%s" % (self.stub_dir, os.pathsep, self.env["PATH"])
        self.env["STUB_ARGV_FILE"] = str(self.argv_file)
        self.codex_home = self.tmp_path / "codex-home"
        self.codex_home.mkdir()
        self.workdir = self.tmp_path / "work"
        self.workdir.mkdir()
        self.prompt = self.tmp_path / "prompt.md"
        self.prompt.write_text("say hi\n", encoding="utf-8")
        self.out_file = self.tmp_path / "out.md"

    def codex_run(self, *extra, env=None, sandbox="read-only"):
        argv = [
            CODEX_RUN, "-H", self.codex_home, "-m", "gpt-test", "-C", self.workdir,
            "-p", self.prompt, "-o", self.out_file, "-s", sandbox, *extra,
        ]
        return run(argv, env=env or self.env)

    def exec_argv(self):
        data = self.argv_file.read_bytes()
        return [a.decode("utf-8") for a in data.split(b"\0") if a]

    def c_values(self, argv):
        return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-c"]

    def markers(self):
        return sorted(self.cache_dir.glob("guard-ok-*")) if self.cache_dir.exists() else []

    def test_default_arms_guard_and_caches_preflight(self):
        completed = self.codex_run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("preflight: ok (codex-cli 0.0.0-stub", completed.stderr)
        self.assertIn("never-rules guard armed (9 rules; hook=%s)" % ARMED_HOOK, completed.stderr)
        self.assertIn("codex-run: OK attempt=1", completed.stdout)
        argv = self.exec_argv()
        self.assertEqual(argv[0], "exec")
        self.assertIn("--skip-git-repo-check", argv)
        overrides = [v for v in self.c_values(argv) if v.startswith("hooks={")]
        self.assertEqual(len(overrides), 1, argv)
        self.assertIn('trusted_hash="%s"' % python_trust_hash(str(ARMED_HOOK)), overrides[0])
        self.assertEqual(overrides[0], run([GUARD, "override"], env=self.env).stdout.rstrip("\n"))
        self.assertEqual(len(self.markers()), 1)
        marker_text = self.markers()[0].read_text(encoding="utf-8")
        self.assertIn("version=codex-cli 0.0.0-stub", marker_text)
        self.assertEqual(self.out_file.read_text(encoding="utf-8"), "ok\n")

    def test_second_run_uses_cached_preflight(self):
        first = self.codex_run()
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.codex_run()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("preflight: cached ok (codex-cli 0.0.0-stub)", second.stderr)
        self.assertIn("guard armed", second.stderr)
        self.assertEqual(len(self.markers()), 1)

    def test_cache_key_covers_codex_home_and_version(self):
        self.assertEqual(self.codex_run().returncode, 0)
        other_home = self.tmp_path / "other-home"
        other_home.mkdir()
        self.codex_home = other_home
        completed = self.codex_run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("cached ok", completed.stderr)
        self.assertEqual(len(self.markers()), 2)

    def test_guard_off_env_disables(self):
        env = self.env.copy()
        env["CODEX_RUN_GUARD"] = "off"
        completed = self.codex_run(env=env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("never-rules guard DISABLED (CODEX_RUN_GUARD=off)", completed.stderr)
        argv = self.exec_argv()
        self.assertFalse(any(v.startswith("hooks=") for v in self.c_values(argv)), argv)
        self.assertEqual(self.markers(), [])

    def test_untrusted_preflight_refuses_to_launch(self):
        env = self.env.copy()
        env["STUB_TRUST"] = "untrusted"
        completed = self.codex_run(env=env)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("preflight: FAILED", completed.stderr)
        self.assertIn("trustStatus=untrusted", completed.stderr)
        self.assertIn("guard preflight FAILED (see preflight output above)", completed.stderr)
        self.assertIn("CODEX_RUN_GUARD=off to bypass", completed.stderr)
        self.assertFalse(self.argv_file.exists(), "codex exec must not run")
        self.assertEqual(self.markers(), [])

    def test_refused_launch_does_not_salvage_or_push(self):
        # The guard refuses BEFORE the salvage trap is armed: a launch that never
        # happened must not snapshot dirty state to refs/codex-salvage/* (or push
        # it with -b).
        git = shutil.which("git")
        if git is None:
            self.skipTest("git is not installed")
        subprocess.run([git, "init", "-q", str(self.workdir)], check=True,
                       capture_output=True, timeout=SUBPROCESS_TIMEOUT)
        subprocess.run([git, "-C", str(self.workdir), "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-q", "--allow-empty", "-m", "init"], check=True,
                       capture_output=True, timeout=SUBPROCESS_TIMEOUT)
        (self.workdir / "dirty.txt").write_text("wip\n", encoding="utf-8")
        env = self.env.copy()
        env["STUB_TRUST"] = "untrusted"
        completed = self.codex_run("-b", "salvage-branch", "-R", "nonexistent-remote",
                                   env=env, sandbox="workspace-write")
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertNotIn("salvaged dirty state", completed.stderr)
        refs = subprocess.run([git, "-C", str(self.workdir), "for-each-ref", "refs/codex-salvage"],
                              capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
        self.assertEqual(refs.stdout.strip(), "", refs.stdout)
        self.assertFalse(self.argv_file.exists())
        # ...whereas a completed launch still salvages (behavior preserved).
        completed = self.codex_run(sandbox="workspace-write")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("salvaged dirty state", completed.stderr)
        refs = subprocess.run([git, "-C", str(self.workdir), "for-each-ref", "refs/codex-salvage"],
                              capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
        self.assertEqual(len(refs.stdout.strip().splitlines()), 1, refs.stdout)

    def test_missing_codex_home_refuses_to_launch(self):
        # codex 0.144.0 does not create a missing CODEX_HOME ("Error finding
        # codex home"), so preflight fails clearly before anything else runs.
        self.codex_home = self.tmp_path / "does-not-exist"
        completed = self.codex_run()
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("preflight: codex home not found", completed.stderr)
        self.assertIn("guard preflight FAILED (see preflight output above)", completed.stderr)
        self.assertFalse(self.argv_file.exists())
        self.assertFalse(self.codex_home.exists())

    def test_modified_or_disabled_preflight_refuses_to_launch(self):
        env = self.env.copy()
        env["STUB_TRUST"] = "modified"
        completed = self.codex_run(env=env)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("trustStatus=modified", completed.stderr)
        env = self.env.copy()
        env["STUB_ENABLED"] = "false"
        completed = self.codex_run(env=env)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("enabled=false", completed.stderr)
        self.assertFalse(self.argv_file.exists())

    def test_warnings_are_surfaced_not_fatal(self):
        env = self.env.copy()
        env["STUB_WARNINGS"] = '"some hooks/list warning"'
        completed = self.codex_run(env=env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("hooks/list warning: some hooks/list warning", completed.stderr)
        self.assertIn("guard armed", completed.stderr)

    def test_effort_flag_still_passes_through(self):
        completed = self.codex_run("-e", "ultra")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        values = self.c_values(self.exec_argv())
        self.assertIn('model_reasoning_effort="ultra"', values)
        self.assertTrue(any(v.startswith("hooks={") for v in values))

    def test_workspace_write_keeps_writable_roots(self):
        git = shutil.which("git")
        if git is None:
            self.skipTest("git is not installed")
        subprocess.run([git, "init", "-q", str(self.workdir)], check=True,
                       capture_output=True, timeout=SUBPROCESS_TIMEOUT)
        completed = self.codex_run(sandbox="workspace-write")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        argv = self.exec_argv()
        values = self.c_values(argv)
        self.assertTrue(any(v.startswith("sandbox_workspace_write.writable_roots=") for v in values), values)
        self.assertTrue(any(v.startswith("hooks={") for v in values), values)
        self.assertIn("--sandbox", argv)
        self.assertEqual(argv[argv.index("--sandbox") + 1], "workspace-write")

    def test_usage_errors_unchanged(self):
        completed = run([CODEX_RUN, "-H", self.codex_home, "-m", "m", "-C", self.workdir], env=self.env)
        self.assertEqual(completed.returncode, 2)
        self.assertRegex(completed.stderr, r"codex-run: missing -[pP]")  # pre-existing wording
        completed = self.codex_run("-p", self.tmp_path / "missing.md")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("prompt file not found", completed.stderr)
        self.assertFalse(self.argv_file.exists())

    def test_preflight_missing_codex_fails(self):
        env = self.env.copy()
        (self.tmp_path / "empty-bin").mkdir()
        env["PATH"] = os.pathsep.join([str(self.tmp_path / "empty-bin"), "/usr/bin", "/bin"])
        completed = run([GUARD, "preflight", "-H", self.codex_home, "-C", self.workdir], env=env)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("codex not found", completed.stderr)
        self.assertEqual(self.markers(), [])


class PreflightTests(GuardTestCase):
    """`codex-guard preflight` pipeline behavior with a stubbed codex: the
    scratch probe home, the config-aware cache key, fail-fast on an app-server
    that dies without answering, and the watchdog for one that wedges."""

    def setUp(self):
        super().setUp()
        self.stub_dir = self.tmp_path / "stubbin"
        self.stub_dir.mkdir()
        stub = self.stub_dir / "codex"
        stub.write_text(STUB_CODEX.replace("__KEY__", KEY), encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.env["PATH"] = "%s%s%s" % (self.stub_dir, os.pathsep, self.env["PATH"])
        self.info_file = self.tmp_path / "appserver-info.txt"
        self.env["STUB_APPSERVER_INFO"] = str(self.info_file)
        self.lane = self.tmp_path / "lane-home"
        self.lane.mkdir()
        self.workdir = self.tmp_path / "work"
        self.workdir.mkdir()

    def preflight(self, *extra, env=None, timeout=SUBPROCESS_TIMEOUT):
        return run([GUARD, "preflight", "-H", self.lane, "-C", self.workdir, *extra],
                   env=env or self.env, timeout=timeout)

    def info(self):
        text = self.info_file.read_text(encoding="utf-8").splitlines()
        return {
            "home": [l[len("CODEX_HOME="):] for l in text if l.startswith("CODEX_HOME=")][0],
            "args": [l[len("ARG="):] for l in text if l.startswith("ARG=")],
            "files": sorted(l[len("FILE="):] for l in text if l.startswith("FILE=")),
            "cfg": "\n".join(l[len("CFG="):] for l in text if l.startswith("CFG=")),
        }

    def markers(self):
        return sorted(self.cache_dir.glob("guard-ok-*")) if self.cache_dir.exists() else []

    def lane_snapshot(self):
        return {p.name: (p.read_bytes() if p.is_file() else sorted(q.name for q in p.iterdir()))
                for p in self.lane.iterdir()}

    def test_probe_runs_in_scratch_home_seeded_with_lane_config(self):
        (self.lane / "config.toml").write_text('model = "gpt-test"\n[features]\nhooks = true\n', encoding="utf-8")
        (self.lane / "hooks.json").write_text('{"hooks": {}}\n', encoding="utf-8")
        (self.lane / "auth.json").write_text('{"secret": "never-copied"}\n', encoding="utf-8")
        (self.lane / "state_5.sqlite").write_bytes(b"not a real db")
        (self.lane / "sessions").mkdir()
        before = self.lane_snapshot()
        completed = self.preflight()  # fresh cache dir: a real probe, marker written
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(completed.stdout.startswith("preflight: ok ("), completed.stdout)
        info = self.info()
        # Never the lane home; a scratch dir seeded with exactly the user-layer hook sources.
        self.assertNotEqual(Path(info["home"]).resolve(), self.lane.resolve())
        self.assertEqual(info["files"], ["config.toml", "hooks.json"])
        self.assertEqual(info["cfg"], 'model = "gpt-test"\n[features]\nhooks = true')
        self.assertFalse(Path(info["home"]).exists(), "scratch home must be removed afterwards")
        # Plugin-marketplace sync is switched off for the probe; our override is passed.
        self.assertIn("features.plugins=false", info["args"])
        override = run([GUARD, "override"], env=self.env).stdout.rstrip("\n")
        self.assertIn(override, info["args"])
        self.assertEqual(info["args"][0], "app-server")
        # The lane home is byte-for-byte untouched.
        self.assertEqual(self.lane_snapshot(), before)
        marker = self.markers()
        self.assertEqual(len(marker), 1)
        text = marker[0].read_text(encoding="utf-8")
        self.assertIn("home=%s" % self.lane.resolve(), text)
        self.assertRegex(text, r"config=[0-9a-f]{64}")

    def test_cache_key_covers_lane_config(self):
        (self.lane / "config.toml").write_text('model = "gpt-test"\n', encoding="utf-8")
        first = self.preflight()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue(first.stdout.startswith("preflight: ok ("), first.stdout)
        cached = self.preflight()
        self.assertTrue(cached.stdout.startswith("preflight: cached ok ("), cached.stdout)
        self.assertEqual(len(self.markers()), 1)
        # Editing the lane config (say, features.hooks = false) must re-verify.
        with open(self.lane / "config.toml", "a", encoding="utf-8") as fh:
            fh.write("[features]\nhooks = false\n")
        third = self.preflight()
        self.assertEqual(third.returncode, 0, third.stderr)  # the stub still says trusted
        self.assertTrue(third.stdout.startswith("preflight: ok ("), third.stdout)
        self.assertEqual(len(self.markers()), 2)
        # A hooks.json appearing also changes the key.
        (self.lane / "hooks.json").write_text("{}\n", encoding="utf-8")
        fourth = self.preflight()
        self.assertTrue(fourth.stdout.startswith("preflight: ok ("), fourth.stdout)
        self.assertEqual(len(self.markers()), 3)

    def test_no_cache_neither_reads_nor_writes(self):
        first = self.preflight()
        self.assertTrue(first.stdout.startswith("preflight: ok ("), first.stdout)
        marker = self.markers()
        self.assertEqual(len(marker), 1)
        before = (marker[0].read_bytes(), marker[0].stat().st_mtime_ns)
        # Not read: an untrusted answer fails even though a marker exists...
        env = self.env.copy()
        env["STUB_TRUST"] = "untrusted"
        completed = self.preflight("--no-cache", env=env)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("trustStatus=untrusted", completed.stderr)
        # ...and a trusted answer probes for real, without touching the cache.
        completed = self.preflight("--no-cache")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(completed.stdout.startswith("preflight: ok ("), completed.stdout)
        self.assertNotIn("cached", completed.stdout)
        marker = self.markers()
        self.assertEqual(len(marker), 1)
        self.assertEqual((marker[0].read_bytes(), marker[0].stat().st_mtime_ns), before)
        # A temp lane home checked with --no-cache leaves no orphan marker.
        temp_lane = self.tmp_path / "temp-lane"
        temp_lane.mkdir()
        completed = run([GUARD, "preflight", "--no-cache", "-H", temp_lane, "-C", self.workdir], env=self.env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(self.markers()), 1)

    def test_stale_markers_pruned_on_write(self):
        self.cache_dir.mkdir()
        stale = self.cache_dir / ("guard-ok-" + "0" * 64)
        stale.write_text("version=old\n", encoding="utf-8")
        old = time.time() - 40 * 86400
        os.utime(str(stale), (old, old))
        recent = self.cache_dir / ("guard-ok-" + "1" * 64)
        recent.write_text("version=recent\n", encoding="utf-8")
        unrelated = self.cache_dir / "guard-denials.log"
        unrelated.write_text("keep\n", encoding="utf-8")
        os.utime(str(unrelated), (old, old))
        completed = self.preflight()
        self.assertTrue(completed.stdout.startswith("preflight: ok ("), completed.stdout)
        self.assertFalse(stale.exists(), "marker older than 30 days must be pruned on write")
        self.assertTrue(recent.exists())
        self.assertTrue(unrelated.exists(), "only guard-ok-* markers are pruned")
        self.assertEqual(len(self.markers()), 2)

    def test_app_server_dying_without_answer_fails_fast(self):
        env = self.env.copy()
        env["STUB_APPSERVER_MODE"] = "dies"
        started = time.monotonic()
        completed = self.preflight("--no-cache", env=env)
        elapsed = time.monotonic() - started
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("exited without answering hooks/list", completed.stderr)
        self.assertIn("dying without answering", completed.stderr)  # app-server stderr tail surfaced
        self.assertLess(elapsed, 20, "must not wait out the full deadline")
        self.assertEqual(self.markers(), [])

    def test_wedged_app_server_is_killed_at_deadline(self):
        env = self.env.copy()
        env["STUB_APPSERVER_MODE"] = "hang"
        env["STUB_PID_FILE"] = str(self.tmp_path / "stub.pid")
        env["CODEX_GUARD_PREFLIGHT_TIMEOUT"] = "2"
        started = time.monotonic()
        completed = self.preflight("--no-cache", env=env)
        elapsed = time.monotonic() - started
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("no hooks/list response within 2s", completed.stderr)
        self.assertIn("app-server killed", completed.stderr)
        self.assertLess(elapsed, 20)
        stub_pid = int((self.tmp_path / "stub.pid").read_text().strip())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(stub_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            self.fail("stub app-server (pid %d) still alive" % stub_pid)
        # ...and its child (the wedged process holding stdout) is gone too.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            left = run(["/usr/bin/pgrep", "-f", "^sleep 977$"]).stdout.strip()
            if not left:
                break
            time.sleep(0.1)
        self.assertEqual(left, "", "orphaned app-server child left behind: %s" % left)
        self.assertEqual(self.markers(), [])

    def test_bad_timeout_env_is_rejected(self):
        env = self.env.copy()
        env["CODEX_GUARD_PREFLIGHT_TIMEOUT"] = "soon"
        completed = self.preflight("--no-cache", env=env)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("CODEX_GUARD_PREFLIGHT_TIMEOUT must be a positive integer", completed.stderr)
        self.assertFalse(self.info_file.exists(), "app-server must not have been started")

    def test_missing_lane_home_or_workdir_fails_clearly(self):
        completed = run([GUARD, "preflight", "-H", self.tmp_path / "nope", "-C", self.workdir], env=self.env)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("preflight: codex home not found", completed.stderr)
        self.assertFalse((self.tmp_path / "nope").exists())
        completed = run([GUARD, "preflight", "-H", self.lane, "-C", self.tmp_path / "nowhere"], env=self.env)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("preflight: workdir not found", completed.stderr)
        self.assertFalse(self.info_file.exists())


def real_codex():
    return shutil.which("codex")


@unittest.skipUnless(real_codex(), "no real codex on PATH")
class LiveCodexTests(GuardTestCase):
    """Integration against the installed codex; empty temp CODEX_HOME, no
    network or auth needed (app-server hooks/list only)."""

    def setUp(self):
        super().setUp()
        self.codex_home = self.tmp_path / "codex-home"
        self.codex_home.mkdir()
        self.workdir = self.tmp_path / "work"
        self.workdir.mkdir()

    def test_preflight_ok_against_installed_codex(self):
        completed = run(
            [GUARD, "preflight", "--no-cache", "-H", self.codex_home, "-C", self.workdir],
            env=self.env, timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue(completed.stdout.startswith("preflight: ok ("), completed.stdout)
        # --no-cache neither reads nor writes the cache.
        self.assertEqual(list(self.cache_dir.glob("guard-ok-*")) if self.cache_dir.exists() else [], [])
        fresh = run(
            [GUARD, "preflight", "-H", self.codex_home, "-C", self.workdir],
            env=self.env, timeout=120,
        )
        self.assertEqual(fresh.returncode, 0, fresh.stderr + fresh.stdout)
        self.assertTrue(fresh.stdout.startswith("preflight: ok ("), fresh.stdout)
        self.assertEqual(len(list(self.cache_dir.glob("guard-ok-*"))), 1)
        cached = run(
            [GUARD, "preflight", "-H", self.codex_home, "-C", self.workdir],
            env=self.env, timeout=120,
        )
        self.assertEqual(cached.returncode, 0, cached.stderr)
        self.assertTrue(cached.stdout.startswith("preflight: cached ok ("), cached.stdout)

    def test_preflight_leaves_lane_home_untouched(self):
        # Real codex writes its own state (sqlite DBs, installation_id,
        # .personality_migration, tmp/, and with plugins on a .tmp/ clone) into
        # whatever CODEX_HOME it starts with. The probe must run in a scratch
        # home so the lane home stays byte-for-byte as it was.
        (self.codex_home / "config.toml").write_text('model = "gpt-test"\n', encoding="utf-8")
        before = {p.name: p.read_bytes() for p in self.codex_home.iterdir()}
        scratch_root = self.tmp_path / "tmpdir"  # isolate the probe's mktemp from other lanes
        scratch_root.mkdir()
        env = self.env.copy()
        env["TMPDIR"] = str(scratch_root)
        completed = run(
            [GUARD, "preflight", "--no-cache", "-H", self.codex_home, "-C", self.workdir],
            env=env, timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertTrue(completed.stdout.startswith("preflight: ok ("), completed.stdout)
        after = {p.name: p.read_bytes() for p in self.codex_home.iterdir()}
        self.assertEqual(after, before)
        self.assertEqual(sorted(after), ["config.toml"])
        leftovers = sorted(scratch_root.glob("codex-guard-preflight.*"))
        self.assertEqual(leftovers, [], "scratch probe dirs must be cleaned up")

    def test_lane_config_disabling_hooks_fails_preflight(self):
        # The scratch probe is seeded with the lane's config.toml, so a lane
        # that switches the hooks feature off is caught (hook not listed) and
        # codex-run refuses to launch instead of running unguarded.
        (self.codex_home / "config.toml").write_text("[features]\nhooks = false\n", encoding="utf-8")
        completed = run(
            [GUARD, "preflight", "--no-cache", "-H", self.codex_home, "-C", self.workdir],
            env=self.env, timeout=120,
        )
        self.assertEqual(completed.returncode, 1, completed.stderr + completed.stdout)
        self.assertIn("hook not listed under key %s" % KEY, completed.stderr)
        self.assertEqual(list(self.cache_dir.glob("guard-ok-*")), [])

    def test_hooks_list_hash_matches_codex_guard_hash(self):
        override = run([GUARD, "override"], env=self.env).stdout.rstrip("\n")
        expected = run([GUARD, "hash"], env=self.env).stdout.strip()
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"clientInfo": {"name": "test", "title": "test", "version": "0.0.1"}}},
            {"jsonrpc": "2.0", "method": "initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "hooks/list",
             "params": {"cwds": [str(self.workdir)]}},
        ]
        env = self.env.copy()
        env["CODEX_HOME"] = str(self.codex_home)
        stderr_path = self.tmp_path / "app-server.err"
        response = {}
        got = threading.Event()
        with open(stderr_path, "w", encoding="utf-8") as stderr_file:
            proc = subprocess.Popen(
                [real_codex(), "app-server", "-c", "features.plugins=false", "-c", override],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr_file,
                text=True, env=env, cwd=str(self.workdir),
            )

        def reader():
            # Drain stdout to EOF so app-server never blocks on a full pipe.
            for line in proc.stdout:
                try:
                    parsed = json.loads(line)
                except ValueError:
                    continue
                if isinstance(parsed, dict) and parsed.get("id") == 2 and not got.is_set():
                    response.update(parsed)
                    got.set()

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        try:
            proc.stdin.write("".join(json.dumps(m) + "\n" for m in messages))
            proc.stdin.flush()
            got.wait(timeout=90)
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
            thread.join(timeout=10)
            proc.stdout.close()
        self.assertTrue(
            got.is_set(),
            "no hooks/list response: %s" % stderr_path.read_text(encoding="utf-8")[-2000:],
        )
        hooks = response["result"]["data"][0]["hooks"]
        ours = [h for h in hooks if h["key"] == KEY]
        self.assertEqual(len(ours), 1, hooks)
        self.assertEqual(ours[0]["currentHash"], expected)
        self.assertEqual(ours[0]["trustStatus"], "trusted")
        self.assertIs(ours[0]["enabled"], True)
        self.assertEqual(ours[0]["command"], str(ARMED_HOOK))
        self.assertEqual(ours[0]["source"], "sessionFlags")


if __name__ == "__main__":
    unittest.main()
