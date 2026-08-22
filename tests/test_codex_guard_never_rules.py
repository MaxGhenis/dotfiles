"""Tests for the 2026-08-19 never-rules port in bin/codex-guard-hook.

Covers what test_codex_guard.py does not: the seven NEVER-rule blocks ported
verbatim from ~/.claude/hooks/guard-never-rules.sh (tg-getupdates,
keychain-dump, trust-root, corpus-squash, corpus-push, stash-shared,
local-main), the hf-dest adapter (freeform apply_patch payloads and the Bash
heredoc form), the codex-lane deny suffix for Bash commands carrying a patch
body, per-rule byte-identity drift pins, Claude/codex decision parity,
codex-guard's --matcher/--status/--tool/- additions, and codex-run's -b
main|master refusal and CODEX_RUN_UNIFIED_EXEC opt-out.

Runs under pytest and plain unittest next to test_codex_guard.py (python
3.9+), importing its helpers and path/identity constants:

    /opt/homebrew/bin/pytest -q ~/dotfiles/tests/test_codex_guard.py \
        ~/dotfiles/tests/test_codex_guard_never_rules.py
    python3 -m unittest discover -s ~/dotfiles/tests -p 'test_codex_guard*.py'

Candidate copies are honored through the same env overrides
(CODEX_GUARD_HOOK, CLAUDE_GUARD_HOOK). Documented gaps and accepted false
positives are pinned AS THEY BEHAVE TODAY in test_documented_gaps_and_fps
(and marked in the corpus), so a Claude-side rule change surfaces here
deliberately instead of silently. Until the guard-portback ~/.claude install
lands, [unscoped-search] deny REASONS differ between the hooks (the installed
Claude hook still carries the old region text), so the parity reason-prefix
check for that one tag is gated on CLAUDE_PORTBACK_LANDED; decisions and rule
tags are compared unconditionally.
"""
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

from test_codex_guard import (
    CLAUDE_HOOK,
    CLAUDE_PORTBACK_LANDED,
    CODEX_RUN,
    GUARD,
    HOOK,
    KEY,
    MATCHER,
    PENDING_CLAUDE_INSTALL,
    PINNED_HASH,
    PINNED_HASH_V2,
    PINNED_HOOK_PATH,
    REGION_BEGIN,
    REGION_END,
    STATUS_MESSAGE,
    SUBPROCESS_TIMEOUT,
    GuardTestCase,
    hook_reason,
    python_trust_hash,
    run,
)

RULES = (
    "tg-getupdates",
    "keychain-dump",
    "trust-root",
    "corpus-squash",
    "corpus-push",
    "stash-shared",
    "local-main",
)

HEREDOC_NOTE = (
    " [codex lane: this shell command carries an apply_patch body; the patch "
    "text was judged as shell text, as the Claude hook judges Bash heredocs. "
    "Use the apply_patch tool for file edits.]"
)

HF_FENCE_BEGIN = "# --- codex-lane additions (hf-dest via shell heredoc): begin ---"
HF_FENCE_END = "# --- codex-lane additions (hf-dest via shell heredoc): end ---"


def payload(command, cwd, tool_name="Bash", tool_input=None):
    return json.dumps(
        {
            "session_id": "s",
            "turn_id": "t",
            "tool_use_id": "u",
            "hook_event_name": "PreToolUse",
            "permission_mode": "never",
            "tool_name": tool_name,
            "cwd": cwd,
            "tool_input": tool_input if tool_input is not None else {"command": command},
        }
    )


def rule_tag(reason):
    m = re.match(r"^(\[[^\]]+\])", reason)
    return m.group(1) if m else ""


def edit_payload(file_path, new_string, cwd="/tmp"):
    return payload(
        None, cwd, tool_name="Edit",
        tool_input={"file_path": file_path, "old_string": "x", "new_string": new_string},
    )


def write_payload(file_path, content, cwd="/tmp"):
    return payload(
        None, cwd, tool_name="Write",
        tool_input={"file_path": file_path, "content": content},
    )


def patch_for_edit(file_path, new_string):
    lines = ["*** Begin Patch", "*** Update File: %s" % file_path, "@@"]
    lines += ["+%s" % l for l in new_string.split("\n")]
    lines.append("*** End Patch")
    return "\n".join(lines)


def patch_for_write(file_path, content):
    lines = ["*** Begin Patch", "*** Add File: %s" % file_path]
    lines += ["+%s" % l for l in content.split("\n")]
    lines.append("*** End Patch")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fixtures (ASSESSMENT-DECISIONS D6): built fresh per test class in
# setUpClass; treated as immutable afterwards.
# ---------------------------------------------------------------------------

def _git(cwd, *args):
    subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True, capture_output=True, timeout=SUBPROCESS_TIMEOUT,
    )


def build_fixtures(root):
    root = Path(root)
    fx = {}
    # plain: single worktree, no origin, on main
    fx["plain"] = root / "plain"
    fx["plain"].mkdir()
    _git(fx["plain"], "init", "-q", "-b", "main")
    _git(fx["plain"], "commit", "-q", "--allow-empty", "-m", "init")
    # shared + shared-wt2
    fx["shared"] = root / "shared"
    fx["shared"].mkdir()
    _git(fx["shared"], "init", "-q", "-b", "main")
    _git(fx["shared"], "commit", "-q", "--allow-empty", "-m", "init")
    _git(fx["shared"], "worktree", "add", "-q", str(root / "shared-wt2"), "-b", "wt2")
    fx["shared-wt2"] = root / "shared-wt2"
    # withorigin: clone of a bare origin; branch other; + worktrees
    origin = root / "origin.git"
    origin.mkdir()
    _git(origin, "init", "-q", "--bare", "-b", "main")
    seed = root / "seed"
    seed.mkdir()
    _git(seed, "init", "-q", "-b", "main")
    _git(seed, "commit", "-q", "--allow-empty", "-m", "init")
    _git(seed, "remote", "add", "origin", str(origin))
    _git(seed, "push", "-q", "origin", "main")
    subprocess.run(["git", "clone", "-q", str(origin), str(root / "withorigin")],
                   check=True, capture_output=True, timeout=SUBPROCESS_TIMEOUT)
    fx["withorigin"] = root / "withorigin"
    _git(fx["withorigin"], "branch", "other")
    _git(fx["withorigin"], "worktree", "add", "-q", str(root / "withorigin-wt"),
         "-b", "lane/x", "origin/main")
    fx["withorigin-wt"] = root / "withorigin-wt"
    _git(fx["withorigin"], "worktree", "add", "-q", "--detach",
         str(root / "withorigin-detached"), "origin/main")
    fx["withorigin-detached"] = root / "withorigin-detached"
    # upstreamclone: clone of a bare fork, plus an `upstream` remote (the org)
    org = root / "org.git"
    org.mkdir()
    _git(org, "init", "-q", "--bare", "-b", "main")
    seed2 = root / "seed2"
    seed2.mkdir()
    _git(seed2, "init", "-q", "-b", "main")
    _git(seed2, "commit", "-q", "--allow-empty", "-m", "init")
    _git(seed2, "remote", "add", "origin", str(org))
    _git(seed2, "push", "-q", "origin", "main")
    subprocess.run(["git", "clone", "-q", "--bare", str(org), str(root / "fork.git")],
                   check=True, capture_output=True, timeout=SUBPROCESS_TIMEOUT)
    subprocess.run(["git", "clone", "-q", str(root / "fork.git"), str(root / "upstreamclone")],
                   check=True, capture_output=True, timeout=SUBPROCESS_TIMEOUT)
    fx["upstreamclone"] = root / "upstreamclone"
    _git(fx["upstreamclone"], "remote", "add", "upstream", str(org))
    _git(fx["upstreamclone"], "fetch", "-q", "upstream")
    # corpus (+ worktree on lane/y), rulespec, pe
    fx["corpus"] = root / "corpus"
    fx["corpus"].mkdir()
    _git(fx["corpus"], "init", "-q", "-b", "main")
    _git(fx["corpus"], "commit", "-q", "--allow-empty", "-m", "init")
    _git(fx["corpus"], "remote", "add", "origin",
         "https://github.com/TheAxiomFoundation/axiom-corpus.git")
    _git(fx["corpus"], "worktree", "add", "-q", str(root / "corpus-wt"), "-b", "lane/y")
    fx["corpus-wt"] = root / "corpus-wt"
    fx["rulespec"] = root / "rulespec"
    fx["rulespec"].mkdir()
    _git(fx["rulespec"], "init", "-q", "-b", "main")
    _git(fx["rulespec"], "commit", "-q", "--allow-empty", "-m", "init")
    _git(fx["rulespec"], "remote", "add", "origin",
         "https://github.com/TheAxiomFoundation/rulespec-us.git")
    fx["pe"] = root / "pe"
    fx["pe"].mkdir()
    _git(fx["pe"], "init", "-q", "-b", "main")
    _git(fx["pe"], "commit", "-q", "--allow-empty", "-m", "init")
    _git(fx["pe"], "remote", "add", "origin",
         "https://github.com/PolicyEngine/policyengine-us.git")
    # nonrepo + uk-data tree
    fx["nonrepo"] = root / "nonrepo"
    fx["nonrepo"].mkdir()
    fx["pe_dir"] = root / "PolicyEngine"
    fx["uk"] = fx["pe_dir"] / "policyengine-uk-data"
    fx["uk"].mkdir(parents=True)
    fx["ukwt"] = fx["pe_dir"] / "_worktrees" / "uk-data-f1"
    fx["ukwt"].mkdir(parents=True)
    return fx


# ---------------------------------------------------------------------------
# Per-rule Bash decision corpora: (cwd_key, command, expect, parity)
#   expect  "allow" or "[rule]"
#   parity  include in ParityTests (False for codex-only semantics: the
#           hf-dest heredoc/base-dir shapes the Claude hook cannot see)
# BASH_CASES holds the intended behavior; BASH_DOCUMENTED pins accepted false
# positives (denies) and documented gaps (allows) exactly as they behave
# today, so any Claude-side change to a rule block surfaces here on purpose.
# ---------------------------------------------------------------------------

HD = "\n".join  # heredoc/multiline helper

STASH_HEREDOC = HD([
    "apply_patch <<'EOF'",
    "*** Begin Patch",
    "*** Update File: README.md",
    "@@",
    "-old",
    "+run git stash",
    "*** End Patch",
    "EOF",
])

UNSCOPED_HEREDOC = HD([
    "apply_patch <<'EOF'",
    "*** Begin Patch",
    "*** Update File: notes.md",
    "@@",
    "+Do not run: find /Users/maxghenis -name x",
    "*** End Patch",
    "EOF",
])

BASH_CASES = (
    # --- tg-getupdates ---
    ("plain", "curl -s https://api.telegram.org/bot123/getUpdates", "[tg-getupdates]", True),
    ("plain", 'curl -s "$TG_API/getUpdates?offset=1"', "[tg-getupdates]", True),
    ("plain", 'python -c "bot.get_updates(timeout=30)"', "[tg-getupdates]", True),
    ("plain", 'curl -s "https://api.telegram.org/bot$T/getUpdates?offset=-1"', "[tg-getupdates]", True),
    ("plain", "curl https://api.telegram.org/bot123/getUpdates 2>/dev/null | jq .", "[tg-getupdates]", True),
    ("plain", HD(["python - <<'EOF'", "bot.get_updates()", "EOF"]), "[tg-getupdates]", True),
    ("plain", "curl -s https://api.telegram.org/bot123/sendMessage -d chat_id=1 -d text=hi", "allow", True),
    ("plain", 'git commit -m "docs: NEVER call Telegram getUpdates from agents"', "allow", True),
    ("plain", "curl -s https://api.telegram.org/bot123/getMe", "allow", True),
    ("plain", "curl -X POST https://api.telegram.org/bot123/setWebhook -d url=x", "allow", True),
    ("plain", 'grep -rn "get_updates(" src/', "allow", True),
    ("plain", "rg -n getUpdates docs/", "allow", True),
    ("plain", "git log --grep getUpdates", "allow", True),
    ("plain", 'git commit -m "docs: never call getUpdates"', "allow", True),
    # --- keychain-dump ---
    ("plain", "security dump-keychain -d", "[keychain-dump]", True),
    ("plain", "security dump-keychain -d login.keychain-db", "[keychain-dump]", True),
    ("plain", "security dump-keychain -a -d", "[keychain-dump]", True),
    ("plain", 'security dump-keychain -d "$HOME/Library/Keychains/login.keychain-db"', "[keychain-dump]", True),
    ("plain", HD(["echo x", "security dump-keychain -d"]), "[keychain-dump]", True),
    ("plain", "sudo security dump-keychain -d", "[keychain-dump]", True),
    ("plain", "security dump-keychain -d /tmp/scratch.keychain", "allow", True),
    ("plain", "security find-generic-password -s claude-env -w", "allow", True),
    ("plain", "security list-keychains -d user", "allow", True),
    ("plain", "security dump-keychain | head", "allow", True),
    ("plain", "security dump-keychain -a", "allow", True),
    ("plain", "agent-secret get OPENAI_API_KEY", "allow", True),
    # --- trust-root ---
    ("plain", "gh variable set AXIOM_CORPUS_RELEASE_PUBLIC_KEY --org TheAxiomFoundation --body abc", "[trust-root]", True),
    ("plain", "gh variable delete AXIOM_ENCODE_APPLY_SIGNING_PUBLIC_KEY --org TheAxiomFoundation", "[trust-root]", True),
    ("plain", "gh api orgs/TheAxiomFoundation/actions/variables/AXIOM_CORPUS_RELEASE_PUBLIC_KEY -X PATCH -f value=new", "[trust-root]", True),
    ("plain", "gh api -XPATCH orgs/TheAxiomFoundation/actions/variables/AXIOM_CORPUS_RELEASE_PUBLIC_KEY -f value=x", "[trust-root]", True),
    ("plain", "gh api --method PUT orgs/TheAxiomFoundation/actions/variables/AXIOM_X_PUBLIC_KEY -f value=x", "[trust-root]", True),
    ("plain", "gh api -X POST orgs/O/actions/variables -f name=AXIOM_X_PUBLIC_KEY -f value=new", "[trust-root]", True),
    ("plain", "GH_TOKEN=x gh api -X DELETE orgs/o/actions/variables/AXIOM_X_PUBLIC_KEY", "[trust-root]", True),
    ("plain", "curl -X PATCH https://api.github.com/orgs/O/actions/variables/AXIOM_X_PUBLIC_KEY -d x", "[trust-root]", True),
    ("plain", "gh variable list --org TheAxiomFoundation | grep AXIOM_CORPUS_RELEASE_PUBLIC_KEY", "allow", True),
    ("plain", "gh api orgs/TheAxiomFoundation/actions/variables/AXIOM_CORPUS_RELEASE_PUBLIC_KEY --jq .value", "allow", True),
    ("plain", "AXIOM_CORPUS_RELEASE_PUBLIC_KEY=$(gh variable get AXIOM_CORPUS_RELEASE_PUBLIC_KEY --org TheAxiomFoundation) python verify.py", "allow", True),
    ("plain", "gh variable get AXIOM_X_PUBLIC_KEY --org O", "allow", True),
    # --- corpus-squash ---
    ("corpus", "gh pr merge 42 --squash", "[corpus-squash]", True),
    ("corpus", "gh pr merge 42 -s --delete-branch", "[corpus-squash]", True),
    ("corpus", "gh pr merge 42 --auto --squash", "[corpus-squash]", True),
    ("corpus", "gh pr merge 42 --squash --admin", "[corpus-squash]", True),
    ("corpus", "gh pr merge https://github.com/TheAxiomFoundation/axiom-corpus/pull/42 --squash", "[corpus-squash]", True),
    ("corpus", HD(["gh pr checks 42", "gh pr merge 42 --squash"]), "[corpus-squash]", True),
    ("corpus-wt", "gh pr merge 42 --squash", "[corpus-squash]", True),
    ("plain", "gh pr merge 7 --squash -R TheAxiomFoundation/rulespec-us", "[corpus-squash]", True),
    ("plain", "gh pr merge 42 --squash -R github.com/TheAxiomFoundation/axiom-corpus", "[corpus-squash]", True),
    ("plain", "gh pr merge -R TheAxiomFoundation/rulespec-uk 3 -s", "[corpus-squash]", True),
    ("plain", "gh pr merge 3 --squash --repo TheAxiomFoundation/rulespec-uk", "[corpus-squash]", True),
    ("corpus", "gh pr merge 42 --merge", "allow", True),
    ("corpus", "gh pr merge 42 --merge --auto", "allow", True),
    ("corpus", "gh pr merge 42 -m", "allow", True),
    ("corpus", "gh pr merge 42 --squash -R PolicyEngine/policyengine-us", "allow", True),
    ("plain", "gh pr merge 42 --squash", "allow", True),
    ("pe", "gh pr merge 99 --squash", "allow", True),
    # --- corpus-push ---
    ("corpus", "git push origin main", "[corpus-push]", True),
    ("corpus", "git push origin feature:main", "[corpus-push]", True),
    ("corpus", "git push", "[corpus-push]", True),
    ("corpus", "git push --force-with-lease origin main", "[corpus-push]", True),
    ("corpus", "git push -f origin HEAD:main", "[corpus-push]", True),
    ("corpus", "git push https://github.com/TheAxiomFoundation/axiom-corpus.git HEAD:main", "[corpus-push]", True),
    ("corpus", "git push origin feat && git push origin feat:main", "[corpus-push]", True),
    ("corpus-wt", "git push origin lane/y:main", "[corpus-push]", True),
    ("corpus-wt", "git push origin HEAD:main", "[corpus-push]", True),
    ("corpus-wt", "git push --force origin HEAD:main", "[corpus-push]", True),
    ("corpus-wt", "git push --dry-run origin main", "[corpus-push]", True),
    ("corpus", "git push origin my-branch", "allow", True),
    ("corpus", "git push -u origin fix/thing", "allow", True),
    ("corpus", "git push origin v1.2.3", "allow", True),
    ("corpus", "cd ../corpus-wt && git push -u origin lane/y", "allow", True),
    ("corpus-wt", "git push origin HEAD", "allow", True),
    ("corpus-wt", "git push", "allow", True),
    ("corpus-wt", "git push -u origin HEAD", "allow", True),
    ("corpus-wt", "git push origin HEAD:refs/heads/lane/y", "allow", True),
    ("corpus-wt", "git push origin :lane/y", "allow", True),
    ("corpus-wt", "git push origin --delete lane/y", "allow", True),
    ("corpus-wt", "git push --force-with-lease origin lane/y", "allow", True),
    ("corpus-wt", "git push origin lane/y && gh pr create --fill", "allow", True),
    ("plain", "git push origin main", "allow", True),
    ("rulespec", "git push origin main", "allow", True),
    ("pe", "git push origin main", "allow", True),
    # --- stash-shared ---
    ("shared", "git stash pop", "[stash-shared]", True),
    ("shared-wt2", "git stash push -m wip", "[stash-shared]", True),
    ("withorigin-wt", "git stash", "[stash-shared]", True),
    ("withorigin-wt", "git stash push -m wip", "[stash-shared]", True),
    ("withorigin-wt", "git stash pop", "[stash-shared]", True),
    ("withorigin-wt", "git stash apply abc1234", "[stash-shared]", True),
    ("withorigin-wt", "git stash -u && git pull --rebase && git stash pop", "[stash-shared]", True),
    ("withorigin-wt", "git stash show -p", "[stash-shared]", True),
    ("withorigin-wt", "git stash | cat", "[stash-shared]", True),
    ("withorigin-detached", "git stash", "[stash-shared]", True),
    ("shared", "git stash list", "allow", True),
    ("plain", "git stash", "allow", True),
    ("withorigin-wt", "git stash list", "allow", True),
    ("withorigin-wt", "git pull --rebase --autostash", "allow", True),
    ("withorigin-wt", "git rebase --autostash origin/main", "allow", True),
    ("withorigin-wt", "git -c rebase.autoStash=true pull --rebase", "allow", True),
    ("withorigin-wt", "git commit -F msg.txt", "allow", True),
    ("withorigin-wt", "git add stash_utils.py", "allow", True),
    ("nonrepo", "git stash", "allow", True),
    # --- local-main ---
    ("withorigin", "git checkout -b feat main", "[local-main]", True),
    ("withorigin", "git switch -c feat main", "[local-main]", True),
    ("withorigin", "git checkout -b feat", "[local-main]", True),
    ("withorigin", "git checkout -b feat && git push -u origin feat", "[local-main]", True),
    ("withorigin", "git checkout -b feat; git status", "[local-main]", True),
    ("withorigin", "git checkout -b feat main 2>&1", "[local-main]", True),
    ("withorigin", "git -C . checkout -b feat main", "[local-main]", True),
    ("withorigin", "git switch -c feat master", "[local-main]", True),
    ("withorigin-wt", "git checkout -b sub main", "[local-main]", True),
    ("withorigin-detached", "git checkout -b sub main", "[local-main]", True),
    ("withorigin", "git fetch origin && git checkout -b feat origin/main", "allow", True),
    ("withorigin", "git checkout -b feat origin/main", "allow", True),
    ("withorigin", "git checkout -b feat -t origin/main", "allow", True),
    ("withorigin", "git checkout --track -b feat origin/main", "allow", True),
    ("withorigin", "git checkout -b feat origin/main --no-track", "allow", True),
    ("withorigin", "git checkout -b feat upstream/main", "allow", True),
    ("withorigin", "git checkout -b feat $(git rev-parse origin/main)", "allow", True),
    ("withorigin", "git checkout -b feat main~3", "allow", True),
    ("withorigin", "git checkout -b feat refs/remotes/origin/main", "allow", True),
    ("withorigin", 'git checkout -b "feat/x y" origin/main', "allow", True),
    ("withorigin", "git checkout -b feat origin/main 2>&1 | tail -1", "allow", True),
    ("withorigin", "git worktree add ../wt -b x origin/main", "allow", True),
    ("withorigin", "git worktree add -b x ../wt origin/main", "allow", True),
    ("withorigin", "git worktree add -b x ../wt", "allow", True),
    ("withorigin", "git worktree add ../wt -b x", "allow", True),
    ("withorigin", "git worktree add --detach ../wt origin/main", "allow", True),
    ("withorigin", 'git commit -m "never git checkout -b x main"', "allow", True),  # prose
    ("withorigin-wt", "git checkout -b sub/feature", "allow", True),
    ("withorigin-wt", "git checkout -b feat2", "allow", True),  # bare -b on a feature branch
    ("withorigin-wt", "git switch -c sub/feature", "allow", True),
    ("withorigin-wt", "git fetch origin && git checkout -b sub origin/main && git push -u origin sub", "allow", True),
    ("withorigin-detached", "git checkout -b feat", "allow", True),
    ("withorigin-detached", "git switch -c feat", "allow", True),
    ("upstreamclone", "git fetch upstream && git checkout -b feat upstream/main", "allow", True),
    ("upstreamclone", "git switch -c feat upstream/main", "allow", True),
    ("upstreamclone", "git worktree add ../wt -b feat upstream/main", "allow", True),
    ("nonrepo", "git checkout -b feat main", "allow", True),
    ("plain", "git checkout -b feat main", "allow", True),
    # --- unscoped-search (both-hook subset; the full corpus lives in
    # test_codex_guard.py) + rule ORDER proof ---
    ("plain", "find ~/TheAxiomFoundation -name x", "[unscoped-search]", True),
    ("plain", "grep -rn pattern ~/PolicyEngine", "[unscoped-search]", True),
    ("plain", 'rg -l "13 passed" /tmp /private/tmp', "[unscoped-search]", True),
    ("plain", "find ~/TheAxiomFoundation -maxdepth 2 -type d -name releases", "allow", True),
    ("plain", "rg -n TODO ~/TheAxiomFoundation/axiom-claude", "allow", True),
    ("plain", 'find . -name "*.rac"', "allow", True),
    ("plain", "grep pattern /tmp/build.log", "allow", True),
    ("plain", 'find src -name "*.py"', "allow", True),
    ("plain", "grep -rn pattern ~/PolicyEngine/populace/src", "allow", True),
    ("corpus", "git push origin main && find ~ -name x", "[corpus-push]", True),  # rule order proof
    # heredoc bodies are judged as shell text (D2; pinned in both hooks)
    ("shared", STASH_HEREDOC, "[stash-shared]", True),
    ("plain", STASH_HEREDOC, "allow", True),
    ("plain", UNSCOPED_HEREDOC, "[unscoped-search]", True),
    # --- innocent traffic ---
    ("plain", "ls -la", "allow", True),
    ("plain", "git status", "allow", True),
    # --- Bash-form hf-dest (codex-only semantics; skipped by ParityTests) ---
    ("pe_dir", HD(["cd policyengine-uk-data && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    ("pe_dir", HD(["cd 'policyengine-uk-data' && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    ("pe_dir", HD(["true; cd policyengine-uk-data && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    ("pe_dir", HD(["cd policyengine-uk-data; apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    ("pe_dir", HD(["pushd policyengine-uk-data && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    # `applypatch` (no underscore) is the other PATH alias arg0 installs; the
    # hook keys on `*** Begin Patch` + cd targets, so the spelling is judged the
    # same (D6 also pins the quoted-absolute cd form — see the hardening class).
    ("pe_dir", HD(["cd 'policyengine-uk-data' && applypatch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    # cd end-of-options terminator: `cd -- <dir>` and `cd -L <dir>` — the target
    # must still be recovered (regression pin: the operand used to be lost to the
    # `--`/option token, so an in-scope heredoc slipped through as allow).
    ("pe_dir", HD(["cd -- policyengine-uk-data && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    ("pe_dir", HD(["cd -L -- policyengine-uk-data && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    # backslash forms (sol adjudication 2026-08-20): `\cd` disables an alias but still
    # runs cd, and `uk\-data` is an escaped spelling of the real dir — both must be caught.
    ("pe_dir", HD(["true; \\cd policyengine-uk-data && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    ("pe_dir", HD(["true; cd policyengine-uk\\-data && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),
    # glob target needs filesystem resolution — a documented gap (like `cd $VAR`).
    ("pe_dir", HD(["true; cd policyengine-uk-dat? && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "allow", False),
    ("uk", HD(["apply_patch <<'EOF'", "*** Begin Patch", "*** Update File: upload.py",
               "@@", "+repo_id=1", "*** End Patch", "EOF && git add -A"]), "[hf-dest]", False),
    ("uk", HD(["echo x; apply_patch <<'EOF'", "*** Begin Patch",
               "*** Update File: policyengine_uk_data/upload.py", "@@", "+repo_id=1",
               "*** End Patch", "EOF"]), "[hf-dest]", False),
    ("uk", HD(["apply_patch <<'EOF'", "*** Begin Patch", "*** Update File: other.py", "@@",
               "+nothing", "*** End Patch", "EOF; apply_patch <<'EOF'", "*** Begin Patch",
               "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "[hf-dest]", False),  # two patches; only the second touches uk-data
    ("uk", 'echo "*** Begin Patch"', "allow", True),
    ("plain", HD(["cd /tmp/nowhere-such && apply_patch <<'EOF'", "*** Begin Patch",
                  "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "allow", False),  # cd target outside uk-data
)

# Accepted false positives (deny) and documented gaps (allow), pinned as they
# behave TODAY. Fixing any of these starts at the Claude hook (the source of
# truth; see the Claude-side follow-ups list in bin/README-codex-guard.md),
# after which this pin is updated deliberately in the same change.
BASH_DOCUMENTED = (
    # tg-getupdates
    ("plain", 'grep -n "\\.get_updates(" src/bot.py', "[tg-getupdates]", True),  # FP: prose/pattern
    ("plain", "curl -s https://api.telegram.org/bot123/getupdates", "allow", True),  # gap: lowercase
    ("plain", 'python -c "app.run_polling()"', "allow", True),  # gap: polling wrapper
    ("plain", 'node -e "bot.getUpdates()"', "allow", True),  # gap: no URL/telegram context
    # keychain-dump
    ("plain", "security dump-keychain '-d'", "allow", True),  # gap: quoted flag
    ("plain", "security dump-keychain -d /Users/x/Library/Keychains/login.keychain-db ~/Library/Keychains/other.keychain", "allow", True),  # gap: second keychain masks login
    # trust-root
    ("plain", "curl --request PATCH https://api.github.com/orgs/O/actions/variables/AXIOM_X_PUBLIC_KEY -d x", "allow", True),  # gap: --request
    ("plain", "gh api orgs/O/actions/variables -f name=AXIOM_X_PUBLIC_KEY --field value=new", "allow", True),  # gap: --field
    ("plain", "gh secret set AXIOM_X_PUBLIC_KEY --org O --body y", "allow", True),  # gap: secret set
    # corpus-squash
    ("corpus", "gh pr merge 42 --rebase", "allow", True),  # documented: decide per .github#39 rule 6
    ("corpus", "gh pr merge 42 --squash=true", "allow", True),  # gap: = form
    ("corpus", "gh pr merge 42 -sd", "allow", True),  # gap: combined short flags
    ("corpus", "gh api -X PUT repos/TheAxiomFoundation/axiom-corpus/pulls/42/merge -f merge_method=squash", "allow", True),  # gap: API merge
    ("plain", "gh pr merge 99 --squash --repo=TheAxiomFoundation/axiom-corpus", "allow", True),  # gap: --repo=
    ("plain", "GH_REPO=TheAxiomFoundation/axiom-corpus gh pr merge 42 --squash", "allow", True),  # gap: GH_REPO env
    # corpus-push
    ("corpus", "git push --tags origin", "[corpus-push]", True),  # FP: bare-push path on main
    ("corpus", "git push myfork main", "[corpus-push]", True),  # FP: remote name not checked
    ("corpus", "cd ../corpus-wt && git push origin HEAD", "[corpus-push]", True),  # FP: payload cwd wins
    ("corpus", HD(["git add -A", "git commit -m wip", "git push origin main"]), "allow", True),  # gap: multi-line (tokenizer)
    ("corpus", "git -C . push origin main", "allow", True),  # gap: needs `git push` adjacency
    ("corpus", "git -c push.default=current push origin main", "allow", True),  # gap
    ("corpus", "git --no-pager push origin main", "allow", True),  # gap
    ("corpus", "git push origin 'main'", "allow", True),  # gap: quoted refspec
    ("corpus", "git push -f origin HEAD:refs/heads/main", "allow", True),  # gap: qualified refspec
    ("corpus", "git push origin HEAD:refs/heads/main", "allow", True),  # gap
    ("corpus", "git push -o ci.skip origin main", "allow", True),  # gap: -o value read as remote
    ("rulespec", "cd ../corpus && git push origin main", "allow", True),  # gap: cwd-only repo identity
    # stash-shared
    ("withorigin-wt", "git -C ../plain stash", "[stash-shared]", True),  # FP: payload cwd wins
    ("withorigin-wt", 'git commit -m "remove git stash usage from CI"', "[stash-shared]", True),  # FP: prose
    ("withorigin-wt", "git log --grep stash", "[stash-shared]", True),  # FP: prose
    ("withorigin-wt", "git diff -- src/stash.py", "[stash-shared]", True),  # FP: pathname
    ("withorigin-wt", "git stash list && git stash pop", "allow", True),  # gap: list exemption is whole-command
    ("withorigin-wt", HD(["git stash list", "git stash pop"]), "allow", True),  # gap
    ("plain", "cd ../shared-wt2 && git stash", "allow", True),  # gap: payload cwd wins
    ("plain", "git -C ../shared-wt2 stash", "allow", True),  # gap
    # local-main
    ("withorigin", "cd ../withorigin-wt && git checkout -b sub2", "[local-main]", True),  # FP: payload cwd wins
    ("withorigin", "git -C ../withorigin-wt checkout -b sub2", "[local-main]", True),  # FP
    ("withorigin", "git checkout -b feat origin/main && git checkout -b feat2", "[local-main]", True),  # FP: second -b
    ("upstreamclone", "git checkout -b feat", "[local-main]", True),  # documented false advice: names origin/main (stale fork)
    ("withorigin", "git checkout -b feat HEAD", "allow", True),  # gap: HEAD-on-main
    ("withorigin", "git worktree add ../wt -b x main", "allow", True),  # gap: worktree add form
    ("withorigin", "git checkout -q -b feat", "allow", True),  # gap: -q before -b
    ("withorigin", "git switch --create feat", "allow", True),  # gap: long flag
    ("withorigin", "git branch feat && git checkout feat", "allow", True),  # gap: two-step
    ("withorigin", "git checkout -B feat main", "allow", True),  # gap: -B
    ("withorigin", "git checkout -b feat 'main'", "allow", True),  # gap: quoted start point
    ("nonrepo", "cd ../withorigin && git checkout -b feat", "allow", True),  # gap: payload cwd wins
    # hf-dest (Bash side; the outcome without an apply_patch edit)
    ("pe_dir", HD(['UK=policyengine-uk-data; cd "$UK" && apply_patch <<\'EOF\'', "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "allow", False),  # gap: `cd $VAR` — a shell variable target can't be resolved from the text
    ("pe_dir", HD(["UK=policyengine-uk-data", "cd ${UK} && apply_patch <<'EOF'", "*** Begin Patch",
                   "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"]),
     "allow", False),  # gap: `cd ${VAR}` — same
    ("uk", "apply_patch < fix.patch", "allow", True),  # gap: patch text not in payload
    ("uk", "sed -i '' 's#policyengine/uk-data#evil/x#' policyengine_uk_data/upload.py", "allow", True),  # gap: shell write
    ("uk", "hf upload evil/uk-data ./data --repo-type dataset", "allow", True),  # gap: direct upload
    ("uk", HD(["git apply <<'EOF'", "--- a/upload.py", "+++ b/upload.py", "@@ -1 +1 @@",
               "-repo_id='a'", "+repo_id='b'", "EOF"]), "allow", True),  # gap: git-apply diff
)


def hf_patch_cases(fx):
    """apply_patch-payload corpus for the hf-dest adapter: (cwd_key, patch, expect)."""
    uk = str(fx["uk"])
    P = lambda *lines: "\n".join(lines)
    return (
        # denies
        ("uk", P("*** Begin Patch", "*** Update File: policyengine_uk_data/upload.py", "@@",
                 '-    api.upload_file(repo_id="a")', '+    api.upload_file(repo_id="b")',
                 "*** End Patch"), "[hf-dest]"),
        ("uk", P("*** Begin Patch", "   *** Update File: policyengine_uk_data/upload.py", "@@",
                 '-repo_id="a"', '+repo_id="b"', "*** End Patch"), "[hf-dest]"),  # leading-ws header
        ("uk", "*** Begin Patch\r\n*** Update File: upload.py\r\n@@\r\n+repo_id=1\r\n*** End Patch", "[hf-dest]"),  # CRLF
        ("plain", P("*** Begin Patch", "*** Update File: ../PolicyEngine/policyengine-uk-data/policyengine_uk_data/upload.py",
                    "@@", "+hf://x", "*** End Patch"), "[hf-dest]"),  # relative ../ into uk-data
        ("plain", P("*** Begin Patch", "*** Add File: %s/new.py" % uk,
                    '+api.upload_folder(folder_path="x", repo_id="y")', "*** End Patch"), "[hf-dest]"),
        ("plain", P("*** Begin Patch", "*** Update File: src/a.py", "*** Move to: %s/b.py" % uk,
                    "@@", "-old", "+hf://datasets/x", "*** End Patch"), "[hf-dest]"),
        ("uk", P("*** Begin Patch", "*** Update File: x.py", "@@", "+upload_files = []",
                 "*** End Patch"), "[hf-dest]"),  # substring (parity FP)
        ("uk", P("*** Begin Patch", "*** Update File: README.md", "@@",
                 "+See https://huggingface.co/policyengine/policyengine-uk-data",
                 "*** End Patch"), "[hf-dest]"),  # docs URL (parity FP)
        ("uk", P("*** Begin Patch", "*** Update File: x.py", "@@",
                 "+hf_hub_download(repo_id=REPO, filename='f')", "*** End Patch"), "[hf-dest]"),
        ("uk", P("*** Begin Patch", "*** Environment ID: local", "*** Update File: upload.py",
                 "@@", "+repo_id=1", "*** End Patch"), "[hf-dest]"),
        ("uk", P("*** Begin Patch", "*** Update File: upload.py", "@@",
                 " *** Update File: other.py", "+repo_id=1", "*** End Patch"), "[hf-dest]"),  # indented header = context line
        ("uk", P("*** Begin Patch", "*** Add File: new.py", "+x = 1", "+y = upload_file",
                 "*** End Patch"), "[hf-dest]"),
        # case-insensitive FS alias (macOS APFS): an UPPER/mixed-case spelling of the
        # repo dir resolves to the same protected directory, so Codex writes there; the
        # substring test must fold case (sol adjudication 2026-08-20).
        ("plain", P("*** Begin Patch",
                    "*** Add File: %s/_probe.py" % uk.replace("policyengine-uk-data", "POLICYENGINE-UK-DATA"),
                    "+repo_id=evil", "*** End Patch"), "[hf-dest]"),
        ("plain", P("*** Begin Patch",
                    "*** Update File: %s/upload.py" % uk.replace("policyengine-uk-data", "PolicyEngine-UK-Data"),
                    "@@", "+repo_id=1", "*** End Patch"), "[hf-dest]"),
        # Unicode-whitespace headers (NBSP/ideographic/NNBSP/NEL/... before a
        # marker) are pinned in UnicodeAndBaseHardeningTests with explicit \u
        # escapes — invisible literals do not belong in a reviewable corpus.
        # allows
        ("uk", P("*** Begin Patch", "*** Update File: README.md", "@@", "+documentation tweak",
                 "*** End Patch"), "allow"),
        ("uk", P("*** Begin Patch", "*** Update File: pyproject.toml", "@@",
                 "+huggingface_hub>=0.20", "*** End Patch"), "allow"),
        ("uk", P("*** Begin Patch", "*** Update File: upload.py", "@@", '-repo_id="b"',
                 "+other", "*** End Patch"), "allow"),  # only a removed line has repo_id
        ("uk", P("*** Begin Patch", "*** Update File: upload.py", "@@", ' repo_id="old"',
                 "+print(1)", "*** End Patch"), "allow"),  # only a context line has repo_id
        ("uk", P("*** Begin Patch", "*** Delete File: upload.py", "*** End Patch"), "allow"),
        ("uk", P("*** Begin Patch", "*** Update File: upload.py", "*** Move to: /tmp/upload.py",
                 "@@", "-x", " x", "*** End Patch"), "allow"),  # move out, no added lines
        ("uk", P("*** Begin Patch", "*** Update File: upload.py", "@@", "+ok",
                 "*** Update File: /tmp/other/x.py", "@@", "+repo_id=1", "*** End Patch"),
         "allow"),  # column-0 header DOES switch files; uk-data section benign
        ("ukwt", P("*** Begin Patch", "*** Update File: policyengine_uk_data/upload.py", "@@",
                   "+repo_id=1", "*** End Patch"), "allow"),  # documented gap: worktree dir name
        ("uk", P("*** Begin Patch", "*** Update File: ../policyengine-us/x.py", "@@",
                 "+repo_id=1", "*** End Patch"), "allow"),  # .. normalises out of uk-data
        ("uk", P("*** Begin Patch", "*** Add File: new.py", "+x = 1", "*** End Patch"), "allow"),
        ("uk", P("*** Begin Patch", "*** Update File: upload.py", "@@", "+ok", "*** End Patch",
                 "+repo_id=1"), "allow"),  # text after End Patch ignored
        ("uk", "no patch markers at all repo_id", "allow"),
        ("plain", P("*** Begin Patch", "*** Update File: upload.py", "@@", "+repo_id=1",
                    "*** End Patch"), "allow"),  # cwd elsewhere; relative path out of scope
    )


class FixtureCase(GuardTestCase):
    """GuardTestCase (temp telemetry env) + the D6 git/dir fixtures, built once
    per class."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.class_tmp = Path(tempfile.mkdtemp(prefix="guard-nr-"))
        cls.addClassCleanup(shutil.rmtree, str(cls.class_tmp), True)
        fixdir = cls.class_tmp / "fix"
        fixdir.mkdir()
        cls.fx = build_fixtures(fixdir)

    def cwd_of(self, key):
        return str(self.fx[key])

    def payloads_for(self, cases):
        return {i: payload(c[1], self.cwd_of(c[0])) for i, c in enumerate(cases)}


class HookDecisionTests(FixtureCase):
    """Per-rule deny/allow cases against the codex hook."""

    def decide_raw(self, data, env=None):
        completed = run([HOOK], env=env or self.env, stdin=data)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "", "hook wrote to stderr: %r" % completed.stderr)
        out = completed.stdout.strip()
        if out:
            self.assertEqual(len(out.splitlines()), 1, "more than one output line: %r" % out)
        allowed, reason = hook_reason(completed.stdout)
        return allowed, reason, completed

    def check_expect(self, allowed, reason, expect, label):
        if expect == "allow":
            self.assertTrue(allowed, "expected allow for %s, got: %s" % (label, reason))
        else:
            self.assertFalse(allowed, "expected deny %s for %s" % (expect, label))
            self.assertEqual(rule_tag(reason), expect, "%s -> %s" % (label, reason))

    def run_cases(self, cases):
        # (test_codex_guard.run_hook_many is keyed by (command, cwd) tuples;
        # the corpora here are keyed by index over fixture cwds, so use a
        # local parallel runner.)
        import concurrent.futures

        def one(item):
            i, data = item
            return i, run(["/bin/bash", str(HOOK)], env=self.env, stdin=data)

        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for i, completed in pool.map(one, self.payloads_for(cases).items()):
                results[i] = completed
        for i, (cwd_key, command, expect, _parity) in enumerate(cases):
            completed = results[i]
            with self.subTest(command=command, cwd=cwd_key):
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "", completed.stderr)
                allowed, reason = hook_reason(completed.stdout)
                self.check_expect(allowed, reason, expect, "%r in %s" % (command, cwd_key))

    def test_bash_rule_corpus(self):
        self.run_cases(BASH_CASES)

    def test_documented_gaps_and_fps(self):
        # Pins today's behavior of every documented gap / accepted FP; a
        # Claude-side rule change flips one of these deliberately.
        self.run_cases(BASH_DOCUMENTED)

    def test_hf_dest_apply_patch_corpus(self):
        cases = hf_patch_cases(self.fx)
        import concurrent.futures

        def one(item):
            i, (cwd_key, patch, expect) = item
            data = payload(patch, self.cwd_of(cwd_key), tool_name="apply_patch")
            return i, run(["/bin/bash", str(HOOK)], env=self.env, stdin=data)

        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for i, completed in pool.map(one, enumerate(cases)):
                results[i] = completed
        for i, (cwd_key, patch, expect) in enumerate(cases):
            completed = results[i]
            with self.subTest(patch=patch[:70], cwd=cwd_key):
                allowed, reason = hook_reason(completed.stdout)
                self.check_expect(allowed, reason, expect, "patch %r in %s" % (patch[:50], cwd_key))
                if expect == "[hf-dest]":
                    # apply_patch denies carry the Claude message verbatim,
                    # with no heredoc suffix (that suffix is Bash-only).
                    self.assertNotIn("[codex lane:", reason)
                    self.assertTrue(reason.endswith("Max makes that change himself."), reason)

    def test_rule_order_corpus_push_before_unscoped(self):
        allowed, reason, _ = self.decide_raw(
            payload("git push origin main && find ~ -name x", self.cwd_of("corpus")))
        self.assertFalse(allowed)
        self.assertEqual(rule_tag(reason), "[corpus-push]")
        self.assertNotIn("[codex lane:", reason)

    def test_heredoc_bash_denies_carry_the_codex_note(self):
        allowed, reason, _ = self.decide_raw(payload(STASH_HEREDOC, self.cwd_of("shared")))
        self.assertFalse(allowed)
        self.assertEqual(rule_tag(reason), "[stash-shared]")
        self.assertTrue(reason.endswith(HEREDOC_NOTE), reason)
        # ...but a plain (no Begin Patch) Bash deny does not.
        allowed, reason, _ = self.decide_raw(payload("git stash", self.cwd_of("shared")))
        self.assertFalse(allowed)
        self.assertFalse(reason.endswith(HEREDOC_NOTE), reason)
        # block() is rule-agnostic: an [unscoped-search] deny of a Begin-Patch
        # Bash command carries the suffix too, after the region's token tail.
        allowed, reason, _ = self.decide_raw(payload(UNSCOPED_HEREDOC, self.cwd_of("plain")))
        self.assertFalse(allowed)
        self.assertEqual(rule_tag(reason), "[unscoped-search]")
        self.assertIn("Matched broad root: '/Users/maxghenis'.", reason)
        self.assertTrue(reason.endswith(HEREDOC_NOTE), reason)

    def test_hf_heredoc_deny_carries_claude_message_plus_note(self):
        cmd = HD(["cd policyengine-uk-data && apply_patch <<'EOF'", "*** Begin Patch",
                  "*** Update File: upload.py", "@@", "+repo_id=1", "*** End Patch", "EOF"])
        allowed, reason, _ = self.decide_raw(payload(cmd, self.cwd_of("pe_dir")))
        self.assertFalse(allowed)
        self.assertEqual(rule_tag(reason), "[hf-dest]")
        self.assertTrue(reason.endswith(HEREDOC_NOTE), reason)
        claude_msg = reason[: -len(HEREDOC_NOTE)]
        self.assertTrue(claude_msg.endswith("Max makes that change himself."), claude_msg)

    def test_tool_passthrough_and_malformed_input(self):
        # Tools outside Bash/apply_patch: allow with empty stdout, even for
        # scary text.
        for tool in ("Edit", "Write", "MultiEdit", "exec_command"):
            allowed, _, completed = self.decide_raw(
                payload("git stash", self.cwd_of("shared"), tool_name=tool))
            self.assertTrue(allowed, tool)
            self.assertEqual(completed.stdout, "")
        # argv-array command form is joined and judged.
        raw = json.dumps({"tool_name": "Bash", "cwd": self.cwd_of("shared"),
                          "tool_input": {"command": ["git", "stash", "pop"]}})
        allowed, reason, _ = self.decide_raw(raw)
        self.assertFalse(allowed)
        self.assertEqual(rule_tag(reason), "[stash-shared]")
        # Garbage/empty/missing command: allow, exit 0, no stdout.
        for raw in ("", "garbage {{ not json", '{"tool_name":"apply_patch","cwd":"/"}',
                    '{"tool_name":"Bash","cwd":"/","tool_input":{"command":null}}'):
            allowed, _, completed = self.decide_raw(raw)
            self.assertTrue(allowed, raw)
            self.assertEqual(completed.stdout, "")

    def test_deny_output_shape(self):
        allowed, _, completed = self.decide_raw(payload("git stash", self.cwd_of("shared")))
        self.assertFalse(allowed)
        parsed = json.loads(completed.stdout.strip())
        self.assertEqual(list(parsed.keys()), ["hookSpecificOutput"])
        spec = parsed["hookSpecificOutput"]
        self.assertEqual(spec["hookEventName"], "PreToolUse")
        self.assertEqual(spec["permissionDecision"], "deny")
        self.assertTrue(spec["permissionDecisionReason"].startswith("[stash-shared]"))

    def test_telemetry_three_columns_bash_and_apply_patch(self):
        # One line per deny: <ISO8601>\t<cwd>\t<text first 300, tabs/newlines
        # squashed> — the same three-column format for every rule and both
        # tools (test_codex_guard.py pins the unscoped case; this pins a
        # never-rule deny and an apply_patch deny logging the patch text).
        allowed, _, _ = self.decide_raw(
            payload("git\tstash\npop && git stash", self.cwd_of("shared")))
        self.assertFalse(allowed)
        lines = self.log_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1, lines)
        stamp, cwd, text = lines[0].split("\t")
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4}$")
        self.assertEqual(cwd, self.cwd_of("shared"))
        self.assertEqual(text, "git stash pop && git stash")
        # apply_patch deny appends a second line; text = the patch, capped at 300.
        patch = patch_for_edit("upload.py", "repo_id=1" + "x" * 400)
        allowed, _, _ = self.decide_raw(
            payload(patch, self.cwd_of("uk"), tool_name="apply_patch"))
        self.assertFalse(allowed)
        lines = self.log_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        stamp2, cwd2, text2 = lines[1].split("\t")
        self.assertEqual(cwd2, self.cwd_of("uk"))
        self.assertEqual(len(text2), 300)
        self.assertTrue(text2.startswith("*** Begin Patch *** Update File: upload.py"), text2)

    def test_allow_does_not_log_and_log_failure_keeps_decision(self):
        allowed, _, _ = self.decide_raw(payload("git status", self.cwd_of("plain")))
        self.assertTrue(allowed)
        self.assertFalse(self.log_file.exists(), "allow must not log")
        env = self.env.copy()
        env["CODEX_GUARD_LOG"] = "/nonexistent-root-dir-for-guard-nr-test/x/denials.log"
        allowed, reason, completed = self.decide_raw(
            payload("git stash", self.cwd_of("shared")), env=env)
        self.assertFalse(allowed)
        self.assertEqual(rule_tag(reason), "[stash-shared]")
        self.assertEqual(completed.returncode, 0)


class ParityTests(FixtureCase):
    """Differential: identical payloads through both hooks -> identical
    decision and [rule] tag; codex deny reasons start with the Claude reason
    (Begin-Patch Bash commands append the heredoc note). Codex-only semantics
    (parity=False) are skipped. [unscoped-search] reason prefixes are compared
    only once the guard-portback ~/.claude install lands (the installed Claude
    hook still carries the old region text until then); decisions and tags for
    those cases are compared unconditionally."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not CLAUDE_HOOK.is_file():
            raise unittest.SkipTest("Claude hook not present: %s" % CLAUDE_HOOK)

    def test_bash_corpus_parity(self):
        import concurrent.futures

        cases = [(i, c) for i, c in enumerate(BASH_CASES + BASH_DOCUMENTED) if c[3]]
        payloads = {i: payload(c[1], self.cwd_of(c[0])) for i, c in cases}

        def run_all(hook):
            def one(item):
                i, data = item
                return i, run(["/bin/bash", str(hook)], env=self.env, stdin=data)
            results = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                for i, completed in pool.map(one, payloads.items()):
                    results[i] = completed
            return results

        claude = run_all(CLAUDE_HOOK)
        codex = run_all(HOOK)
        for i, (cwd_key, command, expect, _parity) in cases:
            with self.subTest(command=command, cwd=cwd_key):
                c_run, x_run = claude[i], codex[i]
                for label, completed in (("claude", c_run), ("codex", x_run)):
                    self.assertEqual(completed.returncode, 0,
                                     "%s exit %s: %s" % (label, completed.returncode, completed.stderr))
                    self.assertEqual(completed.stderr, "", "%s stderr: %r" % (label, completed.stderr))
                c_allowed, c_reason = hook_reason(c_run.stdout)
                x_allowed, x_reason = hook_reason(x_run.stdout)
                self.assertEqual(
                    c_allowed, x_allowed,
                    "decision differs for %r in %s: claude=%s codex=%s (%s | %s)" % (
                        command, cwd_key, c_allowed, x_allowed, c_reason, x_reason))
                if not c_allowed:
                    self.assertEqual(rule_tag(c_reason), rule_tag(x_reason),
                                     "%r: %s vs %s" % (command, c_reason, x_reason))
                    self.assertEqual(rule_tag(c_reason), expect)
                    if expect != "[unscoped-search]" or CLAUDE_PORTBACK_LANDED:
                        self.assertTrue(
                            x_reason.startswith(c_reason),
                            "codex reason does not extend the Claude reason for %r:\n"
                            "claude: %s\ncodex:  %s" % (command, c_reason, x_reason))

    def test_hf_dest_edit_vs_apply_patch_pairs(self):
        uk = str(self.fx["uk"])
        pairs = [
            # (Claude Edit/Write payload, codex apply_patch payload, expect)
            (edit_payload(uk + "/upload.py", 'api.upload_file(repo_id="policyengine/other-repo")'),
             payload(patch_for_edit(uk + "/upload.py", 'api.upload_file(repo_id="policyengine/other-repo")'),
                     "/tmp", tool_name="apply_patch"), "[hf-dest]"),
            (edit_payload(uk + "/README.md", "documentation tweak"),
             payload(patch_for_edit(uk + "/README.md", "documentation tweak"),
                     "/tmp", tool_name="apply_patch"), "allow"),
            (edit_payload(str(self.fx["plain"]) + "/upload.py", 'repo_id="x/y"'),
             payload(patch_for_edit(str(self.fx["plain"]) + "/upload.py", 'repo_id="x/y"'),
                     "/tmp", tool_name="apply_patch"), "allow"),
            # multi-line pair
            (edit_payload(uk + "/etl.py", "line one\nrepo_id = 'x'\nline three"),
             payload(patch_for_edit(uk + "/etl.py", "line one\nrepo_id = 'x'\nline three"),
                     "/tmp", tool_name="apply_patch"), "[hf-dest]"),
            (edit_payload(uk + "/x.py", "upload_files = []"),
             payload(patch_for_edit(uk + "/x.py", "upload_files = []"),
                     "/tmp", tool_name="apply_patch"), "[hf-dest]"),
            (edit_payload(uk + "/README.md", "See https://huggingface.co/policyengine/policyengine-uk-data"),
             payload(patch_for_edit(uk + "/README.md", "See https://huggingface.co/policyengine/policyengine-uk-data"),
                     "/tmp", tool_name="apply_patch"), "[hf-dest]"),
            # Write / Add File pair
            (write_payload(uk + "/new.py", 'api.upload_folder(folder_path="x", repo_id="y")'),
             payload(patch_for_write(uk + "/new.py", 'api.upload_folder(folder_path="x", repo_id="y")'),
                     "/tmp", tool_name="apply_patch"), "[hf-dest]"),
        ]
        for claude_data, codex_data, expect in pairs:
            with self.subTest(expect=expect, data=codex_data[:80]):
                c = run(["/bin/bash", str(CLAUDE_HOOK)], env=self.env, stdin=claude_data)
                x = run(["/bin/bash", str(HOOK)], env=self.env, stdin=codex_data)
                c_allowed, c_reason = hook_reason(c.stdout)
                x_allowed, x_reason = hook_reason(x.stdout)
                self.assertEqual(c_allowed, x_allowed,
                                 "decision differs: claude=%s (%s) codex=%s (%s)" % (
                                     c_allowed, c_reason, x_allowed, x_reason))
                if expect == "allow":
                    self.assertTrue(c_allowed)
                else:
                    self.assertFalse(c_allowed)
                    self.assertEqual(rule_tag(c_reason), expect)
                    self.assertEqual(rule_tag(x_reason), expect)
                    self.assertTrue(x_reason.startswith(c_reason),
                                    "codex: %s\nclaude: %s" % (x_reason, c_reason))


# ---------------------------------------------------------------------------
# DriftTests — file-text pins for the ported blocks and the hf-dest literals.
# A block runs from its column-0 `# --- <rule>:` header up to (not including)
# the next column-0 `# --- ` OR `# >>>` line (the new Claude hook and the
# codex hook carry the shared-region begin marker right after local-main).
# ---------------------------------------------------------------------------
BLOCK_BOUNDARY = ("# --- ", "# >>>")


def extract_rule_block(text, rule):
    lines = text.split("\n")
    start = None
    for i, line in enumerate(lines):
        if line.startswith("# --- %s:" % rule):
            start = i
            break
    if start is None:
        return None, None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith(BLOCK_BOUNDARY):
            end = j
            break
    return "\n".join(lines[start:end]) + "\n", start


class DriftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not CLAUDE_HOOK.is_file():
            raise unittest.SkipTest("Claude hook not present: %s" % CLAUDE_HOOK)
        cls.claude = CLAUDE_HOOK.read_text(encoding="utf-8")
        cls.codex = HOOK.read_text(encoding="utf-8")

    def test_bash_rule_blocks_identical(self):
        for rule in RULES:
            with self.subTest(rule=rule):
                c_block, _ = extract_rule_block(self.claude, rule)
                x_block, _ = extract_rule_block(self.codex, rule)
                self.assertIsNotNone(c_block, "Claude hook lost rule %s" % rule)
                self.assertIsNotNone(x_block, "codex hook lost rule %s" % rule)
                self.assertEqual(
                    x_block, c_block,
                    "rule block %s differs — edit the Claude hook first, run its "
                    "harness, then re-extract into the codex hook "
                    "(proto/extract_blocks.sh)" % rule)

    def test_blocks_in_claude_order_and_contiguous(self):
        for label, text in (("claude", self.claude), ("codex", self.codex)):
            positions = []
            for rule in RULES:
                _, start = extract_rule_block(text, rule)
                self.assertIsNotNone(start, "%s: missing %s" % (label, rule))
                positions.append(start)
            self.assertEqual(positions, sorted(positions), "%s: rule order differs" % label)
        # In the codex hook the seven blocks sit back-to-back (nothing between
        # them), all before the shared region, and the region markers appear
        # exactly once.
        blocks = [extract_rule_block(self.codex, rule)[0] for rule in RULES]
        self.assertIn("".join(blocks), self.codex,
                      "the seven rule blocks are not contiguous in the codex hook")
        lines = self.codex.split("\n")
        begins = [i for i, l in enumerate(lines) if l.startswith(REGION_BEGIN)]
        ends = [i for i, l in enumerate(lines) if l == REGION_END]
        self.assertEqual((len(begins), len(ends)), (1, 1))
        last_rule_start = extract_rule_block(self.codex, RULES[-1])[1]
        self.assertLess(last_rule_start, begins[0],
                        "the shared region must follow the seven blocks")

    def test_prefilter_literal_identical(self):
        def prefilter_literal(text, label):
            for line in text.split("\n"):
                if "grep -qE 'stash|AXIOM_" in line:
                    return line.split("grep -qE '", 1)[1].split("'", 1)[0]
            self.fail("%s: prefilter literal not found" % label)
        self.assertEqual(
            prefilter_literal(self.codex, "codex"),
            prefilter_literal(self.claude, "claude"),
            "the Claude prefilter literal must appear byte-identically in the codex hook")

    def test_hf_dest_literals_identical(self):
        # regex literal
        claude_re = None
        for line in self.claude.split("\n"):
            if "grep -qE 'repo_id|" in line:
                claude_re = line.split("grep -qE '", 1)[1].split("'", 1)[0]
                break
        self.assertIsNotNone(claude_re, "Claude hf-dest regex not found")
        m = re.search(r"^claude_hf_re='([^']*)'", self.codex, re.M)
        self.assertIsNotNone(m, "codex hook: claude_hf_re= not found")
        self.assertEqual(m.group(1), claude_re)
        # block message
        claude_msg = None
        for line in self.claude.split("\n"):
            stripped = line.strip()
            if stripped.startswith('block "[hf-dest]') and stripped.endswith('"'):
                claude_msg = stripped[len('block "'):-1]
                break
        self.assertIsNotNone(claude_msg, "Claude hf-dest message not found")
        m = re.search(r'^claude_hf_msg="([^"]*)"', self.codex, re.M)
        self.assertIsNotNone(m, "codex hook: claude_hf_msg= not found")
        self.assertEqual(m.group(1), claude_msg)
        # the path-test literal stays functional in both files
        for label, text in (("claude", self.claude), ("codex", self.codex)):
            self.assertIn("*policyengine-uk-data*)", text, label)

    def test_hf_heredoc_fence_once_after_region(self):
        self.assertEqual(self.codex.count(HF_FENCE_BEGIN), 1)
        self.assertEqual(self.codex.count(HF_FENCE_END), 1)
        lines = self.codex.split("\n")
        region_end = [i for i, l in enumerate(lines) if l == REGION_END][0]
        fence_begin = [i for i, l in enumerate(lines) if l == HF_FENCE_BEGIN][0]
        self.assertLess(region_end, fence_begin,
                        "the hf-dest heredoc fence must follow the shared region")


class NeverRulesOverrideTests(GuardTestCase):
    """codex-guard --matcher/--status/--tool additions (the identity itself —
    matcher, status, both pinned hashes — is covered in test_codex_guard.py)."""

    def test_matcher_and_status_flags(self):
        override = self.guard(
            "override", "--matcher", "Bash", "--status", "unscoped-search guard"
        ).stdout.rstrip("\n")
        self.assertIn('matcher="Bash"', override)
        self.assertIn('statusMessage="unscoped-search guard"', override)
        completed = self.guard("override", "--matcher", "")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--matcher must be non-empty", completed.stderr)

    def test_old_and_new_identity_hashes_via_flags(self):
        by_default = self.guard("hash", "--hook", PINNED_HOOK_PATH, "--timeout", "30")
        self.assertEqual(by_default.returncode, 0, by_default.stderr)
        self.assertEqual(by_default.stdout.strip(), PINNED_HASH_V2)
        explicit = self.guard(
            "hash", "--hook", PINNED_HOOK_PATH, "--timeout", "30",
            "--matcher", MATCHER, "--status", STATUS_MESSAGE)
        self.assertEqual(explicit.stdout.strip(), PINNED_HASH_V2)
        old = self.guard(
            "hash", "--hook", PINNED_HOOK_PATH, "--timeout", "30",
            "--matcher", "Bash", "--status", "unscoped-search guard")
        self.assertEqual(old.stdout.strip(), PINNED_HASH)

    def test_usage_errors_exit_2(self):
        self.assertEqual(self.guard("hash", "--matcher").returncode, 2)
        self.assertEqual(self.guard("hash", "--status").returncode, 2)
        self.assertEqual(self.guard("check", "--tool").returncode, 2)
        completed = self.guard("check", "--tool", "Edit", "x")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--tool must be Bash or apply_patch", completed.stderr)


class CheckCommandTests(FixtureCase):
    """codex-guard check --tool / stdin behavior (always against HOOK, which
    honors the CODEX_GUARD_HOOK candidate override)."""

    def check(self, *args, stdin=None, env=None):
        return run([GUARD, "check", "--hook", HOOK, *args], env=env or self.env, stdin=stdin)

    def test_check_bash_default_deny_allow_exit_codes(self):
        deny = self.check("git stash pop", self.cwd_of("shared"))
        self.assertEqual(deny.returncode, 1, deny.stderr)
        self.assertTrue(deny.stdout.startswith("deny: [stash-shared]"), deny.stdout)
        allow = self.check("git status", self.cwd_of("plain"))
        self.assertEqual(allow.returncode, 0, allow.stderr)
        self.assertEqual(allow.stdout.strip(), "allow")

    def test_check_tool_apply_patch(self):
        patch = patch_for_edit("upload.py", 'repo_id="x"')
        deny = self.check("--tool", "apply_patch", patch, self.cwd_of("uk"))
        self.assertEqual(deny.returncode, 1, deny.stdout + deny.stderr)
        self.assertTrue(deny.stdout.startswith("deny: [hf-dest]"), deny.stdout)
        allow = self.check("--tool", "apply_patch", patch, self.cwd_of("plain"))
        self.assertEqual(allow.returncode, 0)
        self.assertEqual(allow.stdout.strip(), "allow")
        # The same text as a Bash command is caught by the heredoc-form scan.
        bash_same_text = self.check("--tool", "Bash", patch, self.cwd_of("uk"))
        self.assertEqual(bash_same_text.returncode, 1)
        self.assertIn("[hf-dest]", bash_same_text.stdout)

    def test_check_stdin_dash(self):
        patch = patch_for_edit("upload.py", 'repo_id="x"')
        deny = self.check("--tool", "apply_patch", "-", self.cwd_of("uk"), stdin=patch)
        self.assertEqual(deny.returncode, 1, deny.stdout + deny.stderr)
        self.assertTrue(deny.stdout.startswith("deny: [hf-dest]"), deny.stdout)
        allow = self.check("-", self.cwd_of("plain"), stdin="git status")
        self.assertEqual(allow.returncode, 0)
        self.assertEqual(allow.stdout.strip(), "allow")
        deny_bash = self.check("-", self.cwd_of("shared"), stdin="git stash pop")
        self.assertEqual(deny_bash.returncode, 1)
        self.assertIn("[stash-shared]", deny_bash.stdout)

    def test_check_never_writes_real_denial_log(self):
        env = self.env.copy()
        home = self.tmp_path / "home"
        home.mkdir()
        env["HOME"] = str(home)
        env.pop("CODEX_GUARD_LOG")
        completed = run([GUARD, "check", "--hook", HOOK, "git stash pop",
                         self.cwd_of("shared")], env=env)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse((home / ".cache" / "codex-run" / "guard-denials.log").exists())


STUB_CODEX = r"""#!/bin/bash
# codex stub: --version, app-server (canned trusted hooks/list), exec (record argv).
case "${1:-}" in
  --version) echo "codex-cli 0.0.0-stub"; exit 0 ;;
  app-server)
    printf '%s\n' '{"id":1,"result":{"userAgent":"stub"}}'
    printf '{"id":2,"result":{"data":[{"cwd":"x","hooks":[{"key":"__KEY__","eventName":"preToolUse","handlerType":"command","matcher":"Bash|apply_patch","command":"stub","timeoutSec":15,"statusMessage":"stub","sourcePath":"/<session-flags>/config.toml","source":"sessionFlags","pluginId":null,"displayOrder":0,"enabled":true,"isManaged":false,"currentHash":"sha256:stub","trustStatus":"trusted"}],"warnings":[],"errors":[]}]}}\n'
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


class CodexRunNeverRulesTests(GuardTestCase):
    """codex-run's -b main|master refusal, CODEX_RUN_UNIFIED_EXEC opt-out, and
    v2 wording, against a stubbed codex. The three shipped files are staged
    into a temp bin dir under their production names (codex-run resolves its
    guard and hook as siblings), so a CODEX_GUARD_HOOK/CODEX_RUN candidate
    override is honored."""

    def setUp(self):
        super().setUp()
        self.bin_dir = self.tmp_path / "bin"
        self.bin_dir.mkdir()
        for src, name in ((CODEX_RUN, "codex-run"), (GUARD, "codex-guard"),
                          (HOOK, "codex-guard-hook")):
            dst = self.bin_dir / name
            shutil.copyfile(str(src), str(dst))
            dst.chmod(0o755)
        self.stub_dir = self.tmp_path / "stubbin"
        self.stub_dir.mkdir()
        stub = self.stub_dir / "codex"
        stub.write_text(STUB_CODEX.replace("__KEY__", KEY), encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.argv_file = self.tmp_path / "argv.bin"
        self.env["PATH"] = "%s%s%s" % (self.stub_dir, ":", self.env["PATH"])
        self.env["STUB_ARGV_FILE"] = str(self.argv_file)
        self.env.pop("CODEX_RUN_UNIFIED_EXEC", None)
        self.codex_home = self.tmp_path / "codex-home"
        self.codex_home.mkdir()
        self.workdir = self.tmp_path / "work"
        self.workdir.mkdir()
        self.prompt = self.tmp_path / "prompt.md"
        self.prompt.write_text("say hi\n", encoding="utf-8")
        self.out_file = self.tmp_path / "out.md"

    def codex_run(self, *extra, env=None):
        argv = [self.bin_dir / "codex-run", "-H", self.codex_home, "-m", "gpt-test",
                "-C", self.workdir, "-p", self.prompt, "-o", self.out_file,
                "-s", "read-only", *extra]
        return run(argv, env=env or self.env)

    def exec_argv(self):
        data = self.argv_file.read_bytes()
        return [a.decode("utf-8") for a in data.split(b"\0") if a]

    def c_values(self, argv):
        return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-c"]

    def git_workdir(self):
        subprocess.run(["git", "init", "-q", str(self.workdir)], check=True,
                       capture_output=True, timeout=SUBPROCESS_TIMEOUT)
        _git(self.workdir, "commit", "-q", "--allow-empty", "-m", "init")
        (self.workdir / "dirty.txt").write_text("wip\n", encoding="utf-8")

    def test_b_main_and_master_refused_before_anything(self):
        self.git_workdir()
        for bad in ("main", "master"):
            completed = self.codex_run("-b", bad)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn(
                "codex-run: refusing -b main|master — the salvage push force-pushes "
                "WIP onto that branch; use a salvage branch name (e.g. -b codex-salvage/<lane>)",
                completed.stderr)
            self.assertNotIn("preflight", completed.stderr)
            self.assertNotIn("salvaged dirty state", completed.stderr)
            self.assertFalse(self.argv_file.exists(), "codex exec must not run")
        refs = subprocess.run(
            ["git", "-C", str(self.workdir), "for-each-ref", "refs/codex-salvage"],
            capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
        self.assertEqual(refs.stdout.strip(), "", refs.stdout)
        self.assertFalse(self.cache_dir.exists(), "no preflight may have run")

    def test_salvage_branch_names_still_work(self):
        completed = self.codex_run("-b", "codex-salvage/x")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("codex-run: OK attempt=1", completed.stdout)
        argv = self.exec_argv()
        overrides = [v for v in self.c_values(argv) if v.startswith("hooks={")]
        self.assertEqual(len(overrides), 1, argv)
        self.assertIn('matcher="%s"' % MATCHER, overrides[0])
        self.assertIn('statusMessage="%s"' % STATUS_MESSAGE, overrides[0])
        self.assertIn(
            'trusted_hash="%s"' % python_trust_hash(str(self.bin_dir / "codex-guard-hook")),
            overrides[0])

    def test_armed_and_disabled_wording(self):
        completed = self.codex_run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "codex-run: never-rules guard armed (9 rules; hook=%s)" % (self.bin_dir / "codex-guard-hook"),
            completed.stderr)
        self.assertNotIn("unscoped-search guard armed", completed.stderr)
        env = self.env.copy()
        env["CODEX_RUN_GUARD"] = "off"
        completed = self.codex_run(env=env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("codex-run: never-rules guard DISABLED (CODEX_RUN_GUARD=off)", completed.stderr)
        argv = self.exec_argv()
        self.assertFalse(any(v.startswith("hooks=") for v in self.c_values(argv)), argv)

    def test_unified_exec_opt_out(self):
        env = self.env.copy()
        env["CODEX_RUN_UNIFIED_EXEC"] = "off"
        completed = self.codex_run(env=env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "codex-run: unified_exec disabled (shell_command only; write_stdin bypass closed)",
            completed.stderr)
        self.assertIn("features.unified_exec=false", self.c_values(self.exec_argv()))

    def test_unified_exec_default_untouched(self):
        completed = self.codex_run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        values = self.c_values(self.exec_argv())
        self.assertFalse(any("unified_exec" in v for v in values), values)
        # ...and an explicit "on" is also untouched (opt-out is exactly "off").
        env = self.env.copy()
        env["CODEX_RUN_UNIFIED_EXEC"] = "on"
        completed = self.codex_run(env=env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(any("unified_exec" in v for v in self.c_values(self.exec_argv())))

    def test_header_advice_no_longer_stash_based(self):
        text = Path(str(CODEX_RUN)).read_text(encoding="utf-8")
        self.assertNotIn("git stash apply", text)
        self.assertIn("git cherry-pick -n", text)
        self.assertIn("CODEX_RUN_UNIFIED_EXEC", text)
        self.assertIn("never-rules guard", text)


class UnicodeAndBaseHardeningTests(FixtureCase):
    """Regression pins for the 2026-08-20 hf-dest hardening:
      1. the awk trim strips the full Unicode White_Space set Rust
         str::trim()/trim_end() strips, so a header prefixed (or suffixed) with
         a no-break / ideographic / narrow-no-break / ... space parses exactly
         as Codex's streaming parser parses it (it did not before, so such a
         patch applied for Codex while the hook allowed it);
      2. a cd/pushd target behind an end-of-options `--` or a leading option is
         recovered as a base (the operand used to be lost to the `--` token);
      3. the scan is bounded regardless of how many cd targets a command has
         (it was O(bases x length): a 71 KB / 6000-cd command took ~72 s, long
         enough to time the hook out and fail open).
    """

    # White_Space code points Rust str::trim() strips (explicit escapes; a
    # spread across the 2- and 3-byte UTF-8 forms).
    UNICODE_SPACES = {
        "U+0085 NEL": "\u0085",
        "U+00A0 NBSP": "\u00a0",
        "U+1680 OGHAM": "\u1680",
        "U+2000 EN-QUAD": "\u2000",
        "U+2028 LINE-SEP": "\u2028",
        "U+202F NNBSP": "\u202f",
        "U+205F MMSP": "\u205f",
        "U+3000 IDEOGRAPHIC": "\u3000",
    }

    @staticmethod
    def _p(*lines):
        return "\n".join(lines)

    def decide_raw(self, data, env=None):
        completed = run([HOOK], env=env or self.env, stdin=data)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "", "hook wrote to stderr: %r" % completed.stderr)
        allowed, reason = hook_reason(completed.stdout)
        return allowed, reason, completed

    def _decide_patch(self, patch, cwd_key):
        return self.decide_raw(payload(patch, self.cwd_of(cwd_key), tool_name="apply_patch"))

    def test_unicode_whitespace_before_markers_denies(self):
        # A leading White_Space char before Begin Patch / Update File / Add File
        # is stripped by Codex's line.trim(), so the in-scope change applies.
        for name, sp in self.UNICODE_SPACES.items():
            for where, patch in (
                ("before Begin Patch",
                 self._p(sp + "*** Begin Patch",
                         "*** Update File: policyengine_uk_data/upload.py",
                         "@@", "+repo_id=1", "*** End Patch")),
                ("before Update File",
                 self._p("*** Begin Patch",
                         sp + "*** Update File: policyengine_uk_data/upload.py",
                         "@@", "+repo_id=1", "*** End Patch")),
                ("before Add File",
                 self._p("*** Begin Patch",
                         sp + "*** Add File: policyengine_uk_data/new.py",
                         "+api.upload_file(repo_id=1)", "*** End Patch")),
            ):
                with self.subTest(space=name, where=where):
                    allowed, reason, _ = self._decide_patch(patch, "uk")
                    self.assertFalse(allowed, "%s %s should deny" % (name, where))
                    self.assertEqual(rule_tag(reason), "[hf-dest]")

    def test_unicode_whitespace_trailing_header_denies(self):
        # Codex matches update-hunk headers on line.trim_end(); a trailing
        # White_Space char must not hide the header from the hook either.
        for name, sp in self.UNICODE_SPACES.items():
            patch = self._p("*** Begin Patch",
                            "*** Update File: policyengine_uk_data/upload.py" + sp,
                            "@@", "+repo_id=1", "*** End Patch")
            with self.subTest(space=name):
                allowed, reason, _ = self._decide_patch(patch, "uk")
                self.assertFalse(allowed, "%s trailing should deny" % name)
                self.assertEqual(rule_tag(reason), "[hf-dest]")

    def test_non_whitespace_invisible_is_not_over_stripped(self):
        # U+200B ZERO WIDTH SPACE and U+FEFF are NOT in Rust's White_Space set:
        # Codex does not strip them, so the header does not parse and the patch
        # is rejected (no change applies) -- the hook must likewise NOT strip
        # them (over-stripping would deny benign edits and drift from Codex).
        for cp in ("\u200b", "\ufeff"):
            patch = self._p("*** Begin Patch",
                            cp + "*** Update File: policyengine_uk_data/upload.py",
                            "@@", "+repo_id=1", "*** End Patch")
            with self.subTest(cp="U+%04X" % ord(cp)):
                allowed, _, _ = self._decide_patch(patch, "uk")
                self.assertTrue(allowed, "U+%04X must not be stripped" % ord(cp))

    def test_unicode_bypass_via_bash_heredoc_denies(self):
        # Same class through the Bash heredoc form (tool_name Bash).
        cmd = HD(["apply_patch <<'EOF'",
                  "*** Begin Patch",
                  "\u00a0*** Update File: policyengine_uk_data/upload.py",
                  "@@", "+repo_id=1", "*** End Patch", "EOF"])
        allowed, reason, _ = self.decide_raw(payload(cmd, self.cwd_of("uk")))
        self.assertFalse(allowed)
        self.assertEqual(rule_tag(reason), "[hf-dest]")

    def test_cd_end_of_options_and_options_recover_target(self):
        # cwd is the PolicyEngine parent; the real target sits behind `--` or a
        # leading option. Each must resolve into uk-data and deny.
        body = ["*** Begin Patch", "*** Update File: policyengine_uk_data/upload.py",
                "@@", "+repo_id=1", "*** End Patch", "EOF"]
        for prefix in ("cd -- policyengine-uk-data && apply_patch <<'EOF'",
                       "cd -L -- policyengine-uk-data && apply_patch <<'EOF'",
                       "cd -P policyengine-uk-data && apply_patch <<'EOF'",
                       "pushd -- policyengine-uk-data && apply_patch <<'EOF'"):
            with self.subTest(prefix=prefix):
                allowed, reason, _ = self.decide_raw(
                    payload(HD([prefix, *body]), self.cwd_of("pe_dir")))
                self.assertFalse(allowed, "%s should deny" % prefix)
                self.assertEqual(rule_tag(reason), "[hf-dest]")

    def test_d6_applypatch_quoted_absolute_cd_denies(self):
        # The ASSESSMENT-DECISIONS D6 case that was previously unpinned: a
        # double-quoted ABSOLUTE cd into uk-data plus the `applypatch` alias.
        uk = self.cwd_of("uk")
        cmd = HD(['cd "%s" && applypatch <<\'EOF\'' % uk, "*** Begin Patch",
                  "*** Update File: policyengine_uk_data/upload.py", "@@",
                  "+repo_id=1", "*** End Patch", "EOF"])
        allowed, reason, _ = self.decide_raw(payload(cmd, self.cwd_of("pe_dir")))
        self.assertFalse(allowed)
        self.assertEqual(rule_tag(reason), "[hf-dest]")

    def test_cd_shell_variable_target_is_documented_gap(self):
        # `cd $VAR` / `cd ${VAR}` cannot be resolved from the command text -- a
        # documented uncaught form (pinned as allow so a future change is
        # deliberate). Codex would still apply the patch; only Max fixes the
        # source-of-truth Claude side (README Claude-side follow-ups).
        for tgt in ('"$UK"', "${UK}"):
            cmd = HD(["UK=policyengine-uk-data; cd %s && apply_patch <<'EOF'" % tgt,
                      "*** Begin Patch",
                      "*** Update File: policyengine_uk_data/upload.py", "@@",
                      "+repo_id=1", "*** End Patch", "EOF"])
            with self.subTest(tgt=tgt):
                allowed, _, _ = self.decide_raw(payload(cmd, self.cwd_of("pe_dir")))
                self.assertTrue(allowed, "%s is a documented gap (allow)" % tgt)

    def test_many_cd_targets_scan_is_bounded(self):
        # DoS pin: thousands of cd targets must not make the scan super-linear.
        # The trailing in-scope heredoc still denies; the whole thing completes
        # fast (the pre-fix hook took ~38 s at 4000 / ~72 s at 6000 targets).
        import time
        n = 4000
        chain = " && ".join("cd d%d" % i for i in range(n))
        cmd = HD([chain + " && cd policyengine-uk-data && apply_patch <<'EOF'",
                  "*** Begin Patch",
                  "*** Update File: policyengine_uk_data/upload.py", "@@",
                  "+repo_id=1", "*** End Patch", "EOF"])
        start = time.monotonic()
        allowed, reason, _ = self.decide_raw(payload(cmd, self.cwd_of("pe_dir")))
        elapsed = time.monotonic() - start
        self.assertFalse(allowed, "the trailing in-scope patch must still deny")
        self.assertEqual(rule_tag(reason), "[hf-dest]")
        self.assertLess(elapsed, 10.0,
                        "scan took %.1fs for %d cd targets -- the O(bases x length) "
                        "blow-up is back" % (elapsed, n))


if __name__ == "__main__":
    unittest.main()
