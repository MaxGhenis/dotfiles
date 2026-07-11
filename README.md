# dotfiles

Config and scripts for my development machine. The interesting part is `bin/`:

| Script | What it does |
|--------|--------------|
| [`claude-model`](bin/claude-model) | Which model is *actually* serving a Claude Code session — reads the transcript's per-message model field; `-e <model>` exits 1 on a silent downgrade. See [docs/model-self-knowledge.md](docs/model-self-knowledge.md). |
| [`codex-run`](bin/codex-run) | Hardened `codex exec` dispatch — retries transient failures, salvages work on crash, unbreaks git in sandboxed worktrees. Documented below. |
| [`cc`](bin/cc) | Claude Code pane launcher (superseded by [tmux-claude-code](https://github.com/MaxGhenis/tmux-claude-code)) |
| [`sweep-worktrees`](bin/sweep-worktrees) | Rescue-and-bundle stale git worktrees before removing them |

## Workflow docs

- [Cross-model orchestration](docs/model-orchestration.md) — standing delegation defaults: judgment on Fable, heavy lifting and cyber to Sol subagents, blind two-family review
- [Your agent doesn't know which model it is](docs/model-self-knowledge.md) — Claude Code shows *you* the serving model; Claude itself can't tell when Fable is silently Opus. A drop-in self-check so it can, and what it should do when it fires

## codex-run

A wrapper for dispatching long `codex exec` runs from an orchestrating agent (or a shell). Raw `codex exec` lost work three different ways in one day; this fixes each of them.

### Usage

```bash
codex-run -H <codex_home> -m <model> -C <workdir> -p <prompt_file> -o <out_file> \
          [-s read-only|workspace-write] [-b <salvage_branch>] [-R <salvage_remote>] \
          [-r <max_retries>]
```

| Flag | Required | Meaning |
|------|----------|---------|
| `-H` | yes | `CODEX_HOME` for the run (auth, config) |
| `-m` | yes | Model, e.g. `gpt-5.6-sol` |
| `-C` | yes | Working directory (repo or worktree) |
| `-p` | yes | Prompt file — contents become the codex prompt |
| `-o` | yes | Output file — codex writes its final message here |
| `-s` | no | Sandbox mode; default `workspace-write`, use `read-only` for reviews |
| `-b` | no | Salvage branch — on any exit, push HEAD to this branch (see caveat) |
| `-R` | no | Remote for the salvage push; default `origin` |
| `-r` | no | Max retries for transient failures; default 2 |

Example dispatches:

```bash
# Read-only review — no salvage branch needed, nothing to lose
codex-run -H ~/.codex -m gpt-5.6-sol -C ~/src/dep-audit \
          -p prompt.md -o findings.md -s read-only

# Editing run in a worktree, with salvage
codex-run -H ~/.codex -m gpt-5.6-terra -C ~/worktrees/feature \
          -p prompt.md -o out.md -b salvage/feature-run

# Public origin: salvage to a private mirror instead (see caveat below)
codex-run -H ~/.codex -m gpt-5.6-terra -C ~/src/public-repo \
          -p prompt.md -o out.md -b salvage/run -R mirror
```

### The three failure modes it fixes

1. **Sandbox denies git in external worktrees.** Codex's `workspace-write` sandbox scopes writes to the working directory — but an external worktree's git metadata lives in the parent repo's *common* dir, so agents finish their edits and then can't commit (`.git/worktrees/<x>/index.lock: Operation not permitted`). The wrapper resolves `git rev-parse --git-common-dir` and adds it to `sandbox_workspace_write.writable_roots`.

2. **Transient deaths.** Model-at-capacity, 401s from token rotation, rate limits, disconnects, and timeouts are retried with linear backoff (60s × attempt, up to `-r` retries). **Content-filter refusals are not retried** — they fail fast with exit code 3, because a refusal is a framing problem, not an availability problem. Rewrite the prompt defensively (frame reviews as correctness/completeness audits, not construct-the-exploit exercises) and re-dispatch.

3. **Evaporating uncommitted work.** An EXIT/INT/TERM trap auto-commits any dirty state in the workdir (`WIP salvage: codex-run auto-commit`), and with `-b` force-pushes HEAD to the salvage branch. A killed or crashed run costs minutes to recover from, not the workstream.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success: codex exited 0 **and** the output file is non-empty |
| 2 | Usage error (missing flag, prompt file not found) |
| 3 | Content-filtered — rewrite the prompt, don't retry |
| other | Codex's own exit code after retries were exhausted |

A run where codex exits 0 but writes an empty output file (a known `codex exec -o` failure mode) is reported as a failure and exits nonzero.

Diagnostics: codex's stderr goes to `<out_file's .md stripped>.err.log` next to the output file; the output file is truncated at the start of each attempt.

### Public-repo caveat (`-b` / `-R`)

The `-b` salvage push fires on **every** exit — including success. With a public `origin`, that means content reaches the public remote *before* any review. Two safe configurations:

- **Omit `-b`.** The salvage *commit* still protects local work; nothing is pushed.
- **Pass `-R <private-mirror-remote>`.** Salvage pushes go to the private mirror; push to the public origin yourself after the review gate.

Also note the salvage push is a force-push (`push -f HEAD:<branch>`) — use a dedicated `salvage/*` branch name, never a branch anything else depends on.
