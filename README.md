# dotfiles

Config and scripts for my development machine. The interesting part is `bin/`:

| Script | What it does |
|--------|--------------|
| [`claude-model`](bin/claude-model) | Which model is *actually* serving a Claude Code session — reads the transcript's per-message model field; `-e <model>` exits 1 on a silent downgrade. See [docs/model-self-knowledge.md](docs/model-self-knowledge.md). |
| [`cc`](bin/cc) | Claude Code pane launcher (superseded by [tmux-claude-code](https://github.com/MaxGhenis/tmux-claude-code)) |
| [`sweep-worktrees`](bin/sweep-worktrees) | Rescue-and-bundle stale git worktrees before removing them |
| [`claude-statusline`](bin/claude-statusline) | Claude Code status line: `model · 5h % · wk % · dir` from the statusLine JSON on stdin. Render-only: writes nothing (the subfleet v1 tap it replaces teed usage to disk). Wire it with `~/.claude/settings.json` `statusLine.command` → `~/bin/claude-statusline` (symlink). Tests: [tests/test_claude_statusline.py](tests/test_claude_statusline.py). |

## Workflow docs

- [Cross-model orchestration](docs/model-orchestration.md) — standing delegation defaults: judgment on Fable, heavy lifting and cyber to Sol subagents, blind two-family review
- [Your agent doesn't know which model it is](docs/model-self-knowledge.md) — Claude Code shows *you* the serving model; Claude itself can't tell when Fable is silently Opus. A drop-in self-check so it can, and what it should do when it fires

## carpool (moved)

`codex-run`, `claude-lane`, the `codex` PATH shim, `codex-guard`, and `cc-mirror-sessions` used to live here. They are now subcommands of **carpool** — my multi-account AI capacity stack (one package: `carpool status|pick|run|codex|claude|login|mirror|watch`), which lives in a private repo; a public snapshot will follow under the same name. This repo keeps only the generic scripts above.
