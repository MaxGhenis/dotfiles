# === Secrets (macOS Keychain, service="claude-env") ===
# Manage with: ~/.claude/manage-secret.sh {set|get|del|list}
source ~/.claude/load-secrets.sh

# === History ===
HISTSIZE=100000
SAVEHIST=100000
setopt SHARE_HISTORY HIST_IGNORE_DUPS HIST_IGNORE_SPACE

# === Bun ===
[ -s "/Users/maxghenis/.bun/_bun" ] && source "/Users/maxghenis/.bun/_bun"
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"

# === PATH ===
export PATH="$HOME/.local/bin:$HOME/bin:/opt/homebrew/bin:$PATH"
export PATH="/Users/maxghenis/.antigravity/antigravity/bin:$PATH"

# === Aliases ===
alias gpum='git pull upstream master'
alias c='claude'
alias chrome='/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222 > /dev/null 2>&1 &'

# Supabase account switching
alias sb-policyengine='export SUPABASE_PROFILE=policyengine && echo "Using PolicyEngine Supabase account"'
alias sb-hivesight='export SUPABASE_PROFILE=hivesight && echo "Using HiveSight Supabase account"'
alias sb='bunx supabase --profile ${SUPABASE_PROFILE:-supabase}'

# === fzf ===
source <(fzf --zsh)

# === Claude Code ===
unset CLAUDE_CODE_TASK_LIST_ID  # Per-session tasks only; no shared task list

# uv: use committed lockfile as-is; `uv sync` never regenerates it.
# Prevents spurious uv.lock drift in fresh worktrees when local dep
# resolution differs from the upstream committer's. Override for a
# single command with UV_FROZEN=0, or run `uv lock` to intentionally
# refresh the lockfile.
export UV_FROZEN=1

# bun
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"
