# === Secrets (macOS Keychain, service="claude-env") ===
# Manage with: ~/.claude/manage-secret.sh {set|get|del|list}
source ~/.claude/load-secrets.sh

# === History ===
HISTSIZE=100000
SAVEHIST=100000
setopt SHARE_HISTORY HIST_IGNORE_DUPS HIST_IGNORE_SPACE

# === Conda (lazy-loaded) ===
conda() {
    unfunction conda
    __conda_setup="$('/Users/maxghenis/miniconda3/bin/conda' 'shell.zsh' 'hook' 2>/dev/null)"
    if [ $? -eq 0 ]; then eval "$__conda_setup"
    elif [ -f "/Users/maxghenis/miniconda3/etc/profile.d/conda.sh" ]; then . "/Users/maxghenis/miniconda3/etc/profile.d/conda.sh"
    else export PATH="/Users/maxghenis/miniconda3/bin:$PATH"
    fi
    unset __conda_setup
    conda "$@"
}

# === NVM (lazy-loaded) ===
export NVM_DIR="$HOME/.nvm"
nvm() {
    unfunction nvm
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    [ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"
    nvm "$@"
}

# === Julia ===
path=('/Users/maxghenis/.juliaup/bin' $path)
export PATH

# === Bun ===
[ -s "/Users/maxghenis/.bun/_bun" ] && source "/Users/maxghenis/.bun/_bun"
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"

# === PATH ===
export PATH="$HOME/.local/bin:$HOME/bin:/opt/homebrew/bin:/opt/homebrew/opt/python@3.12/bin:$PATH"
export PATH="/Users/maxghenis/.antigravity/antigravity/bin:$PATH"

# === Aliases ===
alias gpum='git pull upstream master'
alias c='claude'
alias t='tmux attach -t'

# Supabase account switching
alias sb-policyengine='export SUPABASE_PROFILE=policyengine && echo "Using PolicyEngine Supabase account"'
alias sb-hivesight='export SUPABASE_PROFILE=hivesight && echo "Using HiveSight Supabase account"'
alias sb='bunx supabase --profile ${SUPABASE_PROFILE:-supabase}'

# === fzf ===
source <(fzf --zsh)

# === Claude Code ===
unset CLAUDE_CODE_TASK_LIST_ID  # Per-session tasks only; no shared task list

# === tmux ===
# Skip auto-attach in VS Code terminals (use VS Code's Claude Code panel instead)
if [[ -z "$TMUX" && -z "$VSCODE_INJECTION" ]]; then
  if [[ -n "$SSH_CONNECTION" ]]; then
    # Remote: grouped session with its own window running Claude Code
    tmux new-session -A -t c -s "remote-$$" \; new-window -n remote 'claude; exec zsh' 2>/dev/null || tmux new -s c 'claude; exec zsh'
  else
    # Local: attach to main session
    tmux attach -t c 2>/dev/null || tmux new -s c 'claude; exec zsh'
  fi
fi
