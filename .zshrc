# === Secrets (macOS Keychain, service="claude-env") ===
# Manage with: ~/.claude/manage-secret.sh {set|get|del|list}
source ~/.claude/load-secrets.sh

# === Google Cloud SDK ===
if [ -f '/Users/maxghenis/Downloads/google-cloud-sdk/path.zsh.inc' ]; then . '/Users/maxghenis/Downloads/google-cloud-sdk/path.zsh.inc'; fi
if [ -f '/Users/maxghenis/Downloads/google-cloud-sdk/completion.zsh.inc' ]; then . '/Users/maxghenis/Downloads/google-cloud-sdk/completion.zsh.inc'; fi

# === Conda ===
__conda_setup="$('/Users/maxghenis/miniconda3/bin/conda' 'shell.zsh' 'hook' 2>/dev/null)"
if [ $? -eq 0 ]; then
    eval "$__conda_setup"
else
    if [ -f "/Users/maxghenis/miniconda3/etc/profile.d/conda.sh" ]; then
        . "/Users/maxghenis/miniconda3/etc/profile.d/conda.sh"
    else
        export PATH="/Users/maxghenis/miniconda3/bin:$PATH"
    fi
fi
unset __conda_setup

# === NVM ===
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"

# === Julia ===
path=('/Users/maxghenis/.juliaup/bin' $path)
export PATH

# === Bun ===
[ -s "/Users/maxghenis/.bun/_bun" ] && source "/Users/maxghenis/.bun/_bun"
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"

# === PATH ===
export PATH="$HOME/bin:/opt/homebrew/bin:/opt/homebrew/opt/python@3.12/bin:$PATH"
export PATH="/Users/maxghenis/.antigravity/antigravity/bin:$PATH"
export PYTHONPATH="$PWD/src:$PYTHONPATH"
. "$HOME/.local/bin/env"


# === Aliases ===
alias gpum='git pull upstream master'
alias c='claude --dangerously-skip-permissions'
alias claude='claude --dangerously-skip-permissions'
alias pip="pip3"
alias t='tmux attach -t'

# Supabase account switching
alias sb-policyengine='export SUPABASE_PROFILE=policyengine && echo "Using PolicyEngine Supabase account"'
alias sb-hivesight='export SUPABASE_PROFILE=hivesight && echo "Using HiveSight Supabase account"'
alias sb='npx supabase --profile ${SUPABASE_PROFILE:-supabase}'

# === fzf ===
source <(fzf --zsh)

# === Claude Code ===
unset CLAUDE_CODE_TASK_LIST_ID  # Per-session tasks only; no shared task list

# === tmux ===
if [[ -z "$TMUX" ]]; then
  if [[ -n "$SSH_CONNECTION" ]]; then
    # Remote: grouped session with its own window running Claude Code
    tmux new-session -A -t c -s "remote-$$" \; new-window -n remote 'claude --dangerously-skip-permissions' 2>/dev/null || tmux new -s c 'claude --dangerously-skip-permissions'
  else
    # Local: attach to main session
    tmux attach -t c 2>/dev/null || tmux new -s c 'claude --dangerously-skip-permissions'
  fi
fi
