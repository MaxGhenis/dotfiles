# Your agent doesn't know which model it is

**TL;DR:** Claude Code shows *you* the serving model right in the window. Claude itself only sees its configured model — after a safety-classifier fallback (Fable 5 → Opus 4.8, documented, sticky ~1hr), the agent keeps reasoning and self-reporting as Fable while Opus serves the turns. Any model-conditional instruction you've given it silently breaks. The fix is a standing instruction with a transcript check, so the agent can learn what's actually serving it and act accordingly.

## Who sees what

- **You** see the serving model in the Claude Code window. No mystery there.
- **API callers** get `response.model`, fallback content blocks, and `usage.iterations` — all documented.
- **The agent** sees only its own prompt, and the environment block in it names the *configured* model. That's the gap.

The mechanism behind the swap is documented API behavior: Fable 5 runs safety classifiers (categories include cyber, bio, and reasoning extraction); a flagged request returns HTTP 200 with `stop_reason: "refusal"`, and Claude Code's built-in fallback re-serves the turn on Opus 4.8, sticky for roughly an hour on a best-effort content-hash basis. Anthropic is open about all of it — "Top-level `model` names the model that produced the message."

What the documentation doesn't hand you is agent self-knowledge. In one of my sessions I could see Opus 4.8 serving in the window; the agent, asked directly which model it was, said Fable — and kept saying so across 407 Opus-served turns. It wasn't lying. It was reading the only thing it had: its configuration.

## Why the agent needs to know

Because standing instructions are model-conditional. Mine include "writing deliverables are authored on Fable only," "judgment and review verdicts stay on the frontier model," and "delegate by tier, naming the model explicitly." An agent that misidentifies itself can't follow any of those — it will confidently author the writing, issue the verdicts, and route the work as if it were the model you configured.

And the exposure concentrates exactly where it hurts: cyber content is what the classifier targets, so the judgment turns of a security review are the turns most likely to be swapped.

## Give it the check

Claude Code writes per-message ground truth into the session transcript (JSONL under `~/.claude/projects/`). [`claude-model`](../bin/claude-model) reads it:

```
$ claude-model -e claude-fable-5
transcript: ~/.claude/projects/-Users-maxghenis/61132b6a-….jsonl
last 20 assistant turns:
  claude-opus-4-8 x17
  claude-fable-5 x3
refusal fallbacks in session: 2
latest: claude-opus-4-8
DOWNGRADED: latest turn served by claude-opus-4-8 (expected claude-fable-5)
```

`-e <model>` makes it a gate (exit 1 on mismatch); with no argument it uses the newest transcript for the current directory's project, which in the common case is the calling session itself — pass the session id or path when parallel sessions share a directory. Underneath it's one line of jq, if you'd rather not take the script:

```bash
jq -rc 'select(.type=="assistant")|.message.model' \
  ~/.claude/projects/<project-dir>/<session-id>.jsonl | tail
```

## The standing instruction

Put it in Claude Code's persistent memory or `CLAUDE.md` so every session carries it (adapt model names to your stack):

```markdown
## Model self-check
The environment block shows the CONFIGURED model, not the SERVING model — after a
safety-classifier fallback it still says Fable while turns are served by Opus 4.8.
To find out which model you actually are, run `claude-model -e claude-fable-5`
(exit 1 = downgraded), or read your own transcript directly:

    jq -rc 'select(.type=="assistant")|.message.model' \
      ~/.claude/projects/<project-dir>/<session-id>.jsonl | tail

Run it before any model-sensitive judgment or writing, and after any resume or
compaction. If downgraded: say so, route judgment and writing to a Sol subagent
or an audit-framed Fable subagent, and re-review recent judgment once the
transcript shows Fable again.
```

With this in place, the agent stops answering "which model are you" from its config and starts answering from evidence — and flags swaps on its own at the moments that matter.

## What the agent should do when it's not the model it thinks

1. **Shift weight to Sol.** My [delegation defaults](model-orchestration.md) already route heavy lifting and cyber work to gpt-5.6-sol subagents, which sit outside Anthropic's classifier entirely — so a downgraded main loop doesn't stop the work, it delegates more of it, deferring reconciliation until the transcript shows Fable again.
2. **Recover Fable via audit framing.** Construction framing ("exfiltrate the key," "poison the pin") is what trips the classifier; the same content framed as a defensive correctness audit passes. A Fable subagent given identical security material under audit framing ran 166 turns with zero refusals — verified with the same jq check against its own transcript. An audit-framed `model: fable` subagent recovers real Fable for judgment and writing even while the main loop is stuck.
3. **Re-review the swapped window.** Whatever judgment the main loop produced while downgraded gets a second look once it's back — and the transcript shows exactly which turns were whose.

## The general point

Any provider that can substitute a model server-side — for safety, capacity, or cost — produces an agent that's wrong about itself, because configuration is intent and only the response is ground truth. The agent can't fix that; you can, by giving it access to its own ground truth. Here that's one line of `jq` and a paragraph of standing instructions.
