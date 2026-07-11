# Cross-model orchestration

How I split work between Claude Fable 5 (every Claude Code session's main model) and OpenAI's gpt-5.6-sol dispatched through the Codex CLI. None of it is per-session prompting: the rules live as standing instructions in Claude Code's persistent memory / `CLAUDE.md`, so every session applies them by default. Adapt the model names to your stack — the structure is what matters.

## The split is by how work fails

- **Loud failures** — the test goes red, the import doesn't resolve, CI blocks the merge. Any capable model plus a feedback loop converges. Delegate these.
- **Silent failures** — the review that approves a defect, the architecture call that boxes you in later, the paragraph that says something you didn't mean. No feedback loop exists; the only defense is the judgment of the model doing the work. Keep these on your strongest model.

Concretely: the main session (Fable) keeps design, review verdicts, data semantics, prose, and anything launch-gating. It dispatches the grinds to Sol: exhaustive repo audits, does-every-import-resolve checks, git-history sweeps, multi-repo migrations. Mid-tier subagents (Opus for long orchestration loops, Haiku for bulk mechanical edits) fill the middle.

**Cyber and security-adjacent work also defaults to Sol** — not only because it's usually grind-shaped, but because Sol has no Anthropic safety classifier. Fable's classifier targets cyber content and, when tripped, silently swaps the session onto Opus 4.8 ([details](model-self-knowledge.md)); routing that work cross-vendor by default means the main loop never invites the swap.

Three operational rules:

1. **Always pass the model explicitly when delegating.** Subagents inherit the main session's model by default — a grep sweep at frontier prices is a $50-per-million-output-tokens grep.
2. **Pick the orchestrator tier by loop length, not task difficulty.** A cheaper model's per-token edge doesn't survive long loops: every extra turn re-pays the whole context, and one coordination error (bad merge, wrong attribution) costs more than the price delta.
3. **Frame security reviews as defensive audits, not exploit construction.** Audit framing passes both Fable's classifier and Codex's content filter; construction framing trips both.

### Standing instruction (drop-in)

The delegation defaults, as they'd sit in persistent memory or `CLAUDE.md`:

```markdown
## Delegation defaults
- Heavy lifting (exhaustive audits, repo-wide greps, git-history sweeps,
  multi-repo migrations) goes to Sol subagents via codex-run — don't grind
  in the main loop.
- Cyber/security-adjacent work goes to Sol by default: it's heavy lifting,
  and Sol has no Anthropic safety classifier, so it can't trip the
  Fable → Opus fallback that security content invites. Frame review prompts
  as defensive correctness audits, never exploit construction.
- Always pass the model explicitly when delegating — subagents inherit the
  main session's model otherwise.
- Judgment, review verdicts, and writing stay on Fable; verify you're
  actually Fable first (see the model self-check).
```

## Cross-family blind review

Same-family self-review fails by **leniency**: a reviewer walks past defects shaped like the ones it would have written, because it shares the blind spot that produced them. A second model from the same family adds redundancy, not independence. A different family — different training, different failure distribution — catches what one family structurally can't.

For anything review-shaped (audits, pre-merge checks, launch-gating judgments):

1. **Scout inline.** The main session enumerates the surface and stages pinned read-only checkouts, so findings cite exact SHAs.
2. **Fan out blind, in parallel.** The cross-family model gets the grind; a same-family subagent gets the judgment axes (does the type guarantee what its name claims, is the verification circular, does the claim overstate the mechanism). Neither sees the other's findings — a reviewer that reads another's report anchors on it, and you've paid for two reviews and gotten one.
3. **Reconcile.** The main loop merges and ranks by confidence: two-family agreement highest; single-family findings flagged as such and spot-verified at the line level before anything is relayed.
4. **Gate, don't merge.** Read-only throughout; nothing lands on a model's say-so.

Calibration note: when a reviewer is harsh on its own family's output, that's signal, not pedantry — leniency is the failure mode you hired it to break.

## Dispatch

Cross-vendor dispatch goes through [`codex-run`](../bin/codex-run) — a hardened `codex exec` wrapper that retries transient failures, fails fast on content-filter refusals (they're framing problems; rewrite the prompt as a defensive audit instead of retrying), and salvage-commits work on kill or crash. Full usage, flags, and the public-repo `-R` caveat: [README § codex-run](../README.md#codex-run).

For reviews, dispatch read-only:

```bash
codex-run -H ~/.codex -m gpt-5.6-sol -C ~/src/target-repo \
          -p prompt.md -o findings.md -s read-only
```

## Related

The swap these defaults defend against has a second wrinkle: when it happens, the agent itself doesn't know — it keeps identifying as the configured model. Giving it self-knowledge (a transcript check as a standing instruction) is the other half of the setup: [model-self-knowledge.md](model-self-knowledge.md).
