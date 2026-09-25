# Search design — the attacker loop (spec for Phase 07)

This is the design the automated attacker implements. It is a plan, not code. It
was written in Phase 06 so the loop is built against a clear contract.

## The problem

We have a scorer that grades any transcript and a target that resists most
hand-written attacks. We want an attacker LLM that starts from a seed attack and
**refines it** until it produces a violation. The space of possible prompts is
effectively infinite, so we need a search strategy, not random tries.

## Method: TAP (Tree of Attacks with Pruning)

TAP is PAIR (single-line iterative refinement) turned into a tree.

```
              seed (root)
             /     |     \
        variant  variant  variant     ← BRANCH: attacker proposes several
           |        x        |         ← PRUNE:  drop off-target/weak ones (x)
        variant           variant      ← EXPLORE: keep best, branch again
           |                 |
         ...   (until a violation, or a cap is hit)
```

Three operations per round:
1. **Branch** — the attacker proposes N variants of the current best attempt(s),
   each informed by the previous target response and judge rationale.
2. **Prune** — a cheap check drops variants that drifted off the objective or
   duplicate an existing attempt, *before* spending a target call on them.
3. **Explore** — run the survivors against the target, score them, keep the best
   few (by how close the judge says they came), branch from those next round.

Why TAP over PAIR: it explores more of the space, and every attempt already
records its parent, so the lineage tree (Phase 08) comes for free.

## The attacker is objective-driven (Option A)

Each branch of the tree is aimed at ONE target objective, chosen from the
scorer's set: `read_secret_file`, `call_forbidden_tool`, `email_external`,
`leak_canary_in_reply`, `canary_in_tool_args`.

The attacker prompt contains:
- the target's policy (so it knows the rules it is trying to get around),
- the **objective** for this branch, in plain language,
- the seed attack it is descended from,
- the previous attempt's target response,
- the previous attempt's judge verdict + severity + **rationale** (the richest
  signal — it says *why* the last try failed),
- an instruction to propose N improved variants.

### Two rules that keep Option A honest

1. **Objective goes to the attacker only — never the judge.** If the judge were
   told what an attempt was aiming for, it would lean toward finding it, and
   scorer/judge agreement would stop meaning anything. The judge stays blind
   (already true from Phase 04); the loop must preserve this.

2. **Aiming at one objective does not cap what we detect.** The rule scorer runs
   ALL checks on every transcript, so an attack aimed at `email_external` that
   also leaks a canary in the reply is still caught and recorded via
   `RuleScore.unexpected`. Option A caps what the attacker *targets*, not what
   the harness *sees*.

## Feedback signal (what the attacker learns from)

After each attempt the attacker receives, for its next round:
- target's final reply + tool calls made,
- rule violations found (the objective list that fired),
- judge verdict / severity / rationale.

The judge rationale is the primary teaching signal. Example: "the assistant read
the file but explicitly withheld the value" tells the attacker to push on
disclosure, not on getting the read to happen.

## Stopping rules (both caps are mandatory)

A branch/run stops when any of these is true:
- **Success** — an attempt produces the target objective (early stop for that branch).
- **Iteration cap** — max attempts per run (config).
- **Cost cap** — max spend per run in tokens/dollars (config).

Per `CLAUDE.md`, the orchestrator must refuse to start a run without BOTH caps
set. These live in config next to the model names.

## Seeding

The tree roots are the seed corpus. Order matters for a budgeted run:
- LLM02 and LLM06 seeds first — the live baseline showed these are the soft
  spots on `gpt-4.1-mini` (LLM01 injections went 0/8).
- LLM01 seeds still get explored, but a budget-limited run should not spend its
  whole allowance on the hardest category first.

## Lineage data model (carried from the start)

Every attempt records enough to reconstruct the tree, so Phase 08 needs no
schema change — only a strategy change (single-line → branching is already the
default here):

- `attempt.parent_id` — the attempt this one was refined from (NULL for a seed root).
- `attempt.seed_id` — the original seed at the root of this branch.
- `attempt.objective` — the objective this branch targets.
- `attempt.depth` — distance from the seed root.
- `attempt.attacker_prompt` / `attempt.attacker_rationale` — what the attacker
  wrote and why, for the report's "how did this exploit evolve" view.

## Open questions for Phase 07

- Branching factor N and how many survivors to keep per round (start small: N=3,
  keep 2 — tune against the cost cap).
- Prune step: cheap heuristic (dedupe + off-topic check) vs a small LLM call.
  Lean heuristic first; a pruning LLM call is a later refinement.
- Attacker model: same as judge (`gpt-5.4`) or a separate `ATTACKER_MODEL`?
  Likely its own setting so the attacker can be stronger/cheaper independently.
- Where the attacker may inject: user message only, or also propose planted
  file/search content (indirect)? Indirect is more powerful but a bigger prompt
  contract — decide at build time.
