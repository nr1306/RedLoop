# RedLoop

Automated red-teaming harness for tool-calling LLM agents. An attacker LLM iteratively searches for prompt-injection and tool-misuse exploits against a target agent; a hybrid scorer (deterministic checks + LLM judge) grades every attempt; results and lineage are logged and rolled up into a robustness report.

This file is project context for Claude Code (and any Claude session working in this repo) — read it before touching code, and keep it in sync as the project's actual structure diverges from the plan below.

## How I want to build this

I am building this to learn, not to ship fast. Do not "vibe code" this project — do not generate large blocks of working code I haven't asked to walk through. Default mode:

1. Before writing code for a new module, explain the approach in a few sentences (what it does, why this design) and wait for a go-ahead if the module is non-trivial (the attacker loop, the scorers, the orchestrator).
2. Prefer small, reviewable diffs over big single-shot file generations.
3. Keep `BUILD_LOG.md` up to date: at the end of each phase, append a section with what was built, the decisions behind it, and a checklist of topics I should study. I work through that list at my own pace — do NOT pause building to wait for me to learn something, and don't teach unprompted; log it instead.
4. When you introduce a concept I haven't used before (asyncio patterns, a search/optimization technique, an eval-judge pattern), briefly explain it inline as a comment or in your response — don't just use it silently.
5. If I ask you to just "build phase N," it's fine to move faster, but still keep functions small and named clearly enough that I can read the diff and understand it without you re-explaining from scratch.

## Current status

Following the phased roadmap (target agent → attack taxonomy/seed corpus → deterministic scorer → LLM-judge scorer → static harness MVP → search theory → automated attacker loop → lineage/orchestration → reporting → patch & re-run → polish). Check with me which phase is active before assuming — update this section as phases complete.

- [x] Phase 01 — Target agent
- [x] Phase 02 — Attack taxonomy / seed corpus
- [x] Phase 03 — Deterministic scorer
- [x] Phase 04 — LLM-judge scorer
- [x] Phase 05 — Static harness (MVP, v0.1)
- [x] Phase 06 — Search theory (PAIR/TAP)
- [x] Phase 07 — Automated attacker loop (v0.5)
- [ ] Phase 08 — Lineage + orchestration
- [ ] Phase 09 — Reporting (v1.0)
- [ ] Phase 10 — Patch & re-run
- [ ] Phase 11 — Portfolio polish

## Architecture

- `target/` — the agent under test: system prompt + policy, mocked tools (`send_email`, `execute_code`, `search_web`, `read_file`), planted canary secrets. Tools must never have real side effects — every tool call is logged and simulated, never actually executed against a real service.
- `attacks/seed_attacks.json` — hand-written attack corpus, each entry tagged with an OWASP LLM Top 10 category (e.g. LLM01 Prompt Injection, LLM02 Insecure Output Handling, LLM06 Excessive Agency).
- `scoring/scorer_rules.py` — deterministic checks against the raw tool-call trace (forbidden tool calls, canary leaks). No LLM calls in this module.
- `scoring/scorer_judge.py` — LLM-judge scorer: rubric-driven prompt that reads a full transcript and returns verdict + rationale + severity.
- `harness/run_static.py` — runs the seed corpus against the target, logs transcripts + scores to SQLite. This is the v0.1 milestone — get this fully working before touching the attacker loop.
- `attacker/attacker.py` — the core search loop: attacker LLM proposes an attack, target responds, both scorers grade it, attacker sees the result and proposes the next attempt (PAIR/TAP-style iterative refinement). v0.5 milestone.
- `orchestrator/orchestrator.py` — runs multiple attack threads concurrently (asyncio), tracks attack lineage (which mutation descended from which seed), enforces hard iteration/cost budget caps.
- `report/report.py` — aggregates a run into vulnerability-by-category breakdown, success-rate-over-iterations curve, top exploits found, and an overall robustness score. v1.0 milestone. Optional Streamlit dashboard on top.
- `data/redloop.db` — SQLite store for transcripts, scores, and lineage. Never commit this file — it will contain full attack transcripts including canary values.

## Tech stack

- Python 3.11+
- OpenAI SDK (`openai>=2.33,<3`), **Responses API** (not Chat Completions), for all LLM roles: target, attacker, and judge. Switched from Anthropic during Phase 01 — don't mix providers without discussing
- Target calls use `store=False` + `include=["reasoning.encrypted_content"]` (transcripts contain canaries, so nothing is stored server-side); reasoning items are replayed to the API but not kept in `Transcript.messages`
- `Transcript.stop_reason` uses provider-neutral values (`completed` / `refusal` / `incomplete` / `max_turns`) so downstream phases never depend on OpenAI's response shapes
- SQLite for storage (stdlib `sqlite3` is enough — no ORM needed at this scale)
- `asyncio` for concurrent attack execution
- `pytest` for the deterministic scorer's tests — this module should be the most heavily tested since everything else's trust depends on it
- Streamlit, optional, only for Phase 09's dashboard

## Conventions

- Type hints on all function signatures.
- Every module should be runnable/testable in isolation — no module should require the full pipeline to be wired up just to unit test it.
- Config (API keys, budget caps, model names) goes in a `.env` file, never hardcoded. Add `.env` to `.gitignore` immediately if it isn't already there.
- Canary secrets used for exfiltration testing are realistic-looking but non-functional random values (no "canary"/"test" labels, so the target model can't tell it's being tested), generated per-run, never real credentials, and never mimicking a real provider's key format.
- Every attack run must respect a hard iteration cap and a cost cap read from config — the orchestrator should refuse to start a run without both set.

## Known limitations (revisit after Phase 09)

- **Single-message attacks only.** `run_agent` takes one user message per conversation; the target's internal tool loop is multi-step, but there are no multi-turn (gradual-escalation) attacks across several user messages. The attacker, scoring attribution, and lineage are all designed around single prompts. The v1.0 robustness score says nothing about multi-turn attacks — reports should state this. Revisit after Phase 09 as an extension.

## Safety notes

- All target-agent tools are mocked. If a tool implementation ever makes a real network call, a real filesystem write outside a scratch directory, or a real email send, treat that as a bug to fix immediately, not a feature.
- This harness is for testing an agent I built and control. Do not point it at third-party services or production systems.
