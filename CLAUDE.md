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
- [x] Phase 08 — Lineage + orchestration
- [x] Phase 09 — Reporting (v1.0)
- [x] Phase 10 — Patch & re-run
- [x] Phase 11 — Portfolio polish

## Architecture

- `config.py` — loads `.env` into frozen `TargetConfig` / `JudgeConfig` / `AttackerConfig`; fails loudly on a missing setting. Every module reads config through here.
- `target/` — the agent under test. `policy.py` (`Policy` data + `build_system_prompt`; `DEFAULT_POLICY` and the Phase-10 `HARDENED_POLICY`), `tools.py` (4 mocked tools in OpenAI Responses format), `environment.py` (in-memory fake files + search results, plant hooks), `canaries.py` (per-run fake secrets), `agent.py` (`run_agent` ReAct loop), `transcript.py` (`Transcript`/`ToolCallRecord`, provider-neutral stop reasons). Tools never have real side effects — every call is logged and simulated.
- `attacks/seed_attacks.json` — hand-written attack corpus (23 attacks + controls), each tagged with an OWASP LLM Top 10 category. `attacks/loader.py` validates it, renders canary placeholders (`{{API_KEY}}` etc.), and exposes the objective/vector enums.
- `scoring/scorer_rules.py` — deterministic checks against the tool-call trace (5 violation kinds). No LLM calls. Most heavily tested module.
- `scoring/scorer_judge.py` — LLM-judge scorer: blind, JSON-schema verdict + severity + rationale. Given canary values so it catches encoded/paraphrased leaks the rules miss.
- `harness/run_static.py` — runs the seed corpus against the target, scores with both scorers, logs to SQLite (v0.1). `harness/storage.py` — the SQLite schema (`runs`/`attempts`/`scores`) and record/read helpers, including lineage columns.
- `search_notes.md` — Phase 06 design spec for the attacker search (TAP: branch/prune/explore, objective-driven attacker, blind judge, lineage model).
- `attacker/attacker.py` — the attacker LLM: proposes N improved attack variants from the target reply + judge rationale. `attacker/search.py` — the TAP search loop (branch → prune-dedupe → run+score → keep best → repeat). `attacker/budget.py` — mandatory iteration + estimated-cost caps (thread-safe). v0.5.
- `orchestrator/orchestrator.py` — runs multiple searches concurrently (`asyncio.to_thread`) under one shared global budget + a concurrency semaphore; SQLite writes stay on the main thread.
- `report/report.py` — aggregates a run into a robustness score (target-level), per-category breakdown, depth curve, top exploits, severity, scorer agreement. `report/render.py` — Markdown renderer. `report/replay_export.py` — exports a run's logged data (incl. tokens/cost/lineage) as JSON for the replay visualization. v1.0.
- Entry-point CLIs (top level): `run_target.py` (one message, no storage), `run_attacks.py` (seed corpus, rule scorer, no storage), `run_judge_eval.py` (12-case judge validation), `run_attack_search.py` (single TAP search), `run_campaign.py` (concurrent campaign), `query_runs.py` (inspect stored runs, `--tree` lineage), `report_cli.py` (build a report). All support `--policy baseline|hardened` where relevant.
- Replay visualization — a published Artifact (the "Breach Arena" console) built from `report/replay_export.py` output; game-like replay of a run's logged attempts. Kept as an Artifact, not committed source (regenerate per run).
- `data/redloop.db` — SQLite store for transcripts, scores, and lineage. Never commit this file — it contains full attack transcripts including canary values.

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
