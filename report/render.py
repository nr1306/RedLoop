"""Render a Report as Markdown (Phase 09). No dependencies; a Streamlit dashboard
can layer on top later."""

from report.report import Report

# Known caveats stated in every report, so a headline number is never read alone.
_CAVEATS = [
    "Single-message attacks only — no multi-turn (gradual-escalation) conversations are tested.",
    "The cost cap can overshoot slightly under concurrency, so it is a safety rail, not a hard ceiling.",
    "The LLM judge is validated on 12 hand-labelled cases, not a large human-labelled set.",
    "Results are non-deterministic; a single run is a sample, not a fixed measurement.",
]


def _bar(value: float, width: int = 20) -> str:
    filled = round(value / 100 * width)
    return "█" * filled + "░" * (width - filled)


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"# RedLoop robustness report — run {report.run_id}")
    lines.append("")
    lines.append(f"Target model: `{report.target_model}`  ·  Judge: `{report.judge_model or 'none'}`")
    if report.notes:
        lines.append(f"Notes: {report.notes}")
    lines.append("")

    # Headline
    lines.append("## Overall robustness")
    lines.append("")
    lines.append(f"**{report.robustness_score:.1f} / 100**  `{_bar(report.robustness_score)}`")
    lines.append("")
    lines.append(f"- Targets held: **{report.targets_total - report.targets_breached} / "
                 f"{report.targets_total}** (a target = one seed+objective goal; breached if any attempt landed)")
    lines.append(f"- Total attempts: {report.attack_attempts} attacks + {report.control_attempts} controls")
    lines.append(f"- Control false positives: **{report.control_false_positives} / {report.control_attempts}** "
                 f"(a trustworthy score needs this at 0)")
    lines.append("")

    # Per category
    lines.append("## Vulnerability by category")
    lines.append("")
    lines.append("| Category | Targets breached | Attempts flagged |")
    lines.append("|---|---|---|")
    for cat in sorted(report.per_category):
        c = report.per_category[cat]
        if cat == "CONTROL":
            continue
        lines.append(f"| {cat} | {c['breached']}/{c['targets']} | {c['flagged']}/{c['attempts']} |")
    lines.append("")

    # Severity
    if report.severity_breakdown:
        lines.append("## Severity of exploits found (judge)")
        lines.append("")
        for sev in ("critical", "high", "medium", "low"):
            if sev in report.severity_breakdown:
                lines.append(f"- **{sev}**: {report.severity_breakdown[sev]}")
        lines.append("")

    # Depth curve
    if report.depth_curve:
        lines.append("## Exploits found as the search goes deeper")
        lines.append("")
        lines.append("| Depth | Cumulative targets breached |")
        lines.append("|---|---|")
        for depth, cumulative in report.depth_curve:
            lines.append(f"| {depth} | {cumulative} |")
        lines.append("")
        seed_wins = report.depth_curve[0][1]
        if seed_wins:
            lines.append(f"_{seed_wins} target(s) broke on the seed itself (depth 0); "
                         f"the rest required attacker refinement._")
            lines.append("")

    # Top exploits
    lines.append("## Top exploits")
    lines.append("")
    if not report.top_exploits:
        lines.append("_No exploits found — the target held against every attempt._")
    else:
        for i, ex in enumerate(report.top_exploits, 1):
            sev = ex.judge_severity or "n/a"
            scorers = []
            if ex.rule_flagged:
                scorers.append("rules")
            if ex.judge_flagged:
                scorers.append("judge")
            kind = "hit its target" if ex.achieved_target else "tripped a different rule"
            fired = ", ".join(ex.violations) or "judge-only"
            lines.append(f"**{i}. {ex.seed_id} → {ex.objective}** "
                         f"(severity: {sev}, depth {ex.depth}, caught by: {', '.join(scorers) or '—'})")
            lines.append(f"> {kind}: fired [{fired}]")
            lines.append(f"> {ex.message[:200].strip()}")
            if ex.judge_rationale:
                lines.append(f"> _{ex.judge_rationale[:200].strip()}_")
            lines.append("")

    # Scorer agreement
    sa = report.scorer_agreement
    lines.append("## Scorer agreement")
    lines.append("")
    lines.append(f"- Agree: {sa['agree']}  ·  Disagree: {sa['disagree']}  ·  Judge missing/errored: {sa['judge_missing']}")
    if sa["disagree"]:
        lines.append("- Disagreements are the interesting cases (usually the judge catching an encoded or "
                     "paraphrased leak the deterministic rules missed).")
    lines.append("")

    # Caveats
    lines.append("## Caveats")
    lines.append("")
    for caveat in _CAVEATS:
        lines.append(f"- {caveat}")
    lines.append("")

    return "\n".join(lines)
