"""Build a standalone replay-visualization HTML for a stored run (Phase 11).

Injects a run's exported data into report/replay.html and writes a self-contained
page you can open locally or publish as an Artifact.

    python -m report.build_replay --run 7 --out replay_run7.html
    python -m report.build_replay --run 7            # -> replay_run<N>.html
"""

import argparse
import json
from pathlib import Path

from harness import storage
from report.replay_export import export_replay

TEMPLATE = Path(__file__).parent / "replay.html"
PLACEHOLDER = "__REPLAY_DATA__"


def build(conn, run_id: int) -> str:
    data = json.dumps(export_replay(conn, run_id))
    template = TEMPLATE.read_text()
    if PLACEHOLDER not in template:
        raise RuntimeError(f"{TEMPLATE} is missing the {PLACEHOLDER} placeholder")
    # str.replace, not regex — the JSON contains \u escapes a regex repl would choke on.
    return template.replace(PLACEHOLDER, data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the replay visualization for a stored run.")
    parser.add_argument("--run", type=int, required=True)
    parser.add_argument("--db", type=Path, default=storage.DEFAULT_DB_PATH)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    conn = storage.connect(args.db)
    html = build(conn, args.run)
    out = args.out or Path(f"replay_run{args.run}.html")
    out.write_text(html)
    print(f"wrote {out} ({len(html)} bytes) — open it, or publish it as an Artifact")


if __name__ == "__main__":
    main()
