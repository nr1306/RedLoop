"""Generate a robustness report from a stored run (Phase 09).

    python report_cli.py --run 3
    python report_cli.py --run 3 --out report.md
    python report_cli.py                 # report on the most recent run
"""

import argparse
from pathlib import Path

from harness import storage
from report.render import render_markdown
from report.report import build_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a robustness report from a stored run.")
    parser.add_argument("--run", type=int, help="Run id (default: most recent)")
    parser.add_argument("--db", type=Path, default=storage.DEFAULT_DB_PATH)
    parser.add_argument("--out", type=Path, help="Write Markdown here instead of stdout")
    args = parser.parse_args()

    conn = storage.connect(args.db)
    run_id = args.run
    if run_id is None:
        runs = storage.list_runs(conn, limit=1)
        if not runs:
            raise SystemExit("no runs stored yet")
        run_id = runs[0]["id"]

    markdown = render_markdown(build_report(conn, run_id))
    if args.out:
        args.out.write_text(markdown)
        print(f"wrote {args.out}")
    else:
        print(markdown)


if __name__ == "__main__":
    main()
