"""Command line: python -m lurecheck message.eml"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from lurecheck.analysis import analyze
from lurecheck.checks import Options
from lurecheck.message import MessageError, load_email
from lurecheck.report import render_text, to_dict
from lurecheck.text import visible


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lurecheck",
        description="Read saved emails (.eml) and explain how likely each is to be phishing. "
        "Nothing in a message is opened, run or fetched.",
    )
    parser.add_argument("files", nargs="+", help="saved email files (.eml)")
    parser.add_argument("--json", action="store_true", help="print the results as JSON instead of text")
    parser.add_argument(
        "--trusted-server",
        metavar="NAME",
        help="the name your own mail server writes in Authentication-Results, such as mx.google.com. "
        "Results from any other server are then ignored. Default: use the topmost results",
    )
    args = parser.parse_args(argv)
    options = Options(trusted_server=args.trusted_server)

    reports, failed = [], 0
    for path in args.files:
        try:
            reports.append(analyze(load_email(path), source=path, options=options))
        except MessageError as error:
            failed += 1
            # Not being readable is unusual for genuine mail, so say so instead of just failing.
            print(f"{visible(path, 200)}: could not be analysed: {error}", file=sys.stderr)
    if args.json:
        print(json.dumps([to_dict(report) for report in reports], indent=2))
    else:
        print(("\n" + "=" * 100 + "\n\n").join(render_text(report) for report in reports), end="")
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
