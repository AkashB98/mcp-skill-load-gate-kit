"""CLI: python -m mcp_skill_gate check <bundle.json> [--registry r.json]
       python -m mcp_skill_gate classify "<command>"
       python -m mcp_skill_gate demo [--bundles data/bundles]
Exit codes: check -> 0 ALLOW/ALLOW_STRIPPED, 2 QUARANTINE; demo -> 0.
"""
from __future__ import annotations

import argparse
import glob
import json
import sys

from .classifier import classify
from .gate import load_bundle, load_registry, vet


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp_skill_gate")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="vet one bundle JSON file")
    p_check.add_argument("bundle")
    p_check.add_argument("--registry", default=None)

    p_cls = sub.add_parser("classify", help="classify one shell command")
    p_cls.add_argument("command")

    p_demo = sub.add_parser("demo", help="vet every bundle in a directory")
    p_demo.add_argument("--bundles", default="data/bundles")
    p_demo.add_argument("--registry", default=None)

    args = parser.parse_args(argv)

    if args.cmd == "classify":
        print(json.dumps(classify(args.command), indent=2))
        return 0

    registry = load_registry(args.registry) if args.registry else {}

    if args.cmd == "check":
        record = vet(load_bundle(args.bundle), registry)
        print(json.dumps(record, indent=2))
        return 2 if record["decision"] == "QUARANTINE" else 0

    if args.cmd == "demo":
        paths = sorted(glob.glob(f"{args.bundles}/*.json"))
        if not paths:
            print(f"no bundles found in {args.bundles}", file=sys.stderr)
            return 1
        for path in paths:
            record = vet(load_bundle(path), registry)
            drift = " DRIFT->RE-VET" if record["drift_detected"] else ""
            print(f"{record['decision']:<15} {record['skill']}@{record['version']}{drift}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
