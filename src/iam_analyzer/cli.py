"""Command-line interface.

    iam-analyzer check --policy FILE [--policy FILE ...] --action ACTION --resource ARN
    iam-analyzer check --account FILE --principal user/NAME --action ACTION --resource ARN

Exit codes: 0 = allowed, 1 = denied, 2 = input error.
"""

import argparse
import sys
from collections.abc import Sequence

from iam_analyzer.account import load_account_file
from iam_analyzer.errors import PolicyError
from iam_analyzer.evaluator import evaluate
from iam_analyzer.loader import load_policy_file
from iam_analyzer.models import EvaluationResult, Request

EXIT_ALLOWED = 0
EXIT_DENIED = 1
EXIT_INPUT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-analyzer", description="Evaluate AWS IAM policies locally."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    check = subcommands.add_parser(
        "check", help="Can these policies perform ACTION on RESOURCE?"
    )
    source = check.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--policy",
        action="append",
        metavar="FILE",
        help="identity policy JSON file (repeat for multiple policies)",
    )
    source.add_argument(
        "--account",
        metavar="FILE",
        help="account JSON file with users, groups and roles (use with --principal)",
    )
    check.add_argument("--principal", help="user/NAME or role/NAME from the --account file")
    check.add_argument("--action", required=True, help="e.g. s3:GetObject")
    check.add_argument("--resource", required=True, help="e.g. arn:aws:s3:::bucket/key")
    return parser


def format_result(result: EvaluationResult) -> str:
    lines = [result.decision.value]
    if not result.reasons:
        lines.append("  No statement matched; access is denied by default.")
    for reason in result.reasons:
        sid = reason.statement.sid or "(no Sid)"
        source = reason.policy_name
        if reason.via_group:
            source += f" (via group {reason.via_group})"
        lines.append(f"  {reason.statement.effect.value:<6} {source}  Sid={sid}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.account) != bool(args.principal):
        parser.error("--account and --principal must be used together")

    try:
        if args.account:
            policies = load_account_file(args.account).policies_for(args.principal)
        else:
            policies = [load_policy_file(path) for path in args.policy]
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    result = evaluate(Request(action=args.action, resource=args.resource), policies)
    print(format_result(result))
    return EXIT_ALLOWED if result.allowed else EXIT_DENIED


if __name__ == "__main__":
    sys.exit(main())
