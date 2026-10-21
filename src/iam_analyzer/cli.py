"""Command-line interface.

    iam-analyzer check --policy FILE [--policy FILE ...] [--boundary FILE]
                       --action ACTION --resource ARN
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
from iam_analyzer.models import EvaluationResult, Layer, MatchedStatement, PolicyType, Request

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
    check.add_argument(
        "--boundary",
        metavar="FILE",
        help="permissions boundary policy JSON file (with --policy; account files set "
        "PermissionsBoundary on the user or role instead)",
    )
    check.add_argument("--action", required=True, help="e.g. s3:GetObject")
    check.add_argument("--resource", required=True, help="e.g. arn:aws:s3:::bucket/key")
    return parser


def format_result(result: EvaluationResult) -> str:
    lines = [result.decision.value]
    lines += [f"  {_not_allowed_message(layer)}" for layer in result.not_allowed_by]
    for reason in result.reasons:
        sid = reason.statement.sid or "(no Sid)"
        lines.append(f"  {reason.statement.effect.value:<6} {_source(reason)}  Sid={sid}")
    return "\n".join(lines)


def _source(reason: MatchedStatement) -> str:
    """The policy a statement came from, plus how that policy applies to the principal."""
    source = reason.policy_name
    if reason.via_group:
        source += f" (via group {reason.via_group})"
    if reason.layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        source += " (permissions boundary)"
    return source


def _not_allowed_message(layer: Layer) -> str:
    if layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        return "The permissions boundary does not allow this."
    return "No identity policy allows this; access is denied by default."


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.account) != bool(args.principal):
        parser.error("--account and --principal must be used together")
    if args.account and args.boundary:
        parser.error(
            "--boundary only works with --policy; in an account file, "
            "set PermissionsBoundary on the user or role"
        )

    try:
        if args.account:
            account = load_account_file(args.account)
            policies = account.policies_for(args.principal)
            boundary = account.boundary_for(args.principal)
        else:
            policies = [load_policy_file(path) for path in args.policy]
            boundary = load_policy_file(args.boundary) if args.boundary else None
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    request = Request(action=args.action, resource=args.resource)
    result = evaluate(request, policies, boundary=boundary)
    print(format_result(result))
    return EXIT_ALLOWED if result.allowed else EXIT_DENIED


if __name__ == "__main__":
    sys.exit(main())
