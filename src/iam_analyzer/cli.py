"""Command-line interface.

    iam-analyzer check --policy FILE [--policy FILE ...] [--boundary FILE]
                       --action ACTION --resource ARN
    iam-analyzer check --account FILE --principal user/NAME [--org FILE]
                       --action ACTION --resource ARN

Exit codes: 0 = allowed, 1 = denied, 2 = input error.
"""

import argparse
import sys
from collections.abc import Sequence

from iam_analyzer.account import Account, load_account_file
from iam_analyzer.errors import AccountError, PolicyError
from iam_analyzer.evaluator import evaluate
from iam_analyzer.loader import load_policy_file
from iam_analyzer.models import (
    EvaluationResult,
    Layer,
    MatchedStatement,
    OrgTarget,
    PolicyType,
    Request,
    ScpLevel,
    TargetType,
)
from iam_analyzer.organization import load_organization_file

EXIT_ALLOWED = 0
EXIT_DENIED = 1
EXIT_INPUT_ERROR = 2


class _StoreOnce(argparse.Action):
    """Store an option's value, but make giving the option twice a usage error.

    argparse normally keeps the last value, so `--boundary A --boundary B` would silently
    evaluate only B.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} can only be given once")
        setattr(namespace, self.dest, values)


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
        action=_StoreOnce,
        metavar="FILE",
        help="account JSON file with users, groups and roles (use with --principal)",
    )
    check.add_argument(
        "--principal", action=_StoreOnce, help="user/NAME or role/NAME from the --account file"
    )
    check.add_argument(
        "--boundary",
        action=_StoreOnce,
        metavar="FILE",
        help="permissions boundary policy JSON file (with --policy; account files set "
        "PermissionsBoundary on the user or role instead)",
    )
    check.add_argument(
        "--org",
        action=_StoreOnce,
        metavar="FILE",
        help="organization JSON file with SCPs (with --account; the account file needs an "
        "AccountId)",
    )
    check.add_argument("--action", action=_StoreOnce, required=True, help="e.g. s3:GetObject")
    check.add_argument(
        "--resource", action=_StoreOnce, required=True, help="e.g. arn:aws:s3:::bucket/key"
    )
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
    elif reason.layer.policy_type is PolicyType.SCP:
        source += f" (SCP on {_target(reason.layer.org_target)})"
    return source


def _not_allowed_message(layer: Layer) -> str:
    if layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        return "The permissions boundary does not allow this."
    if layer.policy_type is PolicyType.SCP:
        return f"No SCP attached to {_target(layer.org_target)} allows this."
    return "No identity policy allows this; access is denied by default."


def _target(target: OrgTarget) -> str:
    if target.type is TargetType.ROOT:
        return "the root"
    if target.type is TargetType.ORGANIZATIONAL_UNIT:
        return f"OU {target.name}"
    return f"account {target.name}"


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
    if args.org and not args.account:
        parser.error("--org only works with --account")

    try:
        request = Request(action=args.action, resource=args.resource)
        if args.account:
            account = load_account_file(args.account)
            policies = account.policies_for(args.principal)
            boundary = account.boundary_for(args.principal)
            scps = _scp_levels(account, args.org) if args.org else ()
        else:
            policies = [load_policy_file(path) for path in args.policy]
            boundary = load_policy_file(args.boundary) if args.boundary else None
            scps = ()
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    result = evaluate(request, policies, boundary=boundary, scps=scps)
    print(format_result(result))
    return EXIT_ALLOWED if result.allowed else EXIT_DENIED


def _scp_levels(account: Account, org_file: str) -> tuple[ScpLevel, ...]:
    """The SCP levels in the organization file that apply to `account`."""
    if account.account_id is None:
        raise AccountError(f"{account.name}: needs an 'AccountId' to look up its SCPs")
    return load_organization_file(org_file).scp_levels_for(account.account_id)


if __name__ == "__main__":
    sys.exit(main())
