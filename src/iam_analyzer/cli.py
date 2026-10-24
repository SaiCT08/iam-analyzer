"""Command-line interface.

    iam-analyzer check --policy FILE [--policy FILE ...] [--boundary FILE]
                       [--resource-policy FILE | --no-resource-policy]
                       --action ACTION --resource ARN [CONTEXT]
    iam-analyzer check --account FILE --principal user/NAME [--org FILE] [--no-session-tags]
                       --action ACTION --resource ARN [CONTEXT]

CONTEXT describes the request's condition keys:
    --context KEY=VALUE   a key's value (repeat for more keys, or for more values of one key)
    --absent KEY          a key the request doesn't include

A request on a specific resource also needs the resource described. With --account, the
account file's Resources describe it. With --policy, --resource-policy FILE gives its
resource-based policy, such as its bucket's policy, and --no-resource-policy says it has none.
Either flag says the resource is in the same account, and for an S3 bucket, that its ACLs are
disabled.

Exit codes: 0 = allowed, 1 = denied, 2 = input error.
"""

import argparse
import sys
from collections.abc import Sequence

from iam_analyzer import resources
from iam_analyzer.account import Account, load_account_file
from iam_analyzer.context import RequestContext
from iam_analyzer.errors import AccountError, MissingContextError, MissingResourceError, PolicyError
from iam_analyzer.evaluator import evaluate
from iam_analyzer.loader import load_policy_file
from iam_analyzer.models import (
    Condition,
    EvaluationResult,
    Layer,
    MatchedStatement,
    OrgTarget,
    PolicyType,
    PrincipalMatch,
    Request,
    ScpLevel,
    TargetType,
)
from iam_analyzer.organization import load_organization_file

EXIT_ALLOWED = 0
EXIT_DENIED = 1
EXIT_INPUT_ERROR = 2
MISSING_CONTEXT_HINT = (
    "hint: give each key a value with --context KEY=VALUE, "
    "or use --absent KEY if the request doesn't include it"
)
MISSING_RESOURCE_HINT = {
    "account": "hint: describe it in the account file's Resources, as {} if it has no "
    "resource-based policy",
    "policy": "hint: give its resource-based policy with --resource-policy FILE, or "
    "--no-resource-policy if it has none; either says it is in the same account",
}
# How a resource-based policy's statement named the caller.
NAMES = {
    PrincipalMatch.EVERYONE: "everyone",
    PrincipalMatch.USER: "the user",
    PrincipalMatch.ROLE: "the role",
    PrincipalMatch.ACCOUNT: "the account",
}


class _StoreOnce(argparse.Action):
    """Store an option's value, but make giving the option twice a usage error.

    argparse normally keeps the last value, so `--boundary A --boundary B` would silently
    evaluate only B.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} can only be given once")
        setattr(namespace, self.dest, values)


def _key_value(text: str) -> tuple[str, str]:
    """Split a --context argument at its first "=", so values may contain "=" themselves."""
    key, equals, value = text.partition("=")
    if not equals or not key:
        raise argparse.ArgumentTypeError(f"expected KEY=VALUE, got {text!r}")
    return key, value


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
    check.add_argument(
        "--resource-policy",
        action=_StoreOnce,
        metavar="FILE",
        help="with --policy: the resource-based policy on the request's resource, such as its "
        "bucket's policy. It also says the resource is in the same account, and for an S3 "
        "bucket, that its ACLs are disabled (Object Ownership: Bucket owner enforced)",
    )
    check.add_argument(
        "--no-resource-policy",
        action="store_true",
        help="with --policy: the request's resource is in the same account and has no "
        "resource-based policy; for an S3 bucket, also that its ACLs are disabled (Object "
        "Ownership: Bucket owner enforced). With --account, describe resources in the account "
        "file's Resources instead",
    )
    check.add_argument(
        "--no-session-tags",
        action="store_true",
        help="with --account: a role's session has no session tags, so the role's own tags are "
        "its only aws:PrincipalTag keys",
    )
    check.add_argument("--action", action=_StoreOnce, required=True, help="e.g. s3:GetObject")
    check.add_argument(
        "--resource", action=_StoreOnce, required=True, help="e.g. arn:aws:s3:::bucket/key"
    )
    check.add_argument(
        "--context",
        action="append",
        type=_key_value,
        metavar="KEY=VALUE",
        help="a condition key's value in the request, e.g. aws:username=jsmith (repeat for more "
        "keys, or for more values of one key)",
    )
    check.add_argument(
        "--absent",
        action="append",
        metavar="KEY",
        help="a condition key the request doesn't include, e.g. aws:MultiFactorAuthPresent",
    )
    return parser


def format_result(result: EvaluationResult, context: RequestContext = RequestContext()) -> str:
    """The decision, then each statement behind it. `context` is the request's context, used to
    show the values each condition was checked against."""
    lines = [result.decision.value]
    lines += [f"  {_not_allowed_message(layer)}" for layer in result.not_allowed_by]
    for reason in result.reasons:
        sid = reason.statement.sid or "(no Sid)"
        lines.append(f"  {reason.statement.effect.value:<6} {_source(reason)}  Sid={sid}")
        lines += [f"         {_condition(c, context)}" for c in reason.statement.conditions]
    return "\n".join(lines)


def _condition(condition: Condition, context: RequestContext) -> str:
    """A condition with the request's value for its key: "Bool aws:SecureTransport: true
    (request: true)"."""
    found = context.get(condition.key)
    request = "not present" if found is None else _values(found)
    return f"{condition.name} {condition.key}: {_values(condition.values)} (request: {request})"


def _values(values: Sequence[str]) -> str:
    return ", ".join(value or '""' for value in values)


def _source(reason: MatchedStatement) -> str:
    """The policy a statement came from, plus how that policy applies to the principal."""
    source = reason.policy_name
    if reason.via_group:
        source += f" (via group {reason.via_group})"
    if reason.layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        source += " (permissions boundary)"
    elif reason.layer.policy_type is PolicyType.SCP:
        source += f" (SCP on {_target(reason.layer.org_target)})"
    elif reason.layer.policy_type is PolicyType.RESOURCE_BASED:
        resource = reason.layer.resource
        on = "" if reason.policy_name == resource else f" on {resource}"
        source += f" (resource-based policy{on}, names {NAMES[reason.principal_match]})"
    return source


def _not_allowed_message(layer: Layer) -> str:
    if layer.policy_type is PolicyType.PERMISSIONS_BOUNDARY:
        return "The permissions boundary does not allow this."
    if layer.policy_type is PolicyType.SCP:
        return f"No SCP attached to {_target(layer.org_target)} allows this."
    if layer.policy_type is PolicyType.RESOURCE_BASED:
        return f"The resource-based policy on {layer.resource} does not allow this either."
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
    if args.no_session_tags and not args.account:
        parser.error("--no-session-tags only works with --account")
    for flag, given in (("--resource-policy", args.resource_policy),
                        ("--no-resource-policy", args.no_resource_policy)):
        if given and args.account:
            parser.error(
                f"{flag} only works with --policy; in an account file, describe the resource in "
                "Resources"
            )
    if args.resource_policy and args.no_resource_policy:
        parser.error("--resource-policy and --no-resource-policy can't be used together")

    try:
        context = RequestContext.of(args.context or (), args.absent or ())
        if args.account:
            account = load_account_file(args.account)
            policies = account.policies_for(args.principal)
            boundary = account.boundary_for(args.principal)
            scps = _scp_levels(account, args.principal, args.org) if args.org else ()
            principal = account.principal_context(
                args.principal, session_tags=not args.no_session_tags
            )
            context = principal.merged(context)
            resource = account.resource_for(args.resource, args.action)
        else:
            policies = [load_policy_file(path) for path in args.policy]
            boundary = load_policy_file(args.boundary) if args.boundary else None
            scps = ()
            resource = None
            if args.resource_policy:
                resource = resources.load_resource_policy_file(
                    args.resource_policy, args.resource, args.action
                )
            elif args.no_resource_policy:
                resource = resources.describe(args.resource, args.action)
        request = Request(action=args.action, resource=args.resource, context=context)
        result = evaluate(request, policies, boundary=boundary, scps=scps, resource=resource)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if isinstance(exc, MissingContextError):
            print(MISSING_CONTEXT_HINT, file=sys.stderr)
        elif isinstance(exc, MissingResourceError):
            print(MISSING_RESOURCE_HINT["account" if args.account else "policy"], file=sys.stderr)
        return EXIT_INPUT_ERROR

    print(format_result(result, request.context))
    return EXIT_ALLOWED if result.allowed else EXIT_DENIED


def _scp_levels(account: Account, principal: str, org_file: str) -> tuple[ScpLevel, ...]:
    """The SCP levels in the organization file that apply to `principal` in `account`."""
    if account.account_id is None:
        raise AccountError(f"{account.name}: needs an 'AccountId' to look up its SCPs")
    return load_organization_file(org_file).scp_levels_for(
        account.account_id, service_linked=account.is_service_linked(principal)
    )


if __name__ == "__main__":
    sys.exit(main())
